//go:build linux

package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

const (
	// SteerMark marks UID UDP/443 (and TCP when T3) for policy routing into denyout0 ('tun').
	SteerMark = 0x64756e
	// SteerTableID is the routing table for TUN path.
	SteerTableID = 647
	// SteerRulePriority for the fwmark → TUN table rule.
	SteerRulePriority = 6470
)

// StartOpts configures real denyout0 bring-up.
type StartOpts struct {
	UID        int
	ProxyPort  int  // local proxyd for T3 TCP handoff
	EnableTCP  bool // T3: steer TCP 80/443 into gVisor
	QUICMITM   bool // Q2 gate (inspector); actual MITM sessions optional
	MITM       MITMConfig
	OnSighting func(QUICDecision)
}

// StartReal creates denyout0, steers traffic, and reads/drops (or netstacks TCP).
func (r *Runtime) StartReal(uid int) error {
	return r.StartRealOpts(StartOpts{UID: uid, EnableTCP: true})
}

// StartRealOpts is the full G3–G6 bring-up entrypoint.
func (r *Runtime) StartRealOpts(opts StartOpts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return nil
	}
	uid := opts.UID
	if uid <= 0 {
		return fmt.Errorf("tun: uid required")
	}

	_ = destroyDeviceBestEffort()
	_ = removeSteerBestEffort(uid)

	dev, err := wgtun.CreateTUN(DeviceName, 1500)
	if err != nil {
		return fmt.Errorf("tun: create %s: %w", DeviceName, err)
	}
	name, _ := dev.Name()
	if name != "" && name != DeviceName {
		_ = dev.Close()
		return fmt.Errorf("tun: got iface %q want %s", name, DeviceName)
	}
	if err := exec.Command("ip", "addr", "replace", AddrCIDR, "dev", DeviceName).Run(); err != nil {
		_ = dev.Close()
		_ = destroyDeviceBestEffort()
		return fmt.Errorf("tun: addr: %w", err)
	}
	if err := exec.Command("ip", "link", "set", DeviceName, "up").Run(); err != nil {
		_ = dev.Close()
		_ = destroyDeviceBestEffort()
		return fmt.Errorf("tun: link up: %w", err)
	}
	if err := applySteer(uid, opts.EnableTCP); err != nil {
		_ = dev.Close()
		_ = destroyDeviceBestEffort()
		_ = removeSteerBestEffort(uid)
		return err
	}

	var ns *Netstack
	if opts.EnableTCP {
		proxyPort := opts.ProxyPort
		ns, err = NewNetstack(func(conn net.Conn, dstIP net.IP, dstPort uint16) {
			defer conn.Close()
			if proxyPort <= 0 {
				return
			}
			upstream, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()
			errCh := make(chan struct{}, 2)
			go func() { _, _ = copyClose(upstream, conn); errCh <- struct{}{} }()
			go func() { _, _ = copyClose(conn, upstream); errCh <- struct{}{} }()
			<-errCh
			_ = dstIP
			_ = dstPort
		})
		if err != nil {
			_ = dev.Close()
			_ = destroyDeviceBestEffort()
			_ = removeSteerBestEffort(uid)
			return err
		}
	}

	mitmOn := opts.QUICMITM || WantQUICMITM()
	var bridge *quicTUNPacketConn
	var mitmCancel context.CancelFunc
	if mitmOn && opts.MITM.GetCertificate != nil {
		bridge = newQUICTUNPacketConn(func(dst, src *net.UDPAddr, payload []byte) error {
			pkt := buildIPv4UDP(src, dst, payload)
			_, err := writeTUN(dev, pkt)
			return err
		})
		mitmCtx, cancel := context.WithCancel(context.Background())
		mitmCancel = cancel
		ln, lerr := ListenMITM(mitmCtx, bridge, opts.MITM)
		if lerr != nil {
			cancel()
			_ = bridge.Close()
			if ns != nil {
				ns.Close()
			}
			_ = dev.Close()
			_ = destroyDeviceBestEffort()
			_ = removeSteerBestEffort(uid)
			return fmt.Errorf("tun: quic mitm listen: %w", lerr)
		}
		go func() {
			_ = ServeHTTP3MITM(mitmCtx, ln, opts.MITM, nil)
			_ = ln.Close()
		}()
	}

	done := make(chan struct{})
	var closed bool
	insp := DefaultQUICInspector{MITM: mitmOn}
	onSight := opts.OnSighting
	if onSight == nil {
		onSight = func(dec QUICDecision) {
			r.RecordSighting(dec.SNI)
			log.Printf("denyout tun quic sight action=%s sni=%q reason=%s", dec.Action, dec.SNI, dec.Reason)
		}
	} else {
		user := onSight
		onSight = func(dec QUICDecision) {
			r.RecordSighting(dec.SNI)
			user(dec)
		}
	}
	if ns != nil {
		go func() {
			_ = ns.ReadOutbound(&tunWriter{dev: dev})
		}()
	}
	go readLoop(dev, r, ns, insp, onSight, bridge, done)
	r.cancel = func() {
		if !closed {
			closed = true
			close(done)
		}
		if mitmCancel != nil {
			mitmCancel()
		}
		if bridge != nil {
			_ = bridge.Close()
		}
		if ns != nil {
			ns.Close()
		}
		_ = dev.Close()
	}
	r.active = true
	r.uid = uid
	r.resetCountersLocked()
	return nil
}

// tunWriteOffset is headroom for virtio_net_hdr required by wireguard-go TUN Write.
const tunWriteOffset = 16

type tunWriter struct{ dev wgtun.Device }

func writeTUN(dev wgtun.Device, p []byte) (int, error) {
	buf := make([]byte, tunWriteOffset+len(p))
	copy(buf[tunWriteOffset:], p)
	n, err := dev.Write([][]byte{buf}, tunWriteOffset)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return len(p), nil
	}
	return 0, nil
}

func (t *tunWriter) Write(p []byte) (int, error) {
	return writeTUN(t.dev, p)
}

func copyClose(dst, src net.Conn) (int64, error) {
	n, err := ioCopy(dst, src)
	return n, err
}

func ioCopy(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
		}
		if er != nil {
			return written, er
		}
	}
}

// StopReal removes steer, stops reader, deletes denyout0.
func (r *Runtime) StopReal() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	uid := r.uid
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
		time.Sleep(50 * time.Millisecond)
	}
	_ = removeSteerBestEffort(uid)
	_ = destroyDeviceBestEffort()
	r.active = false
	r.uid = 0
	return nil
}

func readLoop(dev wgtun.Device, r *Runtime, ns *Netstack, insp DefaultQUICInspector, onSight func(QUICDecision), bridge *quicTUNPacketConn, done <-chan struct{}) {
	defer func() { _ = dev.Close() }()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 2048)
	sizes := make([]int, 1)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			cl, cerr := ClassifyIPPacket(pkt, SteerMark, 0)
			if cerr == nil && strings.EqualFold(cl.Proto, "udp") && cl.DstPort == 443 {
				src, dst, payload, pok := parseIPv4UDP(pkt)
				decideBuf := pkt
				if pok {
					decideBuf = payload
				}
				dec := insp.Decide(nil, decideBuf)
				if onSight != nil && (dec.Action == QUICActionSight || dec.Action == QUICActionMITM || dec.HasSNI()) {
					onSight(dec)
				}
				if dec.Action == QUICActionMITM && bridge != nil && pok {
					bridge.push(quicDatagram{payload: payload, from: src, to: dst})
					continue
				}
				r.addDrop(len(pkt))
				continue
			}
			if ns != nil && cerr == nil && strings.EqualFold(cl.Proto, "tcp") {
				ns.InjectInbound(pkt)
				continue
			}
			if ns != nil && cerr != nil {
				ver := 0
				if len(pkt) > 0 {
					ver = int(pkt[0] >> 4)
				}
				if ver == 4 || ver == 6 {
					ns.InjectInbound(pkt)
					continue
				}
			}
			r.addDrop(len(pkt))
		}
	}
}

func (d QUICDecision) HasSNI() bool { return strings.TrimSpace(d.SNI) != "" }

func applySteer(uid int, enableTCP bool) error {
	tcpRules := ""
	if enableTCP {
		tcpRules = fmt.Sprintf(`
    meta skuid %d tcp dport { 80, 443 } counter meta mark set 0x%x comment "denyout-tun-tcp"
`, uid, SteerMark)
	}
	script := strings.Join([]string{
		`nft delete table inet denyout-tun 2>/dev/null || true`,
		fmt.Sprintf(`nft -f - <<'EOF'
table inet denyout-tun {
  chain output {
    type route hook output priority -150; policy accept;
    meta mark 0x%x return
    meta skuid %d udp dport 443 counter meta mark set 0x%x comment "denyout-tun-quic"
%s  }
}
EOF`, DenyOutMark, uid, SteerMark, tcpRules),
		fmt.Sprintf(`ip route replace default dev %s table %d`, DeviceName, SteerTableID),
		fmt.Sprintf(`ip rule del fwmark 0x%x lookup %d priority %d 2>/dev/null || true`, SteerMark, SteerTableID, SteerRulePriority),
		fmt.Sprintf(`ip rule add fwmark 0x%x lookup %d priority %d`, SteerMark, SteerTableID, SteerRulePriority),
	}, "\n")
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: steer: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeSteerBestEffort(uid int) error {
	_ = uid
	_ = exec.Command("nft", "delete", "table", "inet", "denyout-tun").Run()
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", SteerMark), "lookup", fmt.Sprintf("%d", SteerTableID), "priority", fmt.Sprintf("%d", SteerRulePriority)).Run()
	_ = exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", SteerTableID)).Run()
	return nil
}

func destroyDeviceBestEffort() error {
	_ = exec.Command("ip", "link", "delete", DeviceName).Run()
	return nil
}
