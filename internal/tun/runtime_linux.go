//go:build linux

package tun

import (
	"context"
	"fmt"
	"github.com/nareyko/denyout/internal/privexec"
	"log"
	"net"
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
//
// Every step that leaves state behind registers an undo on the rollback list;
// a failing step runs the list newest-first (steer is removed before the device
// goes away) and the list is discarded on success.
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

	var undo undoList
	fail := func(err error) error { undo.run(); return err }

	dev, err := createDevice(&undo)
	if err != nil {
		return fail(err)
	}
	undo.add(func() { _ = removeSteerBestEffort(uid) })
	if err := applySteer(uid, opts.EnableTCP); err != nil {
		return fail(err)
	}

	var ns *Netstack
	if opts.EnableTCP {
		if ns, err = NewNetstack(proxyHandoff(opts.ProxyPort)); err != nil {
			return fail(err)
		}
		undo.add(ns.Close)
	}

	mitmOn := opts.QUICMITM || WantQUICMITM()
	bridge, mitmCancel, err := startQUICMITM(dev, opts, mitmOn, &undo)
	if err != nil {
		return fail(err)
	}

	done := make(chan struct{})
	insp := DefaultQUICInspector{MITM: mitmOn}
	onSight := r.sightingHandler(opts.OnSighting)
	if ns != nil {
		go func() {
			_ = ns.ReadOutbound(&tunWriter{dev: dev})
		}()
	}
	go readLoop(dev, r, ns, insp, onSight, bridge, done)
	r.cancel = newStopFunc(done, mitmCancel, bridge, ns, dev)
	r.active = true
	r.uid = uid
	r.resetCountersLocked()
	return nil
}

// undoList is a rollback list: add after each successful step, run on failure.
type undoList []func()

func (u *undoList) add(f func()) { *u = append(*u, f) }

// run executes the undos newest-first and empties the list.
func (u *undoList) run() {
	for i := len(*u) - 1; i >= 0; i-- {
		(*u)[i]()
	}
	*u = nil
}

// createDevice creates denyout0, addresses it and brings it up. On success
// the device-close+delete undo is registered; on failure nothing is left.
func createDevice(undo *undoList) (wgtun.Device, error) {
	dev, err := wgtun.CreateTUN(DeviceName, 1500)
	if err != nil {
		return nil, fmt.Errorf("tun: create %s: %w", DeviceName, err)
	}
	name, _ := dev.Name()
	if name != "" && name != DeviceName {
		_ = dev.Close()
		return nil, fmt.Errorf("tun: got iface %q want %s", name, DeviceName)
	}
	undo.add(func() {
		_ = dev.Close()
		_ = destroyDeviceBestEffort()
	})
	if err := privexec.Run("ip", "addr", "replace", AddrCIDR, "dev", DeviceName); err != nil {
		return nil, fmt.Errorf("tun: addr: %w", err)
	}
	if err := privexec.Run("ip", "link", "set", DeviceName, "up"); err != nil {
		return nil, fmt.Errorf("tun: link up: %w", err)
	}
	return dev, nil
}

// proxyHandoff returns the gVisor TCP handler that relays each accepted
// connection to the local proxy on 127.0.0.1:proxyPort (dial timeout 5s).
// proxyPort <= 0 closes the connection.
func proxyHandoff(proxyPort int) TCPHandler {
	return func(conn net.Conn, _ net.IP, _ uint16) {
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
	}
}

// startQUICMITM brings up the QUIC MITM bridge+listener when requested and a
// certificate source is configured; otherwise returns nils.
func startQUICMITM(dev wgtun.Device, opts StartOpts, mitmOn bool, undo *undoList) (*quicTUNPacketConn, context.CancelFunc, error) {
	if !mitmOn || opts.MITM.GetCertificate == nil {
		return nil, nil, nil
	}
	bridge := newQUICTUNPacketConn(func(dst, src *net.UDPAddr, payload []byte) error {
		pkt := buildIPv4UDP(src, dst, payload)
		_, err := writeTUN(dev, pkt)
		return err
	})
	mitmCtx, cancel := context.WithCancel(context.Background())
	ln, lerr := ListenMITM(mitmCtx, bridge, opts.MITM)
	if lerr != nil {
		cancel()
		_ = bridge.Close()
		return nil, nil, fmt.Errorf("tun: quic mitm listen: %w", lerr)
	}
	undo.add(func() { cancel(); _ = bridge.Close() })
	go func() {
		_ = ServeHTTP3MITM(mitmCtx, ln, opts.MITM, nil)
		_ = ln.Close()
	}()
	return bridge, cancel, nil
}

// sightingHandler wraps the optional user callback: every sighting is recorded
// in the runtime counters first; without a callback it is logged.
func (r *Runtime) sightingHandler(user func(QUICDecision)) func(QUICDecision) {
	if user == nil {
		return func(dec QUICDecision) {
			r.RecordSighting(dec.SNI)
			log.Printf("denyout tun quic sight action=%s sni=%q reason=%s", dec.Action, dec.SNI, dec.Reason)
		}
	}
	return func(dec QUICDecision) {
		r.RecordSighting(dec.SNI)
		user(dec)
	}
}

// newStopFunc builds Runtime.cancel: idempotent close of done, then tear down
// MITM, bridge, netstack and device.
func newStopFunc(done chan struct{}, mitmCancel context.CancelFunc, bridge *quicTUNPacketConn, ns *Netstack, dev wgtun.Device) func() {
	var closed bool
	return func() {
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
			dispatchPacket(bufs[i][:sizes[i]], r, ns, insp, onSight, bridge)
		}
	}
}

// dispatchPacket applies routePacket's decision to one packet.
func dispatchPacket(pkt []byte, r *Runtime, ns *Netstack, insp DefaultQUICInspector, onSight func(QUICDecision), bridge *quicTUNPacketConn) {
	rd := routePacket(pkt, insp, ns != nil, bridge != nil)
	if rd.sight && onSight != nil {
		onSight(rd.decision)
	}
	switch rd.verdict {
	case verdictNetstack:
		ns.InjectInbound(pkt)
	case verdictMITMQUIC:
		bridge.push(quicDatagram{payload: rd.payload, from: rd.src, to: rd.dst})
	default:
		r.addDrop(len(pkt))
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
	if err := privexec.ValidUID(uid); err != nil {
		return fmt.Errorf("tun: steer: %w", err)
	}
	ruleset := fmt.Sprintf(`table inet denyout-tun {
  chain output {
    type route hook output priority -150; policy accept;
    meta mark 0x%x return
    meta skuid %d udp dport 443 counter meta mark set 0x%x comment "denyout-tun-quic"
%s  }
}
`, DenyOutMark, uid, SteerMark, tcpRules)
	tbl, mark, prio := fmt.Sprintf("%d", SteerTableID), fmt.Sprintf("0x%x", SteerMark), fmt.Sprintf("%d", SteerRulePriority)
	privexec.Best("nft", "delete", "table", "inet", "denyout-tun")
	if out, err := privexec.OutputStdin(ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("tun: steer: nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := privexec.Run("ip", "route", "replace", "default", "dev", DeviceName, "table", tbl); err != nil {
		return fmt.Errorf("tun: steer: %w", err)
	}
	privexec.Best("ip", "rule", "del", "fwmark", mark, "lookup", tbl, "priority", prio)
	if err := privexec.Run("ip", "rule", "add", "fwmark", mark, "lookup", tbl, "priority", prio); err != nil {
		return fmt.Errorf("tun: steer: %w", err)
	}
	return nil
}

func removeSteerBestEffort(uid int) error {
	_ = uid
	privexec.Best("nft", "delete", "table", "inet", "denyout-tun")
	privexec.Best("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", SteerMark), "lookup", fmt.Sprintf("%d", SteerTableID), "priority", fmt.Sprintf("%d", SteerRulePriority))
	privexec.Best("ip", "route", "flush", "table", fmt.Sprintf("%d", SteerTableID))
	return nil
}

func destroyDeviceBestEffort() error {
	privexec.Best("ip", "link", "delete", DeviceName)
	return nil
}
