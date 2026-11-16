//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	// SteerMark marks UID UDP/443 for policy routing into denyout0 ('tun').
	SteerMark = 0x64756e
	// SteerTableID is the routing table for TUN UDP drop path.
	SteerTableID = 647
	// SteerRulePriority for the fwmark → TUN table rule.
	SteerRulePriority = 6470
)

// StartReal creates denyout0, steers UDP/443, and reads/drops packets.
func (r *Runtime) StartReal(uid int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return nil
	}
	if uid <= 0 {
		return fmt.Errorf("tun: uid required")
	}

	// Tear down leftovers from a crashed helper.
	_ = destroyDeviceBestEffort()
	_ = removeSteerBestEffort(uid)

	dev, err := tun.CreateTUN(DeviceName, 1500)
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
	if err := applySteer(uid); err != nil {
		_ = dev.Close()
		_ = destroyDeviceBestEffort()
		_ = removeSteerBestEffort(uid)
		return err
	}

	done := make(chan struct{})
	var closed bool
	go readLoop(dev, r, done)
	r.cancel = func() {
		if !closed {
			closed = true
			close(done)
		}
		_ = dev.Close()
	}
	r.active = true
	r.uid = uid
	r.packets.Store(0)
	r.bytes.Store(0)
	return nil
}

// StopReal removes steer, stops reader, deletes denyout0.
func (r *Runtime) StopReal() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	uid := r.uid
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
		// Allow reader to exit before deleting device.
		time.Sleep(50 * time.Millisecond)
	}
	_ = removeSteerBestEffort(uid)
	_ = destroyDeviceBestEffort()
	r.active = false
	r.uid = 0
	return nil
}

func readLoop(dev tun.Device, r *Runtime, done <-chan struct{}) {
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
			if cerr != nil {
				// Non-UDP or short: still count as dropped (blackhole path).
				r.addDrop(len(pkt))
				continue
			}
			if DecideT1(cl.Packet) == ActionDropLog {
				r.addDrop(len(pkt))
			} else {
				// Unexpected traffic on denyout0 — drop and count.
				r.addDrop(len(pkt))
			}
		}
	}
}

func applySteer(uid int) error {
	// Mark UID UDP/443 early enough to affect routing (route hook), then
	// policy-route marked packets into denyout0. T0 nft UDP drop must be
	// suppressed by the helper while this path is active.
	script := strings.Join([]string{
		`nft delete table inet denyout-tun 2>/dev/null || true`,
		fmt.Sprintf(`nft -f - <<'EOF'
table inet denyout-tun {
  chain output {
    type route hook output priority -150; policy accept;
    meta mark 0x%x return
    meta skuid %d udp dport 443 counter meta mark set 0x%x comment "denyout-tun-quic"
  }
}
EOF`, DenyOutMark, uid, SteerMark),
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
