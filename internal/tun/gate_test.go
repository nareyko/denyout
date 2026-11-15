package tun_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestWantDeviceDefaultOff(t *testing.T) {
	t.Setenv(tun.EnvE2E, "")
	if tun.WantDevice() {
		t.Fatal("default must not want TUN device")
	}
	if tun.ActivePhase() != tun.PhaseT0NFTOnly {
		t.Fatalf("phase=%s", tun.ActivePhase())
	}
}

func TestWantDeviceE2EOptIn(t *testing.T) {
	t.Setenv(tun.EnvE2E, "1")
	if !tun.WantDevice() {
		t.Fatal("DENYOUT_TUN_E2E=1 must opt in")
	}
	if tun.ActivePhase() != tun.PhaseT1UDP443 {
		t.Fatalf("phase=%s", tun.ActivePhase())
	}
	// Even with opt-in, EnabledForPhase is about phase shape — device open still elsewhere.
	if !tun.EnabledForPhase(tun.ActivePhase()) {
		t.Fatal("T1 phase enables TUN shape")
	}
}

func TestShouldSkipIface(t *testing.T) {
	for _, name := range []string{"lo", "docker0", "br-abc", "veth123", "wg0", "tun0", "zt0", "tailscale0", "Cloudflare"} {
		if !tun.ShouldSkipIface(name) {
			t.Fatalf("expected skip %q", name)
		}
	}
	if tun.ShouldSkipIface(tun.DeviceName) {
		t.Fatal("denyout0 is ours, not skipped")
	}
	if tun.ShouldSkipIface("eth0") {
		t.Fatal("eth0 must not be skipped")
	}
}
