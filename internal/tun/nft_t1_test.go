package tun_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestRenderT1SteerTable(t *testing.T) {
	out := tun.RenderT1SteerTable(1000)
	for _, want := range []string{
		"table inet denyout-tun",
		fmt.Sprintf("meta mark %d return", tun.DenyOutMark),
		"meta skuid 1000 udp dport 443",
		"denyout-tun-quic",
		"meta mark set",
		"type route hook output",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// Must not open a device or reference hostguard apply side effects.
	if strings.Contains(out, "/dev/net/tun") {
		t.Fatal("render must stay string-only")
	}
}

func TestRollbackHint(t *testing.T) {
	h := tun.RollbackHint()
	if !strings.Contains(h, tun.DeviceName) || !strings.Contains(h, "tun-stop") {
		t.Fatalf("%q", h)
	}
}

func TestDeviceConstants(t *testing.T) {
	if tun.DeviceName != "denyout0" {
		t.Fatal(tun.DeviceName)
	}
	if !strings.HasPrefix(tun.AddrCIDR, "198.18.") {
		t.Fatal(tun.AddrCIDR)
	}
}
