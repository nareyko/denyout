package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestBuildDevicePlan(t *testing.T) {
	p := tun.BuildDevicePlan()
	if p.Name != tun.DeviceName || p.Addr != tun.AddrCIDR {
		t.Fatalf("%+v", p)
	}
	txt := strings.Join(p.Lines, "\n")
	for _, want := range []string{
		"ip tuntap add mode tun " + tun.DeviceName,
		"ip addr add " + tun.AddrCIDR,
		"ip link set " + tun.DeviceName + " up",
		tun.EnvE2E,
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("missing %q in:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "/dev/net/tun") && strings.Contains(txt, "open(") {
		t.Fatal("plan must not open the device")
	}
}

func TestFormatDeviceRollback(t *testing.T) {
	s := tun.FormatDeviceRollback()
	if !strings.Contains(s, "ip link delete "+tun.DeviceName) {
		t.Fatal(s)
	}
	if !strings.Contains(s, "hostctl apply") {
		t.Fatal(s)
	}
}
