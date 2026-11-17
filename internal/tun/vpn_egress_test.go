package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestBuildVPNEgressPlanWireGuard(t *testing.T) {
	p, err := tun.BuildVPNEgressPlan("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mark != tun.DenyOutMark || p.Table != tun.VPNTableID {
		t.Fatalf("%+v", p)
	}
	txt := strings.Join(p.Lines, "\n")
	for _, want := range []string{
		"fwmark 0x646e79",
		"lookup 646",
		"default dev wg0",
		"table 646",
		tun.EnvVPNEgressE2E,
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("missing %q in:\n%s", want, txt)
		}
	}
}

func TestValidateVPNEgressIfaceRejectsBridge(t *testing.T) {
	for _, bad := range []string{"", "lo", "docker0", "br-abc", "veth123", tun.DeviceName} {
		if err := tun.ValidateVPNEgressIface(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestValidateVPNEgressIfaceAllowsVPNNames(t *testing.T) {
	for _, ok := range []string{"wg0", "wg-home", "cloudflare0", "tailscale0", "tun0"} {
		if err := tun.ValidateVPNEgressIface(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}

func TestWantVPNEgressApplyDefaultOff(t *testing.T) {
	t.Setenv(tun.EnvVPNEgressE2E, "")
	if tun.WantVPNEgressApply() {
		t.Fatal("default must not apply ip rules")
	}
	t.Setenv(tun.EnvVPNEgressE2E, "1")
	if !tun.WantVPNEgressApply() {
		t.Fatal("E2E opt-in")
	}
}

func TestFormatVPNEgressRollback(t *testing.T) {
	s := tun.FormatVPNEgressRollback()
	if !strings.Contains(s, "ip rule del") || !strings.Contains(s, "flush table 646") {
		t.Fatal(s)
	}
}

func TestValidateVPNEgressIfaceRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"wg0;touch${IFS}/x", "wg0$(id)", "wg0`id`", "wg0|id", "wg0&id", "wg 0",
		"wg0\nid", "wg0/../x", "wg0'", "wg0\"", "wg01234567890123456", " wg0", "wg0 ",
	} {
		if err := tun.ValidateVPNEgressIface(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
	if err := tun.ValidateVPNEgressIface("wg0"); err != nil {
		t.Errorf("wg0 should be valid: %v", err)
	}
}
