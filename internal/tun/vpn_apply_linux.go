//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strings"
)

// ApplyVPNEgress installs mark→table→iface routes (root). Caller must gate with WantVPNEgressApply.
func ApplyVPNEgress(iface string) error {
	if err := ValidateVPNEgressIface(iface); err != nil {
		return err
	}
	if !WantVPNEgressApply() {
		return fmt.Errorf("tun: vpn egress apply disabled (set %s=1)", EnvVPNEgressE2E)
	}
	tbl := fmt.Sprintf("%d", VPNTableID)
	mark := fmt.Sprintf("0x%x", DenyOutMark)
	prio := fmt.Sprintf("%d", VPNRulePriority)
	// No shell: argv only, so the interface name can never be interpreted.
	if out, err := exec.Command("ip", "route", "replace", "default", "dev", iface, "table", tbl).CombinedOutput(); err != nil {
		return fmt.Errorf("tun: vpn egress apply: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("ip", "rule", "del", "fwmark", mark, "lookup", tbl, "priority", prio).Run()
	if out, err := exec.Command("ip", "rule", "add", "fwmark", mark, "lookup", tbl, "priority", prio).CombinedOutput(); err != nil {
		return fmt.Errorf("tun: vpn egress apply: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveVPNEgress deletes DenyOut VPN policy routing (best-effort).
func RemoveVPNEgress() error {
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", DenyOutMark), "lookup", fmt.Sprintf("%d", VPNTableID), "priority", fmt.Sprintf("%d", VPNRulePriority)).Run()
	_ = exec.Command("ip", "route", "flush", "table", fmt.Sprintf("%d", VPNTableID)).Run()
	return nil
}
