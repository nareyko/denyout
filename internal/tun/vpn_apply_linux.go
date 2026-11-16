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
	script := strings.Join([]string{
		fmt.Sprintf("ip route replace default dev %s table %d", iface, VPNTableID),
		fmt.Sprintf("ip rule del fwmark 0x%x lookup %d priority %d 2>/dev/null || true", DenyOutMark, VPNTableID, VPNRulePriority),
		fmt.Sprintf("ip rule add fwmark 0x%x lookup %d priority %d", DenyOutMark, VPNTableID, VPNRulePriority),
	}, "\n")
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
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
