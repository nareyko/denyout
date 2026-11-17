//go:build linux

package tun

import (
	"fmt"
	"github.com/nareyko/denyout/internal/privexec"
)

// ApplyVPNEgress installs mark→table→iface routes (root). Caller must gate with WantVPNEgressApply.
func ApplyVPNEgress(iface string) error {
	if err := ValidateVPNEgressIface(iface); err != nil {
		return err
	}
	if !WantVPNEgressApply() {
		return fmt.Errorf("tun: vpn egress apply disabled (set %s=1)", EnvVPNEgressE2E)
	}
	tbl, mark, prio := fmt.Sprintf("%d", VPNTableID), fmt.Sprintf("0x%x", DenyOutMark), fmt.Sprintf("%d", VPNRulePriority)
	if err := privexec.Run("ip", "route", "replace", "default", "dev", iface, "table", tbl); err != nil {
		return fmt.Errorf("tun: vpn egress apply: %w", err)
	}
	privexec.Best("ip", "rule", "del", "fwmark", mark, "lookup", tbl, "priority", prio)
	if err := privexec.Run("ip", "rule", "add", "fwmark", mark, "lookup", tbl, "priority", prio); err != nil {
		return fmt.Errorf("tun: vpn egress apply: %w", err)
	}
	return nil
}

// RemoveVPNEgress deletes DenyOut VPN policy routing (best-effort).
func RemoveVPNEgress() error {
	privexec.Best("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", DenyOutMark), "lookup", fmt.Sprintf("%d", VPNTableID), "priority", fmt.Sprintf("%d", VPNRulePriority))
	privexec.Best("ip", "route", "flush", "table", fmt.Sprintf("%d", VPNTableID))
	return nil
}
