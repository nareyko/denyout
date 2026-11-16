package tun

import (
	"fmt"
	"os"
	"strings"
)

// VPN egress routing (Linux): marked DenyOut upstream dials → VPN iface.
// Closed-loop: render/validate only unless DENYOUT_VPN_EGRESS_E2E=1 (VM).

const (
	// EnvVPNEgressE2E opts into real ip rule/route mutation (never default Protect).
	EnvVPNEgressE2E = "DENYOUT_VPN_EGRESS_E2E"

	// VPNTableID is a stable custom routing table id for DenyOut→VPN.
	VPNTableID = 646
	// VPNTableName is the iproute2 name we document alongside the numeric id.
	VPNTableName = "denyout-vpn"
	// VPNRulePriority keeps DenyOut VPN policy above typical user rules, below local.
	VPNRulePriority = 6460
)

// WantVPNEgressApply reports whether kernel ip rule/route may be changed.
func WantVPNEgressApply() bool {
	return os.Getenv(EnvVPNEgressE2E) == "1"
}

// VPNEgressPlan is the closed-loop command list (not executed here).
type VPNEgressPlan struct {
	Iface  string
	Mark   uint32
	Table  int
	Priority int
	Lines  []string // shell-like commands for operators / future helper
}

// ValidateVPNEgressIface rejects loopback, our TUN, and coexistence denylist names
// that must not be used as VPN egress.
func ValidateVPNEgressIface(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fmt.Errorf("tun: vpn egress iface required")
	}
	if iface == DeviceName {
		return fmt.Errorf("tun: %s is DenyOut ingress, not VPN egress", DeviceName)
	}
	if ShouldSkipIface(iface) {
		// Note: wg* / cloudflare / tailscale are skip-listed as "do not steal".
		// Using them *as* the egress target is the intended VPN case — allow those.
		n := strings.ToLower(iface)
		vpnOK := strings.HasPrefix(n, "wg") ||
			strings.HasPrefix(n, "cloudflare") ||
			strings.HasPrefix(n, "tailscale") ||
			strings.HasPrefix(n, "zt") ||
			n == "tun0" // common userspace VPN tun name (not denyout0)
		if !vpnOK {
			return fmt.Errorf("tun: iface %q is not a valid VPN egress target", iface)
		}
	}
	low := strings.ToLower(iface)
	if low == "lo" || low == "docker0" || strings.HasPrefix(low, "br-") || strings.HasPrefix(low, "veth") {
		return fmt.Errorf("tun: iface %q cannot be VPN egress", iface)
	}
	return nil
}

// BuildVPNEgressPlan returns ip-rule/ip-route commands for DenyOut mark → VPN.
func BuildVPNEgressPlan(iface string) (VPNEgressPlan, error) {
	if err := ValidateVPNEgressIface(iface); err != nil {
		return VPNEgressPlan{}, err
	}
	p := VPNEgressPlan{
		Iface:    iface,
		Mark:     DenyOutMark,
		Table:    VPNTableID,
		Priority: VPNRulePriority,
	}
	p.Lines = []string{
		fmt.Sprintf("# DenyOut → VPN egress (mark 0x%x → table %d/%s via %s)", DenyOutMark, VPNTableID, VPNTableName, iface),
		fmt.Sprintf("# Apply only with %s=1 on a VM; Protect Off must remove these.", EnvVPNEgressE2E),
		fmt.Sprintf("ip route replace default dev %s table %d", iface, VPNTableID),
		fmt.Sprintf("ip rule add fwmark 0x%x lookup %d priority %d", DenyOutMark, VPNTableID, VPNRulePriority),
		fmt.Sprintf("# rollback: ip rule del fwmark 0x%x lookup %d priority %d; ip route flush table %d", DenyOutMark, VPNTableID, VPNRulePriority, VPNTableID),
	}
	return p, nil
}

// FormatVPNEgressPlan prints the plan for hostctl / docs.
func FormatVPNEgressPlan(iface string) (string, error) {
	p, err := BuildVPNEgressPlan(iface)
	if err != nil {
		return "", err
	}
	return strings.Join(p.Lines, "\n") + "\n", nil
}

// FormatVPNEgressRollback is the remove half (closed-loop string).
func FormatVPNEgressRollback() string {
	return strings.Join([]string{
		fmt.Sprintf("ip rule del fwmark 0x%x lookup %d priority %d 2>/dev/null || true", DenyOutMark, VPNTableID, VPNRulePriority),
		fmt.Sprintf("ip route flush table %d 2>/dev/null || true", VPNTableID),
	}, "\n") + "\n"
}
