package tun

import (
	"fmt"
	"strings"
)

// DevicePlan is the closed-loop command list to create denyout0 (not executed here).
type DevicePlan struct {
	Name   string
	Addr   string
	Lines  []string
}

// BuildDevicePlan returns ip tuntap / addr / link commands for T1 device bring-up.
// Kernel apply stays behind DENYOUT_TUN_E2E=1 on a VM (G3); this is G2 render only.
func BuildDevicePlan() DevicePlan {
	p := DevicePlan{
		Name: DeviceName,
		Addr: AddrCIDR,
	}
	p.Lines = []string{
		fmt.Sprintf("# T1 TUN device plan (%s %s) — render only", DeviceName, AddrCIDR),
		fmt.Sprintf("# Apply only with %s=1 on a throwaway VM; Protect Off must delete the device.", EnvE2E),
		fmt.Sprintf("ip tuntap add mode tun %s", DeviceName),
		fmt.Sprintf("ip addr add %s dev %s", AddrCIDR, DeviceName),
		fmt.Sprintf("ip link set %s up", DeviceName),
		fmt.Sprintf("# rollback: ip link delete %s 2>/dev/null || true", DeviceName),
	}
	return p
}

// FormatDevicePlan prints the bring-up plan for hostctl / docs.
func FormatDevicePlan() string {
	return strings.Join(BuildDevicePlan().Lines, "\n") + "\n"
}

// FormatDeviceRollback is the remove half (closed-loop string).
func FormatDeviceRollback() string {
	return strings.Join([]string{
		fmt.Sprintf("ip link delete %s 2>/dev/null || true", DeviceName),
		"# then restore T0: denyout-cli hostctl apply (nft denyout-block-quic)",
	}, "\n") + "\n"
}
