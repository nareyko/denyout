package tun

import (
	"fmt"
	"strings"
)

// DeviceName is the planned Linux TUN iface for T1 (not created in CI).
const DeviceName = "denyout0"

// AddrCIDR is a Clash-like CGNAT block reserved for the TUN address.
const AddrCIDR = "198.18.0.1/16"

// RenderT1SteerTable returns nft rules that steer UID UDP/443 toward denyout0
// via fwmark (closed-loop string — applied by Runtime.StartReal on Linux).
func RenderT1SteerTable(uid int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet denyout-tun {\n")
	fmt.Fprintf(&b, "  chain output {\n")
	fmt.Fprintf(&b, "    type route hook output priority -150; policy accept;\n")
	fmt.Fprintf(&b, "    meta mark %d return\n", DenyOutMark)
	fmt.Fprintf(&b, "    meta skuid %d udp dport 443 counter meta mark set 0x%x comment \"denyout-tun-quic\"\n", uid, SteerMarkDoc)
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "# ip rule add fwmark 0x%x lookup %d priority %d\n", SteerMarkDoc, SteerTableDoc, SteerPrioDoc)
	fmt.Fprintf(&b, "# ip route replace default dev %s table %d\n", DeviceName, SteerTableDoc)
	return b.String()
}

// Documented steer constants for render/tests (keep in sync with runtime_linux.go).
const (
	SteerMarkDoc  = 0x64756e
	SteerTableDoc = 647
	SteerPrioDoc  = 6470
)

// RollbackHint is the operator-facing restore path to T0 nft-only Protect.
func RollbackHint() string {
	return "tun-stop; ip link delete " + DeviceName + " 2>/dev/null; restore T0 hostguard apply (nft denyout-block-quic)"
}
