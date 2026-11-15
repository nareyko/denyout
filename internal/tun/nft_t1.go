package tun

import (
	"fmt"
	"strings"
)

// DeviceName is the planned Linux TUN iface for T1 (not created in CI).
const DeviceName = "denyout0"

// AddrCIDR is a Clash-like CGNAT block reserved for the TUN address.
const AddrCIDR = "198.18.0.1/16"

// RenderT1SteerTable returns nft rules that would steer UID UDP/443 toward the
// TUN path instead of silent drop. Closed-loop string only — never applied here.
//
// Note: real steering needs tproxy/policy-routing glue in the helper; this table
// documents the intended filter shape and keeps mark-skip parity with T0.
func RenderT1SteerTable(uid int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet denyout-tun {\n")
	fmt.Fprintf(&b, "  chain output {\n")
	fmt.Fprintf(&b, "    type filter hook output priority -150; policy accept;\n")
	fmt.Fprintf(&b, "    meta mark %d return\n", DenyOutMark)
	// Comment marks intent; helper will replace "drop" with tproxy/tun redirect later.
	fmt.Fprintf(&b, "    meta skuid %d udp dport 443 counter drop comment \"denyout-tun-quic\"\n", uid)
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// RollbackHint is the operator-facing restore path to T0 nft-only Protect.
func RollbackHint() string {
	return "tun-stop; ip link delete " + DeviceName + " 2>/dev/null; restore T0 hostguard apply (nft denyout-block-quic)"
}
