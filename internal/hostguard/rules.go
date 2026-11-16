package hostguard

import (
	"fmt"
	"runtime"
	"strings"
)

// renderRules returns platform-specific redirect configuration text (no side effects).
func renderRules(spec Spec) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return renderLinuxNFT(spec), nil
	case "darwin":
		return renderDarwinPF(spec), nil
	case "windows":
		return renderWindowsDivert(spec), nil
	default:
		return "", ErrUnsupported
	}
}

func renderLinuxNFT(spec Spec) string {
	// Redirect this user's TCP 80/443 (IPv4+IPv6) to local proxy; skip loopback.
	// Skip mark 0x646e79 ('dny') so DenyOut upstream dials are not redirected (loop).
	// Default: also drop UDP/443 (QUIC/HTTP3) so browsers fall back to TCP MITM.
	const mark = 0x646e79
	var b strings.Builder
	fmt.Fprintf(&b, "table inet denyout {\n")
	fmt.Fprintf(&b, "  chain output {\n")
	fmt.Fprintf(&b, "    type nat hook output priority -100; policy accept;\n")
	fmt.Fprintf(&b, "    meta mark %d return\n", mark)
	if !spec.TunTCP {
		fmt.Fprintf(&b, "    meta skuid %d tcp dport { 80, 443 } ip daddr != 127.0.0.0/8 redirect to :%d\n", spec.UID, spec.ProxyPort)
		fmt.Fprintf(&b, "    meta skuid %d tcp dport { 80, 443 } ip6 daddr != ::1 redirect to :%d\n", spec.UID, spec.ProxyPort)
	} else {
		fmt.Fprintf(&b, "    # TunTCP: TCP 80/443 steered to denyout0 / gVisor (no redirect)\n")
	}
	fmt.Fprintf(&b, "  }\n")
	if !spec.AllowQUIC {
		fmt.Fprintf(&b, "  chain output_filter {\n")
		fmt.Fprintf(&b, "    type filter hook output priority 0; policy accept;\n")
		fmt.Fprintf(&b, "    meta mark %d return\n", mark)
		// counter makes silent UDP/443 drops visible via `nft list` / hostctl quic-stats.
		fmt.Fprintf(&b, "    meta skuid %d udp dport 443 counter drop comment \"denyout-block-quic\"\n", spec.UID)
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func renderDarwinPF(spec Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DenyOut pf anchor — redirect user TCP 80/443 to local proxy\n")
	fmt.Fprintf(&b, "rdr pass on lo0 proto tcp from any to any port 80 -> 127.0.0.1 port %d\n", spec.ProxyPort)
	fmt.Fprintf(&b, "rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port %d\n", spec.ProxyPort)
	fmt.Fprintf(&b, "pass out quick on lo0 proto tcp to 127.0.0.1 port %d\n", spec.ProxyPort)
	fmt.Fprintf(&b, "# uid filter applied via group/anchor load; target uid=%d\n", spec.UID)
	fmt.Fprintf(&b, "pass out route-to (lo0 127.0.0.1) proto tcp from any to any port {80,443} user %d\n", spec.UID)
	if !spec.AllowQUIC {
		fmt.Fprintf(&b, "# Block QUIC/HTTP3 so browsers fall back to TCP HTTPS (MITM)\n")
		fmt.Fprintf(&b, "block drop out quick proto udp from any to any port 443 user %d\n", spec.UID)
	}
	return b.String()
}

func renderWindowsDivert(spec Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DenyOut WinDivert filter — capture outbound TCP 80/443 for local divert\n")
	fmt.Fprintf(&b, "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443)\n")
	fmt.Fprintf(&b, "# proxy_port=%d\n", spec.ProxyPort)
	fmt.Fprintf(&b, "# ca=%s\n", spec.CACert)
	return b.String()
}
