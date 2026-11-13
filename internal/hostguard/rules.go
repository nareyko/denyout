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
	// Redirect this user's TCP 80/443 to local proxy; skip loopback and proxy port itself.
	var b strings.Builder
	fmt.Fprintf(&b, "table ip denyout {\n")
	fmt.Fprintf(&b, "  chain output {\n")
	fmt.Fprintf(&b, "    type nat hook output priority -100; policy accept;\n")
	fmt.Fprintf(&b, "    meta skuid %d tcp dport { 80, 443 } ip daddr != 127.0.0.0/8 redirect to :%d\n", spec.UID, spec.ProxyPort)
	fmt.Fprintf(&b, "  }\n")
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
