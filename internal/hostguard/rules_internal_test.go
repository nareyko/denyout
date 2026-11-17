package hostguard

import (
	"strings"
	"testing"
)

func TestRenderNFTKeepsIPv6GuardUnderTUN(t *testing.T) {
	out := renderLinuxNFT(Spec{ProxyPort: 18443, UID: 1000, TunTCP: true, TunV6Guard: true, AllowQUIC: true, TunV6DropQUIC: true})
	if strings.Contains(out, "ip daddr != 127.0.0.0/8 redirect") {
		t.Error("IPv4 redirect must be omitted while TUN owns IPv4")
	}
	if !strings.Contains(out, "ip6 daddr != ::1 redirect to :18443") {
		t.Error("IPv6 redirect must stay under TUN")
	}
	if !strings.Contains(out, "nfproto ipv6") || !strings.Contains(out, "udp dport 443") {
		t.Error("IPv6 QUIC drop must stay under TUN")
	}
	plain := renderLinuxNFT(Spec{ProxyPort: 18443, UID: 1000, TunTCP: true, AllowQUIC: true})
	if strings.Contains(plain, "ip6 daddr") {
		t.Error("without TunV6Guard nothing is redirected (legacy behaviour)")
	}
}
