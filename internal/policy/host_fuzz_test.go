package policy

import (
	"strings"
	"testing"
)

func hostLike(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '*' || r == '_') {
			return false
		}
	}
	return true
}

// FuzzHostMatch checks HostMatch/normalizeHost never panic and keep the matching
// invariants the allow/deny lists depend on.
func FuzzHostMatch(f *testing.F) {
	for _, s := range [][2]string{
		{"example.com", "example.com"}, {"*.example.com", "a.example.com"},
		{"*.example.com", "example.com"}, {"*", "evil.com"}, {"*.*", "a.b"},
		{"*.com", "x.com"}, {"example.com", "EXAMPLE.com.."}, {"bücher.example", "xn--bcher-kva.example"},
		{"*.example.com", "evilexample.com"}, {"", ""}, {"*.", "a."}, {"a.b", "\x00"},
		{"K.example", "k.example"}, {"*.example.com", "a.b.example.com"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		m := HostMatch(pattern, host)
		np, nh := normalizeHost(pattern), normalizeHost(host)
		// Idempotence is only required when both normalised forms look like hostnames:
		// invalid UTF-8 / embedded whitespace are not hostnames (ToLower rewrites them and
		// a second pass may differ) and can never reach a dial.
		if hostLike(np) && hostLike(nh) && m != HostMatch(np, nh) {
			t.Fatalf("HostMatch not stable under normalisation: %q %q", pattern, host)
		}
		if np == "*" || np == "*.*" || np == "" {
			if m {
				t.Fatalf("bare wildcard/empty pattern %q matched %q", pattern, host)
			}
		}
		if strings.HasPrefix(np, "*.") {
			if m && nh == np[2:] {
				t.Fatalf("wildcard %q matched its apex", np)
			}
			if m && !strings.HasSuffix(nh, np[1:]) {
				t.Fatalf("wildcard %q matched non-subdomain %q", np, nh)
			}
		} else if m && nh != np {
			t.Fatalf("exact pattern %q matched %q", np, nh)
		}
		if strings.HasSuffix(nh, ".") {
			t.Fatalf("normalizeHost(%q) = %q keeps trailing dot", host, nh)
		}
	})
}
