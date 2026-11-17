package policy

import "testing"

func TestNormalizeHostIDNAndDots(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM..":     "example.com",
		"bücher.de":         "xn--bcher-kva.de",
		"xn--bcher-kva.de.": "xn--bcher-kva.de",
		// Found by FuzzHostMatch: IDNA maps these to "." and left a trailing dot, so a deny
		// rule for evil.com missed "evil.com｡".
		"evil.com｡": "evil.com",
		"evil.com。": "evil.com",
		"evil．com｡": "evil.com",
	} {
		if got := normalizeHost(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
	if !HostMatch("bücher.de", "xn--bcher-kva.de") {
		t.Fatal("unicode rule must match punycode host")
	}
}

func TestUserAllowAllIgnoresTLDWildcard(t *testing.T) {
	cfg := &Config{Allow: []Rule{{Host: "*.com", Reason: "user_always"}}}
	if UserAllowAll(cfg, "evil.com") {
		t.Fatal("*.com must not grant blanket trust")
	}
	cfg = &Config{Allow: []Rule{{Host: "*.example.com", Reason: "user_always"}}}
	if !UserAllowAll(cfg, "a.example.com") {
		t.Fatal("site wildcard should still grant trust")
	}
}
