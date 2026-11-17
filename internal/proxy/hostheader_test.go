package proxy

import "testing"

func TestHostHeaderMatches(t *testing.T) {
	for _, c := range []struct {
		hdr, host string
		want      bool
	}{
		{"example.com", "example.com", true}, {"EXAMPLE.com:443", "example.com", true}, {"", "example.com", true},
		{"evil.com", "example.com", false}, {"example.com.evil.com", "example.com", false}, {"[::1]:443", "::1", true},
	} {
		if got := hostHeaderMatches(c.hdr, c.host); got != c.want {
			t.Errorf("hostHeaderMatches(%q,%q)=%v", c.hdr, c.host, got)
		}
	}
}
