package proxy

import "testing"

func TestRedirectTarget(t *testing.T) {
	cases := []struct {
		loc    string
		cross  bool
		host   string
		scheme string
	}{
		{"/local/path", false, "", ""},
		{"relative", false, "", ""},
		{"https://evil.example/x", true, "evil.example", "https"},
		{"//evil.example/x", true, "evil.example", "https"},
		{"/\\evil.example/x", true, "evil.example", "https"},
		{"\\\\evil.example", true, "evil.example", "https"},
		{"//\tevil.example/x", true, "evil.example", "https"},
		{"  //evil.example", true, "evil.example", "https"},
		{"http://a.example", true, "a.example", "http"},
	}
	for _, c := range cases {
		u, ok := redirectTarget(c.loc, "https")
		if ok != c.cross {
			t.Fatalf("%q: cross=%v want %v", c.loc, ok, c.cross)
		}
		if ok && (u.Hostname() != c.host || u.Scheme != c.scheme) {
			t.Fatalf("%q: got %s://%s want %s://%s", c.loc, u.Scheme, u.Hostname(), c.scheme, c.host)
		}
	}
	if u, _ := redirectTarget("//x.example/", "http"); u.Scheme != "http" {
		t.Fatalf("protocol-relative must inherit base scheme, got %s", u.Scheme)
	}
}
