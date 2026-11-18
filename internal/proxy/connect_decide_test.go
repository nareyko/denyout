package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestParseConnectTarget(t *testing.T) {
	cases := []struct {
		in         string
		host, port string
		portN      int
		ok         bool
	}{
		{"example.com:443", "example.com", "443", 443, true},
		{"example.com", "example.com", "443", 443, true},
		{"example.com:8443", "example.com", "8443", 8443, true},
		{"[::1]:443", "::1", "443", 443, true},
		{"example.com:0", "", "", 0, false},
		{"example.com:65536", "", "", 0, false},
		{"example.com:65616", "", "", 0, false}, // must not wrap to 80
		{"example.com:-1", "", "", 0, false},
		{"example.com:http", "", "", 0, false},
		{"example.com:65535", "example.com", "65535", 65535, true},
	}
	for _, c := range cases {
		h, p, n, ok := parseConnectTarget(c.in)
		if h != c.host || p != c.port || n != c.portN || ok != c.ok {
			t.Errorf("%q -> %q %q %d %v", c.in, h, p, n, ok)
		}
	}
}

func connectServer(t *testing.T, dnsDeny *bool) *Server {
	t.Helper()
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Allow = []policy.Rule{{Host: "ok.test"}}
	cfg.DenyOnDNSFailure = dnsDeny
	return &Server{cfg: Config{Engine: policy.NewEngine(cfg), SessionID: "s1", TLSMode: TLSIntercept}}
}

func TestDecideConnect(t *testing.T) {
	pub := []net.IP{net.ParseIP("93.184.216.34")}
	f := false
	cases := []struct {
		name    string
		dnsDeny *bool
		host    string
		ips     []net.IP
		rerr    error
		deny    bool
		reason  string
	}{
		{"allowed host", nil, "ok.test", pub, nil, false, ""},
		{"unlisted host", nil, "evil.test", pub, nil, true, policy.ReasonHostNotAllowed},
		{"dns failure denies by default", nil, "ok.test", nil, errors.New("nx"), true, policy.ReasonDNSFailure},
		{"dns failure tolerated when disabled", &f, "ok.test", pub, errors.New("nx"), false, ""},
		{"already denied keeps its reason", nil, "evil.test", nil, errors.New("nx"), true, policy.ReasonHostNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := connectServer(t, c.dnsDeny)
			rv, d := s.decideConnect(c.host, 443, c.ips, c.rerr)
			if (d.Verdict == "deny") != c.deny {
				t.Fatalf("verdict %q reasons %v", d.Verdict, d.Reasons)
			}
			if c.reason != "" && (len(d.Reasons) == 0 || d.Reasons[0] != c.reason) {
				t.Fatalf("reasons %v want %s", d.Reasons, c.reason)
			}
			if rv.Method != http.MethodConnect || rv.DestPort != 443 || rv.DestHost != c.host ||
				rv.RawURL != "https://"+c.host+"/" || rv.Inspection != string(TLSIntercept) || rv.SessionID != "s1" {
				t.Fatalf("view %+v", rv)
			}
		})
	}
}

func TestMisdirectedResponse(t *testing.T) {
	r := misdirectedResponse()
	if r.StatusCode != http.StatusMisdirectedRequest {
		t.Fatal(r.StatusCode)
	}
	b, _ := io.ReadAll(r.Body)
	if string(b) != "host header does not match tunnel host\n" {
		t.Fatalf("%q", b)
	}
}
