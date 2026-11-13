package policy_test

import (
	"net"
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestHostMatch(t *testing.T) {
	if !policy.HostMatch("api.anthropic.com", "api.anthropic.com") {
		t.Fatal("exact")
	}
	if policy.HostMatch("*.example.com", "example.com") {
		t.Fatal("wildcard must not match apex")
	}
	if !policy.HostMatch("*.example.com", "a.example.com") {
		t.Fatal("wildcard subdomain")
	}
	if policy.HostMatch("*", "evil.com") {
		t.Fatal("bare star forbidden")
	}
}

func TestUnsafeMetadata(t *testing.T) {
	ip := net.ParseIP("169.254.169.254")
	if !policy.UnsafeIP(ip, false) {
		t.Fatal("metadata must be unsafe")
	}
	priv := net.ParseIP("10.0.0.1")
	if !policy.UnsafeIP(priv, false) {
		t.Fatal("private denied by default")
	}
	if policy.UnsafeIP(priv, true) {
		t.Fatal("private allowed when flag set")
	}
}

func TestEnforceDenyUnknown(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	d, err := policy.EvaluateURL(cfg, "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "deny" {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateDNSFailureAndPortAndDenyList(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowedPorts = []int{443}
	cfg.Deny = append(cfg.Deny, policy.Rule{Host: "blocked.example"})
	eng := policy.NewEngine(cfg)
	eng.Resolve = func(host string) ([]net.IP, error) {
		return nil, net.UnknownNetworkError("dns")
	}
	d := eng.Evaluate(policy.RequestView{DestHost: "api.anthropic.com", DestPort: 443, RawURL: "https://api.anthropic.com/"})
	if d.Verdict != "deny" {
		t.Fatalf("dns: %+v", d)
	}

	eng.Resolve = func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	d = eng.Evaluate(policy.RequestView{DestHost: "api.anthropic.com", DestPort: 8443, RawURL: "https://api.anthropic.com:8443/"})
	if d.Verdict != "deny" {
		t.Fatalf("port: %+v", d)
	}

	d = eng.Evaluate(policy.RequestView{DestHost: "blocked.example", DestPort: 443, DestIPs: []net.IP{net.ParseIP("1.1.1.1")}, RawURL: "https://blocked.example/"})
	if d.Verdict != "deny" {
		t.Fatalf("deny list: %+v", d)
	}
}

func TestEvaluateRateLimit(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Limits.PerHostRPM = 1
	eng := policy.NewEngine(cfg)
	rv := policy.RequestView{
		DestHost: "api.anthropic.com",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://api.anthropic.com/",
	}
	if d := eng.Evaluate(rv); d.Verdict != "allow" {
		t.Fatalf("first: %+v", d)
	}
	if d := eng.Evaluate(rv); d.Verdict != "deny" {
		t.Fatalf("second should rate-limit: %+v", d)
	}
}

func TestHostMatchProperty(t *testing.T) {
	// Properties: reflexive exact match; wildcard never matches apex; empty never matches.
	hosts := []string{"a.example.com", "example.com", "API.Anthropic.com", ""}
	for _, h := range hosts {
		if h != "" && !policy.HostMatch(h, h) {
			t.Fatalf("reflexive %q", h)
		}
		if policy.HostMatch("", h) {
			t.Fatalf("empty pattern matched %q", h)
		}
		if policy.HostMatch("*.example.com", "example.com") {
			t.Fatal("apex property")
		}
	}
}

func TestAuditWouldDeny(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte(`
apiVersion: denyout/v1
kind: Config
mode: audit
preset: none
scanners:
  hard_secrets_in_audit_mode: false
  canaries: ["DENYOUT_CANARY_"]
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := policy.EvaluateURL(cfg, "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "allow" || !d.WouldDeny {
		t.Fatalf("%+v", d)
	}
}
