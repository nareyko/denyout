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
