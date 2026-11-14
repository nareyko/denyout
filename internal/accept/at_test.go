package accept_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/secrets"
)

func TestAT01AllowModelHost(t *testing.T) {
	cfg := mustDefault(t)
	res, err := check.URL(cfg, "https://api.anthropic.com/")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != check.VerdictAllow {
		t.Fatalf("%+v", res)
	}
}

func TestAT02DenyUnknownHost(t *testing.T) {
	cfg := mustDefault(t)
	d, err := policy.EvaluateURL(cfg, "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "deny" || !has(d.Reasons, "host_not_allowed") {
		t.Fatalf("%+v", d)
	}
}

func TestAT03SecretInQuery(t *testing.T) {
	cfg := mustDefault(t)
	d, err := policy.EvaluateURL(cfg, "https://api.anthropic.com/v1/x?api_key=sk-denyouttest000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "deny" || !has(d.Reasons, "secret_in_url") {
		t.Fatalf("%+v", d)
	}
}

func TestAT04Canary(t *testing.T) {
	cfg := mustDefault(t)
	d, err := policy.EvaluateURL(cfg, "https://api.anthropic.com/?q=DENYOUT_CANARY_TEST")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "deny" || !has(d.Reasons, "canary_detected") {
		t.Fatalf("%+v", d)
	}
}

func TestAT05MetadataSSRF(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		cfg, err := policy.LoadBytes([]byte(`
apiVersion: denyout/v1
kind: Config
mode: ` + mode + `
preset: none
scanners:
  canaries: ["DENYOUT_CANARY_"]
`))
		if err != nil {
			t.Fatal(err)
		}
		d, err := policy.EvaluateURL(cfg, "http://169.254.169.254/")
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != "deny" || !has(d.Reasons, "unsafe_ip") {
			t.Fatalf("mode=%s %+v", mode, d)
		}
	}
}

func TestAT06AuditWouldDeny(t *testing.T) {
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
	if d.Verdict != "allow" || !d.WouldDeny || !has(d.Reasons, "host_not_allowed") {
		t.Fatalf("%+v", d)
	}
}

func TestAT07Redaction(t *testing.T) {
	raw := "https://api.anthropic.com/v1/x?api_key=sk-denyouttest000000000000000"
	red := secrets.RedactURL(raw)
	if strings.Contains(red, "sk-denyouttest") {
		t.Fatalf("leaked: %s", red)
	}
	if !strings.Contains(red, "***") && !strings.Contains(red, "%2A%2A%2A") {
		t.Fatalf("expected redaction markers in %s", red)
	}
	res, err := check.URL(mustDefault(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Human(), "sk-denyouttest") || strings.Contains(res.JSON(), "sk-denyouttest") {
		t.Fatal("check output leaked secret")
	}
}

func TestAT08ConfigFailClosed(t *testing.T) {
	_, err := policy.LoadBytes([]byte(`
apiVersion: denyout/v1
kind: Config
mode: enforce
preset: none
scanners:
  custom_regex:
    - id: bad
      pattern: "(unclosed"
`))
	if err == nil {
		t.Fatal("expected invalid regex to fail closed")
	}
}

func TestAT09CheckCLI(t *testing.T) {
	bin := buildDenyout(t)
	cmd := exec.Command(bin, "check", "https://api.anthropic.com/v1/x?api_key=sk-denyouttest000000000000000")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, out=%s", out)
	}
	s := string(out)
	if !strings.Contains(s, "verdict=deny") {
		t.Fatalf("out=%s", s)
	}
	if strings.Contains(s, "sk-denyouttest000000000000000") {
		t.Fatal("raw secret in CLI output")
	}
}

func mustDefault(t *testing.T) *policy.Config {
	t.Helper()
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func buildDenyout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "denyout")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/denyout")
	cmd.Dir = findRepoRoot(t)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}
