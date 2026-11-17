package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs fn and returns what it wrote to stdout and stderr.
func capture(t *testing.T, fn func() int) (code int, stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	code = fn()
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	bo, _ := io.ReadAll(ro)
	be, _ := io.ReadAll(re)
	return code, string(bo), string(be)
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyCheckCLI(t *testing.T) {
	good := write(t, "apiVersion: denyout/v1\nkind: Config\npreset: none\n")
	if code, out, _ := capture(t, func() int { return runMain([]string{"policy", "check", good}) }); code != 0 || !strings.Contains(out, "ok") {
		t.Fatalf("good: %d %q", code, out)
	}
	bad := write(t, "apiVersion: denyout/v1\nkind: Config\nallowed_ports:\n  - 443\n  - nope\n")
	code, _, errOut := capture(t, func() int { return runMain([]string{"policy", "check", bad}) })
	if code == 0 || !strings.Contains(errOut, "line 5") || !strings.Contains(errOut, "- nope") {
		t.Fatalf("bad: %d %q", code, errOut)
	}
	// legacy alias still works
	if code, _, _ := capture(t, func() int { return runMain([]string{"policy", "validate", bad}) }); code == 0 {
		t.Error("validate alias must still fail on bad file")
	}
	if code, _, _ := capture(t, func() int { return runMain([]string{"policy", "check", filepath.Join(t.TempDir(), "missing")}) }); code == 0 {
		t.Error("missing file must fail")
	}
}

func TestConfigShowRedactsAndReportsSource(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("DENYOUT_ALLOW_PRIVATE", "1")
	sp := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "denyout")
	_ = os.MkdirAll(sp, 0o755)
	_ = os.WriteFile(filepath.Join(sp, "desktop.json"),
		[]byte(`{"decision_timeout_sec":42,"account_token":"SECRET-TOKEN","account_email":"me@example.com","custom_command":"run --key=sk-abc"}`), 0o600)

	code, out, _ := capture(t, func() int { return runMain([]string{"config", "show"}) })
	if code != 0 {
		t.Fatal(code)
	}
	for _, leak := range []string{"SECRET-TOKEN", "me@example.com", "sk-abc"} {
		if strings.Contains(out, leak) {
			t.Errorf("config show leaks %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "decision_timeout_sec") || !strings.Contains(out, "[state]") || !strings.Contains(out, "[env]") {
		t.Errorf("sources missing:\n%s", out)
	}

	_, jout, _ := capture(t, func() int { return runMain([]string{"config", "show", "--json"}) })
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Settings      []struct{ Key, Value, Source string }
	}
	if err := json.Unmarshal([]byte(jout), &doc); err != nil || doc.SchemaVersion == 0 || len(doc.Settings) == 0 {
		t.Fatalf("json: %v %q", err, jout)
	}
	if strings.Contains(jout, "SECRET-TOKEN") {
		t.Error("json leaks token")
	}
}

func TestProfileImportExportCLI(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := write(t, "name: Imp\ncommand: [claude]\npreset: agent\n")
	if code, _, e := capture(t, func() int { return runMain([]string{"profile", "import", "imp", f}) }); code != 0 {
		t.Fatalf("import: %s", e)
	}
	out := filepath.Join(t.TempDir(), "exp.yaml")
	if code, _, e := capture(t, func() int { return runMain([]string{"profile", "export", "imp", out}) }); code != 0 {
		t.Fatalf("export: %s", e)
	}
	if code, _, _ := capture(t, func() int { return runMain([]string{"profile", "import", "../escape", f}) }); code == 0 {
		t.Error("escaping id accepted")
	}
	weak := write(t, "name: W\ncommand: [x]\ntls_mode: passthrough\n")
	if code, _, _ := capture(t, func() int { return runMain([]string{"profile", "import", "weak", weak}) }); code == 0 {
		t.Error("passthrough profile accepted")
	}
	if code, _, _ := capture(t, func() int { return runMain([]string{"profile", "import", "imp", f}) }); code == 0 {
		t.Error("overwrite without --force accepted")
	}
}
