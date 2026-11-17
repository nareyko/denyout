package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/diag"
)

func TestListDenialsCarriesExplanation(t *testing.T) {
	p := AuditLogPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(p)
	t.Cleanup(func() { _ = os.WriteFile(p, old, 0o600) })
	var b strings.Builder
	for _, e := range []audit.Event{
		{EventID: "x1", TS: "2026-01-01T00:00:01Z", Verdict: "deny", Reasons: []string{"host_not_allowed"},
			Network: audit.Network{DestHost: "new.example", DestPort: 443}},
		{EventID: "x2", TS: "2026-01-01T00:00:02Z", Verdict: "deny", Reasons: []string{"secret_in_url"},
			Detectors: []string{"github_token"},
			Network:   audit.Network{DestHost: "leak.example", DestPort: 443}},
	} {
		line, _ := json.Marshal(e)
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{state: DefaultState()}
	rows, err := a.ListDenials(DenialQuery{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DenialView{}
	for _, r := range rows {
		by[r.Host] = r
	}
	n := by["new.example"]
	if n.Title == "" || n.Explain == "" || n.Fix == "" || !n.AllowHelps || n.Rule != "Allowlist (default deny)" {
		t.Fatalf("allowlist row: %+v", n)
	}
	l := by["leak.example"]
	if l.AllowHelps || !strings.Contains(l.Rule, "github_token") {
		t.Fatalf("secret row: %+v", l)
	}
}

func TestDenialActionKeepRemembers(t *testing.T) {
	a := &App{state: DefaultState()}
	if _, err := a.UIDenialAction("Keep.Example", "host_not_allowed", "", DenialActionKeep); err != nil {
		t.Fatal(err)
	}
	if !a.state.RememberedKeep("keep.example", "host_not_allowed") {
		t.Fatal("keep should be remembered")
	}
}

func TestDenialActionAllowOnceIsTimed(t *testing.T) {
	a := &App{state: DefaultState()}
	msg, err := a.UIDenialAction("once.example", "host_not_allowed", "", DenialActionAllowOnce)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "15 minutes") {
		t.Fatalf("msg %q", msg)
	}
	if len(a.state.TimedAllows) != 1 || a.state.TimedAllows[0].Host != "once.example" {
		t.Fatalf("timed allows: %+v", a.state.TimedAllows)
	}
	for _, h := range a.state.AlwaysAllowHosts {
		if h == "once.example" {
			t.Fatal("allow once must not persist")
		}
	}
}

func TestDenialActionAlwaysPersists(t *testing.T) {
	a := &App{state: DefaultState()}
	if _, err := a.UIDenialAction("always.example", "host_not_allowed", "", DenialActionAllowAlways); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range a.state.AlwaysAllowHosts {
		found = found || h == "always.example"
	}
	if !found {
		t.Fatalf("always allow missing: %+v", a.state.AlwaysAllowHosts)
	}
}

func TestDenialActionRefusesAllowForContentBlocks(t *testing.T) {
	a := &App{state: DefaultState()}
	for _, code := range []string{"secret_in_url", "canary_detected", "unsafe_ip", "unknown_code"} {
		for _, act := range []string{DenialActionAllowOnce, DenialActionAllowAlways} {
			if _, err := a.UIDenialAction("h.example", code, "", act); err == nil {
				t.Errorf("%s/%s: allow must be refused", code, act)
			}
		}
	}
	if len(a.state.TimedAllows) != 0 || len(a.state.AlwaysAllowHosts) != 0 {
		t.Fatal("refused allow must not change state")
	}
	if _, err := a.UIDenialAction("", "host_not_allowed", "", DenialActionKeep); err == nil {
		t.Fatal("empty host")
	}
	if _, err := a.UIDenialAction("h.example", "host_not_allowed", "", "nuke"); err == nil {
		t.Fatal("unknown action")
	}
	// Keep stays available for every block, including content blocks.
	if _, err := a.UIDenialAction("h.example", "secret_in_url", "", DenialActionKeep); err != nil {
		t.Fatal(err)
	}
}

func TestProxydPort(t *testing.T) {
	if proxydPort([]string{"hostctl", "proxyd", "--port", "41234", "--ca-dir", "/x"}) != 41234 {
		t.Fatal("port")
	}
	if proxydPort(nil) != 0 {
		t.Fatal("none")
	}
}

func TestUIFixCheckRejectsUnknown(t *testing.T) {
	a := &App{state: DefaultState()}
	if _, err := a.UIFixCheck("rm_rf"); err == nil {
		t.Fatal("unknown fix must error")
	}
}

func TestStatusReasonHookIsShown(t *testing.T) {
	StatusReasonHook = func(*App) string { return "helper is degraded" }
	t.Cleanup(func() { StatusReasonHook = nil })
	a := &App{state: DefaultState(), status: "Needs attention"}
	txt := a.UIDiagnosticsText()
	if !strings.Contains(txt, "Needs attention (helper is degraded)") {
		t.Fatalf("status reason missing:\n%s", txt)
	}
}

func TestUIRunSelfCheckNoCAWhileOff(t *testing.T) {
	a := &App{state: DefaultState()}
	checks := a.UIRunSelfCheck()
	if len(checks) == 0 || checks[0].Status == diag.Fail {
		t.Fatalf("Protect off with no CA is not a failure: %+v", checks)
	}
}
