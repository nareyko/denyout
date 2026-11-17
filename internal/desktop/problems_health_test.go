package desktop

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/run"
)

func TestLastErrorSummaryIgnoresPlaceholder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	dir := LogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "last-error.txt")
	if err := os.WriteFile(path, []byte("No errors recorded yet.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LastErrorSummary(); got != "" {
		t.Fatalf("placeholder should be empty, got %q", got)
	}
}

func TestProtectReasonExposed(t *testing.T) {
	a := &App{status: "Off"}
	a.state = DefaultState()
	if got := a.ProtectReason(); got != "" {
		t.Fatalf("off should have no reason, got %q", got)
	}
	a.state.ProtectionOn = true
	if got := a.ProtectReason(); got == "" {
		t.Fatal("intended on without proxyd must explain why")
	}
}

func TestProblemsUnhealthyOffIsHealthy(t *testing.T) {
	a := &App{status: "Off"}
	a.state = DefaultState()
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	if problemsUnhealthyLocked(a) {
		t.Fatal("Off should not be unhealthy")
	}
}

func TestProblemsUnhealthyWantOnNoProxyd(t *testing.T) {
	a := &App{status: "Off"}
	a.state = DefaultState()
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	if !problemsUnhealthyLocked(a) {
		t.Fatal("intended On without proxyd should be unhealthy")
	}
}

func TestProblemsUnhealthyLiveSessionIsHealthy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	caDir := filepath.Join(dir, "denyout", "ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{status: "Session (proxy)", session: &run.Session{}}
	a.state = DefaultState()
	a.state.ProtectionOn = true
	a.state.Scope = ScopeSession
	if problemsUnhealthyLocked(a) {
		t.Fatal("live session should not be unhealthy")
	}
}

func TestUIReadyRestoreSkipsPaused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.ProtectPauseLast = "forever"
	a.opts.OpenUI = func(string) {}
	a.UIReadyRestore()
	if a.proxyd != nil {
		t.Fatal("paused forever must not restore Protect")
	}
}
