package desktop

import (
	"path/filepath"
	"testing"
)

func TestFinishSetupNotNowClearsLeaveOnIntent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_STATE_HOME", dir)

	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = false
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.Scope = ScopeComputer
	a.state.ProtectPausedUntil = "2099-01-01T00:00:00Z"
	a.state.ProtectPauseLast = "1h"

	if err := a.finishSetupNotNow(""); err != nil {
		t.Fatal(err)
	}

	if a.state.ProtectionOn || a.state.ComputerEnabled {
		t.Fatalf("leave-on still set: protection=%v computer=%v", a.state.ProtectionOn, a.state.ComputerEnabled)
	}
	if a.state.Scope != ScopeOff {
		t.Fatalf("scope=%q want off", a.state.Scope)
	}
	if a.state.ProtectPausedUntil != "" || a.state.ProtectPauseLast != "" {
		t.Fatalf("pause leftover: until=%q last=%q", a.state.ProtectPausedUntil, a.state.ProtectPauseLast)
	}
	if problemsUnhealthyLocked(a) {
		t.Fatal("Not now must not leave Needs attention")
	}
	snap := a.GetUISnapshot()
	if snap.ProblemsAlert || snap.ProtectionOn {
		t.Fatalf("snapshot still alert/on: alert=%v protection=%v", snap.ProblemsAlert, snap.ProtectionOn)
	}
}
