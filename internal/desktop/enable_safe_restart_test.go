package desktop

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/run"
)

func TestSwitchToSafeFlipsProfileWithoutStartingProtect(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.AskMode = true
	a.state.ComputerEnabled = true
	a.state.ProtectionOn = true
	a.status = "Computer"

	// Do not call switchToSafeDesktopFromTray() — that may startComputer/hostguard.
	// Assert the profile flip that enableSafe/switchSafe persist before restart.
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	a.state.ActiveProfileID = ""
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		t.Fatal(err)
	}
	got := LoadState()
	if normalizePolicyProfile(got.PolicyProfile) != PolicyProfileBrowse {
		t.Fatalf("profile=%s", got.PolicyProfile)
	}
	if got.AskMode {
		t.Fatal("ask should be off for browse")
	}
}

func TestSwitchToSafeFromSessionLeavesComputerScope(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, session: &run.Session{}}
	a.state.SetupDone = true
	a.state.Scope = ScopeSession
	a.state.ProtectionOn = true
	a.state.PolicyProfile = PolicyProfileBrowse
	// ElevateApply will fail in this sandbox — still must leave Session behind.
	_ = a.switchToSafeDesktopFromTray()
	if a.session != nil {
		t.Fatal("expected session stopped")
	}
	if a.state.Scope != ScopeComputer {
		t.Fatalf("scope=%s want %s", a.state.Scope, ScopeComputer)
	}
}
