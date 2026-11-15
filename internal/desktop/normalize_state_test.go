package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePersistedStateClearsBrowseAsk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = true
	a.state.Notify = false
	a.state.NotifyLevel = ""
	a.state.UXv2Migrated = false
	a.normalizePersistedState()
	if a.state.AskMode {
		t.Fatal("browse must clear ask_mode")
	}
	if !a.state.UXv2Migrated {
		t.Fatal("setup_done should imply ux_v2_migrated")
	}
	if !a.state.AutostartAsked {
		t.Fatal("setup_done should imply autostart_asked")
	}
	if a.state.NotifyLevel != "quiet" || a.state.Notify {
		t.Fatalf("notify=%v level=%q", a.state.Notify, a.state.NotifyLevel)
	}
	// Persisted
	st := LoadState()
	if st.AskMode || st.NotifyLevel != "quiet" {
		t.Fatalf("disk not normalized: %+v", st)
	}
}

func TestNormalizePersistedStateKeepsAgentUXv2Prompt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.UXv2Migrated = false
	a.normalizePersistedState()
	if a.state.UXv2Migrated {
		t.Fatal("legacy Agents only must keep needs_uxv2_migration until in-app choice")
	}
	if !a.state.NeedsUXv2Migration() {
		t.Fatal("expected NeedsUXv2Migration")
	}
}

func TestReconcileAutostartRepairsMissingEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.Autostart = true
	if AutostartRegistered() {
		t.Fatal("expected no autostart")
	}
	a.reconcileAutostart()
	if !AutostartRegistered() {
		t.Fatal("expected repair to create login entry")
	}
	path := filepath.Join(dir, "autostart", "denyout.desktop")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("missing %s: %v", path, err)
	}
}
