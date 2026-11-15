package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallUpgradeKeepsSetupDone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, ".local", "state"))

	prev := DefaultState()
	prev.SetupDone = true
	prev.NotifyLevel = "quiet"
	prev.QuietWhileAwayOff = false
	prev.RespectFullscreenOff = false
	prev.DismissedTips = []string{"glossary"}
	prev.ProtectionOn = true
	prev.ComputerEnabled = true
	prev.Scope = ScopeComputer
	if err := SaveState(prev); err != nil {
		t.Fatal(err)
	}
	// Stale elevate last-error from a fixed bug.
	_ = os.MkdirAll(LogDir(), 0o755)
	RecordError("hostguard.ElevateApply", "Cannot run program --action-id=com.denyout.hostctl: No such file or directory")

	// DetachDesktopOpen will fail without a real binary beside the test exe —
	// call the state-shaping core by invoking Install and accepting start error,
	// or save/check via a thinner path. Prefer: run Install with PATH that has no
	// desktop binary; Detach may still try. Stub by checking SaveState mid-path.
	//
	// Install always StopPreviousInstances + DetachDesktopOpen. In tests Detach
	// often fails. Exercise the upgrade branch via a package-local helper.
	st, err := installPrepareState()
	if err != nil {
		t.Fatal(err)
	}
	if !st.SetupDone {
		t.Fatal("upgrade must keep setup_done")
	}
	if st.NotifyLevel != "quiet" {
		t.Fatalf("notify_level=%q", st.NotifyLevel)
	}
	if st.ProtectionOn || st.ComputerEnabled || st.Scope != ScopeOff {
		t.Fatalf("upgrade must force Off: on=%v computer=%v scope=%q",
			st.ProtectionOn, st.ComputerEnabled, st.Scope)
	}
	if len(st.DismissedTips) != 1 || st.DismissedTips[0] != "glossary" {
		t.Fatalf("tips=%v", st.DismissedTips)
	}
	if ReadLastError() != "" {
		t.Fatalf("last-error should be cleared, got %q", ReadLastError())
	}
}

func TestInstallFreshResetsSetup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, ".local", "state"))

	prev := DefaultState()
	prev.SetupDone = false
	prev.NotifyLevel = "detailed"
	if err := SaveState(prev); err != nil {
		t.Fatal(err)
	}
	st, err := installPrepareState()
	if err != nil {
		t.Fatal(err)
	}
	if st.SetupDone {
		t.Fatal("fresh install must leave setup pending")
	}
	if st.ProtectionOn {
		t.Fatal("fresh install must be Off")
	}
}

func TestClearObsoleteLastErrorDropsActionId(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, ".local", "state"))
	_ = os.MkdirAll(LogDir(), 0o755)
	RecordError("hostguard.ElevateApply", "Cannot run program --action-id=com.denyout.hostctl: No such file")
	clearObsoleteLastError()
	if ReadLastError() != "" {
		t.Fatalf("expected clear, got %q", ReadLastError())
	}
}
