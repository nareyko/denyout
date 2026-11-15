package desktop

import (
	"path/filepath"
	"testing"
)

// TestEnableComputerTestElevateSkipKeepsAvailable: DENYOUT_TEST_NO_ELEVATE must not
// sticky Off (unavailable) / password-cancelled copy — no pkexec was shown.
func TestEnableComputerTestElevateSkipKeepsAvailable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_STATE_HOME", dir)
	t.Setenv("DENYOUT_TEST_NO_ELEVATE", "1")

	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.ComputerAvailable = true
	a.state.ProtectionOn = false
	a.state.Scope = ScopeOff

	err := a.enableComputerFromTray()
	if err == nil {
		t.Fatal("expected elevate skip error")
	}
	if !a.state.ComputerAvailable {
		t.Fatal("test/CI elevate skip must not sticky ComputerAvailable=false (Off unavailable UX)")
	}
	if a.state.ProtectionOn {
		t.Fatal("protection must stay off")
	}
	snap := a.GetUISnapshot()
	if !snap.ComputerAvailable {
		t.Fatal("snapshot must stay available so Home says Off not Off (unavailable)")
	}
}
