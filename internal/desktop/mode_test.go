package desktop

import "testing"

func TestCurrentModeOff(t *testing.T) {
	a := &App{status: "Off"}
	if got := a.currentMode(); got != ModeOff {
		t.Fatalf("got %q", got)
	}
	if modeLabel(ModeComputer) != "Computer" || modeLabel(ModeSession) != "Session" || modeLabel(ModeOff) != "Off" {
		t.Fatal("modeLabel")
	}
}

func TestStopProtectionAlreadyOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	a := &App{state: DefaultState(), status: "Off"}
	// Must not panic / change state when already off.
	a.stopProtectionFromTray()
	if a.currentMode() != ModeOff {
		t.Fatal(a.currentMode())
	}
}
