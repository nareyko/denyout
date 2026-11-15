package desktop

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/run"
)

func TestUIQuitAlwaysClearsLeaveOn(t *testing.T) {
	// Former "keep" choice must not leave restore intent — Quit always unloads.
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.Scope = ScopeComputer
	if err := a.UIQuit("keep"); err != nil {
		t.Fatalf("unload-only quit: %v", err)
	}
	if a.state.ProtectionOn || a.state.ComputerEnabled || a.state.Scope != ScopeOff {
		t.Fatalf("leave-on must clear: on=%v computer=%v scope=%q", a.state.ProtectionOn, a.state.ComputerEnabled, a.state.Scope)
	}
}

func TestUIQuitNeedsChoiceSession(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, session: &run.Session{}}
	if !a.UIQuitNeedsChoice() {
		t.Fatal("session quit should confirm (Cancel keeps running)")
	}
}

func TestUIQuitNeedsChoiceOffHealthy(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	if a.UIQuitNeedsChoice() {
		t.Fatal("healthy off should quit without confirm modal")
	}
}

func TestUIQuitNeedsChoiceWrapsRunning(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{"p1": {}}}
	if !a.UIQuitNeedsChoice() {
		t.Fatal("running My agents wraps should confirm before Quit")
	}
}

func TestTestProtectionMessageUnhealthy(t *testing.T) {
	a := &App{state: DefaultState(), status: "Needs attention", wraps: map[string]*wrapProc{}}
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	msg := a.testProtectionMessage()
	if !strings.Contains(msg, "did not start") && !strings.Contains(msg, "Try Protect") {
		t.Fatalf("expected unhealthy message, got %q", msg)
	}
}
