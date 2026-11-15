package desktop

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/run"
)

func TestUIQuitKeepRejectsSessionOnly(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, session: &run.Session{}}
	a.state.ProtectionOn = true
	a.state.Scope = ScopeSession
	err := a.UIQuit("keep")
	if err == nil {
		t.Fatal("expected keep to fail for in-process session")
	}
	if !strings.Contains(err.Error(), "Session") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestUIQuitNeedsChoiceSession(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, session: &run.Session{}}
	if !a.UIQuitNeedsChoice() {
		t.Fatal("session quit should offer a choice (Cancel)")
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
