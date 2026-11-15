package desktop

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSetupDoneAfterProtect(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_STATE_HOME", dir)

	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.opts.SkipNativeYourSetup = true
	a.state.SetupDone = false

	a.ensureSetupDoneAfterProtect("safe")

	if !a.state.SetupDone {
		t.Fatal("expected setup_done after peek Protect")
	}
	if a.state.PendingYourSetup != "safe" {
		t.Fatalf("pending your setup=%q want safe", a.state.PendingYourSetup)
	}
}

func TestYourSetupTextSession(t *testing.T) {
	text := YourSetupText("session", false, false, true)
	if !strings.Contains(text, "Session protection") {
		t.Fatalf("%q", text)
	}
	if strings.Contains(text, "Protect computer is off for now") {
		t.Fatalf("session must not use agents-off tip: %q", text)
	}
	if got := liveToYourSetupMode("session"); got != "session" {
		t.Fatalf("live map=%q", got)
	}
}

func TestYourSetupTextAgentsOnly(t *testing.T) {
	text := YourSetupText("agents_only", false, false, true)
	if !strings.Contains(text, "Agents only") || !strings.Contains(text, "Everyday browsing") {
		t.Fatalf("unexpected agents_only copy: %q", text)
	}
}

func TestYourSetupTextQuietWhileAway(t *testing.T) {
	on := YourSetupText("safe", false, false, true)
	if !strings.Contains(on, "Stay quiet while away is on") {
		t.Fatalf("quiet on: %q", on)
	}
	off := YourSetupText("safe", false, false, false)
	if !strings.Contains(off, "Stay quiet while away is off") {
		t.Fatalf("quiet off: %q", off)
	}
}

func TestPendingYourSetupModeAgentsOnly(t *testing.T) {
	a := &App{state: State{PendingYourSetup: "agents_only"}}
	if got := pendingYourSetupModeLocked(a, "agents"); got != "agents_only" {
		t.Fatalf("pending mode=%q want agents_only", got)
	}
}

func TestPendingYourSetupModeFollowsLiveOff(t *testing.T) {
	a := &App{state: State{PendingYourSetup: "safe"}}
	if got := pendingYourSetupModeLocked(a, "off"); got != "off" {
		t.Fatalf("pending safe + live off → %q want off", got)
	}
	a.state.PendingYourSetup = "agents_only"
	if got := pendingYourSetupModeLocked(a, "off"); got != "off" {
		t.Fatalf("pending agents_only + live off → %q want off", got)
	}
}

func TestPendingYourSetupModeFollowsLiveOn(t *testing.T) {
	a := &App{state: State{PendingYourSetup: "off"}}
	if got := pendingYourSetupModeLocked(a, "safe"); got != "safe" {
		t.Fatalf("pending off + live safe → %q want safe", got)
	}
	a.state.PendingYourSetup = "agents"
	if got := pendingYourSetupModeLocked(a, "agents"); got != "agents_only" {
		t.Fatalf("pending agents + live agents → %q want agents_only", got)
	}
}

func TestPendingYourSetupModeAgentsTipWhileOff(t *testing.T) {
	a := &App{state: State{PendingYourSetup: "agents"}}
	if got := pendingYourSetupModeLocked(a, "off"); got != "agents" {
		t.Fatalf("pending agents + live off → %q want agents (My agents tip)", got)
	}
}

func TestYourSetupTextUnhealthy(t *testing.T) {
	text := YourSetupText("safe", false, true, true)
	if strings.Contains(text, "You are protected") {
		t.Fatalf("unhealthy setup must not claim protected: %q", text)
	}
	if !strings.Contains(text, "needs your attention") || !strings.Contains(text, "Problems") {
		t.Fatalf("unexpected unhealthy copy: %q", text)
	}
	agents := YourSetupText("agents_only", false, true, true)
	if !strings.Contains(agents, "Agents only needs your attention") {
		t.Fatalf("agents unhealthy: %q", agents)
	}
}
