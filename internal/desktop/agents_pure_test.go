package desktop

import (
	"reflect"
	"testing"
)

func TestProfileSandboxAndIsolation(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	if profileSandbox(AgentProfile{Sandbox: " srt "}) != "srt" ||
		profileSandbox(AgentProfile{RequireIsolation: true}) != "srt" ||
		profileSandbox(AgentProfile{}) != "" {
		t.Fatal("sandbox")
	}
	if isolationError(AgentProfile{}, "", no) != nil {
		t.Fatal("no isolation needed")
	}
	if isolationError(AgentProfile{Sandbox: "srt"}, "srt", yes) != nil {
		t.Fatal("srt available")
	}
	if isolationError(AgentProfile{Sandbox: "srt"}, "srt", no) == nil ||
		isolationError(AgentProfile{RequireIsolation: true}, "other", no) == nil {
		t.Fatal("srt missing must error")
	}
}

func TestWrapEnvironment(t *testing.T) {
	got := wrapEnvironment([]string{"A=1"}, AgentProfile{ID: "p1", Notify: true},
		map[string]string{"K": "v"}, []string{"X=y"})
	want := []string{"A=1", "K=v", "X=y", "DENYOUT_PROFILE_ID=p1", "DENYOUT_DESKTOP_NOTIFY=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	got = wrapEnvironment(nil, AgentProfile{ID: "p2"}, nil, nil)
	if !reflect.DeepEqual(got, []string{"DENYOUT_PROFILE_ID=p2"}) {
		t.Fatalf("%q", got)
	}
}

func TestBuildWizardProfile(t *testing.T) {
	p := buildWizardProfile(wizardAnswers{name: "My agent", cmdLine: "python app.py", workdir: "  /tmp/x ", preset: "models", isolation: true})
	if p.Name != "My agent" || !reflect.DeepEqual(p.Command, []string{"python", "app.py"}) ||
		p.WorkDir != "/tmp/x" || p.Preset != "models" || p.Sandbox != "srt" || !p.RequireIsolation {
		t.Fatalf("%+v", p)
	}
	p = buildWizardProfile(wizardAnswers{name: "A", cmdLine: "claude", preset: "agent"})
	if p.Sandbox != "" || p.RequireIsolation || p.Preset != "agent" {
		t.Fatalf("%+v", p)
	}
	if wizardPackID(AgentProfile{Name: "zzz-unknown", Command: []string{"zzz"}}) == "" {
		t.Fatal("pack id must fall back")
	}
}

func TestHandleActivityActionNoops(t *testing.T) {
	a := &App{}
	// Paths that must not touch dialogs or persistence.
	a.handleActivityAction("details", "", "", nil)
	a.handleActivityAction("always", "", "", nil)
	a.handleActivityAction("undo", "", "", nil)
	a.handleActivityAction("refresh", "h", "r", nil)
	a.handleActivityAction("close", "h", "r", nil)
	a.activityAllowHost("203.0.113.9", "", activityAlwaysMsgs)
	a.activityAllowHost("203.0.113.9", "", activityUndoMsgs)
}
