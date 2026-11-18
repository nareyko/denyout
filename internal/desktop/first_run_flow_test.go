package desktop

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/diag"
)

// flowRec records every dialog and system-changing step so tests can prove
// what was asked and what was installed. Nothing here touches the helper.
type flowRec struct {
	choices    []string // scripted answers for the choice dialog
	confirmYes bool     // answer to the closing dialog
	enableErr  error
	checks     []diag.Check
	toolkit    bool

	chooseCalls   int
	confirmCalls  int
	confirmTexts  []string
	enableCalls   int
	registerCalls int
	selfCheckRuns int
}

func newFlowApp(t *testing.T, r *flowRec, wails bool) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.opts.SkipNativeYourSetup = wails
	a.hooks = firstRunHooks{
		toolkit: func() bool { return r.toolkit },
		choose: func() string {
			r.chooseCalls++
			if len(r.choices) == 0 {
				return "notnow"
			}
			c := r.choices[0]
			r.choices = r.choices[1:]
			return c
		},
		confirm: func(title, text, yes, no string) bool {
			r.confirmCalls++
			r.confirmTexts = append(r.confirmTexts, text)
			return r.confirmYes
		},
		enableSafe: func() error {
			r.enableCalls++
			if r.enableErr != nil {
				return r.enableErr
			}
			a.mu.Lock()
			a.state.ProtectionOn = true
			a.state.ComputerEnabled = true
			a.state.Scope = ScopeComputer
			a.mu.Unlock()
			return nil
		},
		selfCheck: func() []diag.Check {
			r.selfCheckRuns++
			return r.checks
		},
		registerAutostart:   func() error { r.registerCalls++; return nil },
		unregisterAutostart: func() error { return nil },
	}
	return a
}

func TestNativeFirstRunComputerYes(t *testing.T) {
	r := &flowRec{choices: []string{"computer"}, confirmYes: true, toolkit: true,
		checks: []diag.Check{{ID: "ca", Name: "CA files", Status: diag.OK}}}
	a := newFlowApp(t, r, false)
	a.runFirstRunWizard()
	st := a.state
	if !st.SetupDone || !st.ProtectionOn || !st.ComputerEnabled || st.Scope != ScopeComputer {
		t.Fatalf("protect not on: %+v", st)
	}
	if !st.AutostartAsked || !st.Autostart || r.registerCalls != 1 {
		t.Fatalf("autostart yes not recorded: asked=%v on=%v reg=%d", st.AutostartAsked, st.Autostart, r.registerCalls)
	}
	if !st.YourSetupShown || st.PolicyProfile != PolicyProfileBrowse || st.AskMode {
		t.Fatalf("unexpected state: %+v", st)
	}
	// Exactly two dialogs: the choice and the closing one.
	if r.chooseCalls != 1 || r.confirmCalls != 1 || r.enableCalls != 1 || r.selfCheckRuns != 1 {
		t.Fatalf("calls: choose=%d confirm=%d enable=%d check=%d", r.chooseCalls, r.confirmCalls, r.enableCalls, r.selfCheckRuns)
	}
	if !strings.Contains(r.confirmTexts[0], "Protected and verified") {
		t.Fatalf("closing text: %q", r.confirmTexts[0])
	}
}

func TestNativeFirstRunComputerAutostartNo(t *testing.T) {
	r := &flowRec{choices: []string{"computer"}, confirmYes: false, toolkit: true,
		checks: []diag.Check{{ID: "ca", Name: "CA files", Status: diag.OK}}}
	a := newFlowApp(t, r, false)
	a.runFirstRunWizard()
	if !a.state.AutostartAsked || a.state.Autostart || r.registerCalls != 0 {
		t.Fatalf("a No must not register login launch: %+v reg=%d", a.state, r.registerCalls)
	}
	if !a.state.ProtectionOn {
		t.Fatal("protection should still be on")
	}
}

func TestNativeFirstRunComputerFailure(t *testing.T) {
	r := &flowRec{choices: []string{"computer"}, confirmYes: false, toolkit: true,
		enableErr: errors.New("password cancelled")}
	a := newFlowApp(t, r, false)
	a.runFirstRunWizard()
	st := a.state
	if st.ProtectionOn || st.ComputerEnabled || st.Scope == ScopeComputer {
		t.Fatalf("must not claim protection: %+v", st)
	}
	if !strings.Contains(r.confirmTexts[0], "did not turn on") {
		t.Fatalf("closing text: %q", r.confirmTexts[0])
	}
	if r.selfCheckRuns != 0 {
		t.Fatal("no self-check when Protect did not start")
	}
}

func TestNativeFirstRunNotNowInstallsNothing(t *testing.T) {
	r := &flowRec{choices: []string{"notnow"}, confirmYes: true, toolkit: true}
	a := newFlowApp(t, r, false)
	a.runFirstRunWizard()
	st := a.state
	if !st.SetupDone || st.ProtectionOn || st.ComputerEnabled || st.Scope != ScopeOff {
		t.Fatalf("not now state: %+v", st)
	}
	if r.enableCalls != 0 || r.registerCalls != 0 || r.selfCheckRuns != 0 {
		t.Fatalf("not now touched the system: enable=%d reg=%d check=%d", r.enableCalls, r.registerCalls, r.selfCheckRuns)
	}
	if r.confirmCalls != 0 || r.chooseCalls != 1 {
		t.Fatalf("not now must be a single dialog: choose=%d confirm=%d", r.chooseCalls, r.confirmCalls)
	}
	if st.Autostart || !st.AutostartAsked || st.NotNowAt == "" || !st.YourSetupShown {
		t.Fatalf("not now flags: %+v", st)
	}
}

func TestNativeFirstRunAgents(t *testing.T) {
	r := &flowRec{choices: []string{"agents"}, confirmYes: true, toolkit: true}
	a := newFlowApp(t, r, true) // SkipNativeYourSetup: no goroutine dialog
	a.runFirstRunWizard()
	st := a.state
	if !st.SetupDone || st.ProtectionOn || st.Scope != ScopeOff {
		t.Fatalf("agents state: %+v", st)
	}
	if r.enableCalls != 0 {
		t.Fatal("agents path must not turn on host protection")
	}
	if r.confirmCalls != 1 || !st.Autostart || r.registerCalls != 1 {
		t.Fatalf("closing dialog / autostart: confirm=%d %+v", r.confirmCalls, st)
	}
}

func TestNoToolkitNeverDefaultsAutostartOn(t *testing.T) {
	r := &flowRec{toolkit: false, confirmYes: true}
	a := newFlowApp(t, r, false)
	// Without a toolkit the question cannot be asked, so the answer is No.
	a.maybeAskAutostart("protect")
	if a.state.Autostart || r.registerCalls != 0 {
		t.Fatalf("silent autostart: %+v", a.state)
	}
	if !a.state.AutostartAsked {
		t.Fatal("question should be marked settled")
	}
}

func TestCompleteSetupNativeNeverSilentAutostart(t *testing.T) {
	r := &flowRec{toolkit: true, confirmYes: false}
	a := newFlowApp(t, r, false)
	a.completeSetupSideEffects()
	if a.state.Autostart || r.registerCalls != 0 {
		t.Fatalf("native completion must ask, not default on: %+v", a.state)
	}
	if r.confirmCalls != 1 {
		t.Fatalf("expected the explicit question, got %d", r.confirmCalls)
	}
}

func TestWailsProtectFlowStateFields(t *testing.T) {
	r := &flowRec{toolkit: true}
	a := newFlowApp(t, r, true)
	if err := a.enableSafeDesktop(); err != nil {
		t.Fatal(err)
	}
	st := a.state
	if !st.SetupDone || !st.ProtectionOn || !st.ComputerEnabled || !st.AutostartAsked || st.Autostart {
		t.Fatalf("wails protect: %+v", st)
	}
	if st.PendingYourSetup != "safe" {
		t.Fatalf("pending=%q (final screen with self-check expected)", st.PendingYourSetup)
	}
	if r.registerCalls != 0 || r.confirmCalls != 0 {
		t.Fatal("wails must not register autostart or open native dialogs")
	}
	// The final-screen checkbox goes through UISetAutostart once setup is done.
	if err := a.UISetAutostart(false); err != nil {
		t.Fatal(err)
	}
}

func TestWailsProtectFailureKeepsSetupPending(t *testing.T) {
	r := &flowRec{toolkit: true, enableErr: errors.New("cancelled")}
	a := newFlowApp(t, r, true)
	if err := a.enableSafeDesktop(); err == nil {
		t.Fatal("expected error")
	}
	st := a.state
	if st.SetupDone || st.ProtectionOn || st.ComputerEnabled || st.AutostartAsked {
		t.Fatalf("failed consent must leave setup pending: %+v", st)
	}
}

func TestWailsNotNowInstallsNothing(t *testing.T) {
	r := &flowRec{toolkit: true}
	a := newFlowApp(t, r, true)
	if err := a.UIOnboardingNotNow(); err != nil {
		t.Fatal(err)
	}
	st := a.state
	if !st.SetupDone || st.ProtectionOn || st.ComputerEnabled || st.Scope != ScopeOff {
		t.Fatalf("not now: %+v", st)
	}
	if !st.AutostartAsked || st.Autostart || st.NotNowAt == "" || !st.NotNowReminded {
		t.Fatalf("not now flags: %+v", st)
	}
	if !st.YourSetupShown || st.PendingYourSetup != "" {
		t.Fatalf("not now must skip the final screen: %+v", st)
	}
	if r.enableCalls != 0 || r.registerCalls != 0 || r.confirmCalls != 0 {
		t.Fatalf("not now touched the system: %+v", r)
	}
}

func TestWailsAgentsFlow(t *testing.T) {
	r := &flowRec{toolkit: true}
	a := newFlowApp(t, r, true)
	if err := a.UIOnboardingAgents(); err != nil {
		t.Fatal(err)
	}
	st := a.state
	if !st.SetupDone || st.ProtectionOn || st.ComputerEnabled || st.Scope != ScopeOff || st.Autostart || !st.AutostartAsked {
		t.Fatalf("agents: %+v", st)
	}
	if st.PendingYourSetup != "agents" || r.enableCalls != 0 {
		t.Fatalf("agents pending=%q enable=%d", st.PendingYourSetup, r.enableCalls)
	}
}

func TestSetAutostartNeedsFinishedSetup(t *testing.T) {
	r := &flowRec{toolkit: true}
	a := newFlowApp(t, r, true)
	if err := a.UISetAutostart(true); err == nil {
		t.Fatal("autostart must be refused before setup is done")
	}
	if r.registerCalls != 0 {
		t.Fatal("registered before setup")
	}
}

func TestFirstRunSummaryText(t *testing.T) {
	ok := firstRunSummaryText("safe", []diag.Check{{Name: "CA files", Status: diag.OK}})
	if !strings.Contains(ok, "Protected and verified") {
		t.Fatalf("%q", ok)
	}
	bad := firstRunSummaryText("safe", []diag.Check{{Name: "System trust", Status: diag.Fail, Detail: "CA not trusted"}})
	if strings.Contains(bad, "Protected and verified") || !strings.Contains(bad, "CA not trusted") || !strings.Contains(bad, "Problems") {
		t.Fatalf("%q", bad)
	}
	none := firstRunSummaryText("safe", nil)
	if strings.Contains(none, "Protected and verified") {
		t.Fatalf("cannot claim verified without checks: %q", none)
	}
	for _, m := range []string{"safe", "agents", "off"} {
		s := firstRunSummaryText(m, nil)
		if !strings.Contains(s, "start DenyOut when you log in") {
			t.Fatalf("%s: autostart question missing", m)
		}
		for _, r := range s {
			if r > 126 {
				t.Fatalf("non-ASCII in %s copy: %q", m, s)
			}
		}
	}
}

func TestFirstRunChoiceTextConsent(t *testing.T) {
	for _, want := range []string{"helper", "certificate", "password", "Not now: nothing is installed"} {
		if !strings.Contains(firstRunChoiceText, want) {
			t.Fatalf("consent text lost %q", want)
		}
	}
	for _, r := range firstRunChoiceText {
		if r > 126 {
			t.Fatalf("non-ASCII rune %q", r)
		}
	}
}

func TestFirstRunChoiceMappers(t *testing.T) {
	cases := []struct{ got, want string }{
		{firstRunChoiceFromLabel("Protect computer"), "computer"},
		{firstRunChoiceFromLabel("Protect AI agents"), "agents"},
		{firstRunChoiceFromLabel("Not now"), "notnow"},
		{firstRunChoiceFromLabel(""), "notnow"},
		{firstRunChoiceFromKdialog(0), "computer"},
		{firstRunChoiceFromKdialog(1), "agents"},
		{firstRunChoiceFromKdialog(2), "notnow"},
		{firstRunChoiceFromWindows("Yes\r\n"), "computer"},
		{firstRunChoiceFromWindows("No"), "agents"},
		{firstRunChoiceFromWindows("Cancel"), "notnow"},
		{firstRunChoiceFromWindows(""), "notnow"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Fatalf("case %d: got %q want %q", i, c.got, c.want)
		}
	}
}
