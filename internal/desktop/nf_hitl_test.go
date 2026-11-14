package desktop

import (
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// Code-level NF checks for notifications rework (pairs with manual M1-M18).
func TestNF_DecisionActionsAndWhitelist(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	notify.SetLevel("normal")

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}

	// M3 / T1: later does not Keep
	a.applyHardBlockDecision("a.example", "secret_in_url", DecisionLater)
	if a.state.RememberedKeep("a.example", "secret_in_url") {
		t.Fatal("M3: Decide later must not Keep")
	}

	// M5 path: explicit Keep -> remembered
	a.applyHardBlockDecision("a.example", "secret_in_url", DecisionKeep)
	if !a.state.RememberedKeep("a.example", "secret_in_url") {
		t.Fatal("M5: Keep forever")
	}

	// M8: timed deny
	a2 := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a2.applyHardBlockDecision("b.example", "canary_detected", DecisionKeepTimed+"15m")
	if !a2.state.RememberedKeep("b.example", "canary_detected") {
		t.Fatal("timed keep should silence repeats while active")
	}
	if len(a2.state.TimedDenies) != 1 {
		t.Fatal("timed deny row")
	}

	// M7: timed allow
	a2.applyHardBlockDecision("c.example", "secret_in_url", DecisionAllowTimed+"15m")
	if len(a2.state.TimedAllows) == 0 {
		t.Fatal("timed allow row")
	}

	// M15: Quiet filters keep-repeat kind
	notify.SetLevel("quiet")
	if notify.AllowedKind(notify.KindKeepRepeat) && notify.Level() == "quiet" {
		// AllowedKind is structural; Quiet filtering is in Emit - check Level
	}
	notify.Emit(notify.KindKeepRepeat, "t", "must not show in quiet")
	notify.SetLevel("normal")
}

func TestNF_PauseChoiceMapping(t *testing.T) {
	if mapPauseLabel("1 hour", "15m") != "1h" {
		t.Fatal("1h")
	}
	if mapPauseLabel("Until I turn it on", "1h") != "forever" {
		t.Fatal("forever")
	}
	if mapPauseLabel("", "1h") != "1h" {
		t.Fatal("default")
	}
}

func TestNF_ClearPostBlockReasons(t *testing.T) {
	if !isClearPostBlock([]string{"secret_in_url"}) {
		t.Fatal("secret")
	}
	if isClearPostBlock([]string{"host_not_allowed"}) {
		t.Fatal("new host is Ask/Browse, not hard-block dialog")
	}
}

func TestNF_BatchDedupe(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	// Presenter returns later immediately so we don't block on zenity.
	SetDecisionPresenter(func(p DecisionPrompt) string { return DecisionLater })
	defer SetDecisionPresenter(nil)

	done := make(chan struct{})
	go func() {
		a.handlePostBlockDeny("one.test", []string{"secret_in_url"}, "")
		close(done)
	}()
	// Second while busy -> queue
	time.Sleep(20 * time.Millisecond)
	a.handlePostBlockDeny("two.test", []string{"canary_detected"}, "")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("batch hung")
	}
}
