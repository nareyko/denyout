package desktop

import (
	"testing"
	"time"
)

func TestMapDecisionLabel(t *testing.T) {
	if mapDecisionLabel("Keep blocked") != DecisionKeep {
		t.Fatal("keep")
	}
	if mapDecisionLabel("Allow this site") != DecisionAllow {
		t.Fatal("allow")
	}
	if mapDecisionLabel("Decide later") != DecisionLater {
		t.Fatal("later")
	}
	if mapDecisionLabel("Keep blocked for 15 minutes") != DecisionKeepTimed+"15m" {
		t.Fatal("keep timed")
	}
	if mapDecisionLabel("Allow for 1 hour") != DecisionAllowTimed+"1h" {
		t.Fatal("allow timed")
	}
}

func TestParseTimedSuffix(t *testing.T) {
	d, ok := parseTimedSuffix(DecisionKeepTimed+"15m", DecisionKeepTimed)
	if !ok || d != 15*time.Minute {
		t.Fatalf("got %v %v", d, ok)
	}
	d, ok = parseTimedSuffix(DecisionAllowTimed+"1h", DecisionAllowTimed)
	if !ok || d != time.Hour {
		t.Fatalf("got %v %v", d, ok)
	}
}

func TestTimeoutDoesNotRememberKeep(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a.applyHardBlockDecision("example.com", "secret_in_url", DecisionLater)
	if a.state.RememberedKeep("example.com", "secret_in_url") {
		t.Fatal("Decide later must not write Remembered Keep")
	}
	a.applyHardBlockDecision("example.com", "secret_in_url", DecisionKeep)
	if !a.state.RememberedKeep("example.com", "secret_in_url") {
		t.Fatal("explicit Keep should remember")
	}
}

func TestAllowedKindThrottleHelper(t *testing.T) {
	key := "host|reason-test-throttle"
	promptThrottleMu.Lock()
	delete(promptLastAt, key)
	promptThrottleMu.Unlock()
	if shouldThrottlePrompt(key, time.Minute) {
		t.Fatal("first must not throttle")
	}
	if !shouldThrottlePrompt(key, time.Minute) {
		t.Fatal("second within interval must throttle")
	}
}
