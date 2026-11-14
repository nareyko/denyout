package desktop

import (
	"testing"
	"time"
)

func TestTimedDenyExpirySilent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a.addTimedDeny("example.com", "secret_in_url", -time.Minute) // already expired
	a.sweepTimedRules()
	if len(a.state.TimedDenies) != 0 {
		t.Fatalf("expired timed deny should be removed, got %+v", a.state.TimedDenies)
	}
	if a.state.RememberedKeep("example.com", "secret_in_url") {
		t.Fatal("timed deny expiry must not create forever Keep")
	}
}

func TestTimedAllowStored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a.addTimedAllow("ok.example", time.Hour)
	if len(a.state.TimedAllows) != 1 || a.state.TimedAllows[0].Host != "ok.example" {
		t.Fatalf("%+v", a.state.TimedAllows)
	}
}

func TestRememberedKeepIncludesActiveTimedDeny(t *testing.T) {
	st := DefaultState()
	st.TimedDenies = []TimedRule{{
		Host:      "x.test",
		Reason:    "canary_detected",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if !st.RememberedKeep("x.test", "canary_detected") {
		t.Fatal("active timed deny should count as remembered keep for quiet path")
	}
}
