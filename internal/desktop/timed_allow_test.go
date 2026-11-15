package desktop

import (
	"testing"
	"time"
)

func TestLiveAllowHostsIncludesTimed(t *testing.T) {
	st := DefaultState()
	st.AlwaysAllowHosts = []string{"perm.example"}
	st.TimedAllows = []TimedRule{
		{Host: "temp.example", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		{Host: "expired.example", ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)},
	}
	got := liveAllowHostsLocked(st)
	want := map[string]bool{"perm.example": true, "temp.example": true}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("unexpected %s in %v", h, got)
		}
	}
}

func TestAddTimedAllowDoesNotPersistAlways(t *testing.T) {
	a := &App{state: DefaultState()}
	a.addTimedAllow("temp.example", 15*time.Minute)
	if len(a.state.TimedAllows) != 1 {
		t.Fatal("timed row")
	}
	for _, h := range a.state.AlwaysAllowHosts {
		if h == "temp.example" {
			t.Fatal("must not persist always-allow")
		}
	}
}
