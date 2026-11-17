package hostguard

import "testing"

func TestWatchdogDegradeAndRecover(t *testing.T) {
	w := &watchdog{}
	for i := 0; i < watchdogThreshold-1; i++ {
		if e := w.observe(false); e != "" {
			t.Fatalf("early edge %q", e)
		}
	}
	if e := w.observe(false); e != "degrade" {
		t.Fatalf("want degrade, got %q", e)
	}
	if e := w.observe(false); e != "" || !w.isDegraded() {
		t.Fatal("degrade must fire once")
	}
	if e := w.observe(true); e != "recover" || w.isDegraded() {
		t.Fatal("want recover")
	}
	if e := w.observe(true); e != "" {
		t.Fatal("no edge while healthy")
	}
}

func TestWatchdogFlapResetsCounter(t *testing.T) {
	w := &watchdog{}
	w.observe(false)
	w.observe(false)
	w.observe(true) // blip heals: counter resets
	for i := 0; i < watchdogThreshold-1; i++ {
		if e := w.observe(false); e != "" {
			t.Fatalf("counter not reset, edge %q", e)
		}
	}
}

func TestWatchdogFailClosedNeverDegrades(t *testing.T) {
	w := &watchdog{failClosed: true}
	for i := 0; i < 10; i++ {
		if e := w.observe(false); e != "" {
			t.Fatalf("fail-closed must keep rules, got %q", e)
		}
	}
}

func TestWatchdogForceDegradedRetriesRecovery(t *testing.T) {
	w := &watchdog{}
	for i := 0; i < watchdogThreshold; i++ {
		w.observe(false)
	}
	if e := w.observe(true); e != "recover" {
		t.Fatal("want recover")
	}
	w.forceDegraded() // re-apply failed
	if e := w.observe(true); e != "recover" {
		t.Fatalf("recovery must be retried after a failed re-apply, got %q", e)
	}
	w.reset()
	if w.isDegraded() || w.observe(true) != "" {
		t.Fatal("reset must clear degraded state")
	}
}
