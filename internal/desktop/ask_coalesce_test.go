package desktop

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAskFlightCoalesce(t *testing.T) {
	f := newAskFlight()
	var calls atomic.Int32
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = f.Do("evil.example", func() string {
				calls.Add(1)
				time.Sleep(40 * time.Millisecond)
				return "once"
			})
		}(i)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("dialog calls=%d want 1", calls.Load())
	}
	for i, r := range results {
		if r != "once" {
			t.Fatalf("result[%d]=%q", i, r)
		}
	}
}

func TestAskFlightSuppressAfterDeny(t *testing.T) {
	f := newAskFlight()
	var calls atomic.Int32
	a1 := f.Do("nope.example", func() string {
		calls.Add(1)
		return "deny"
	})
	if a1 != "deny" {
		t.Fatalf("a1=%s", a1)
	}
	a2 := f.Do("nope.example", func() string {
		calls.Add(1)
		return "once"
	})
	if a2 != "deny" {
		t.Fatalf("suppressed want deny got %s", a2)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestCoalescedAskIPNoDialog(t *testing.T) {
	a := &App{asks: newAskFlight()}
	if got := a.coalescedAsk("149.154.167.41", "host_not_allowed"); got != "deny" {
		t.Fatalf("got %s", got)
	}
}
