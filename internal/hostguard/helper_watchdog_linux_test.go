//go:build linux

package hostguard

import (
	"errors"
	"strings"
	"testing"
)

type wdRec struct {
	calls    []string
	up       bool
	closed   bool
	applyErr error
}

func stubWatchdog(t *testing.T, applied bool, tunOwns bool) *wdRec {
	t.Helper()
	rec := &wdRec{up: true}
	oldFx := wdFx
	lastApplyMu.Lock()
	oldSpec, oldOK, oldTun := lastApplySpec, lastApplyOK, tunSuppressed
	lastApplySpec, lastApplyOK, tunSuppressed = Spec{ProxyPort: 18443, AllowQUIC: false}, applied, tunOwns
	lastApplyMu.Unlock()
	t.Cleanup(func() {
		wdFx = oldFx
		lastApplyMu.Lock()
		lastApplySpec, lastApplyOK, tunSuppressed = oldSpec, oldOK, oldTun
		lastApplyMu.Unlock()
	})
	wdFx = watchdogEffects{
		probe:      func(int) bool { return rec.up },
		failClosed: func() bool { return rec.closed },
		applyRedirect: func(s Spec) error {
			rec.calls = append(rec.calls, "apply:tcp="+map[bool]string{true: "tun", false: "redir"}[s.TunTCP])
			return rec.applyErr
		},
		removeRedirect: func(Spec) error { rec.calls = append(rec.calls, "remove"); return nil },
		writeState:     func(s string) { rec.calls = append(rec.calls, "state:"+s) },
		fireDegraded:   func() { rec.calls = append(rec.calls, "fired") },
	}
	return rec
}

func (r *wdRec) take() string { s := strings.Join(r.calls, ","); r.calls = nil; return s }

func TestWatchdogFailSoftDegradeAndRecover(t *testing.T) {
	rec := stubWatchdog(t, true, false)
	h := &helperWatchdog{w: &watchdog{}}
	rec.up = false
	for i := 0; i < watchdogThreshold-1; i++ {
		h.tick()
		if got := rec.take(); got != "" {
			t.Fatalf("tick %d acted early: %s", i, got)
		}
	}
	h.tick()
	if got := rec.take(); got != "remove,state:degraded proxy_down,fired" {
		t.Fatalf("degrade: %s", got)
	}
	rec.up = true
	h.tick()
	if got := rec.take(); got != "apply:tcp=redir,state:protected" {
		t.Fatalf("recover: %s", got)
	}
}

func TestWatchdogRecoverUsesTunSuppressedRulesAndRetriesOnFailure(t *testing.T) {
	rec := stubWatchdog(t, true, true)
	h := &helperWatchdog{w: &watchdog{}}
	h.w.forceDegraded()
	rec.applyErr = errors.New("nft")
	h.tick()
	if got := rec.take(); got != "apply:tcp=tun" {
		t.Fatalf("failed recover: %s", got)
	}
	if !h.w.isDegraded() {
		t.Fatal("failed recover must stay degraded")
	}
	rec.applyErr = nil
	h.tick()
	if got := rec.take(); got != "apply:tcp=tun,state:protected" {
		t.Fatalf("retry: %s", got)
	}
}

func TestWatchdogFailClosedBlockedStateAndReclose(t *testing.T) {
	rec := stubWatchdog(t, true, false)
	rec.closed = true
	h := &helperWatchdog{w: &watchdog{failClosed: true}}
	rec.up = false
	for i := 0; i < watchdogThreshold; i++ {
		h.tick()
	}
	if got := rec.take(); got != "state:blocked proxy_down" || !h.blocked {
		t.Fatalf("blocked: %s %v", got, h.blocked)
	}
	rec.up = true
	h.tick()
	if got := rec.take(); got != "state:protected" || h.blocked {
		t.Fatalf("unblocked: %s %v", got, h.blocked)
	}

	// Policy tightened while degraded: rules come back at once, proxy still down.
	rec.closed = false
	h2 := &helperWatchdog{w: &watchdog{}}
	rec.up = false
	for i := 0; i < watchdogThreshold; i++ {
		h2.tick()
	}
	rec.take()
	rec.closed = true
	h2.tick()
	if got := rec.take(); got != "apply:tcp=redir,state:blocked proxy_down" || !h2.blocked {
		t.Fatalf("reclose: %s", got)
	}
}

func TestWatchdogProtectOffResetsAndStaleEdgeIsIgnored(t *testing.T) {
	rec := stubWatchdog(t, false, false)
	h := &helperWatchdog{w: &watchdog{}, blocked: true}
	h.w.forceDegraded()
	h.tick()
	if h.blocked || h.w.isDegraded() || rec.take() != "" {
		t.Fatal("Protect Off must reset without touching rules")
	}

	// Protect turned off between probe and action.
	rec = stubWatchdog(t, true, false)
	h = &helperWatchdog{w: &watchdog{}}
	h.w.forceDegraded()
	rec.up = true
	lastApplyMu.Lock()
	lastApplyOK = false
	lastApplyMu.Unlock()
	h.actOnEdge("recover", Spec{ProxyPort: 18443}, true)
	if rec.take() != "" || h.w.isDegraded() {
		t.Fatal("stale edge must not re-apply")
	}
	// Different port than probed: also stale.
	lastApplyMu.Lock()
	lastApplyOK = true
	lastApplyMu.Unlock()
	h.actOnEdge("recover", Spec{ProxyPort: 1}, true)
	if rec.take() != "" {
		t.Fatal("port-changed edge must not re-apply")
	}
	if !helperOpMu.TryLock() { // must be released by every path
		t.Fatal("helperOpMu left locked")
	}
	helperOpMu.Unlock()
	h.actOnEdge("bogus", Spec{ProxyPort: 18443}, true)
	if !helperOpMu.TryLock() {
		t.Fatal("helperOpMu left locked after unknown edge")
	}
	helperOpMu.Unlock()
}
