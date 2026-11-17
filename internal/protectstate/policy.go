package protectstate

import (
	"os"
	"strings"
	"sync"
)

// FailPolicy decides what happens to the redirect when the local proxy is lost.
type FailPolicy string

const (
	// FailOpen (default, fail-soft): remove the redirect so clients keep working
	// unfiltered; the state becomes Degraded.
	FailOpen FailPolicy = "open"
	// FailClosed (strict): keep the redirect; no web access rather than uninspected.
	FailClosed FailPolicy = "closed"
)

// ParseFailPolicy parses "open"/"closed". Unknown input yields (FailOpen, false).
func ParseFailPolicy(s string) (FailPolicy, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "open", "soft", "fail-open":
		return FailOpen, true
	case "closed", "strict", "fail-closed":
		return FailClosed, true
	}
	return FailOpen, false
}

// FailPolicyFromEnv resolves the policy. DENYOUT_FAIL_CLOSED=1 (legacy) always
// wins; otherwise DENYOUT_FAIL_POLICY=open|closed; otherwise def (empty = open).
func FailPolicyFromEnv(getenv func(string) string, def FailPolicy) FailPolicy {
	if getenv == nil {
		getenv = os.Getenv
	}
	if getenv("DENYOUT_FAIL_CLOSED") == "1" {
		return FailClosed
	}
	if p, ok := ParseFailPolicy(getenv("DENYOUT_FAIL_POLICY")); ok {
		return p
	}
	if def == "" {
		return FailOpen
	}
	return def
}

// Transition is a state change seen by a Tracker.
type Transition struct {
	From, To State
	Reason   string
	Message  string
}

// Tracker remembers the last state and fires hooks on transitions. Hooks run
// synchronously on the Observe caller's goroutine, outside the tracker's lock.
type Tracker struct {
	mu   sync.Mutex
	last State
	seen bool
	// OnTransition fires on every change (not on the first observation).
	OnTransition func(Transition)
	// OnDegraded fires when the state transitions INTO Degraded.
	OnDegraded func(Transition)
}

// Observe feeds a computed Result; it returns the transition if the state changed.
func (t *Tracker) Observe(r Result) (Transition, bool) {
	t.mu.Lock()
	prev, seen := t.last, t.seen
	t.last, t.seen = r.State, true
	onT, onD := t.OnTransition, t.OnDegraded
	t.mu.Unlock()
	if !seen || prev == r.State {
		return Transition{}, false
	}
	tr := Transition{From: prev, To: r.State, Reason: r.Reason, Message: r.Message}
	if onT != nil {
		onT(tr)
	}
	if r.State == Degraded && onD != nil {
		onD(tr)
	}
	return tr, true
}
