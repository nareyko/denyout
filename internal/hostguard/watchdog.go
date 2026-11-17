package hostguard

import "sync"

// watchdogThreshold is how many consecutive failed probes mark the proxy as down.
const watchdogThreshold = 3

// watchdog turns a stream of proxy health probes into degrade/recover edges.
// It is deliberately free of OS calls so the state machine is unit-testable.
//
// Policy (default fail-soft): if the local proxy stays down, the helper removes the
// redirect rules (otherwise every HTTPS client gets "connection refused": the
// orphan-REDIRECT blackhole) and reports "degraded"; once the proxy answers again
// the rules are re-applied. With FailClosed the rules stay in place (strict mode:
// no web access rather than uninspected access).
type watchdog struct {
	mu         sync.Mutex
	fails      int
	degraded   bool
	failClosed bool
}

// observe records one probe result and returns the edge it caused:
// "degrade" (remove rules), "recover" (re-apply rules) or "".
func (w *watchdog) observe(up bool) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if up {
		w.fails = 0
		if w.degraded {
			w.degraded = false
			return "recover"
		}
		return ""
	}
	w.fails++
	if w.fails >= watchdogThreshold && !w.degraded && !w.failClosed {
		w.degraded = true
		return "degrade"
	}
	return ""
}

func (w *watchdog) isDegraded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.degraded
}

// reset clears all memory (Protect Off or a new Apply).
func (w *watchdog) reset() {
	w.mu.Lock()
	w.fails, w.degraded = 0, false
	w.mu.Unlock()
}

// forceDegraded keeps the "down" state after a failed re-apply so the next healthy
// probe retries the recovery.
func (w *watchdog) forceDegraded() {
	w.mu.Lock()
	w.degraded = true
	w.mu.Unlock()
}
