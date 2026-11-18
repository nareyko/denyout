//go:build linux

package hostguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/nareyko/denyout/internal/protectstate"
)

const helperStateFile = "/run/denyout-hostguard.state"

// watchdogEffects are the side effects of one watchdog tick; tests replace them.
type watchdogEffects struct {
	probe          func(port int) bool // proxy answers on 127.0.0.1:port
	failClosed     func() bool         // effective fail policy is closed
	applyRedirect  func(Spec) error
	removeRedirect func(Spec) error
	writeState     func(string)
	fireDegraded   func()
}

var wdFx = watchdogEffects{
	probe: func(port int) bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	},
	failClosed:     func() bool { return FailPolicy() == protectstate.FailClosed },
	applyRedirect:  applyRedirect,
	removeRedirect: removeRedirect,
	writeState:     writeHelperState,
	fireDegraded:   fireDegraded,
}

// helperWatchdog is the stateful side of runWatchdog: the pure edge machine plus
// the "state file says blocked" flag.
type helperWatchdog struct {
	w       *watchdog
	blocked bool // state file says "blocked" (closed policy, proxy down)
}

// runWatchdog probes the proxy port from the last successful Apply and keeps the
// nft redirect consistent with proxy health (see watchdog).
func runWatchdog(ctx context.Context) {
	h := &helperWatchdog{w: &watchdog{failClosed: wdFx.failClosed()}}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.tick()
	}
}

// tick runs one probe cycle.
func (h *helperWatchdog) tick() {
	w := h.w
	lastApplyMu.Lock()
	spec, ok := lastApplySpec, lastApplyOK
	lastApplyMu.Unlock()
	if !ok || spec.ProxyPort <= 0 {
		w.reset() // Protect Off: forget any "degraded" memory
		h.blocked = false
		return
	}
	// The policy is re-read every tick: a live change (fail-policy verb, apply with
	// fail=, or an env var) takes effect within ~2s without restarting the helper.
	policyEdge := w.setPolicy(wdFx.failClosed())
	up := wdFx.probe(spec.ProxyPort)
	edge := w.observe(up)
	if policyEdge == "reclose" {
		edge = "reclose"
	}
	if edge == "" {
		h.steadyState(up)
		return
	}
	if up {
		h.blocked = false
	}
	h.actOnEdge(edge, spec, up)
}

// steadyState keeps the state file honest when no edge fired.
func (h *helperWatchdog) steadyState(up bool) {
	switch {
	case !up && h.w.proxyDown() && h.w.closed() && !h.blocked:
		h.blocked = true
		wdFx.writeState("blocked proxy_down")
	case up && h.blocked:
		h.blocked = false
		wdFx.writeState("protected")
	}
}

// actOnEdge acts only under helperOpMu and only if Protect is still On with the
// same intent: a Protect Off (remove/teardown) can land between the probe and the
// action, and a stale edge must never re-apply rules the user just removed.
func (h *helperWatchdog) actOnEdge(edge string, spec Spec, up bool) {
	w := h.w
	helperOpMu.Lock()
	lastApplyMu.Lock()
	cur, still, tunOwns := lastApplySpec, lastApplyOK, tunSuppressed
	lastApplyMu.Unlock()
	if !still || cur.ProxyPort != spec.ProxyPort {
		helperOpMu.Unlock()
		w.reset()
		return
	}
	switch edge {
	case "reclose":
		// Policy tightened while the redirect was removed: restore the rules now.
		if !h.reapply(cur, tunOwns) {
			return
		}
		if up {
			wdFx.writeState("protected")
		} else {
			h.blocked = true
			wdFx.writeState("blocked proxy_down")
		}
	case "degrade":
		h.blocked = false
		_ = wdFx.removeRedirect(cur)
		helperOpMu.Unlock()
		wdFx.writeState("degraded proxy_down")
		wdFx.fireDegraded()
	case "recover":
		// Rules only (CA is already trusted); keep "degraded" if this fails so the
		// next tick retries instead of believing protection is back.
		if !h.reapply(cur, tunOwns) {
			return
		}
		wdFx.writeState("protected")
	default:
		helperOpMu.Unlock()
	}
}

// reapply puts the redirect rules back (the TUN-suppressed variant while the
// data plane owns IPv4 TCP) and releases helperOpMu. On failure it keeps the
// "degraded" memory so the next healthy probe retries, and reports false.
func (h *helperWatchdog) reapply(cur Spec, tunOwns bool) bool {
	rules := cur
	if tunOwns {
		rules = suppressedSpec(cur)
	}
	err := wdFx.applyRedirect(rules)
	helperOpMu.Unlock()
	if err != nil {
		h.w.forceDegraded()
		return false
	}
	return true
}

func writeHelperState(s string) {
	_ = os.WriteFile(helperStateFile, []byte(s+"\n"), 0o644)
}
