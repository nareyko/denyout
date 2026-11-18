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

// runWatchdog probes the proxy port from the last successful Apply and keeps the
// nft redirect consistent with proxy health (see watchdog).
func runWatchdog(ctx context.Context) {
	w := &watchdog{failClosed: FailPolicy() == protectstate.FailClosed}
	blocked := false // state file says "blocked" (closed policy, proxy down)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		lastApplyMu.Lock()
		spec, ok := lastApplySpec, lastApplyOK
		lastApplyMu.Unlock()
		if !ok || spec.ProxyPort <= 0 {
			w.reset() // Protect Off: forget any "degraded" memory
			blocked = false
			continue
		}
		// The policy is re-read every tick: a live change (fail-policy verb, apply with
		// fail=, or an env var) takes effect within ~2s without restarting the helper.
		policyEdge := w.setPolicy(FailPolicy() == protectstate.FailClosed)
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ProxyPort), 500*time.Millisecond)
		up := err == nil
		if up {
			_ = c.Close()
		}
		edge := w.observe(up)
		if policyEdge == "reclose" {
			edge = "reclose"
		}
		if edge == "" {
			switch {
			case !up && w.proxyDown() && w.closed() && !blocked:
				blocked = true
				writeHelperState("blocked proxy_down")
			case up && blocked:
				blocked = false
				writeHelperState("protected")
			}
			continue
		}
		if up {
			blocked = false
		}
		// Act only under helperOpMu and only if Protect is still On with the same intent:
		// a Protect Off (remove/teardown) can land between the probe and the action, and a
		// stale edge must never re-apply rules the user just removed.
		helperOpMu.Lock()
		lastApplyMu.Lock()
		cur, still, tunOwns := lastApplySpec, lastApplyOK, tunSuppressed
		lastApplyMu.Unlock()
		if !still || cur.ProxyPort != spec.ProxyPort {
			helperOpMu.Unlock()
			w.reset()
			continue
		}
		switch edge {
		case "reclose":
			// Policy tightened while the redirect was removed: restore the rules now.
			rules := cur
			if tunOwns {
				rules = suppressedSpec(cur)
			}
			err := applyRedirect(rules)
			helperOpMu.Unlock()
			if err != nil {
				w.forceDegraded()
				continue
			}
			if up {
				writeHelperState("protected")
			} else {
				blocked = true
				writeHelperState("blocked proxy_down")
			}
		case "degrade":
			blocked = false
			_ = removeRedirect(cur)
			helperOpMu.Unlock()
			writeHelperState("degraded proxy_down")
			fireDegraded()
		case "recover":
			// Rules only (CA is already trusted); keep "degraded" if this fails so the
			// next tick retries instead of believing protection is back.
			rules := cur
			if tunOwns {
				rules = suppressedSpec(cur)
			}
			err := applyRedirect(rules)
			helperOpMu.Unlock()
			if err != nil {
				w.forceDegraded()
				continue
			}
			writeHelperState("protected")
		}
	}
}

func writeHelperState(s string) {
	_ = os.WriteFile(helperStateFile, []byte(s+"\n"), 0o644)
}
