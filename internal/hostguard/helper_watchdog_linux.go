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
			continue
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ProxyPort), 500*time.Millisecond)
		up := err == nil
		if up {
			_ = c.Close()
		}
		edge := w.observe(up)
		if edge == "" {
			continue
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
		case "degrade":
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
