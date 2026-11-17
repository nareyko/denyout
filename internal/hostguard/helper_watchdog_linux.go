//go:build linux

package hostguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

const helperStateFile = "/run/denyout-hostguard.state"

// runWatchdog probes the proxy port from the last successful Apply and keeps the
// nft redirect consistent with proxy health (see watchdog).
func runWatchdog(ctx context.Context) {
	w := &watchdog{failClosed: os.Getenv("DENYOUT_FAIL_CLOSED") == "1"}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		lastApplyMu.Lock()
		spec, ok, tunOwns := lastApplySpec, lastApplyOK, tunSuppressed
		lastApplyMu.Unlock()
		if !ok || spec.ProxyPort <= 0 {
			continue
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ProxyPort), 500*time.Millisecond)
		up := err == nil
		if up {
			_ = c.Close()
		}
		switch w.observe(up) {
		case "degrade":
			helperOpMu.Lock()
			_ = removeRedirect(spec)
			helperOpMu.Unlock()
			writeHelperState("degraded proxy_down")
		case "recover":
			helperOpMu.Lock()
			if tunOwns {
				helperOpMu.Unlock()
				suppressT0ForTUN(true)
			} else {
				_ = Apply(spec)
				helperOpMu.Unlock()
			}
			writeHelperState("protected")
		}
	}
}

func writeHelperState(s string) {
	_ = os.WriteFile(helperStateFile, []byte(s+"\n"), 0o644)
}
