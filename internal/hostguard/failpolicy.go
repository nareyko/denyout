package hostguard

import (
	"sync"

	"github.com/nareyko/denyout/internal/protectstate"
)

var (
	failPolicyMu  sync.Mutex
	failPolicyCfg protectstate.FailPolicy // configured default; env overrides
	degradedHook  func()
)

// SetFailPolicy sets the configured fail policy (open = fail-soft default, closed =
// keep the redirect when the proxy is lost). The environment still wins:
// DENYOUT_FAIL_CLOSED=1 (legacy) forces closed, DENYOUT_FAIL_POLICY=open|closed
// overrides the configured value.
func SetFailPolicy(p protectstate.FailPolicy) {
	failPolicyMu.Lock()
	failPolicyCfg = p
	failPolicyMu.Unlock()
}

// FailPolicy resolves the effective policy (env over configured value over open).
func FailPolicy() protectstate.FailPolicy {
	failPolicyMu.Lock()
	def := failPolicyCfg
	failPolicyMu.Unlock()
	return protectstate.FailPolicyFromEnv(nil, def)
}

// SetDegradedHook registers a callback fired in the helper when the watchdog
// transitions into degraded (redirect removed). It must not block.
func SetDegradedHook(f func()) {
	failPolicyMu.Lock()
	degradedHook = f
	failPolicyMu.Unlock()
}

func fireDegraded() {
	failPolicyMu.Lock()
	f := degradedHook
	failPolicyMu.Unlock()
	if f != nil {
		f()
	}
}
