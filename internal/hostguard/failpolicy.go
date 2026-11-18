package hostguard

import (
	"fmt"
	"strings"
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

// ConfiguredFailPolicy returns the configured (non-env) policy; "" = never set.
func ConfiguredFailPolicy() protectstate.FailPolicy {
	failPolicyMu.Lock()
	defer failPolicyMu.Unlock()
	return failPolicyCfg
}

// FailPolicy resolves the effective policy (env over configured value over open).
func FailPolicy() protectstate.FailPolicy {
	p, _ := EffectiveFailPolicy()
	return p
}

// EffectiveFailPolicy resolves the effective policy and its source
// (protectstate.PolicySource*): DENYOUT_FAIL_CLOSED=1 > DENYOUT_FAIL_POLICY >
// configured setting > default open.
func EffectiveFailPolicy() (protectstate.FailPolicy, string) {
	return protectstate.ResolveFailPolicy(nil, ConfiguredFailPolicy())
}

// FailPolicyStatus is the helper's report of the policy in force.
type FailPolicyStatus struct {
	Policy     protectstate.FailPolicy
	Source     string
	Configured protectstate.FailPolicy // the persisted setting (may be overridden by env)
}

// CapFailPolicy is advertised by helpers that understand fail-policy/fail-status.
const CapFailPolicy = "fail1"

// FormatFailPolicyReply builds the helper reply for fail-policy / fail-status.
func FormatFailPolicyReply(policy protectstate.FailPolicy, source string, configured protectstate.FailPolicy) string {
	c := string(configured)
	if c == "" {
		c = "-"
	}
	return "OK " + CapFailPolicy + " policy=" + string(policy) + " source=" + source + " configured=" + c
}

// ParseFailPolicyReply parses FormatFailPolicyReply output.
func ParseFailPolicyReply(resp string) (FailPolicyStatus, error) {
	var st FailPolicyStatus
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return st, fmt.Errorf("helper fail-policy: %s", resp)
	}
	for _, f := range strings.Fields(resp) {
		switch {
		case strings.HasPrefix(f, "policy="):
			st.Policy = protectstate.FailPolicy(strings.TrimPrefix(f, "policy="))
		case strings.HasPrefix(f, "source="):
			st.Source = strings.TrimPrefix(f, "source=")
		case strings.HasPrefix(f, "configured="):
			if c := strings.TrimPrefix(f, "configured="); protectstate.ValidFailPolicy(c) {
				st.Configured = protectstate.FailPolicy(c)
			}
		}
	}
	if !protectstate.ValidFailPolicy(string(st.Policy)) {
		return st, fmt.Errorf("helper fail-policy: bad reply %q", resp)
	}
	return st, nil
}

// HelperSetFailPolicy tells the helper which policy to use and returns what it reports
// as effective (env vars on the helper may override the value).
func HelperSetFailPolicy(p protectstate.FailPolicy) (FailPolicyStatus, error) {
	if !protectstate.ValidFailPolicy(string(p)) {
		return FailPolicyStatus{}, fmt.Errorf("fail policy must be open or closed")
	}
	return helperFailCall("fail-policy 0 0 " + string(p))
}

// HelperFailPolicyStatus asks the helper for the effective policy and its source.
func HelperFailPolicyStatus() (FailPolicyStatus, error) {
	return helperFailCall("fail-status 0 0 -")
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
