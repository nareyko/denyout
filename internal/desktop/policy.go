package desktop

import (
	"strings"

	"github.com/nareyko/denyout/internal/policy"
)

// Policy profiles for desktop Computer/Session.
const (
	PolicyProfileAgent  = "agent"  // default-deny allowlist (Rule of Two on egress)
	PolicyProfileBrowse = "browse" // legacy blocklist
)

func normalizePolicyProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case PolicyProfileBrowse:
		return PolicyProfileBrowse
	default:
		return PolicyProfileAgent
	}
}

// desktopPolicyConfig builds the live policy for session/proxyd from state.
func (a *App) desktopPolicyConfig() (*policy.Config, error) {
	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	ask := a.state.AskMode
	always := append([]string{}, a.state.AlwaysAllowHosts...)
	a.mu.Unlock()

	if profile == PolicyProfileBrowse {
		return policy.DefaultWholeDeviceBrowse()
	}

	var rules []policy.Rule
	for _, h := range always {
		h = strings.TrimSpace(h)
		if h != "" {
			rules = append(rules, policy.Rule{Host: h, Reason: "user_always"})
		}
	}
	// Ask mode and/or AlwaysAllow both need the Ask config loader (enforce+agent+extra allow).
	if ask || len(rules) > 0 {
		return policy.DefaultWholeDeviceAsk(rules)
	}
	return policy.DefaultWholeDevice()
}
