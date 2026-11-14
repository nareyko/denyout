package desktop

import (
	"strings"

	"github.com/nareyko/denyout/internal/policy"
)

// Policy profiles for desktop Computer.
const (
	PolicyProfileAgent  = "agent"  // Agents only — default-deny allowlist
	PolicyProfileBrowse = "browse" // Safe desktop — web OK, scanners on
)

func normalizePolicyProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case PolicyProfileAgent:
		return PolicyProfileAgent
	default:
		return PolicyProfileBrowse
	}
}

// desktopPolicyConfig builds the live policy for proxyd/session from state.
func (a *App) desktopPolicyConfig() (*policy.Config, error) {
	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	ask := a.state.AskMode
	always := append([]string{}, a.state.AlwaysAllowHosts...)
	activeID := a.state.ActiveProfileID
	a.mu.Unlock()

	var rules []policy.Rule
	for _, h := range always {
		h = strings.TrimSpace(h)
		if h != "" {
			rules = append(rules, policy.Rule{Host: h, Reason: "user_always"})
		}
	}

	// Named profile overlay on Computer (preset + allows), no child command.
	if activeID != "" && profile == PolicyProfileAgent {
		if np, err := LoadProfile(activeID); err == nil {
			for _, h := range append(append([]string{}, np.ExtraAllow...), np.PendingOnce...) {
				h = strings.TrimSpace(h)
				if h != "" {
					rules = append(rules, policy.Rule{Host: h, Reason: "profile"})
				}
			}
			ask = ask || np.AskMode
		}
	}

	if profile == PolicyProfileBrowse {
		cfg, err := policy.DefaultWholeDeviceBrowse()
		if err != nil {
			return nil, err
		}
		cfg.Allow = append(cfg.Allow, rules...)
		return cfg, nil
	}

	if ask || len(rules) > 0 {
		return policy.DefaultWholeDeviceAsk(rules)
	}
	return policy.DefaultWholeDevice()
}
