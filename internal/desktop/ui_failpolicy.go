package desktop

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/protectstate"
)

// FailPolicyView is the Settings payload for "If DenyOut's proxy stops".
type FailPolicyView struct {
	// Setting is the user's choice: "open" (default) or "closed".
	Setting string `json:"setting"`
	// Effective is what is actually enforced (an env var on the helper may override).
	Effective string `json:"effective"`
	// Source is setting | default | env:DENYOUT_FAIL_POLICY | env:DENYOUT_FAIL_CLOSED.
	Source string `json:"source"`
	// EnvOverride is true when an environment variable decides, not the setting.
	EnvOverride bool `json:"env_override"`
	// Note is a plain-language sentence for the UI ("" when nothing to add).
	Note string `json:"note,omitempty"`
}

// failPolicyViewLocked builds the view (caller holds a.mu). While Protect is live the
// root helper's own report wins (its environment is what actually applies); otherwise
// this process's environment is the best local estimate.
func failPolicyViewLocked(a *App) FailPolicyView {
	raw := protectstate.FailPolicy(appstateNormalizeFailPolicy(a.state.FailPolicy))
	setting := raw
	if setting == "" {
		setting = protectstate.FailOpen
	}
	eff, src := protectstate.ResolveFailPolicy(nil, raw)
	if a.proxyd != nil && a.failHelper != nil {
		eff, src = a.failHelper.Policy, a.failHelper.Source
	}
	v := FailPolicyView{Setting: string(setting), Effective: string(eff), Source: src}
	v.EnvOverride = strings.HasPrefix(src, "env:")
	if v.EnvOverride {
		name := strings.TrimPrefix(src, "env:")
		v.Note = fmt.Sprintf("%s is set, so it decides this (%s) regardless of the choice above.", name, plainFailPolicy(eff))
	}
	return v
}

func plainFailPolicy(p protectstate.FailPolicy) string {
	if p == protectstate.FailClosed {
		return "block web traffic until it recovers"
	}
	return "keep the internet working"
}

// effectiveFailPolicyLocked is the policy protectstate wording should mention.
func effectiveFailPolicyLocked(a *App) protectstate.FailPolicy {
	return protectstate.FailPolicy(failPolicyViewLocked(a).Effective)
}

// UIFailPolicy returns the current setting, the effective policy and its source.
func (a *App) UIFailPolicy() FailPolicyView {
	a.mu.Lock()
	defer a.mu.Unlock()
	return failPolicyViewLocked(a)
}

// UISetFailPolicy sets what happens when DenyOut's proxy stops while Protect is on:
// "open" (default: keep the internet working) or "closed" (block web traffic until it
// recovers). Only those two values are accepted. The choice is saved and, if Protect is
// on, sent to the root helper right away (no restart).
func (a *App) UISetFailPolicy(policy string) error {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if !protectstate.ValidFailPolicy(policy) {
		return fmt.Errorf("fail policy must be \"open\" or \"closed\"")
	}
	a.mu.Lock()
	a.state.FailPolicy = policy
	live := a.proxyd != nil
	st := a.state
	a.failHelper = nil
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	LogEvent("fail_policy_setting", map[string]any{"policy": policy, "live": live})
	if err := a.pushFailPolicy(live); err != nil {
		return fmt.Errorf("Saved, but could not tell the protection helper: %w", err)
	}
	return nil
}

// pushFailPolicy makes the helper process use the saved policy. The desktop-side value
// is always refreshed (it rides along on the next apply); the helper is called only
// while Protect is live.
func (a *App) pushFailPolicy(live bool) error {
	a.mu.Lock()
	policy := protectstate.FailPolicy(a.state.FailPolicy)
	a.mu.Unlock()
	hostguard.SetFailPolicy(policy)
	if !live || !protectstate.ValidFailPolicy(string(policy)) || hostguard.ElevateDisabledByEnv() {
		return nil
	}
	st, err := hostguard.HelperSetFailPolicy(policy)
	if err != nil {
		if errors.Is(err, hostguard.ErrHelperUnavailable) {
			// No (or an older) helper: the policy rides along on the next Protect On.
			AppendDesktopLog("INFO fail policy not pushed live: %v", err)
			return nil
		}
		return err
	}
	a.mu.Lock()
	a.failHelper = &st
	a.mu.Unlock()
	return nil
}

// refreshFailHelper caches the helper's report of the effective policy (best effort).
func (a *App) refreshFailHelper() {
	if hostguard.ElevateDisabledByEnv() {
		return
	}
	st, err := hostguard.HelperFailPolicyStatus()
	if err != nil {
		return
	}
	a.mu.Lock()
	a.failHelper = &st
	a.mu.Unlock()
}
