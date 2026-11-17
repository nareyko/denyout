package desktop

import (
	"strings"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/run"
)

func (a *App) onWrapDeny(sess *run.Session, profileID, profileName string, ask, notifyBlocks bool, host string, reasons []string, redactedURL string) {
	a.mu.Lock()
	a.lastDeny = host
	a.state.LastDenyHost = host
	a.state.LastDenySummary = notify.HumanReasons(reasons)
	a.state.LastDenyURL = strings.TrimSpace(redactedURL)
	a.state.LastDenyProcess = "wrap:" + profileID
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	a.logPolicyDeny("wrap", host, reasons, redactedURL, "wrap:"+profileID)

	// Notify off: still record Last blocked / audit; skip Ask/post-block dialogs.
	if !notifyBlocks {
		return
	}

	hostNotAllowed := false
	for _, r := range reasons {
		if r == "host_not_allowed" {
			hostNotAllowed = true
		}
	}
	if isIPLiteral(host) {
		if a.asks == nil {
			a.asks = newAskFlight()
		}
		a.asks.notifyIPBlocked(host)
		return
	}
	if ask && hostNotAllowed {
		action := a.coalescedAskProfile(host, "host_not_allowed", profileName, profileID)
		switch action {
		case "once":
			if sess != nil {
				sess.AllowHost(host, "user_once")
			}
			_ = a.recordProfileOnce(profileID, host)
			LogBlock("allow_once", map[string]any{
				"host": host, "scope": "wrap", "profile_id": profileID, "source": "ask",
			})
		case "always":
			if sess != nil {
				sess.AllowHost(host, "user_always")
			}
			_ = a.recordProfileAlways(profileID, host)
			LogBlock("always_allow_add", map[string]any{
				"host": host, "source": "ask", "profile_id": profileID, "scope": "wrap",
			})
		}
		return
	}
	if isClearPostBlock(reasons) {
		go a.handlePostBlockDenyProfile(profileID, host, reasons, redactedURL)
		return
	}
	// Other denies (e.g. host_not_allowed without Ask): History only.
}

// allowHostOnRunningWraps applies a host allow to every live wrap session.
func (a *App) allowHostOnRunningWraps(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	a.mu.Lock()
	wraps := make([]*wrapProc, 0, len(a.wraps))
	for _, wp := range a.wraps {
		wraps = append(wraps, wp)
	}
	a.mu.Unlock()
	for _, wp := range wraps {
		if wp != nil && wp.sess != nil {
			wp.sess.AllowHost(host, "user_always")
		}
	}
}

// allowWrapHostLive unblocks a host for one wrap and optionally pins it on the profile.
func (a *App) allowWrapHostLive(profileID, host string, permanent bool) {
	profileID = strings.TrimSpace(profileID)
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if profileID != "" {
		a.mu.Lock()
		wp := a.wraps[profileID]
		a.mu.Unlock()
		if wp != nil && wp.sess != nil {
			if permanent {
				wp.sess.AllowHost(host, "user_always")
			} else {
				wp.sess.AllowHost(host, "user_once")
			}
		}
		if permanent {
			_ = a.recordProfileAlways(profileID, host)
		}
		return
	}
	a.allowHostOnRunningWraps(host)
}

// revokeWrapHostLive undoes a wrap Allow (session + optional profile pin).
func (a *App) revokeWrapHostLive(profileID, host string, unpin bool) {
	profileID = strings.TrimSpace(profileID)
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if profileID != "" {
		a.mu.Lock()
		wp := a.wraps[profileID]
		a.mu.Unlock()
		if wp != nil && wp.sess != nil {
			wp.sess.RevokeHost(host)
		}
		if unpin {
			_ = a.unpinProfileHost(profileID, host)
		}
		return
	}
	a.revokeHostEverywhere(host)
}

func (a *App) unpinProfileHost(id, host string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	want := strings.ToLower(strings.TrimSpace(host))
	if want == "" {
		return nil
	}
	filter := func(in []string) []string {
		out := in[:0]
		for _, h := range in {
			if strings.ToLower(strings.TrimSpace(h)) == want {
				continue
			}
			out = append(out, h)
		}
		return out
	}
	p.ExtraAllow = filter(p.ExtraAllow)
	p.PendingOnce = filter(p.PendingOnce)
	return SaveProfile(p)
}

func (a *App) recordProfileOnce(id, host string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	if p.Learning.Enabled {
		p.AddPendingOnce(host)
	} else {
		// Learning off: Once is session-only (already AllowHost).
		return nil
	}
	return SaveProfile(p)
}

func (a *App) recordProfileAlways(id, host string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	p.PinPending([]string{host})
	if len(p.ExtraAllow) == 0 || !containsFold(p.ExtraAllow, host) {
		p.ExtraAllow = append(p.ExtraAllow, strings.ToLower(strings.TrimSpace(host)))
	}
	return SaveProfile(p)
}

func containsFold(list []string, host string) bool {
	for _, h := range list {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
