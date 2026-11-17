package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
)

// UIPauseAsks pauses new-host Ask dialogs for 15 minutes (persisted).
func (a *App) UIPauseAsks() string {
	until := time.Now().Add(askPauseDefault).UTC().Format(time.RFC3339)
	a.mu.Lock()
	a.state.AskPausedUntil = until
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if a.asks == nil {
		a.asks = newAskFlight()
	}
	a.asks.SetPaused(askPauseDefault)
	LogBlock("ask_paused", map[string]any{"until": until})
	return "Asks paused for 15 minutes. New sites stay blocked."
}

// UIResumeAsks clears Ask storm pause. Returns in-app status (OS Info toasts are no-ops).
func (a *App) UIResumeAsks() string {
	a.mu.Lock()
	a.state.AskPausedUntil = ""
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if a.asks != nil {
		a.asks.ClearPause()
	}
	LogBlock("ask_resumed", nil)
	return "Asks resumed."
}

// UIUndoLastAlwaysAllow removes the last Always-allow host.
func (a *App) UIUndoLastAlwaysAllow() (string, error) {
	a.mu.Lock()
	hosts := a.state.AlwaysAllowHosts
	if len(hosts) == 0 {
		a.mu.Unlock()
		return "", fmt.Errorf("Allowed list is empty — nothing to undo")
	}
	last := hosts[len(hosts)-1]
	a.mu.Unlock()
	if err := a.removeAlwaysHost(last); err != nil {
		return "", err
	}
	return "Undid always-allow: " + last, nil
}

// UIBulkAlwaysAllow adds many hosts to Always allow.
// Returns a summary; error when any host failed (including partial success).
func (a *App) UIBulkAlwaysAllow(hosts []string) (string, error) {
	seen := map[string]bool{}
	var okN int
	var failed []string
	var last error
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if err := a.UIAlwaysAllowHost(h, ""); err != nil {
			last = err
			failed = append(failed, h)
			continue
		}
		okN++
	}
	if okN > 0 {
		LogBlock("bulk_always_allow", map[string]any{"count_ok": okN, "failed": failed})
	}
	if len(failed) == 0 {
		if okN == 0 {
			return "", fmt.Errorf("No hosts to allow")
		}
		return fmt.Sprintf("Allowed %d site(s).", okN), nil
	}
	msg := fmt.Sprintf("Allowed %d of %d. Failed: %s", okN, okN+len(failed), strings.Join(failed, ", "))
	if last != nil {
		msg += " (" + last.Error() + ")"
	}
	return msg, fmt.Errorf("%s", msg)
}

// activeTimedRulesLocked returns only unexpired timed allow/deny rows for the UI.
func activeTimedRulesLocked(rules []TimedRule) []TimedRule {
	now := time.Now()
	out := make([]TimedRule, 0, len(rules))
	for _, t := range rules {
		exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
		if err != nil || !now.Before(exp) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ListDenials returns filtered recent denials for Activity.
func (a *App) ListDenials(q DenialQuery) ([]DenialView, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	events, err := audit.RecentDenials(AuditLogPath(), limit*2) // over-fetch then filter
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	keeps := append([]string(nil), a.state.RememberedKeeps...)
	a.mu.Unlock()
	keepSet := map[string]bool{}
	for _, k := range keeps {
		keepSet[k] = true
	}

	search := strings.ToLower(strings.TrimSpace(q.Search))
	reasonF := strings.TrimSpace(q.Reason)
	procF := strings.TrimSpace(q.Process)

	out := make([]DenialView, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if !denialUsefulForUI(e) {
			continue
		}
		host := e.Network.DestHost
		urlStr := audit.DisplayURL(e.Network, e.HTTP)
		why := notify.HumanReasons(e.Reasons)
		code := primaryPostBlockReason(e.Reasons)
		if code == "" && len(e.Reasons) > 0 {
			code = e.Reasons[0]
		}
		remembered := keepSet[postBlockKey(host, code)]
		if !remembered {
			a.mu.Lock()
			remembered = a.state.RememberedKeep(host, code)
			a.mu.Unlock()
		}
		if q.Remembered && !remembered {
			continue
		}
		if reasonF != "" {
			match := false
			for _, r := range e.Reasons {
				if r == reasonF {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if procF != "" && !strings.Contains(e.Process, procF) {
			continue
		}
		if search != "" {
			blob := strings.ToLower(host + " " + urlStr + " " + why + " " + e.Process + " " + strings.Join(e.Reasons, " "))
			if !strings.Contains(blob, search) {
				continue
			}
		}
		method := ""
		if e.HTTP != nil {
			method = e.HTTP.Method
		}
		id := e.EventID
		if id == "" {
			id = fmt.Sprintf("%s|%s|%d", e.TS, host, i)
		}
		out = append(out, DenialView{
			ID:            id,
			TS:            e.TS,
			Host:          host,
			URL:           urlStr,
			Why:           why,
			Reasons:       append([]string(nil), e.Reasons...),
			PrimaryReason: code,
			Process:       e.Process,
			Method:        method,
			Detectors:     append([]string(nil), e.Detectors...),
			PolicyProfile: e.PolicyProfile,
			Remembered:    remembered,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// UIAlwaysAllowHost persists Always allow and forgets Keep for primary reason if set.
// When reason is empty, clears all silenced Keep keys for that host.
// process may be "wrap:<profileID>" from History — also pins the agent allowlist.
func (a *App) UIAlwaysAllowHost(host, reason string) error {
	return a.UIAlwaysAllowHostFrom(host, reason, "")
}

// UIAlwaysAllowHostFrom is History-aware Always allow (optional wrap process).
func (a *App) UIAlwaysAllowHostFrom(host, reason, process string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if isIPLiteral(host) {
		return fmt.Errorf("raw IP addresses cannot be always-allowed; Safe browse already allows public IPs")
	}
	if reason != "" {
		a.forgetKeep(host, reason)
	} else {
		a.forgetKeepsForHost(host)
	}
	if err := a.persistAlwaysHostFrom(host, "history"); err != nil {
		return err
	}
	// Also unblock any running My agents wraps for this host.
	a.allowHostOnRunningWraps(host)
	if id := strings.TrimPrefix(strings.TrimSpace(process), "wrap:"); id != "" && id != process {
		_ = a.recordProfileAlways(id, host)
	}
	return nil
}

// UIForgetKeep removes a remembered Keep key (host|reason or host + reason).
func (a *App) UIForgetKeep(host, reason string) error {
	if strings.Contains(host, "|") && reason == "" {
		parts := strings.SplitN(host, "|", 2)
		host, reason = parts[0], parts[1]
	}
	a.forgetKeep(host, reason)
	return nil
}

// UIClearAllKeeps clears remembered post-block Keeps.
func (a *App) UIClearAllKeeps() error {
	a.mu.Lock()
	a.state.RememberedKeeps = nil
	st := a.state
	a.mu.Unlock()
	LogBlock("forget_keep", map[string]any{"all": true})
	return SaveState(st)
}

// UIRemoveAlwaysAllow removes a host from always-allow.
func (a *App) UIRemoveAlwaysAllow(host string) error {
	return a.removeAlwaysHost(host)
}

// UIRemoveTimedAllow removes a timed allow by host and refreshes live policy.
func (a *App) UIRemoveTimedAllow(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	a.mu.Lock()
	out := a.state.TimedAllows[:0]
	for _, t := range a.state.TimedAllows {
		if strings.ToLower(strings.TrimSpace(t.Host)) != h {
			out = append(out, t)
		}
	}
	a.state.TimedAllows = out
	st := a.state
	sess := a.session
	wasProxy := a.proxyd != nil
	a.mu.Unlock()
	LogBlock("timed_allow_remove", map[string]any{"host": host, "source": "ui"})
	if err := SaveState(st); err != nil {
		return err
	}
	if sess != nil {
		sess.RevokeHost(host)
		a.revokeHostEverywhere(host)
		return nil
	}
	if wasProxy {
		_ = a.stopComputerOpts(true, false)
		return a.startComputer()
	}
	a.revokeHostEverywhere(host)
	return nil
}

// UIRemoveTimedDeny removes a timed deny by host|reason key host.
func (a *App) UIRemoveTimedDeny(host, reason string) error {
	key := postBlockKey(host, reason)
	a.mu.Lock()
	out := a.state.TimedDenies[:0]
	for _, t := range a.state.TimedDenies {
		if postBlockKey(t.Host, t.Reason) != key {
			out = append(out, t)
		}
	}
	a.state.TimedDenies = out
	st := a.state
	a.mu.Unlock()
	LogBlock("timed_deny_remove", map[string]any{"host": host, "reason": reason, "source": "ui"})
	return SaveState(st)
}
