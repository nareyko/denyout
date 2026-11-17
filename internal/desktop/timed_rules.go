package desktop

import (
	"strings"
	"time"
)

func (a *App) rememberKeep(host, reason string) {
	key := postBlockKey(host, reason)
	a.mu.Lock()
	for _, k := range a.state.RememberedKeeps {
		if k == key {
			a.mu.Unlock()
			return
		}
	}
	a.state.RememberedKeeps = append(a.state.RememberedKeeps, key)
	if len(a.state.RememberedKeeps) > 200 {
		a.state.RememberedKeeps = a.state.RememberedKeeps[len(a.state.RememberedKeeps)-200:]
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogBlock("remember_keep", map[string]any{"host": host, "reason": reason})
}

func (a *App) forgetKeep(host, reason string) {
	key := postBlockKey(host, reason)
	a.mu.Lock()
	out := a.state.RememberedKeeps[:0]
	removed := false
	for _, k := range a.state.RememberedKeeps {
		if k != key {
			out = append(out, k)
		} else {
			removed = true
		}
	}
	a.state.RememberedKeeps = out
	// Drop matching timed denies too.
	td := a.state.TimedDenies[:0]
	for _, t := range a.state.TimedDenies {
		if postBlockKey(t.Host, t.Reason) != key {
			td = append(td, t)
		}
	}
	a.state.TimedDenies = td
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if removed {
		LogBlock("forget_keep", map[string]any{"host": host, "reason": reason})
	}
}

// forgetKeepsForHost clears all silenced Keep keys and timed denies for a host.
func (a *App) forgetKeepsForHost(host string) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return
	}
	prefix := h + "|"
	a.mu.Lock()
	out := a.state.RememberedKeeps[:0]
	for _, k := range a.state.RememberedKeeps {
		if k == h || strings.HasPrefix(strings.ToLower(k), prefix) {
			continue
		}
		out = append(out, k)
	}
	a.state.RememberedKeeps = out
	td := a.state.TimedDenies[:0]
	for _, t := range a.state.TimedDenies {
		if strings.ToLower(strings.TrimSpace(t.Host)) == h {
			continue
		}
		td = append(td, t)
	}
	a.state.TimedDenies = td
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
}

func (a *App) addTimedDeny(host, reason string, d time.Duration) {
	exp := time.Now().Add(d).UTC().Format(time.RFC3339)
	key := postBlockKey(host, reason)
	a.mu.Lock()
	out := a.state.TimedDenies[:0]
	for _, t := range a.state.TimedDenies {
		if postBlockKey(t.Host, t.Reason) != key {
			out = append(out, t)
		}
	}
	out = append(out, TimedRule{Host: host, Reason: reason, ExpiresAt: exp})
	a.state.TimedDenies = out
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogBlock("timed_deny", map[string]any{"host": host, "reason": reason, "until": exp})
}

func (a *App) addTimedAllow(host string, d time.Duration) {
	exp := time.Now().Add(d).UTC().Format(time.RFC3339)
	h := strings.ToLower(strings.TrimSpace(host))
	a.mu.Lock()
	out := a.state.TimedAllows[:0]
	for _, t := range a.state.TimedAllows {
		if strings.ToLower(strings.TrimSpace(t.Host)) != h {
			out = append(out, t)
		}
	}
	out = append(out, TimedRule{Host: host, ExpiresAt: exp})
	a.state.TimedAllows = out
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogBlock("timed_allow", map[string]any{"host": host, "until": exp})
	// Timed only — never persist into AlwaysAllowHosts (that made "15 minutes" permanent).
	_ = a.applyLiveAllows(host)
}

// liveAllowHostsLocked returns permanent + still-active timed allow hosts.
func liveAllowHostsLocked(st State) []string {
	now := time.Now()
	seen := map[string]bool{}
	out := make([]string, 0, len(st.AlwaysAllowHosts)+len(st.TimedAllows))
	for _, h := range st.AlwaysAllowHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, t := range st.TimedAllows {
		exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
		if err != nil || !now.Before(exp) {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(t.Host))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// applyLiveAllows pushes permanent+timed allows into the running protector.
func (a *App) applyLiveAllows(justHost string) error {
	a.mu.Lock()
	sess := a.session
	wasProxy := a.proxyd != nil
	a.mu.Unlock()
	if sess != nil {
		host := strings.TrimSpace(justHost)
		if host != "" {
			sess.AllowHost(host, "user_timed")
		}
		return nil
	}
	if wasProxy {
		_ = a.stopComputerOpts(true, false)
		return a.startComputer()
	}
	return nil
}
