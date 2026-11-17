package desktop

import (
	"fmt"
	"github.com/nareyko/denyout/internal/appstate"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

const postBlockQuietEvery = time.Minute // keep-repeat toast throttle (P3 may honor Settings)

// clearPostBlockReasons are Safe-desktop threats that use post-block confirm (not Pre-act Ask).
var clearPostBlockReasons = map[string]bool{
	"secret_in_url":    true,
	"secret_in_header": true,
	"secret_in_body":   true,
	"canary_detected":  true,
	"host_denied":      true,
	"threat_list":      true, // legacy umbrella
	"threat_phishing":  true,
	"threat_malware":   true,
	"threat_ads":       true,
	"unsafe_ip":        true,
	"ip_literal":       true,
}

func primaryPostBlockReason(reasons []string) string {
	for _, r := range reasons {
		if clearPostBlockReasons[r] {
			return r
		}
	}
	return ""
}

func postBlockKey(host, reason string) string { return appstate.PostBlockKey(host, reason) }

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

var postBlockMu sync.Mutex
var postBlockQuietAt = map[string]time.Time{}
var decisionBusy bool

type queuedDecision struct {
	Host      string
	Reason    string
	URL       string
	ProfileID string // wrap profile when deny came from My agents
}

var decisionQueue []queuedDecision

// handlePostBlockDeny runs after a clear Safe-desktop deny (request already blocked).
func (a *App) handlePostBlockDeny(host string, reasons []string, redactedURL string) {
	a.handlePostBlockDenyProfile("", host, reasons, redactedURL)
}

// handlePostBlockDenyProfile is the wrap-aware post-block path (Allow must hit the session).
func (a *App) handlePostBlockDenyProfile(profileID, host string, reasons []string, redactedURL string) {
	reason := primaryPostBlockReason(reasons)
	if reason == "" {
		return
	}
	if reason == "unsafe_ip" || reason == "ip_literal" || isIPLiteral(host) {
		if a.asks == nil {
			a.asks = newAskFlight()
		}
		a.asks.notifyIPBlocked(host)
		return
	}

	a.mu.Lock()
	remembered := a.state.RememberedKeep(host, reason)
	taught := a.state.PostBlockTaught
	a.mu.Unlock()

	key := postBlockKey(host, reason)
	urlLine := strings.TrimSpace(redactedURL)
	if remembered {
		postBlockMu.Lock()
		last := postBlockQuietAt[key]
		quietEvery := reaskInterval(a)
		if quietEvery <= 0 {
			quietEvery = postBlockQuietEvery
		}
		if time.Since(last) < quietEvery {
			postBlockMu.Unlock()
			return
		}
		postBlockQuietAt[key] = time.Now()
		postBlockMu.Unlock()
		// Keep-repeat must never flood the OS (lock screen). Away/fullscreen: bump tray unread.
		if a.isAway() || a.isFullscreenQuiet() {
			a.noteAwayUnread(host, awayUnreadBlock)
		}
		return
	}

	if shouldThrottlePrompt(key, reaskInterval(a)) {
		return
	}

	item := queuedDecision{Host: host, Reason: reason, URL: urlLine, ProfileID: profileID}
	postBlockMu.Lock()
	if decisionBusy {
		// Same dialog session: queue; next presentment is site-grouped list.
		decisionQueue = append(decisionQueue, item)
		postBlockMu.Unlock()
		return
	}
	decisionBusy = true
	batch := append([]queuedDecision{item}, decisionQueue...)
	decisionQueue = nil
	postBlockMu.Unlock()

	if !taught {
		a.mu.Lock()
		a.state.PostBlockTaught = true
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
	}

	for {
		a.runDecisionBatch(batch, taught)
		taught = true
		postBlockMu.Lock()
		batch = decisionQueue
		decisionQueue = nil
		if len(batch) == 0 {
			decisionBusy = false
			postBlockMu.Unlock()
			return
		}
		postBlockMu.Unlock()
	}
}

func (a *App) runDecisionBatch(batch []queuedDecision, taught bool) {
	if len(batch) == 0 {
		return
	}
	// Dedupe by host|reason, keep first URL.
	seen := map[string]queuedDecision{}
	order := []string{}
	for _, it := range batch {
		k := postBlockKey(it.Host, it.Reason)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = it
		order = append(order, k)
	}
	if len(order) == 1 {
		it := seen[order[0]]
		why := notify.HumanReasons([]string{it.Reason})
		action := a.presentHardBlockDecision(DecisionPrompt{
			Host:      it.Host,
			Reason:    it.Reason,
			Why:       why,
			URL:       it.URL,
			Timeout:   decisionTimeout(a),
			Taught:    taught,
			ProfileID: it.ProfileID,
		})
		a.applyHardBlockDecisionProfile(it.ProfileID, it.Host, it.Reason, action)
		return
	}
	// Multi-site list (group by site).
	var body strings.Builder
	body.WriteString("Several blocks need a choice:\n\n")
	hosts := []string{}
	hostKeys := map[string][]string{} // host -> keys
	for _, k := range order {
		it := seen[k]
		hosts = append(hosts, it.Host)
		hostKeys[it.Host] = append(hostKeys[it.Host], k)
		body.WriteString("- ")
		body.WriteString(it.Host)
		body.WriteString(" - ")
		body.WriteString(notify.HumanReasons([]string{it.Reason}))
		body.WriteByte('\n')
	}
	_ = hosts
	// Any wrap in the batch → agent Allow copy (PC timed Allow labels lie for wraps).
	firstProfile := ""
	profiles := map[string]struct{}{}
	for _, k := range order {
		pid := strings.TrimSpace(seen[k].ProfileID)
		if pid == "" {
			continue
		}
		profiles[pid] = struct{}{}
		if firstProfile == "" {
			firstProfile = pid
		}
	}
	action := a.presentHardBlockDecision(DecisionPrompt{
		Host:       fmt.Sprintf("%d sites", len(hostKeys)),
		Reason:     "batch",
		Why:        strings.TrimSpace(body.String()),
		Timeout:    decisionTimeout(a),
		Taught:     true,
		Batch:      true,
		ProfileID:  firstProfile,
		MultiAgent: len(profiles) > 1,
	})
	// Apply same action to every pending item (bulk Keep / Allow / later).
	for _, k := range order {
		it := seen[k]
		a.applyHardBlockDecisionProfile(it.ProfileID, it.Host, it.Reason, action)
	}
}

func (a *App) applyHardBlockDecision(host, reason, action string) {
	a.applyHardBlockDecisionProfile("", host, reason, action)
}

func (a *App) applyHardBlockDecisionProfile(profileID, host, reason, action string) {
	key := postBlockKey(host, reason)
	switch {
	case action == DecisionAllow:
		clearPromptIgnore(key)
		a.forgetKeep(host, reason)
		if profileID != "" {
			a.allowWrapHostLive(profileID, host, true)
			a.emitAllowUndoBanner(host, "Allowed this site: "+host, func() {
				a.revokeWrapHostLive(profileID, host, true)
			})
			break
		}
		if err := a.persistAlwaysHostFrom(host, "hardblock"); err != nil {
			AppendDesktopLog("WARN always-allow persist %s: %v", host, err)
			// Live session-only if possible — never claim a saved Allow when disk write failed.
			a.mu.Lock()
			sess := a.session
			a.mu.Unlock()
			if sess != nil {
				sess.AllowHost(host, "user_once")
				LogBlock("allow_once", map[string]any{"host": host, "scope": "session", "source": "hardblock"})
				a.emitAllowUndoBanner(host, "Allowed for this session only (could not save): "+host, func() {
					a.revokeHostEverywhere(host)
				})
			} else {
				notify.Info("DenyOut", "Could not save Allow for "+host+": "+err.Error())
			}
		} else {
			a.allowHostOnRunningWraps(host)
			a.emitAllowUndoBanner(host, "Allowed this site: "+host, func() {
				_ = a.removeAlwaysHostFrom(host, "undo")
			})
		}
	case strings.HasPrefix(action, DecisionAllowTimed):
		clearPromptIgnore(key)
		if d, ok := parseTimedSuffix(action, DecisionAllowTimed); ok {
			a.forgetKeep(host, reason)
			if profileID != "" {
				// Wrap sessions have no timed allow clock — Allow for this run only.
				a.allowWrapHostLive(profileID, host, false)
				a.emitAllowUndoBanner(host, fmt.Sprintf("Allowed %s for this agent run", host), func() {
					a.revokeWrapHostLive(profileID, host, false)
				})
				break
			}
			a.addTimedAllow(host, d)
			a.allowHostOnRunningWraps(host)
			a.emitAllowUndoBanner(host, fmt.Sprintf("Allowed %s for a while", host), func() {
				_ = a.UIRemoveTimedAllow(host)
				a.revokeHostEverywhere(host)
			})
		}
	case action == DecisionKeep:
		clearPromptIgnore(key)
		a.rememberKeep(host, reason)
	case strings.HasPrefix(action, DecisionKeepTimed):
		clearPromptIgnore(key)
		if d, ok := parseTimedSuffix(action, DecisionKeepTimed); ok {
			a.addTimedDeny(host, reason, d)
		}
	case action == DecisionOpen:
		notePromptIgnore(key)
		a.RequestOpenUI("activity")
	default: // later / timeout / unknown - do NOT remember Keep
		notePromptIgnore(key)
	}
}

var (
	undoBannerMu   sync.Mutex
	undoBannerHost string
	undoBannerAt   time.Time
)

const undoBannerCooldown = 2 * time.Minute

// emitAllowUndoBanner arms ~10s in-app Undo (Pass 29 — no OS Undo button / shade action).
// Same host within undoBannerCooldown does not get a second offer (U6).
func (a *App) emitAllowUndoBanner(host, body string, onUndo func()) {
	host = strings.TrimSpace(strings.ToLower(host))
	undoBannerMu.Lock()
	if host != "" && host == undoBannerHost && time.Since(undoBannerAt) < undoBannerCooldown {
		undoBannerMu.Unlock()
		return
	}
	undoBannerHost = host
	undoBannerAt = time.Now()
	undoBannerMu.Unlock()

	ttl := notify.ExpireFor(notify.KindAllowUndo)
	if ttl <= 0 {
		ttl = undoOfferDefaultAllow
	}
	msg := strings.TrimSpace(body)
	if msg == "" {
		msg = "Allowed."
	}
	if !strings.Contains(strings.ToLower(msg), "undo") {
		msg = msg + "\nUndo within 10 seconds."
	}
	a.armUndoOffer(undoOfferAllow, host, msg, ttl, onUndo)
}

// revokeHostEverywhere drops a live allow from Protect session and running wraps.
func (a *App) revokeHostEverywhere(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	a.mu.Lock()
	sess := a.session
	wraps := make([]*wrapProc, 0, len(a.wraps))
	for _, wp := range a.wraps {
		wraps = append(wraps, wp)
	}
	a.mu.Unlock()
	if sess != nil {
		sess.RevokeHost(host)
	}
	for _, wp := range wraps {
		if wp != nil && wp.sess != nil {
			wp.sess.RevokeHost(host)
		}
	}
}

// isClearPostBlock reports whether reasons warrant post-block confirm on Safe desktop.
func isClearPostBlock(reasons []string) bool {
	return primaryPostBlockReason(reasons) != ""
}
