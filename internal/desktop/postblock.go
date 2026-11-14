package desktop

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

const postBlockQuietEvery = time.Minute // keep-repeat toast throttle (P3 may honor Settings)

// clearPostBlockReasons are Safe-desktop threats that use post-block confirm (not Pre-act Ask).
var clearPostBlockReasons = map[string]bool{
	"secret_in_url": true,
	"secret_in_header": true,
	"secret_in_body": true,
	"canary_detected": true,
	"host_denied": true,
	"threat_list": true,
	"unsafe_ip": true,
}

func primaryPostBlockReason(reasons []string) string {
	for _, r := range reasons {
		if clearPostBlockReasons[r] {
			return r
		}
	}
	return ""
}

func postBlockKey(host, reason string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strings.TrimSpace(reason)
}

func (st State) RememberedKeep(host, reason string) bool {
	key := postBlockKey(host, reason)
	for _, k := range st.RememberedKeeps {
		if k == key {
			return true
		}
	}
	now := time.Now()
	for _, t := range st.TimedDenies {
		if postBlockKey(t.Host, t.Reason) != key {
			continue
		}
		exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
		if err == nil && now.Before(exp) {
			return true
		}
	}
	return false
}

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
}

func (a *App) forgetKeep(host, reason string) {
	key := postBlockKey(host, reason)
	a.mu.Lock()
	out := a.state.RememberedKeeps[:0]
	for _, k := range a.state.RememberedKeeps {
		if k != key {
			out = append(out, k)
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
	_ = a.allowHostOnce(host)
}

var postBlockMu sync.Mutex
var postBlockQuietAt = map[string]time.Time{}
var decisionBusy bool

type queuedDecision struct {
	Host string
	Reason string
	URL string
}

var decisionQueue []queuedDecision

// handlePostBlockDeny runs after a clear Safe-desktop deny (request already blocked).
func (a *App) handlePostBlockDeny(host string, reasons []string, redactedURL string) {
	reason := primaryPostBlockReason(reasons)
	if reason == "" {
		return
	}
	if reason == "unsafe_ip" || isIPLiteral(host) {
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
		msg := fmt.Sprintf("Blocked %s again - %s", host, notify.HumanReasons([]string{reason}))
		if urlLine != "" {
			msg += "\n" + urlLine
		}
		msg += "\nOpen DenyOut -> History if you need to change this later."
		notify.Emit(notify.KindKeepRepeat, "DenyOut", msg)
		return
	}

	if shouldThrottlePrompt(key, reaskInterval(a)) {
		return
	}

	item := queuedDecision{Host: host, Reason: reason, URL: urlLine}
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
			Host: it.Host,
			Reason: it.Reason,
			Why: why,
			URL: it.URL,
			Timeout: decisionTimeout(a),
			Taught: taught,
		})
		a.applyHardBlockDecision(it.Host, it.Reason, action)
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
	action := a.presentHardBlockDecision(DecisionPrompt{
		Host: fmt.Sprintf("%d sites", len(hostKeys)),
		Reason: "batch",
		Why: strings.TrimSpace(body.String()),
		Timeout: decisionTimeout(a),
		Taught: true,
	})
	// Apply same action to every pending item (bulk Keep / Allow / later).
	for _, k := range order {
		it := seen[k]
		a.applyHardBlockDecision(it.Host, it.Reason, action)
	}
}

func (a *App) applyHardBlockDecision(host, reason, action string) {
	key := postBlockKey(host, reason)
	switch {
	case action == DecisionAllow:
		clearPromptIgnore(key)
		a.forgetKeep(host, reason)
		if err := a.persistAlwaysHost(host); err != nil {
			_ = a.allowHostOnce(host)
			a.emitAllowUndoBanner(host, "Undid block for now: "+host, false)
		} else {
			a.emitAllowUndoBanner(host, "Allowed this site: "+host, true)
		}
	case strings.HasPrefix(action, DecisionAllowTimed):
		clearPromptIgnore(key)
		if d, ok := parseTimedSuffix(action, DecisionAllowTimed); ok {
			a.forgetKeep(host, reason)
			a.addTimedAllow(host, d)
			a.emitAllowUndoBanner(host, fmt.Sprintf("Allowed %s for a while", host), false)
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

// emitAllowUndoBanner shows ~10s OS toast with Undo (whitelist allow_undo).
func (a *App) emitAllowUndoBanner(host, body string, removeAlways bool) {
	notify.EmitAction(notify.KindAllowUndo, "DenyOut", body+"\nUndo within 10 seconds.", 10*time.Second,
		[]notify.Action{{ID: "undo", Label: "Undo"}},
		func(id string) {
			if id != "undo" {
				return
			}
			if removeAlways {
				a.removeAlwaysHost(host)
			}
			_ = a.UIRemoveTimedAllow(host)
		},
	)
}

// isClearPostBlock reports whether reasons warrant post-block confirm on Safe desktop.
func isClearPostBlock(reasons []string) bool {
	return primaryPostBlockReason(reasons) != ""
}
