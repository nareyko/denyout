package desktop

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
)

func hostguardHelperOK() bool {
	return hostguard.HelperAvailable()
}

// DenialView is a UI-friendly denial row (secrets already redacted in URL).
type DenialView struct {
	ID            string   `json:"id"`
	TS            string   `json:"ts"`
	Host          string   `json:"host"`
	URL           string   `json:"url"`
	Why           string   `json:"why"`
	Reasons       []string `json:"reasons"`
	PrimaryReason string   `json:"primary_reason,omitempty"`
	Process       string   `json:"process"`
	Method        string   `json:"method,omitempty"`
	Detectors     []string `json:"detectors,omitempty"`
	PolicyProfile string   `json:"policy_profile,omitempty"`
	Remembered    bool     `json:"remembered"`
}

// DenialQuery filters ListDenials.
type DenialQuery struct {
	Search     string `json:"search"`
	Reason     string `json:"reason"`
	Process    string `json:"process"`
	Remembered bool   `json:"remembered_only"`
	Limit      int    `json:"limit"`
}

// UISnapshot is top-bar / settings state for the Wails shell.
type UISnapshot struct {
	Version             string      `json:"version"`
	Status              string      `json:"status"`
	Mode                string      `json:"mode"` // safe | agents | off | session
	ModeLabel           string      `json:"mode_label"`
	ProtectionOn        bool        `json:"protection_on"`
	Notify              bool        `json:"notify"`
	NotifyLevel         string      `json:"notify_level"`
	DecisionTimeoutSec  int         `json:"decision_timeout_sec"`
	ReaskIntervalSec    int         `json:"reask_interval_sec"`
	ProtectPausedUntil  string      `json:"protect_paused_until,omitempty"`
	ProtectPauseLast    string      `json:"protect_pause_last,omitempty"`
	TimedAllows         []TimedRule `json:"timed_allows"`
	TimedDenies         []TimedRule `json:"timed_denies"`
	AskMode             bool        `json:"ask_mode"`
	PolicyProfile       string      `json:"policy_profile"`
	Autostart           bool        `json:"autostart"`
	AlwaysAllow         []string    `json:"always_allow"`
	RememberedKeeps     []string    `json:"remembered_keeps"`
	LastDenyHost        string      `json:"last_deny_host"`
	LastDenyURL         string      `json:"last_deny_url"`
	LastDenySummary     string      `json:"last_deny_summary"`
	LastDenyProcess     string      `json:"last_deny_process,omitempty"`
	BlockedToday        int         `json:"blocked_today"`
	YourSetupShown      bool        `json:"your_setup_shown"`
	SetupDone           bool        `json:"setup_done"`
	HelperOK            bool        `json:"helper_ok"`
	ProtectConfirmTitle string      `json:"protect_confirm_title,omitempty"`
	ProtectConfirmBody  string      `json:"protect_confirm_body,omitempty"`
	NewDenials          int         `json:"new_denials"`
	ControlURL          string      `json:"control_url,omitempty"`
	AuditPath           string      `json:"audit_path"`
	LogDir              string      `json:"log_dir"`
	DismissedTips       []string    `json:"dismissed_tips"`
	AskPaused           bool        `json:"ask_paused"`
	ProblemsAlert       bool        `json:"problems_alert"`
	YourSetupText       string      `json:"your_setup_text"`
	ChecklistDone       bool        `json:"checklist_done"`
	NeedsUXv2Migration  bool        `json:"needs_uxv2_migration"`
	AskPausedUntil      string      `json:"ask_paused_until,omitempty"`
	UpdateAvailable     bool        `json:"update_available"`
	UpdateVersion       string      `json:"update_version,omitempty"`
	UpdateURL           string      `json:"update_url,omitempty"`
	UpdateNotes         string      `json:"update_notes,omitempty"`
	AccountSignedIn     bool        `json:"account_signed_in"`
	AccountEmail        string      `json:"account_email,omitempty"`
	AccountTrustLine    string      `json:"account_trust_line,omitempty"`
	SyncEnabled         bool        `json:"sync_enabled"`
	ComputerAvailable   bool        `json:"computer_available"`
	AgentsRunning       int         `json:"agents_running"`
	ThreatListsWarn     bool        `json:"threat_lists_warn"` // lists on but missing/stale (not Protect failure)
	Notice              string      `json:"notice,omitempty"`  // one-shot in-app note (e.g. legacy Session cleared)
	QuietWhileAway      bool            `json:"quiet_while_away"` // Stay quiet while locked/idle (default on)
	Away                bool            `json:"away"`             // currently treated as Away
	AwayUnread          int             `json:"away_unread"`      // suppressed prompts while Away
	AwayDigest          *AwayDigestView `json:"away_digest,omitempty"`
	NotifySnoozeUntil   string          `json:"notify_snooze_until,omitempty"` // RFC3339 if active
	NotifySnoozeActive  bool            `json:"notify_snooze_active"`
	QuietOvernight      bool            `json:"quiet_overnight"`
	SoundOnlyAnswer     bool            `json:"sound_only_answer"`
	SystemBanners       bool            `json:"system_banners"`
	RespectFullscreen   bool            `json:"respect_fullscreen"`
	SilentWhenOpen      bool            `json:"silent_when_open"`
}

// AwayDigestView is the one-shot "While you were away" card (Phase C).
type AwayDigestView struct {
	Pending bool     `json:"pending"`
	Blocks  int      `json:"blocks"`  // auto-kept / keep-repeat while Away
	Waiting int      `json:"waiting"` // hard-block Decide later while Away
	Hosts   []string `json:"hosts"`
}

// ProblemsView is the Problems screen payload.
type ProblemsView struct {
	LastError           string `json:"last_error"`
	LastDenyHost        string `json:"last_deny_host"`
	LastDenyURL         string `json:"last_deny_url"`
	LastDenySummary     string `json:"last_deny_summary"`
	ControlOK           bool   `json:"control_ok"`
	ProxydRunning       bool   `json:"proxyd_running"`
	SessionRunning      bool   `json:"session_running"`
	CAPresent           bool   `json:"ca_present"`
	ClipboardOK         bool   `json:"clipboard_ok"`
	HelperOK            bool   `json:"helper_ok"`
	ProtectionOn        bool   `json:"protection_on"`
	Unhealthy           bool   `json:"unhealthy"`         // Protect intended on but broken
	ThreatListsWarn     bool   `json:"threat_lists_warn"` // enabled lists missing/stale (not Protect failure)
	LogDir              string `json:"log_dir"`
	AuditPath           string `json:"audit_path"`
	Status              string `json:"status"`
	Mode                string `json:"mode"` // safe | agents | off | session (live)
	ModeLabel           string `json:"mode_label"`
	PolicyProfile       string `json:"policy_profile"`
	ProtectConfirmTitle string `json:"protect_confirm_title,omitempty"`
	ProtectConfirmBody  string `json:"protect_confirm_body,omitempty"`
	ProtectPausedUntil  string `json:"protect_paused_until,omitempty"`
	ProtectPauseLast    string `json:"protect_pause_last,omitempty"`
	AgentsRunning       int    `json:"agents_running,omitempty"`
	ComputerAvailable   bool   `json:"computer_available"`
	UpdateAvailable     bool   `json:"update_available"`
	UpdateVersion       string `json:"update_version,omitempty"`
	UpdateURL           string `json:"update_url,omitempty"`
}

// ProfileView is a profile row for the Profiles screen.
type ProfileView struct {
	AgentProfile
	Running bool `json:"running"`
	PID     int  `json:"pid,omitempty"`
}

// GetUISnapshot returns shell state.
func (a *App) GetUISnapshot() UISnapshot {
	// Open threat cache outside a.mu so threat_lists_warn is honest on first paint
	// (ensureThreatStore takes its own lock; calling it under a.mu deadlocks).
	_ = a.ensureThreatStore(false)
	a.mu.Lock()
	defer a.mu.Unlock()
	mode := uiModeLocked(a)
	// Reflect leave-on intent + live protect/session (ComputerEnabled alone can
	// still mean Needs attention — keep protection_on aligned with that).
	protectionOn := a.state.ProtectionOn || a.state.ComputerEnabled || a.proxyd != nil || a.session != nil
	// Drop stale Last blocked for raw IPs under Safe browse (policy allows public IP literals).
	lastHost, lastURL, lastSum := a.state.LastDenyHost, a.state.LastDenyURL, a.state.LastDenySummary
	lastProc := a.state.LastDenyProcess
	if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse && isIPLiteral(lastHost) {
		lastHost, lastURL, lastSum, lastProc = "", "", "", ""
		a.state.LastDenyHost = ""
		a.state.LastDenyURL = ""
		a.state.LastDenySummary = ""
		a.state.LastDenyProcess = ""
		st := a.state
		go func() { _ = SaveState(st) }()
	}
	pauseUntil := activeProtectPausedUntil(a.state.ProtectPausedUntil)
	// Live Protect supersedes a stale pause timestamp (manual Turn on).
	// Do not hide pause when only ProtectionOn intent remains (proxyd dead).
	if a.proxyd != nil || a.session != nil {
		pauseUntil = ""
	}
	modeLabel := uiModeLabelPaused(mode, pauseUntil)
	// Autostart checkbox = preference after setup. Repair/remove .desktop in
	// Bootstrap / UISetAutostart / completeSetup, plus a throttled repair here so
	// Settings "On" matches a real login entry while the app stays open.
	autostartOn := false
	persist := false
	if a.state.SetupDone {
		autostartOn = a.state.Autostart
		if a.state.Autostart && time.Since(a.lastAutostartCheck) > 60*time.Second {
			a.lastAutostartCheck = time.Now()
			// Unlock before reconcile (it takes its own lock); caller holds a.mu.
			a.mu.Unlock()
			a.reconcileAutostart()
			a.mu.Lock()
			autostartOn = a.state.Autostart
		}
	} else if a.state.Autostart {
		// First-run pending: preference must not stay On (login entry is cleared in Bootstrap).
		a.state.Autostart = false
		persist = true
	}
	// Browse (Protect computer) never uses host Ask — clear stale agent leftover.
	// Also persist notify/ux_v2 honesty so disk matches what the UI shows (Bootstrap
	// normalize may not have run yet if the tray was never restarted).
	askMode := a.state.AskMode
	if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse {
		askMode = false
		if a.state.AskMode {
			a.state.AskMode = false
			persist = true
		}
	}
	// Mark UX v2 migrated only when not still on legacy whole-PC Agents
	// (those users get an in-app migration prompt via needs_uxv2_migration).
	if a.state.SetupDone && !a.state.UXv2Migrated && normalizePolicyProfile(a.state.PolicyProfile) != PolicyProfileAgent {
		a.state.UXv2Migrated = true
		persist = true
	}
	if a.state.SetupDone && !a.state.AutostartAsked {
		a.state.AutostartAsked = true
		persist = true
	}
	lvl := effectiveNotifyLevel(a.state)
	wantNotify := lvl != "quiet"
	if a.state.Notify != wantNotify {
		a.state.Notify = wantNotify
		persist = true
	}
	if strings.TrimSpace(a.state.NotifyLevel) == "" {
		a.state.NotifyLevel = lvl
		persist = true
	}
	if persist {
		// Sync persist — async SaveState raced with test env Cleanup and rewrote dogfood ~/.config.
		_ = SaveState(a.state)
	}
	agentsRunning := 0
	if a.wraps != nil {
		agentsRunning = len(a.wraps)
	}
	snap := UISnapshot{
		Version:            a.opts.Version,
		Status:             a.status,
		Mode:               mode,
		ModeLabel:          modeLabel,
		ProtectionOn:       protectionOn,
		Notify:             effectiveNotifyLevel(a.state) != "quiet",
		NotifyLevel:        effectiveNotifyLevel(a.state),
		DecisionTimeoutSec: effectiveDecisionTimeoutSec(a.state),
		ReaskIntervalSec:   effectiveReaskIntervalSec(a.state),
		ProtectPausedUntil: pauseUntil,
		ProtectPauseLast:   strings.TrimSpace(a.state.ProtectPauseLast),
		TimedAllows:        activeTimedRulesLocked(a.state.TimedAllows),
		TimedDenies:        activeTimedRulesLocked(a.state.TimedDenies),
		AskMode:            askMode,
		PolicyProfile:      normalizePolicyProfile(a.state.PolicyProfile),
		Autostart:          autostartOn,
		AlwaysAllow:        append([]string(nil), a.state.AlwaysAllowHosts...),
		RememberedKeeps:    append([]string(nil), a.state.RememberedKeeps...),
		LastDenyHost:       lastHost,
		LastDenyURL:        lastURL,
		LastDenySummary:    lastSum,
		LastDenyProcess:    lastProc,
		BlockedToday:       countBlockedToday(AuditLogPath(), time.Now()),
		YourSetupShown:     a.state.YourSetupShown,
		SetupDone:          a.state.SetupDone,
		HelperOK:           hostguardHelperOK(),
		ControlURL:         a.controlURL,
		AuditPath:          AuditLogPath(),
		LogDir:             LogDir(),
		DismissedTips:      append([]string(nil), a.state.DismissedTips...),
		AskPaused:          a.state.AskPaused() || (a.asks != nil && a.asks.Paused()),
		AskPausedUntil:     strings.TrimSpace(a.state.AskPausedUntil),
		ProblemsAlert:      problemsUnhealthyLocked(a),
		YourSetupText:      YourSetupText(pendingYourSetupModeLocked(a, mode), a.state.Autostart, problemsUnhealthyLocked(a)),
		ChecklistDone:      tipDismissedLocked(a, "checklist"),
		NeedsUXv2Migration: a.state.NeedsUXv2Migration(),
		ComputerAvailable:  a.state.ComputerAvailable,
		AgentsRunning:      agentsRunning,
		ThreatListsWarn:    a.threatNeedsAttentionLocked(),
		Notice:             strings.TrimSpace(a.legacySessionNote),
		QuietWhileAway:     !a.state.QuietWhileAwayOff,
		Away:               a.isAwayLocked(),
		AwayUnread:         a.state.AwayUnreadBlocks,
		AwayDigest:         a.awayDigestViewLocked(),
		QuietOvernight:     !a.state.QuietOvernightOff,
		SoundOnlyAnswer:    !a.state.SoundOnlyAnswerOff,
		SystemBanners:      !a.state.SystemBannersOff,
		RespectFullscreen:  !a.state.RespectFullscreenOff,
		SilentWhenOpen:     !a.state.SilentWhenOpenOff,
	}
	if until := activeNotifySnoozeUntil(a.state.NotifySnoozeUntil); until != "" {
		snap.NotifySnoozeUntil = until
		snap.NotifySnoozeActive = true
	} else if a.state.NotifySnoozeUntil != "" {
		// Drop expired snooze from disk.
		a.state.NotifySnoozeUntil = ""
		_ = SaveState(a.state)
		notify.SetSnoozeUntil(time.Time{})
	}
	if snap.AskPausedUntil != "" {
		if exp, err := time.Parse(time.RFC3339, snap.AskPausedUntil); err != nil || !time.Now().Before(exp) {
			snap.AskPausedUntil = ""
			// Drop expired pause from disk so Settings Resume matches AskPaused.
			if a.state.AskPausedUntil != "" {
				a.state.AskPausedUntil = ""
				_ = SaveState(a.state)
			}
			if a.asks != nil {
				a.asks.ClearPause()
			}
			snap.AskPaused = false
		}
	}
	snap.ProtectConfirmTitle, snap.ProtectConfirmBody = ProtectConfirmText(snap.HelperOK)
	if newer, ver, url, notes := updateTipLocked(a); newer {
		snap.UpdateAvailable = true
		snap.UpdateVersion = ver
		snap.UpdateURL = url
		snap.UpdateNotes = notes
	}
	acc := accountViewLocked(a)
	snap.AccountSignedIn = acc.SignedIn
	snap.AccountEmail = acc.Email
	snap.AccountTrustLine = acc.TrustLine
	snap.SyncEnabled = acc.SyncEnabled
	return snap
}

// countBlockedToday counts audit denials whose timestamp falls on local calendar day of now.
func countBlockedToday(auditPath string, now time.Time) int {
	events, err := audit.RecentDenials(auditPath, 500)
	if err != nil {
		return 0
	}
	day := now.In(time.Local).Format("2006-01-02")
	n := 0
	for _, e := range events {
		if !denialUsefulForUI(e) {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil {
			t, err = time.Parse(time.RFC3339, e.TS)
			if err != nil {
				continue
			}
		}
		if t.In(time.Local).Format("2006-01-02") == day {
			n++
		}
	}
	return n
}

// denialUsefulForUI drops noise that confuses History/Home (no reason, loopback).
func denialUsefulForUI(e audit.Event) bool {
	host := strings.TrimSpace(e.Network.DestHost)
	if host == "" {
		return false
	}
	if len(e.Reasons) == 0 {
		return false
	}
	low := strings.ToLower(host)
	if low == "localhost" || low == "127.0.0.1" || low == "::1" || strings.HasSuffix(low, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

func tipDismissedLocked(a *App, id string) bool {
	for _, t := range a.state.DismissedTips {
		if t == id {
			return true
		}
	}
	return false
}

// liveToYourSetupMode maps snapshot mode → YourSetupText token.
// Live "agents" is whole-PC Agents only (not tip token "agents" = Protect AI agents / computer off).
func liveToYourSetupMode(liveMode string) string {
	switch strings.TrimSpace(liveMode) {
	case "safe":
		return "safe"
	case "agents":
		return "agents_only"
	case "session":
		return "session"
	default:
		return "off"
	}
}

func pendingYourSetupModeLocked(a *App, liveMode string) string {
	tipLive := liveToYourSetupMode(liveMode)
	m := strings.TrimSpace(a.state.PendingYourSetup)
	switch m {
	case "safe", "agents", "agents_only", "off":
		// Protect AI agents finishes Off but tip token is "agents" (My agents guidance).
		// Do not rewrite that to generic "Protection is off" while still pending.
		if m == "agents" && tipLive == "off" {
			return "agents"
		}
		// Pause / Clear: demote protected / Agents only; turn-on/switch: follow live.
		return tipLive
	default:
		return tipLive
	}
}

func problemsUnhealthyLocked(a *App) bool {
	// Home / tray "Needs attention" = Protect intended on but broken.
	// Off (no proxyd / no ComputerEnabled) is healthy — not an alert.
	// Live in-process session is intentional limited protect — not a failure.
	// Threat-list freshness is Problems/Settings only, not a Protect failure.
	wantOn := a.state.ComputerEnabled || a.state.ProtectionOn || a.proxyd != nil || a.session != nil
	if !wantOn {
		return false
	}
	st := strings.ToLower(a.status)
	if strings.Contains(st, "error") || strings.Contains(a.status, "Needs") {
		return true
	}
	if a.proxyd == nil && a.session == nil {
		return true
	}
	// Computer mode needs CA on disk; session uses the same CA store.
	ca := filepath.Join(CADir(), "ca.crt")
	if _, err := os.Stat(ca); err != nil {
		return true
	}
	return false
}

func uiModeLocked(a *App) string {
	// Mode reflects the live protector only. Leave-on / crash intent is
	// ProtectionOn + problems_alert, not a fake "Protected" pill.
	if a.proxyd != nil {
		if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileAgent {
			return "agents"
		}
		return "safe"
	}
	if a.session != nil {
		return "session"
	}
	return "off"
}

func uiModeLabel(mode string) string {
	switch mode {
	case "safe":
		return "Protected"
	case "agents":
		return "Agents only"
	case "session":
		return "Session"
	default:
		return "Off"
	}
}

// uiModeLabelPaused matches GetUISnapshot ModeLabel (Off + active pause → Paused).
func uiModeLabelPaused(mode, pauseUntil string) string {
	label := uiModeLabel(mode)
	if mode == "off" && strings.TrimSpace(pauseUntil) != "" {
		return "Paused"
	}
	return label
}

// UIClearNotice dismisses the one-shot Home notice (legacy Session clear, etc.).
func (a *App) UIClearNotice() {
	a.mu.Lock()
	a.legacySessionNote = ""
	a.mu.Unlock()
}

// MarkYourSetupShown persists the in-window Your setup dismiss.
func (a *App) MarkYourSetupShown() error {
	a.mu.Lock()
	a.state.YourSetupShown = true
	a.state.PendingYourSetup = ""
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// TipDismissed reports whether a tip id was dismissed forever.
func (a *App) TipDismissed(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return tipDismissedLocked(a, id)
}

// UIDismissTip remembers a tip id so it is not shown again.
func (a *App) UIDismissTip(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	a.mu.Lock()
	if tipDismissedLocked(a, id) {
		a.mu.Unlock()
		return nil
	}
	a.state.DismissedTips = append(a.state.DismissedTips, id)
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

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

// UITestProtection returns plain-language Protect status for the in-app UI.
func (a *App) UITestProtection() string {
	return a.testProtectionMessage()
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
	if err := a.persistAlwaysHost(host); err != nil {
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
	return SaveState(st)
}

// UIRemoveAlwaysAllow removes a host from always-allow.
func (a *App) UIRemoveAlwaysAllow(host string) error {
	return a.removeAlwaysHost(host)
}

// UISetNotify toggles notifications (legacy bool -> Quiet / Normal).
func (a *App) UISetNotify(on bool) error {
	if on {
		return a.UISetNotifyLevel("normal")
	}
	return a.UISetNotifyLevel("quiet")
}

// UISetNotifyUIFocused tells the notify package whether the main window is
// focused so non-critical OS toasts stay silent while the user is looking.
// Focus also counts as user activity (clears Away idle).
func (a *App) UISetNotifyUIFocused(on bool) {
	notify.SetUIFocused(on)
	if on {
		a.noteUserActivity()
	} else {
		a.syncAwayNotify()
	}
}

// UISetQuietWhileAway toggles Stay quiet while away (locked/idle).
func (a *App) UISetQuietWhileAway(on bool) error {
	a.mu.Lock()
	a.state.QuietWhileAwayOff = !on
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	a.syncAwayNotify()
	return nil
}

// UIClearAwayUnread clears the tray "waiting" count (digest dismiss / History).
func (a *App) UIClearAwayUnread() error {
	a.clearAwayUnread()
	return nil
}

// UIDismissAwayDigest dismisses the return digest and clears unread.
func (a *App) UIDismissAwayDigest() error {
	a.clearAwayUnread()
	return nil
}

// awayDigestViewLocked builds AwayDigestView while a.mu is held (GetUISnapshot).
func (a *App) awayDigestViewLocked() *AwayDigestView {
	if !a.awayDigestPending() {
		return nil
	}
	total := a.state.AwayUnreadBlocks
	if total <= 0 {
		return nil
	}
	waiting := a.state.AwayUnreadWaiting
	if waiting < 0 {
		waiting = 0
	}
	if waiting > total {
		waiting = total
	}
	blocks := total - waiting
	hosts := append([]string(nil), a.state.AwayUnreadHosts...)
	if len(hosts) > 5 {
		hosts = hosts[:5]
	}
	return &AwayDigestView{
		Pending: true,
		Blocks:  blocks,
		Waiting: waiting,
		Hosts:   hosts,
	}
}

// UISetNotifyLevel sets quiet | normal | detailed.
func (a *App) UISetNotifyLevel(level string) error {
	a.mu.Lock()
	a.state.NotifyLevel = strings.ToLower(strings.TrimSpace(level))
	if a.state.NotifyLevel == "" {
		a.state.NotifyLevel = "quiet"
	}
	a.state.Notify = a.state.NotifyLevel != "quiet"
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

func activeNotifySnoozeUntil(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || !time.Now().Before(t) {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// UISetNotifySnooze sets temporary OS quiet: "1h" | "tomorrow" | "clear" | "".
// Protection stays on; Ask/Decision in-app still work when Present.
func (a *App) UISetNotifySnooze(choice string) error {
	choice = strings.ToLower(strings.TrimSpace(choice))
	var until time.Time
	switch choice {
	case "", "clear", "off", "none":
		until = time.Time{}
	case "1h", "1hour", "hour":
		until = time.Now().Add(time.Hour)
	case "tomorrow", "until_tomorrow", "until-tomorrow":
		now := time.Now()
		// Local next calendar day 08:00 (after night window).
		y, m, d := now.Date()
		until = time.Date(y, m, d+1, 8, 0, 0, 0, now.Location())
		if !until.After(now) {
			until = until.Add(24 * time.Hour)
		}
	default:
		return fmt.Errorf("Unknown snooze choice")
	}
	a.mu.Lock()
	if until.IsZero() {
		a.state.NotifySnoozeUntil = ""
	} else {
		a.state.NotifySnoozeUntil = until.UTC().Format(time.RFC3339)
	}
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetQuietOvernight toggles no sound at night (default on).
func (a *App) UISetQuietOvernight(on bool) error {
	a.mu.Lock()
	a.state.QuietOvernightOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSoundOnlyAnswer toggles sound only when you must answer (default on).
func (a *App) UISetSoundOnlyAnswer(on bool) error {
	a.mu.Lock()
	a.state.SoundOnlyAnswerOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSystemBanners toggles Allow system banners (protect_failed still passes when off).
func (a *App) UISetSystemBanners(on bool) error {
	a.mu.Lock()
	a.state.SystemBannersOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetRespectFullscreen toggles Respect fullscreen / games (default on).
func (a *App) UISetRespectFullscreen(on bool) error {
	a.mu.Lock()
	a.state.RespectFullscreenOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSilentWhenOpen toggles silent OS while DenyOut is open (default on).
func (a *App) UISetSilentWhenOpen(on bool) error {
	a.mu.Lock()
	a.state.SilentWhenOpenOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetDecisionTimeoutSec sets hard-block decision countdown (seconds).
func (a *App) UISetDecisionTimeoutSec(sec int) error {
	if sec < 5 {
		sec = 5
	}
	if sec > 120 {
		sec = 120
	}
	a.mu.Lock()
	a.state.DecisionTimeoutSec = sec
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UISetReaskIntervalSec sets re-ask / keep-repeat throttle (seconds).
func (a *App) UISetReaskIntervalSec(sec int) error {
	if sec < 15 {
		sec = 15
	}
	if sec > 3600 {
		sec = 3600
	}
	a.mu.Lock()
	a.state.ReaskIntervalSec = sec
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
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

// UIStopProtectionWithChoice turns protection Off using an in-app pause choice
// (15m|1h|tomorrow|forever). Used by Wails so Cancel can stay in the window.
func (a *App) UIStopProtectionWithChoice(choice string) error {
	a.mu.Lock()
	leaveOn := a.state.ProtectionOn || a.state.ComputerEnabled
	live := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	choice = strings.TrimSpace(choice)
	switch choice {
	case "15m", "1h", "tomorrow", "forever":
	default:
		choice = "1h"
	}
	// Already Off (paused / forever): still apply a new duration from PauseModal.
	if a.currentMode() == ModeOff && !leaveOn {
		a.applyProtectPauseChoice(choice)
		return nil
	}
	// Protector dead but leave-on intent remains (Needs attention): clear intent
	// without ElevateRemove — cancel-password must not trap the user in unhealthy.
	if !live {
		a.mu.Lock()
		a.state.ProtectionOn = false
		a.state.ComputerEnabled = false
		a.state.Scope = ScopeOff
		a.state.PendingYourSetup = ""
		a.status = "Off"
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		a.applyProtectPauseChoice(choice)
		return nil
	}
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	a.applyProtectPauseChoice(choice)
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
	return SaveState(st)
}

func effectiveNotifyLevel(st State) string {
	if strings.TrimSpace(st.NotifyLevel) != "" {
		return st.NotifyLevel
	}
	if st.Notify {
		return "normal"
	}
	return "quiet"
}

func effectiveDecisionTimeoutSec(st State) int {
	if st.DecisionTimeoutSec > 0 {
		return st.DecisionTimeoutSec
	}
	return 15
}

func effectiveReaskIntervalSec(st State) int {
	if st.ReaskIntervalSec > 0 {
		return st.ReaskIntervalSec
	}
	return 60
}

// UISetAutostart toggles login autostart for denyout-desktop when available.
func (a *App) UISetAutostart(on bool) error {
	a.mu.Lock()
	if !a.state.SetupDone {
		a.mu.Unlock()
		return fmt.Errorf("finish first-run setup before changing autostart")
	}
	a.state.Autostart = on
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if on {
		if err := RegisterAutostart(); err != nil {
			a.mu.Lock()
			a.state.Autostart = false
			stFail := a.state
			a.mu.Unlock()
			_ = SaveState(stFail)
			return err
		}
		return nil
	}
	return UnregisterAutostart()
}

// UIEnableSafeDesktop turns on Protect computer.
func (a *App) UIEnableSafeDesktop() error {
	return a.enableSafeDesktop()
}

// UIEnableAgentsOnly turns on Agents only (whole PC) - caller must confirm in UI.
func (a *App) UIEnableAgentsOnly() error {
	return a.enableAgentsOnlyWholePC()
}

// UISwitchSafe switches from Agents only back to Safe desktop.
func (a *App) UISwitchSafe() error {
	return a.switchToSafeDesktopFromTray()
}

// UIStopProtection turns protection Off (asks pause duration on desktop).
func (a *App) UIStopProtection() error {
	if a.currentMode() == ModeOff {
		return nil
	}
	choice, ok := a.chooseProtectPause()
	if !ok {
		return nil // cancelled — leave protection on
	}
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	a.applyProtectPauseChoice(choice)
	return nil
}

// GetProblems returns Problems screen data.
func (a *App) GetProblems() ProblemsView {
	_ = a.ensureThreatStore(false)
	a.mu.Lock()
	defer a.mu.Unlock()
	ca := filepath.Join(CADir(), "ca.crt")
	_, caErr := os.Stat(ca)
	// Same leave-on + live bit as GetUISnapshot.
	protectionOn := a.state.ProtectionOn || a.state.ComputerEnabled || a.proxyd != nil || a.session != nil
	lastErr := LastErrorSummary()
	unhealthy := problemsUnhealthyLocked(a)
	lastHost, lastURL, lastSum := a.state.LastDenyHost, a.state.LastDenyURL, a.state.LastDenySummary
	if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse && isIPLiteral(lastHost) {
		lastHost, lastURL, lastSum = "", "", ""
	}
	mode := uiModeLocked(a)
	helperOK := hostguardHelperOK()
	confirmTitle, confirmBody := ProtectConfirmText(helperOK)
	pauseUntil := activeProtectPausedUntil(a.state.ProtectPausedUntil)
	if a.proxyd != nil || a.session != nil {
		pauseUntil = ""
	}
	pv := ProblemsView{
		LastError:           lastErr,
		LastDenyHost:        lastHost,
		LastDenyURL:         lastURL,
		LastDenySummary:     lastSum,
		ControlOK:           a.controlURL != "",
		ProxydRunning:       a.proxyd != nil,
		SessionRunning:      a.session != nil,
		CAPresent:           caErr == nil,
		ClipboardOK:         clipboardAvailable(),
		HelperOK:            helperOK,
		ProtectionOn:        protectionOn,
		Unhealthy:           unhealthy,
		ThreatListsWarn:     a.threatNeedsAttentionLocked(),
		LogDir:              LogDir(),
		AuditPath:           AuditLogPath(),
		Status:              a.status,
		Mode:                mode,
		ModeLabel:           uiModeLabelPaused(mode, pauseUntil),
		PolicyProfile:       normalizePolicyProfile(a.state.PolicyProfile),
		ProtectConfirmTitle: confirmTitle,
		ProtectConfirmBody:  confirmBody,
		ProtectPausedUntil:  pauseUntil,
		ProtectPauseLast:    strings.TrimSpace(a.state.ProtectPauseLast),
		ComputerAvailable:   a.state.ComputerAvailable,
	}
	if a.wraps != nil {
		pv.AgentsRunning = len(a.wraps)
	}
	if newer, ver, url, _ := updateTipLocked(a); newer {
		pv.UpdateAvailable = true
		pv.UpdateVersion = ver
		pv.UpdateURL = url
	}
	return pv
}

// UIOpenLogs opens the diagnostics folder.
func (a *App) UIOpenLogs() error {
	return OpenLogs()
}

// UICopyLastError copies last error to clipboard.
func (a *App) UICopyLastError() (string, error) {
	return CopyLastErrorToClipboard()
}

// UIRetryProtect retries the intended Protect path.
// Broken Agents only keeps PolicyProfileAgent (does not silently flip to browse).
func (a *App) UIRetryProtect() error {
	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	if profile == PolicyProfileAgent {
		if err := a.enableComputerFromTray(); err != nil {
			return err
		}
		a.ensureSetupDoneAfterProtect("agents_only")
		return nil
	}
	return a.enableSafeDesktop()
}

// ListProfileViews returns profiles with running state.
func (a *App) ListProfileViews() ([]ProfileView, error) {
	list, err := ListProfiles()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ProfileView, 0, len(list))
	for _, p := range list {
		v := ProfileView{AgentProfile: p}
		if w, ok := a.wraps[p.ID]; ok && w != nil && w.cmd != nil && w.cmd.Process != nil {
			v.Running = true
			v.PID = w.cmd.Process.Pid
		}
		out = append(out, v)
	}
	return out, nil
}

// UISaveProfile saves a profile definition.
func (a *App) UISaveProfile(p AgentProfile) error {
	// Keep RequireIsolation and Sandbox aligned (UI checkbox must not leave sandbox=srt).
	if !p.RequireIsolation {
		p.Sandbox = ""
	} else if strings.TrimSpace(p.Sandbox) == "" {
		p.Sandbox = "srt"
	}
	if err := SaveProfile(p); err != nil {
		return err
	}
	return a.reapplyRunningProfile(p.ID)
}

// reapplyRunningProfile restarts a live wrap so disk profile changes take effect.
func (a *App) reapplyRunningProfile(id string) error {
	a.mu.Lock()
	_, running := a.wraps[id]
	a.mu.Unlock()
	if !running {
		return nil
	}
	a.stopProfile(id)
	return a.startProfile(id)
}

// ListAllowPacks returns curated Book A starter packs.
func (a *App) ListAllowPacks() ([]AllowPack, error) {
	return ListAllowPacks()
}

// UIApplyAllowPack merges a pack into a profile (idempotent) and saves.
func (a *App) UIApplyAllowPack(profileID, packID string) ([]string, error) {
	p, err := LoadProfile(profileID)
	if err != nil {
		return nil, err
	}
	added, err := ApplyPack(&p, packID)
	if err != nil {
		return nil, err
	}
	if err := SaveProfile(p); err != nil {
		return nil, err
	}
	if err := a.reapplyRunningProfile(profileID); err != nil {
		return added, err
	}
	return added, nil
}

// UIUndoAllowPack removes pack-owned hosts from a profile and saves.
func (a *App) UIUndoAllowPack(profileID, packID string) ([]string, error) {
	p, err := LoadProfile(profileID)
	if err != nil {
		return nil, err
	}
	removed, err := UndoPack(&p, packID)
	if err != nil {
		return nil, err
	}
	if err := SaveProfile(p); err != nil {
		return nil, err
	}
	if err := a.reapplyRunningProfile(profileID); err != nil {
		return removed, err
	}
	return removed, nil
}

// UISuggestAllowPack returns a pack id suggestion for name/command (may be empty).
func (a *App) UISuggestAllowPack(name string, command []string) string {
	return SuggestPackID(name, command)
}

// UIDeleteProfile deletes a profile and stops wrap if running.
func (a *App) UIDeleteProfile(id string) error {
	a.stopProfile(id)
	return DeleteProfile(id)
}

// UIStartProfile starts a wrap profile.
func (a *App) UIStartProfile(id string) error {
	return a.startProfile(id)
}

// UIStopProfile stops a running wrap.
func (a *App) UIStopProfile(id string) {
	a.stopProfile(id)
}

// UIPinLearning pins pending hosts for a profile.
func (a *App) UIPinLearning(id string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	if len(p.PendingOnce) == 0 {
		return fmt.Errorf("nothing to pin for %s", p.Name)
	}
	hosts := append([]string{}, p.PendingOnce...)
	p.PinPending(nil)
	// Keep Learning on so future Allow-once hosts can still be collected.
	if err := SaveProfile(p); err != nil {
		return err
	}
	a.applyPinnedLive(id, hosts)
	return nil
}

// UIDiscardLearning discards pending once hosts.
func (a *App) UIDiscardLearning(id string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	p.DiscardPending()
	return SaveProfile(p)
}

// enableAgentsOnlyWholePC is the confirmed path (UI already confirmed).
func (a *App) enableAgentsOnlyWholePC() error {
	// Wails already confirmed the risk — force-stop wraps (no second native dialog).
	a.stopAllWrapsOpts("Agents only on whole PC - stopping wraps", true)
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.AskMode = true
	a.state.ActiveProfileID = ""
	hadSession := a.session != nil
	hadProxyd := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	var err error
	// Session → Agents only must not restartActiveProtector (that keeps ScopeSession).
	if hadSession {
		a.stopSession()
		a.mu.Lock()
		a.state.Scope = ScopeComputer
		a.state.PolicyProfile = PolicyProfileAgent
		a.state.AskMode = true
		st = a.state
		a.mu.Unlock()
		_ = SaveState(st)
		err = a.enableComputerFromTray()
	} else if hadProxyd {
		err = a.restartActiveProtector()
	} else {
		err = a.enableComputerFromTray()
	}
	if err != nil {
		return err
	}
	a.ensureSetupDoneAfterProtect("agents_only")
	return nil
}

// HealthPing is a cheap binding for Wails readiness.
func (a *App) HealthPing() string {
	return time.Now().UTC().Format(time.RFC3339)
}
