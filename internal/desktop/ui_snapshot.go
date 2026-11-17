package desktop

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
)

func hostguardHelperOK() bool {
	return hostguard.HelperAvailable()
}

// GetUISnapshot returns shell state.
func (a *App) GetUISnapshot() UISnapshot {
	// Open threat cache outside a.mu so threat_lists_warn is honest on first paint
	// (ensureThreatStore takes its own lock; calling it under a.mu deadlocks).
	_ = a.ensureThreatStore(false)
	// Refresh fullscreen detect outside a.mu (probes may exec; presence has its own lock).
	a.pollFullscreenOnce()
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
		YourSetupText:      YourSetupText(pendingYourSetupModeLocked(a, mode), a.state.Autostart, problemsUnhealthyLocked(a), !a.state.QuietWhileAwayOff),
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
		BlockBrowserQUIC:   !a.state.AllowBrowserQUIC,
		TunDataplane:       a.state.TunDataplane && runtime.GOOS == "linux",
		QuicMITM:           a.state.QuicMITM && runtime.GOOS == "linux",
		ExperimentalLinux:  runtime.GOOS == "linux",
		FullscreenDetect:   a.fullscreenDetectOK(),
		FullscreenNow: func() bool {
			a.presence.mu.Lock()
			defer a.presence.mu.Unlock()
			return a.presence.fsActive
		}(),
		FullscreenWayland: sessionLooksWayland(),
		SilentWhenOpen:    !a.state.SilentWhenOpenOff,
		UndoOffer:         a.undoOfferViewLocked(),
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
	// After snooze expiry cleanup so Quiet · snoozed… matches NotifySnoozeActive.
	if qr := a.quietReasonLocked(); qr != "" {
		snap.QuietReason = qr
		snap.Quieting = true
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

// HealthPing is a cheap binding for Wails readiness.
func (a *App) HealthPing() string {
	return time.Now().UTC().Format(time.RFC3339)
}
