package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/threatlists"
)

// DenialView is a UI-friendly denial row (secrets already redacted in URL).
type DenialView struct {
	ID string `json:"id"`
	TS string `json:"ts"`
	Host string `json:"host"`
	URL string `json:"url"`
	Why string `json:"why"`
	Reasons []string `json:"reasons"`
	Process string `json:"process"`
	Method string `json:"method,omitempty"`
	Detectors []string `json:"detectors,omitempty"`
	PolicyProfile string `json:"policy_profile,omitempty"`
	Remembered bool `json:"remembered"`
}

// DenialQuery filters ListDenials.
type DenialQuery struct {
	Search string `json:"search"`
	Reason string `json:"reason"`
	Process string `json:"process"`
	Remembered bool `json:"remembered_only"`
	Limit int `json:"limit"`
}

// UISnapshot is top-bar / settings state for the Wails shell.
type UISnapshot struct {
	Version string `json:"version"`
	Status string `json:"status"`
	Mode string `json:"mode"` // safe | agents | off | session
	ModeLabel string `json:"mode_label"`
	ProtectionOn bool `json:"protection_on"`
	Notify bool `json:"notify"`
	NotifyLevel string `json:"notify_level"`
	DecisionTimeoutSec int `json:"decision_timeout_sec"`
	ReaskIntervalSec int `json:"reask_interval_sec"`
	ProtectPausedUntil string `json:"protect_paused_until,omitempty"`
	TimedAllows []TimedRule `json:"timed_allows"`
	TimedDenies []TimedRule `json:"timed_denies"`
	AskMode bool `json:"ask_mode"`
	Autostart bool `json:"autostart"`
	AlwaysAllow []string `json:"always_allow"`
	RememberedKeeps []string `json:"remembered_keeps"`
	LastDenyHost string `json:"last_deny_host"`
	LastDenyURL string `json:"last_deny_url"`
	LastDenySummary string `json:"last_deny_summary"`
	BlockedToday int `json:"blocked_today"`
	YourSetupShown bool `json:"your_setup_shown"`
	SetupDone bool `json:"setup_done"`
	NewDenials int `json:"new_denials"`
	ControlURL string `json:"control_url,omitempty"`
	AuditPath string `json:"audit_path"`
	LogDir string `json:"log_dir"`
	DismissedTips []string `json:"dismissed_tips"`
	AskPaused bool `json:"ask_paused"`
	ProblemsAlert bool `json:"problems_alert"`
	YourSetupText string `json:"your_setup_text"`
	ChecklistDone bool `json:"checklist_done"`
	UpdateAvailable bool `json:"update_available"`
	UpdateVersion string `json:"update_version,omitempty"`
	UpdateURL string `json:"update_url,omitempty"`
	UpdateNotes string `json:"update_notes,omitempty"`
	AccountSignedIn bool `json:"account_signed_in"`
	AccountEmail string `json:"account_email,omitempty"`
	AccountTrustLine string `json:"account_trust_line,omitempty"`
	SyncEnabled bool `json:"sync_enabled"`
}

// ProblemsView is the Problems screen payload.
type ProblemsView struct {
	LastError string `json:"last_error"`
	LastDenyHost string `json:"last_deny_host"`
	LastDenyURL string `json:"last_deny_url"`
	LastDenySummary string `json:"last_deny_summary"`
	ControlOK bool `json:"control_ok"`
	ProxydRunning bool `json:"proxyd_running"`
	SessionRunning bool `json:"session_running"`
	CAPresent bool `json:"ca_present"`
	ClipboardOK bool `json:"clipboard_ok"`
	LogDir string `json:"log_dir"`
	AuditPath string `json:"audit_path"`
	Status string `json:"status"`
	ModeLabel string `json:"mode_label"`
	UpdateAvailable bool `json:"update_available"`
	UpdateVersion string `json:"update_version,omitempty"`
	UpdateURL string `json:"update_url,omitempty"`
}

// ProfileView is a profile row for the Profiles screen.
type ProfileView struct {
	AgentProfile
	Running bool `json:"running"`
	PID int `json:"pid,omitempty"`
}

// GetUISnapshot returns shell state.
func (a *App) GetUISnapshot() UISnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	mode := uiModeLocked(a)
	snap := UISnapshot{
		Version: a.opts.Version,
		Status: a.status,
		Mode: mode,
		ModeLabel: uiModeLabel(mode),
		ProtectionOn: a.state.ProtectionOn,
		Notify: a.state.Notify && a.state.NotifyLevel != "quiet",
		NotifyLevel: effectiveNotifyLevel(a.state),
		DecisionTimeoutSec: effectiveDecisionTimeoutSec(a.state),
		ReaskIntervalSec: effectiveReaskIntervalSec(a.state),
		ProtectPausedUntil: a.state.ProtectPausedUntil,
		TimedAllows: append([]TimedRule(nil), a.state.TimedAllows...),
		TimedDenies: append([]TimedRule(nil), a.state.TimedDenies...),
		AskMode: a.state.AskMode,
		Autostart: a.state.Autostart,
		AlwaysAllow: append([]string(nil), a.state.AlwaysAllowHosts...),
		RememberedKeeps: append([]string(nil), a.state.RememberedKeeps...),
		LastDenyHost: a.state.LastDenyHost,
		LastDenyURL: a.state.LastDenyURL,
		LastDenySummary: a.state.LastDenySummary,
		BlockedToday: countBlockedToday(AuditLogPath(), time.Now()),
		YourSetupShown: a.state.YourSetupShown,
		SetupDone: a.state.SetupDone,
		ControlURL: a.controlURL,
		AuditPath: AuditLogPath(),
		LogDir: LogDir(),
		DismissedTips: append([]string(nil), a.state.DismissedTips...),
		AskPaused: a.state.AskPaused() || (a.asks != nil && a.asks.Paused()),
		ProblemsAlert: problemsUnhealthyLocked(a),
		YourSetupText: YourSetupText(mode),
		ChecklistDone: tipDismissedLocked(a, "checklist"),
	}
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

func tipDismissedLocked(a *App, id string) bool {
	for _, t := range a.state.DismissedTips {
		if t == id {
			return true
		}
	}
	return false
}

func problemsUnhealthyLocked(a *App) bool {
	st := strings.ToLower(a.status)
	if strings.Contains(st, "error") || strings.Contains(a.status, "Needs") {
		return true
	}
	if a.state.ComputerEnabled || a.proxyd != nil {
		ca := filepath.Join(CADir(), "ca.crt")
		if _, err := os.Stat(ca); err != nil {
			return true
		}
	}
	if LastErrorSummary() != "" && (a.state.ComputerEnabled || a.state.ProtectionOn) && a.proxyd == nil {
		return true
	}
	// Stale Book C (all enabled feeds > 7 days) - no lock: use already-open store only.
	if a.threats != nil {
		if (&threatlists.Updater{Store: a.threats}).NeedsAttention() {
			return true
		}
	}
	return false
}

func uiModeLocked(a *App) string {
	if a.state.ComputerEnabled || a.proxyd != nil {
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

// MarkYourSetupShown persists the in-window Your setup dismiss.
func (a *App) MarkYourSetupShown() error {
	a.mu.Lock()
	a.state.YourSetupShown = true
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

// UIResumeAsks clears Ask storm pause.
func (a *App) UIResumeAsks() {
	a.mu.Lock()
	a.state.AskPausedUntil = ""
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if a.asks != nil {
		a.asks.ClearPause()
	}
	notify.Info("DenyOut", "Asks resumed.")
}

// UIUndoLastAlwaysAllow removes the last Always-allow host.
func (a *App) UIUndoLastAlwaysAllow() {
	a.undoLastAlwaysAllow()
}

// UITestProtection runs the protection self-check toast.
func (a *App) UITestProtection() {
	a.testProtection()
}

// UIBulkAlwaysAllow adds many hosts to Always allow.
func (a *App) UIBulkAlwaysAllow(hosts []string) error {
	var last error
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if err := a.UIAlwaysAllowHost(h, ""); err != nil {
			last = err
		}
	}
	return last
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
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		urlStr := audit.DisplayURL(e.Network, e.HTTP)
		why := notify.HumanReasons(e.Reasons)
		code := primaryPostBlockReason(e.Reasons)
		if code == "" && len(e.Reasons) > 0 {
			code = e.Reasons[0]
		}
		remembered := keepSet[postBlockKey(host, code)]
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
			ID: id,
			TS: e.TS,
			Host: host,
			URL: urlStr,
			Why: why,
			Reasons: append([]string(nil), e.Reasons...),
			Process: e.Process,
			Method: method,
			Detectors: append([]string(nil), e.Detectors...),
			PolicyProfile: e.PolicyProfile,
			Remembered: remembered,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// UIAlwaysAllowHost persists Always allow and forgets Keep for primary reason if set.
func (a *App) UIAlwaysAllowHost(host, reason string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if reason != "" {
		a.forgetKeep(host, reason)
	}
	return a.persistAlwaysHost(host)
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
	a.removeAlwaysHost(host)
	return nil
}

// UISetNotify toggles notifications (legacy bool -> Quiet / Normal).
func (a *App) UISetNotify(on bool) error {
	if on {
		return a.UISetNotifyLevel("normal")
	}
	return a.UISetNotifyLevel("quiet")
}

// UISetNotifyLevel sets quiet | normal | detailed.
func (a *App) UISetNotifyLevel(level string) error {
	a.mu.Lock()
	a.state.NotifyLevel = strings.ToLower(strings.TrimSpace(level))
	if a.state.NotifyLevel == "" {
		a.state.NotifyLevel = "normal"
	}
	a.state.Notify = a.state.NotifyLevel != "quiet"
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

// UIRemoveTimedAllow removes a timed allow by host.
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
	a.mu.Unlock()
	return SaveState(st)
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
	a.state.Autostart = on
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if on {
		return RegisterAutostart()
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
func (a *App) UISwitchSafe() {
	a.switchToSafeDesktopFromTray()
}

// UIStopProtection turns protection Off.
func (a *App) UIStopProtection() {
	a.stopProtectionFromTray()
}

// GetProblems returns Problems screen data.
func (a *App) GetProblems() ProblemsView {
	a.mu.Lock()
	defer a.mu.Unlock()
	ca := filepath.Join(CADir(), "ca.crt")
	_, caErr := os.Stat(ca)
	pv := ProblemsView{
		LastError: LastErrorSummary(),
		LastDenyHost: a.state.LastDenyHost,
		LastDenyURL: a.state.LastDenyURL,
		LastDenySummary: a.state.LastDenySummary,
		ControlOK: a.controlURL != "",
		ProxydRunning: a.proxyd != nil,
		SessionRunning: a.session != nil,
		CAPresent: caErr == nil,
		ClipboardOK: clipboardAvailable(),
		LogDir: LogDir(),
		AuditPath: AuditLogPath(),
		Status: a.status,
		ModeLabel: uiModeLabel(uiModeLocked(a)),
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

// UIRetryProtect retries Safe desktop enable.
func (a *App) UIRetryProtect() error {
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
	return SaveProfile(p)
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
		return nil
	}
	hosts := append([]string{}, p.PendingOnce...)
	p.PinPending(nil)
	p.Learning.Enabled = false
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
	a.stopAllWraps("Agents only on whole PC - stopping wraps")
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.AskMode = true
	a.state.ActiveProfileID = ""
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	return a.enableComputerFromTray()
}

// HealthPing is a cheap binding for Wails readiness.
func (a *App) HealthPing() string {
	return time.Now().UTC().Format(time.RFC3339)
}
