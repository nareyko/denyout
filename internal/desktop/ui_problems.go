package desktop

import (
	"os"
	"path/filepath"
	"strings"
)

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
