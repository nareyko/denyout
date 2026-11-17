package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nareyko/denyout/internal/diag"
	"github.com/nareyko/denyout/internal/explain"
)

// Denial actions for UIDenialAction (the three one-click choices on a block).
const (
	DenialActionAllowOnce   = "allow_once"
	DenialActionAllowAlways = "allow_always"
	DenialActionKeep        = "keep"
)

// "Allow once" is a 15 minute timed allow: DenyOut has no per-request grant,
// so it is the shortest existing timed allow and expires on its own.

// StatusReasonHook lets the protection-state model supply a plain-language
// reason for the current status line. It is nil until that model registers
// one; Diagnostics shows the reason when present and nothing otherwise.
var StatusReasonHook func(a *App) string

// UIDenialAction applies one of the three one-click choices to a blocked host
// without opening logs. process may be "wrap:<profileID>" for agent blocks.
// It returns a short confirmation for the UI.
func (a *App) UIDenialAction(host, reason, process, action string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	reason = strings.TrimSpace(reason)
	switch action {
	case DenialActionKeep:
		if reason == "" {
			return "", fmt.Errorf("missing reason code")
		}
		a.applyHardBlockDecision(host, reason, DecisionKeep)
		return host + " stays blocked and will not ask again for this reason.", nil
	case DenialActionAllowOnce, DenialActionAllowAlways:
		if !explain.Describe(reason).AllowHelps {
			return "", fmt.Errorf("allowing %s would not release this block: %s", host, explain.Describe(reason).Short)
		}
		if isIPLiteral(host) {
			return "", fmt.Errorf("raw IP addresses cannot be allowed; Safe browse already allows public IPs")
		}
		if action == DenialActionAllowAlways {
			if err := a.UIAlwaysAllowHostFrom(host, reason, process); err != nil {
				return "", err
			}
			return "Always allowed " + host + ".", nil
		}
		profileID := strings.TrimPrefix(strings.TrimSpace(process), "wrap:")
		if profileID == strings.TrimSpace(process) {
			profileID = ""
		}
		a.applyHardBlockDecisionProfile(profileID, host, reason, DecisionAllowTimed+"15m")
		if profileID != "" {
			return "Allowed " + host + " for this agent run.", nil
		}
		return "Allowed " + host + " for 15 minutes.", nil
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
}

// DiagnosticsInputs gathers what the report needs from the live app.
func (a *App) diagnosticsInputs() diag.Inputs {
	in := diag.LocalInputs(a.opts.Version)
	in.CADir = CADir()
	in.AuditPath = AuditLogPath()
	a.mu.Lock()
	in.ProtectionOn = a.state.ProtectionOn || a.state.ComputerEnabled || a.proxyd != nil || a.session != nil
	running := a.proxyd != nil || a.session != nil
	in.ProxyRunning = &running
	if a.proxyd != nil {
		in.ProxyPort = proxydPort(a.proxyd.Args)
	}
	in.Status = a.status
	a.mu.Unlock()
	in.LastError = LastErrorSummary()
	if h := StatusReasonHook; h != nil {
		in.StatusReason = h(a)
	}
	return in
}

// proxydPort reads "--port N" from the proxyd command line.
func proxydPort(args []string) int {
	for i, s := range args {
		if s == "--port" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				return n
			}
		}
	}
	return 0
}

// UIDiagnostics returns the redacted report for the Diagnostics view.
func (a *App) UIDiagnostics() diag.Report {
	return diag.Build(a.diagnosticsInputs())
}

// UIDiagnosticsText returns the same report as paste-ready text.
func (a *App) UIDiagnosticsText() string {
	return a.UIDiagnostics().Text()
}

// UIRunSelfCheck runs the in-process CA and interception verification used by
// first-run. It never changes host networking or the trust store.
func (a *App) UIRunSelfCheck() []diag.Check {
	in := a.diagnosticsInputs()
	checks := diag.SelfCheck(in.CADir, in.ProtectionOn)
	// Protect on but the proxy is not up is the most common first-run failure.
	if in.ProtectionOn && in.ProxyRunning != nil && !*in.ProxyRunning {
		checks = append(checks, diag.Check{
			ID: "proxy", Name: "Proxy listening", Status: diag.Fail,
			Detail: "Protect is meant to be on but the proxy is not running",
			Fix:    diag.FixRetryProtect, FixLabel: "Turn Protect on again",
		})
	}
	return checks
}

// UIFixCheck runs the "Fix" action a check offered. Every fix goes through an
// existing consent path (the password prompt for the helper stays).
func (a *App) UIFixCheck(fix string) (string, error) {
	switch fix {
	case diag.FixRetryProtect:
		if err := a.UIRetryProtect(); err != nil {
			return "", err
		}
		return "Protect turned on. Run the check again.", nil
	case diag.FixRegenerateCA:
		if err := a.regenerateCA(); err != nil {
			return "", err
		}
		return "Created a new CA and turned Protect on. Run the check again.", nil
	case diag.FixRefreshThreat:
		if _, err := a.UIRefreshThreatLists(); err != nil {
			return "", err
		}
		return "Threat lists refreshed.", nil
	case diag.FixOpenProblems:
		a.RequestOpenUI("problems")
		return "Opened Problems.", nil
	default:
		return "", fmt.Errorf("unknown fix %q", fix)
	}
}

// regenerateCA replaces a broken CA. Protect is unloaded first so the old CA
// is not in use, the CA files are removed, then the normal Protect path makes
// a new one and asks for trust through the usual admin prompt.
func (a *App) regenerateCA() error {
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	if err := removeCAFiles(CADir()); err != nil {
		return err
	}
	LogEvent("ca_regenerate", map[string]any{"source": "selfcheck"})
	return a.UIRetryProtect()
}

func removeCAFiles(dir string) error {
	for _, n := range []string{"ca.crt", "ca.key"} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
