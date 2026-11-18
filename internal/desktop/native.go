package desktop

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
)

func nativeAllowDialogProfile(host, reason, profileName string) string {
	why := notify.HumanReasons([]string{reason})
	who := "A protected program"
	if profileName != "" {
		who = profileName
	}
	text := fmt.Sprintf(
		"%s wants to reach %s.\n\n%s\n\nAllow once, always allow this site, or keep it blocked?",
		who, host, why,
	)
	return runAskDialog(text)
}

// askViaToastThenDialog shows the Ask dialog only (no duplicate OS teaser toast).
func askViaToastThenDialog(host, reason, profileName string) string {
	return askDialogWithTimeout(host, reason, profileName)
}

func askDialogWithTimeout(host, reason, profileName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	ch := make(chan string, 1)
	go func() {
		ch <- nativeAllowDialogProfile(host, reason, profileName)
	}()
	select {
	case a := <-ch:
		if a == "" {
			return "deny"
		}
		return a
	case <-ctx.Done():
		return "deny"
	}
}

// nativeConfirm Yes/No; returns true if primary (yesLabel) chosen.
func nativeConfirm(title, text, yesLabel, noLabel string) bool {
	if title == "" {
		title = "DenyOut"
	}
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(zenity, "--question", "--title="+title, "--text="+text,
				"--ok-label="+yesLabel, "--cancel-label="+noLabel, "--width=440", "--default-cancel")
			return cmd.Run() == nil
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			return exec.Command(kdialog, "--yesno", text, "--yes-label", yesLabel, "--no-label", noLabel, "--title", title).Run() == nil
		}
	case "darwin":
		script := fmt.Sprintf(`set r to button returned of (display dialog %q buttons {%q,%q} default button %q with title %q)
return r`, text, noLabel, yesLabel, noLabel, title)
		out, err := exec.Command("osascript", "-e", script).Output()
		return err == nil && strings.Contains(string(out), yesLabel)
	case "windows":
		ps := fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
$r = [System.Windows.MessageBox]::Show(%q, %q, 'YesNo', 'Question')
if ($r -eq 'Yes') { 'yes' } else { 'no' }`, text, title)
		out, _ := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
		return strings.TrimSpace(string(out)) == "yes"
	}
	return false
}

// nativeListChoice returns selected string or "".
func nativeEntry(title, text, preset string) (string, bool) {
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			args := []string{"--entry", "--title=" + title, "--text=" + text, "--width=480"}
			if preset != "" {
				args = append(args, "--entry-text="+preset)
			}
			out, err := exec.Command(zenity, args...).Output()
			if err != nil {
				return "", false
			}
			return strings.TrimSpace(string(out)), true
		}
	case "darwin":
		script := fmt.Sprintf(`set r to text returned of (display dialog %q default answer %q with title %q)
return r`, text, preset, title)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}
	return "", false
}

func dialogToolkitAvailable() bool {
	switch runtime.GOOS {
	case "linux":
		_, e1 := exec.LookPath("zenity")
		_, e2 := exec.LookPath("kdialog")
		return e1 == nil || e2 == nil
	case "darwin", "windows":
		return true
	default:
		return false
	}
}

func isIPLiteral(host string) bool {
	return net.ParseIP(strings.TrimSpace(host)) != nil
}

// nativeShowHome is the CLI-tray stand-in for Wails Home (status + Protect / history).
func (a *App) nativeShowHome() {
	mode := a.currentMode()
	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	status := userModeLabel(mode, profile)
	choice, ok := nativeListPick(
		"DenyOut - Home",
		"Status: "+status+"\n\nChoose an action:",
		[]string{"Protect computer", "Turn off", "What was blocked...", "Problems...", "Close"},
	)
	if !ok || choice == "Close" || choice == "" {
		return
	}
	switch choice {
	case "Protect computer":
		a.trayEnableProtectComputer()
	case "Turn off":
		a.stopProtectionFromTray()
	case "What was blocked...":
		a.nativeShowActivity()
	case "Problems...":
		a.showProblems()
	}
}

// nativeShowActivity is Activity v2: human denial list with URL, Always allow / Undo / Details / Problems.
func (a *App) nativeShowActivity() {
	for {
		choice, ok := nativeListPick(
			"DenyOut - What was blocked",
			"Choose a view:",
			[]string{"Blocked sites...", "Problems...", "Close"},
		)
		if !ok || choice == "Close" || choice == "" {
			return
		}
		if choice == "Problems..." {
			a.showProblems()
			continue
		}
		events, err := audit.RecentDenials(AuditLogPath(), 40)
		if err != nil {
			notify.Info("DenyOut", "Could not read denial history: "+err.Error())
			return
		}
		if len(events) == 0 {
			notify.Info("DenyOut", "No denials yet.")
			continue
		}
		host, reason, action, ev := nativeDenialsChooserV2(events)
		a.handleActivityAction(action, host, reason, ev)
	}
}

// activityAllowMsgs are the notices for the always/undo paths of Activity.
type activityAllowMsgs struct{ ip, fail string }

var (
	activityAlwaysMsgs = activityAllowMsgs{"Direct IP addresses cannot be always-allowed.", "Always allow failed: "}
	activityUndoMsgs   = activityAllowMsgs{"Cannot undo IP blocks this way.", "Undo failed: "}
)

func (a *App) handleActivityAction(action, host, reason string, ev *audit.Event) {
	switch action {
	case "details":
		if ev != nil {
			a.showDenialDetails(*ev)
		}
	case "always":
		a.activityAllowHost(host, reason, activityAlwaysMsgs)
	case "undo":
		a.activityAllowHost(host, reason, activityUndoMsgs)
	case "problems":
		a.showProblems()
	}
	// refresh / close / unknown -> back to the menu loop
}

func (a *App) activityAllowHost(host, reason string, m activityAllowMsgs) {
	if host == "" {
		return
	}
	if isIPLiteral(host) {
		notify.Info("DenyOut", m.ip)
		return
	}
	if reason != "" {
		a.forgetKeep(host, reason)
	}
	if err := a.persistAlwaysHostFrom(host, "native"); err != nil {
		notify.Info("DenyOut", m.fail+err.Error())
		return
	}
	notify.Info("DenyOut", "Allowed this site: "+host)
}

func denialDetailText(e audit.Event) string {
	host := e.Network.DestHost
	urlStr := audit.DisplayURL(e.Network, e.HTTP)
	why := notify.HumanReasons(e.Reasons)
	if why == "" {
		why = strings.Join(e.Reasons, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s\n", host)
	if urlStr != "" {
		fmt.Fprintf(&b, "URL: %s\n", urlStr)
	}
	fmt.Fprintf(&b, "Why: %s\n", why)
	if e.HTTP != nil && e.HTTP.Method != "" {
		fmt.Fprintf(&b, "Method: %s\n", e.HTTP.Method)
	}
	if e.Process != "" {
		fmt.Fprintf(&b, "Process: %s\n", e.Process)
	}
	if len(e.Detectors) > 0 {
		fmt.Fprintf(&b, "Detectors: %s\n", strings.Join(e.Detectors, ", "))
	}
	if e.TS != "" {
		fmt.Fprintf(&b, "When: %s\n", e.TS)
	}
	if e.PolicyProfile != "" {
		fmt.Fprintf(&b, "Mode: %s\n", e.PolicyProfile)
	}
	b.WriteString("\nSecrets in URLs are redacted (***).")
	return b.String()
}

func (a *App) showDenialDetails(e audit.Event) {
	host := e.Network.DestHost
	urlStr := audit.DisplayURL(e.Network, e.HTTP)
	text := denialDetailText(e)
	code := primaryPostBlockReason(e.Reasons)
	if code == "" && len(e.Reasons) > 0 {
		code = e.Reasons[0]
	}
	if !dialogToolkitAvailable() {
		notify.Info("DenyOut - Blocked request", text)
		return
	}
	sel, ok := nativeListPick("DenyOut - Blocked request", text+"\n\n", []string{
		"Allow this site",
		"Always allow host",
		"Copy URL",
		"Back",
	})
	if !ok || sel == "Back" || sel == "" {
		return
	}
	switch sel {
	case "Copy URL":
		copyText := urlStr
		if copyText == "" {
			copyText = host
		}
		if err := copyToClipboard(copyText); err != nil {
			notify.Info("DenyOut", "Could not copy: "+err.Error()+"\n"+copyText)
		} else {
			notify.Info("DenyOut", "Copied URL to clipboard.")
		}
	case "Allow this site", "Always allow host":
		if host == "" || isIPLiteral(host) {
			notify.Info("DenyOut", "Direct IP addresses cannot be always-allowed.")
			return
		}
		if code != "" {
			a.forgetKeep(host, code)
		}
		if err := a.persistAlwaysHostFrom(host, "native"); err != nil {
			notify.Info("DenyOut", "Allow failed: "+err.Error())
			return
		}
		notify.Info("DenyOut", "Allowed this site: "+host)
	}
}

func (a *App) showProblems() {
	last := LastErrorSummary()
	if last == "" {
		last = "(no recent elevation/desktop errors)"
	}
	a.mu.Lock()
	denyHost := a.state.LastDenyHost
	denyURL := a.state.LastDenyURL
	denyWhy := a.state.LastDenySummary
	a.mu.Unlock()
	text := "Problems & diagnostics\n\n" +
		"Last error:\n" + last + "\n\n"
	if denyHost != "" {
		text += "Last blocked:\nHost: " + denyHost + "\n"
		if denyURL != "" {
			text += "URL: " + denyURL + "\n"
		}
		if denyWhy != "" {
			text += "Why: " + denyWhy + "\n"
		}
		text += "\n"
	}
	text += "If Protect computer failed, protection stays Off - retry from Home or the tray.\n" +
		"Logs rotate under your user state folder (audit.jsonl, desktop.log)."
	if dialogToolkitAvailable() {
		if nativeConfirm("DenyOut - Problems", text+"\n\n", "Copy last error", "Open diagnostics") {
			copyLastErrorOrPrint()
		} else {
			openLogsOrPrint()
		}
		return
	}
	notify.Info("DenyOut - Problems", last)
	openLogsOrPrint()
}

// helpAndProblems is tray Help & problems...
func (a *App) helpAndProblems() {
	ver := a.opts.Version
	if ver == "" {
		ver = "dev"
	}
	text := fmt.Sprintf(
		"DenyOut %s\n\n"+
			"Protect computer - everyday browsing. Clear threats then Keep blocked or Allow this site.\n"+
			"My agents - wrap a program (Ask before new hosts).\n"+
			"Agents only - whole-PC allowlist (Settings, Advanced - almost nobody needs this).\n\n"+
			"Left-click tray or Open DenyOut... for Home.\n"+
			"History = what was blocked. Settings, Advanced = allowed / silenced sites.\n"+
			"Problems = when Protect failed.\n\n"+
			"Privacy: decisions stay on this computer.",
		ver,
	)
	if dialogToolkitAvailable() {
		sel, ok := nativeListPick("DenyOut - Help & problems", text, []string{
			"Open Problems...",
			"Open diagnostics folder",
			"Copy last error",
			"Close",
		})
		if !ok {
			return
		}
		switch sel {
		case "Open Problems...":
			a.showProblems()
		case "Open diagnostics folder":
			openLogsOrPrint()
		case "Copy last error":
			copyLastErrorOrPrint()
		}
		return
	}
	notify.Info("DenyOut - Help", text)
	a.showProblems()
}
