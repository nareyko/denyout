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

func runAskDialog(text string) string {
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			// Default (cancel) = Keep blocked; OK = Allow once; extra = Always.
			cmd := exec.Command(zenity, "--question",
				"--title=DenyOut",
				"--text="+text,
				"--ok-label=Allow once",
				"--cancel-label=Keep blocked",
				"--extra-button=Always allow",
				"--width=480",
				"--default-cancel",
			)
			out, err := cmd.CombinedOutput()
			s := strings.TrimSpace(string(out))
			if strings.Contains(s, "Always allow") {
				return "always"
			}
			if err == nil {
				return "once"
			}
			return "deny"
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			cmd := exec.Command(kdialog, "--yesnocancel", text,
				"--yes-label", "Allow once",
				"--no-label", "Always allow",
				"--cancel-label", "Keep blocked",
				"--title", "DenyOut",
			)
			err := cmd.Run()
			code := 2
			if err == nil {
				code = 0
			} else if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
			switch code {
			case 0:
				return "once"
			case 1:
				return "always"
			default:
				return "deny"
			}
		}
		notify.Info("DenyOut", "Install zenity for permission dialogs (e.g. apt install zenity).")
		return "deny"
	case "darwin":
		script := fmt.Sprintf(`set r to button returned of (display dialog %q buttons {"Keep blocked","Allow once","Always allow"} default button "Keep blocked" with title "DenyOut")
return r`, text)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "deny"
		}
		s := strings.TrimSpace(string(out))
		switch {
		case strings.Contains(s, "Always"):
			return "always"
		case strings.Contains(s, "once"):
			return "once"
		default:
			return "deny"
		}
	case "windows":
		ps := fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
$r = [System.Windows.MessageBox]::Show(%q, 'DenyOut - new site', 'YesNoCancel', 'Question')
# Yes=Allow once, No=Always allow, Cancel=Keep blocked (default Cancel via focus)
if ($r -eq 'Yes') { 'once' } elseif ($r -eq 'No') { 'always' } else { 'deny' }`, text)
		out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
		if err != nil {
			return "deny"
		}
		s := strings.TrimSpace(strings.ToLower(string(out)))
		if s == "once" || s == "always" || s == "deny" {
			return s
		}
	}
	return "deny"
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
		switch action {
		case "details":
			if ev == nil {
				continue
			}
			a.showDenialDetails(*ev)
		case "always":
			if host == "" {
				continue
			}
			if isIPLiteral(host) {
				notify.Info("DenyOut", "Direct IP addresses cannot be always-allowed.")
				continue
			}
			if reason != "" {
				a.forgetKeep(host, reason)
			}
			if err := a.persistAlwaysHost(host); err != nil {
				notify.Info("DenyOut", "Always allow failed: "+err.Error())
				continue
			}
			notify.Info("DenyOut", "Allowed this site: "+host)
		case "undo":
			if host == "" {
				continue
			}
			if isIPLiteral(host) {
				notify.Info("DenyOut", "Cannot undo IP blocks this way.")
				continue
			}
			if reason != "" {
				a.forgetKeep(host, reason)
			}
			if err := a.persistAlwaysHost(host); err != nil {
				notify.Info("DenyOut", "Undo failed: "+err.Error())
				continue
			}
			notify.Info("DenyOut", "Allowed this site: "+host)
		case "refresh":
			continue
		case "problems":
			a.showProblems()
		default:
			// close -> back to menu
		}
	}
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
		if err := a.persistAlwaysHost(host); err != nil {
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
			"Protect computer - everyday browsing; clear threats -> Keep blocked / Allow this site.\n"+
			"My agents - wrap a program (Ask before new hosts).\n"+
			"Agents only - whole-PC allowlist (Settings -> Advanced; almost nobody needs this).\n\n"+
			"Left-click tray / Open DenyOut... -> Home.\n"+
			"History = what was blocked. Settings -> Advanced = allowed / silenced sites.\n"+
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

// nativeDenialsChooserV2 returns host, reason code, action, and the selected event when known.
// action: always|undo|details|refresh|close|problems
func nativeDenialsChooserV2(events []audit.Event) (host, reason, action string, ev *audit.Event) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			return nativeDenialsChooserZenityV2(events)
		}
		h, act, e := nativeDenialsChooser(events)
		return h, "", act, e
	default:
		h, act, e := nativeDenialsChooser(events)
		return h, "", act, e
	}
}

func nativeDenialsChooser(events []audit.Event) (selectedHost, action string, ev *audit.Event) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			h, _, act, e := nativeDenialsChooserZenityV2(events)
			return h, act, e
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			items := make([]string, 0, len(events)*2)
			byHost := map[string]*audit.Event{}
			for i := len(events) - 1; i >= 0; i-- {
				e := events[i]
				host := e.Network.DestHost
				if host == "" {
					continue
				}
				urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 64)
				why := notify.HumanReasons(e.Reasons)
				label := fmt.Sprintf("%s - %s", host, why)
				if urlStr != "" {
					label = fmt.Sprintf("%s - %s - %s", host, urlStr, why)
				}
				items = append(items, host, label)
				if _, ok := byHost[host]; !ok {
					evCopy := e
					byHost[host] = &evCopy
				}
			}
			if len(items) == 0 {
				return "", "close", nil
			}
			args := append([]string{"--menu", "Recent denials - pick a row (URL shown in label)", "--title", "DenyOut - What was blocked"}, items...)
			out, err := exec.Command(kdialog, args...).Output()
			if err != nil {
				return "", "close", nil
			}
			host := strings.TrimSpace(string(out))
			return host, "details", byHost[host]
		}
	case "darwin":
		var lines []string
		hostByLine := map[string]string{}
		evByLine := map[string]*audit.Event{}
		for i := len(events) - 1; i >= 0 && len(lines) < 25; i-- {
			e := events[i]
			host := e.Network.DestHost
			if host == "" {
				continue
			}
			urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 48)
			why := notify.HumanReasons(e.Reasons)
			line := fmt.Sprintf("%s - %s", host, why)
			if urlStr != "" {
				line = fmt.Sprintf("%s - %s - %s", host, urlStr, why)
			}
			// Escape quotes for AppleScript.
			line = strings.ReplaceAll(line, `"`, `'`)
			lines = append(lines, line)
			hostByLine[line] = host
			evCopy := e
			evByLine[line] = &evCopy
		}
		if len(lines) == 0 {
			return "", "close", nil
		}
		list := strings.Join(lines, `","`)
		script := fmt.Sprintf(`set hostList to {"%s"}
set chosen to choose from list hostList with prompt "Recent denials (host - URL - why). Open details?" OK button name "Details" cancel button name "Close"
if chosen is false then
 return "CLOSE"
end if
return item 1 of chosen`, list)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", "close", nil
		}
		s := strings.TrimSpace(string(out))
		if s == "CLOSE" || s == "" {
			return "", "close", nil
		}
		if h, ok := hostByLine[s]; ok {
			return h, "details", evByLine[s]
		}
		return "", "close", nil
	case "windows":
		var b strings.Builder
		b.WriteString("Recent denials:\n")
		var firstHost string
		var firstEv *audit.Event
		n := 0
		for i := len(events) - 1; i >= 0 && n < 15; i-- {
			e := events[i]
			host := e.Network.DestHost
			if host == "" {
				continue
			}
			if firstHost == "" {
				firstHost = host
				evCopy := e
				firstEv = &evCopy
			}
			urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 72)
			why := notify.HumanReasons(e.Reasons)
			if urlStr != "" {
				fmt.Fprintf(&b, "- %s\n %s\n %s\n", host, urlStr, why)
			} else {
				fmt.Fprintf(&b, "- %s (%s)\n", host, why)
			}
			n++
		}
		msg := b.String() + "\n\nOpen details for first host " + firstHost + "?"
		ps := fmt.Sprintf("Add-Type -AssemblyName PresentationFramework; $r = [System.Windows.MessageBox]::Show(%q, 'DenyOut - What was blocked', 'YesNo', 'Information'); if ($r -eq 'Yes') { 'details' } else { 'close' }", msg)
		out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
		if err != nil {
			return "", "close", nil
		}
		if strings.TrimSpace(string(out)) == "details" {
			return firstHost, "details", firstEv
		}
	}
	notify.Info("DenyOut", "No native list dialog available. See diagnostics folder for audit.jsonl.")
	return "", "close", nil
}

func nativeDenialsChooserZenityV2(events []audit.Event) (selectedHost, reason, action string, ev *audit.Event) {
	zenity, err := exec.LookPath("zenity")
	if err != nil {
		return "", "", "close", nil
	}
	args := []string{
		"--list",
		"--title=DenyOut - What was blocked",
		"--text=Select a row. Secrets in URLs are redacted. Details shows the full request.",
		"--column=#",
		"--column=Time",
		"--column=Host",
		"--column=URL",
		"--column=Why",
		"--print-column=1",
		"--width=920",
		"--height=480",
		"--ok-label=Details",
		"--cancel-label=Back",
		"--extra-button=Always allow",
		"--extra-button=Undo",
		"--extra-button=Refresh",
	}
	byIdx := map[string]*audit.Event{}
	hostReason := map[string]string{}
	row := 0
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		row++
		idx := fmt.Sprintf("%d", row)
		ts := e.TS
		if len(ts) >= 19 {
			ts = ts[11:19]
		}
		if ts == "" {
			ts = "-"
		}
		code := primaryPostBlockReason(e.Reasons)
		if code == "" && len(e.Reasons) > 0 {
			code = e.Reasons[0]
		}
		why := notify.HumanReasons(e.Reasons)
		if why == "" {
			why = "-"
		}
		if len(why) > 72 {
			why = why[:69] + "..."
		}
		urlStr := audit.DisplayURL(e.Network, e.HTTP)
		if urlStr == "" {
			urlStr = host
		}
		urlStr = audit.TruncateMiddle(urlStr, 72)
		args = append(args, idx, ts, host, urlStr, why)
		evCopy := e
		byIdx[idx] = &evCopy
		if _, ok := hostReason[host]; !ok {
			hostReason[host] = code
		}
	}
	if len(byIdx) == 0 {
		return "", "", "close", nil
	}
	cmd := exec.Command(zenity, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "Refresh") {
		return "", "", "refresh", nil
	}
	always := strings.Contains(s, "Always allow")
	undo := strings.Contains(s, "Undo")
	s = strings.ReplaceAll(s, "Always allow", "")
	s = strings.ReplaceAll(s, "Undo", "")
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	idx := strings.TrimSpace(lines[len(lines)-1])
	sel := byIdx[idx]
	if sel == nil {
		if err != nil && !always && !undo {
			return "", "", "close", nil
		}
		return "", "", "close", nil
	}
	host := sel.Network.DestHost
	code := hostReason[host]
	if code == "" {
		code = primaryPostBlockReason(sel.Reasons)
		if code == "" && len(sel.Reasons) > 0 {
			code = sel.Reasons[0]
		}
	}
	if always {
		return host, code, "always", sel
	}
	if undo {
		return host, code, "undo", sel
	}
	if err != nil {
		return "", "", "close", nil
	}
	return host, code, "details", sel
}
