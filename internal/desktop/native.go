package desktop

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
		"%s wants network access.\n\nHost: %s\nWhy: %s\n\nAllow once, always allow this host, or keep it blocked?",
		who, host, why,
	)
	return runAskDialog(text)
}

// askViaToastThenDialog: toast first (no focus steal), then dialog on action / fallback.
func askViaToastThenDialog(host, reason, profileName string) string {
	if runtime.GOOS == "linux" {
		if action, ok := askToastDecide(host, profileName); ok {
			if action == "dismiss" {
				// User opened decide → show dialog
				return askDialogWithTimeout(host, reason, profileName)
			}
			return action
		}
	}
	// Fallback: brief toast then dialog
	who := host
	if profileName != "" {
		who = profileName + " → " + host
	}
	notify.Info("DenyOut needs a decision", who+"\nOpening permission dialog…")
	time.Sleep(400 * time.Millisecond)
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
		notify.Info("DenyOut", "Permission timed out — still blocked: "+host)
		return "deny"
	}
}

// askToastDecide uses notify-send actions. Returns ("dismiss", true) when user clicks Decide.
func askToastDecide(host, profileName string) (string, bool) {
	if _, err := exec.LookPath("notify-send"); err != nil {
		return "", false
	}
	body := host
	if profileName != "" {
		body = profileName + " wants: " + host
	}
	cmd := exec.Command("notify-send",
		"--app-name=DenyOut",
		"--urgency=critical",
		"--expire-time=120000",
		"--wait",
		"--action=decide=Decide",
		"--action=deny=Keep blocked",
		"DenyOut needs a decision",
		body,
	)
	// Play a short bell for Ask only (best-effort).
	_ = exec.Command("paplay", "/usr/share/sounds/freedesktop/stereo/message.oga").Start()
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	switch strings.TrimSpace(string(out)) {
	case "decide":
		return "dismiss", true
	case "deny":
		return "deny", true
	default:
		return "deny", true
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
$r = [System.Windows.MessageBox]::Show(%q, 'DenyOut — new site', 'YesNoCancel', 'Question')
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

// nativeShowActivity lists recent denials and optionally Always-allows the selected host.
func (a *App) nativeShowActivity() {
	for {
		events, err := audit.RecentDenials(AuditLogPath(), 40)
		if err != nil {
			notify.Info("DenyOut", "Could not read denial history: "+err.Error())
			return
		}
		if len(events) == 0 {
			notify.Info("DenyOut", "No denials yet.")
			return
		}
		host, action := nativeDenialsChooser(events)
		switch action {
		case "always":
			if host == "" {
				continue
			}
			if isIPLiteral(host) {
				notify.Info("DenyOut", "Direct IP addresses cannot be always-allowed while IP literals are disabled. Switch to Browse for messengers.")
				continue
			}
			if err := a.persistAlwaysHost(host); err != nil {
				notify.Info("DenyOut", "Always allow failed: "+err.Error())
				continue
			}
			notify.Info("DenyOut", "Always allow: "+host)
			return
		case "refresh":
			continue
		default:
			return
		}
	}
}

func nativeDenialsChooser(events []audit.Event) (selectedHost, action string) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("zenity"); err == nil {
			return nativeDenialsChooserZenity(events)
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			items := make([]string, 0, len(events)*2)
			for i := len(events) - 1; i >= 0; i-- {
				e := events[i]
				host := e.Network.DestHost
				if host == "" {
					continue
				}
				label := fmt.Sprintf("%s — %s", host, strings.Join(e.Reasons, ","))
				items = append(items, host, label)
			}
			if len(items) == 0 {
				return "", "close"
			}
			args := append([]string{"--menu", "Recent denials — pick host to Always allow", "--title", "DenyOut Activity"}, items...)
			out, err := exec.Command(kdialog, args...).Output()
			if err != nil {
				return "", "close"
			}
			return strings.TrimSpace(string(out)), "always"
		}
	case "darwin":
		var lines []string
		hostByLine := map[string]string{}
		for i := len(events) - 1; i >= 0 && len(lines) < 25; i-- {
			e := events[i]
			host := e.Network.DestHost
			if host == "" {
				continue
			}
			line := fmt.Sprintf("%s (%s)", host, strings.Join(e.Reasons, ", "))
			lines = append(lines, line)
			hostByLine[line] = host
		}
		if len(lines) == 0 {
			return "", "close"
		}
		list := strings.Join(lines, `","`)
		script := fmt.Sprintf(`set hostList to {"%s"}
set chosen to choose from list hostList with prompt "Recent denials — Always allow selected host?" OK button name "Always allow" cancel button name "Close"
if chosen is false then
  return "CLOSE"
end if
return item 1 of chosen`, list)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", "close"
		}
		s := strings.TrimSpace(string(out))
		if s == "CLOSE" || s == "" {
			return "", "close"
		}
		if h, ok := hostByLine[s]; ok {
			return h, "always"
		}
		return "", "close"
	case "windows":
		var b strings.Builder
		b.WriteString("Recent denials:\n")
		var firstHost string
		n := 0
		for i := len(events) - 1; i >= 0 && n < 15; i-- {
			e := events[i]
			host := e.Network.DestHost
			if host == "" {
				continue
			}
			if firstHost == "" {
				firstHost = host
			}
			fmt.Fprintf(&b, "- %s (%s)\n", host, strings.Join(e.Reasons, ", "))
			n++
		}
		msg := b.String() + "\n\nAlways allow first host " + firstHost + "?"
		ps := fmt.Sprintf("Add-Type -AssemblyName PresentationFramework; $r = [System.Windows.MessageBox]::Show(%q, 'DenyOut Activity', 'YesNo', 'Information'); if ($r -eq 'Yes') { 'always' } else { 'close' }", msg)
		out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
		if err != nil {
			return "", "close"
		}
		if strings.TrimSpace(string(out)) == "always" {
			return firstHost, "always"
		}
	}
	notify.Info("DenyOut", "No native list dialog available. See diagnostics folder for audit.jsonl.")
	return "", "close"
}

func nativeDenialsChooserZenity(events []audit.Event) (selectedHost, action string) {
	zenity, err := exec.LookPath("zenity")
	if err != nil {
		return "", "close"
	}
	args := []string{
		"--list",
		"--title=DenyOut Activity",
		"--text=Recent denials — select a row, then Always allow",
		"--column=Time",
		"--column=Host",
		"--column=Reasons",
		"--column=Profile",
		"--print-column=2",
		"--width=720",
		"--height=420",
		"--ok-label=Always allow",
		"--cancel-label=Close",
		"--extra-button=Refresh",
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			host = "-"
		}
		ts := e.TS
		if len(ts) >= 19 {
			ts = ts[11:19]
		}
		if ts == "" {
			ts = "-"
		}
		reasons := strings.Join(e.Reasons, ", ")
		if reasons == "" {
			reasons = "-"
		}
		profile := e.PolicyProfile
		if profile == "" {
			profile = "-"
		}
		args = append(args, ts, host, reasons, profile)
	}
	cmd := exec.Command(zenity, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "Refresh") {
		return "", "refresh"
	}
	if err != nil || s == "" || s == "-" {
		return "", "close"
	}
	lines := strings.Split(s, "\n")
	host := strings.TrimSpace(lines[len(lines)-1])
	if host == "" || host == "-" {
		return "", "close"
	}
	return host, "always"
}

func (a *App) nativeManageAlwaysAllow() {
	for {
		a.mu.Lock()
		hosts := append([]string(nil), a.state.AlwaysAllowHosts...)
		a.mu.Unlock()
		if len(hosts) == 0 {
			notify.Info("DenyOut", "Always-allow list is empty. Use Ask → Always allow on a new site.")
			return
		}
		host, action := nativeAlwaysAllowChooser(hosts)
		switch action {
		case "remove":
			if host == "" {
				return
			}
			a.removeAlwaysHost(host)
			notify.Info("DenyOut", "Removed always-allow: "+host)
		default:
			return
		}
	}
}

func nativeAlwaysAllowChooser(hosts []string) (selected, action string) {
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			args := []string{
				"--list",
				"--title=DenyOut Always allow",
				"--text=Select a host to remove from Always allow",
				"--column=Host",
				"--width=480",
				"--height=360",
				"--ok-label=Remove",
				"--cancel-label=Close",
			}
			args = append(args, hosts...)
			out, err := exec.Command(zenity, args...).CombinedOutput()
			s := strings.TrimSpace(string(out))
			if err != nil || s == "" {
				return "", "close"
			}
			lines := strings.Split(s, "\n")
			return strings.TrimSpace(lines[len(lines)-1]), "remove"
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			items := make([]string, 0, len(hosts)*2)
			for _, h := range hosts {
				items = append(items, h, h)
			}
			args := append([]string{"--menu", "Remove from Always allow", "--title", "DenyOut"}, items...)
			out, err := exec.Command(kdialog, args...).Output()
			if err != nil {
				return "", "close"
			}
			return strings.TrimSpace(string(out)), "remove"
		}
	case "darwin":
		list := strings.Join(hosts, `","`)
		script := fmt.Sprintf(`set hostList to {"%s"}
set chosen to choose from list hostList with prompt "Remove from Always allow?" OK button name "Remove" cancel button name "Close"
if chosen is false then
  return "CLOSE"
end if
return item 1 of chosen`, list)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", "close"
		}
		s := strings.TrimSpace(string(out))
		if s == "CLOSE" || s == "" {
			return "", "close"
		}
		return s, "remove"
	case "windows":
		if len(hosts) == 0 {
			return "", "close"
		}
		ps := fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
$r = [System.Windows.MessageBox]::Show("Remove always-allow for %q?", 'DenyOut', 'YesNo', 'Question')
if ($r -eq 'Yes') { 'remove' } else { 'close' }`, hosts[0])
		out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
		if err != nil {
			return "", "close"
		}
		if strings.TrimSpace(string(out)) == "remove" {
			return hosts[0], "remove"
		}
	}
	return "", "close"
}
