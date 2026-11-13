package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// nativeSetup runs a first-run setup without any localhost web UI.
// Uses zenity/kdialog/osascript when available; otherwise stdin prompts.
func (a *App) nativeSetup() error {
	fmt.Fprintln(os.Stderr, "denyout desktop: first-run setup (native, no browser)")

	notify := true
	ask := false
	startNow := true

	switch runtime.GOOS {
	case "linux":
		if path, err := exec.LookPath("zenity"); err == nil {
			notify = zenityQuestion(path, "Show a notification when something is blocked?", true)
			ask = zenityQuestion(path, "Ask before allowing new sites? (stricter)", false)
			startNow = zenityQuestion(path, "Turn on Protect this computer now?\n(Admin password may be required.)", true)
		} else if path, err := exec.LookPath("kdialog"); err == nil {
			notify = kdialogYesNo(path, "Show notifications when something is blocked?")
			ask = kdialogYesNo(path, "Ask before allowing new sites?")
			startNow = kdialogYesNo(path, "Turn on Protect this computer now?")
		} else {
			notify, ask, startNow = promptSetupTTY()
		}
	case "darwin":
		notify = osascriptYesNo("Show a notification when DenyOut blocks something?", true)
		ask = osascriptYesNo("Ask before allowing new sites? (stricter)", false)
		startNow = osascriptYesNo("Turn on Protect this computer now? Admin password may be required.", true)
	case "windows":
		notify = windowsYesNo("DenyOut", "Show notifications when something is blocked?", true)
		ask = windowsYesNo("DenyOut", "Ask before allowing new sites? (stricter)", false)
		startNow = windowsYesNo("DenyOut", "Turn on Protect this computer now? Administrator approval may be required.", true)
	default:
		notify, ask, startNow = promptSetupTTY()
	}

	a.mu.Lock()
	a.state.SetupDone = true
	a.state.Notify = notify
	a.state.AskMode = ask
	st := a.state
	a.mu.Unlock()
	notifySet(notify)
	if err := SaveState(st); err != nil {
		return err
	}
	if startNow {
		if err := a.startComputer(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: could not enable Protect yet: %v\n", err)
			fmt.Fprintln(os.Stderr, "denyout desktop: use the tray menu → Protect this computer")
		}
	}
	return nil
}

func notifySet(on bool) {
	// local import cycle avoided — call via package notify from app.go path
	setNotifyEnabled(on)
}

// set by init in native_notify.go / app uses notify.SetEnabled directly in callers.
var setNotifyEnabled = func(bool) {}

func promptSetupTTY() (notify, ask, startNow bool) {
	notify = askTTY("Show notifications when something is blocked? [Y/n] ", true)
	ask = askTTY("Ask before allowing new sites? [y/N] ", false)
	startNow = askTTY("Turn on Protect this computer now? [Y/n] ", true)
	return
}

func askTTY(prompt string, defYes bool) bool {
	in := os.Stdin
	out := os.Stderr
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		in = tty
		out = tty
	}
	fmt.Fprint(out, prompt)
	var line string
	_, _ = fmt.Fscanln(in, &line)
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defYes
	}
	return line == "y" || line == "yes"
}

func zenityQuestion(zenity, text string, defYes bool) bool {
	args := []string{"--question", "--title=DenyOut", "--width=420", "--text=" + text}
	if !defYes {
		args = append(args, "--default-cancel")
	}
	cmd := exec.Command(zenity, args...)
	err := cmd.Run()
	return err == nil
}

func kdialogYesNo(kdialog, text string) bool {
	cmd := exec.Command(kdialog, "--yesno", text, "--title", "DenyOut")
	return cmd.Run() == nil
}

func osascriptYesNo(text string, defYes bool) bool {
	def := "Yes"
	if !defYes {
		def = "No"
	}
	script := fmt.Sprintf(`display dialog %q buttons {"No","Yes"} default button %q with title "DenyOut"`, text, def)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		return defYes
	}
	return strings.Contains(string(out), "Yes")
}

func windowsYesNo(title, text string, defYes bool) bool {
	// PowerShell MessageBox: Yes=6
	ps := fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework; $r = [System.Windows.MessageBox]::Show(%q, %q, 'YesNo', 'Question'); if ($r -eq 'Yes') { exit 0 } else { exit 1 }`, text, title)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	err := cmd.Run()
	if err != nil {
		return defYes && err == nil
	}
	return true
}

// nativeAllowDialog asks Allow once / Always / Deny without a browser.
// Returns "" if no native dialog toolkit is available (caller may fall back to notify-send).
func nativeAllowDialog(host string) string {
	text := fmt.Sprintf("%s was blocked (Ask mode).\n\nAllow once, Always, or keep blocked?", host)
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(zenity, "--list", "--radiolist", "--title=DenyOut",
				"--text="+text, "--column=Pick", "--column=Action",
				"TRUE", "Allow once", "FALSE", "Always allow", "FALSE", "Keep blocked",
				"--height=280", "--width=420")
			out, err := cmd.Output()
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
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			cmd := exec.Command(kdialog, "--radiolist", "DenyOut Ask", "once", "Allow once", "on",
				"always", "Always allow", "off", "deny", "Keep blocked", "off")
			out, err := cmd.Output()
			if err != nil {
				return "deny"
			}
			s := strings.TrimSpace(string(out))
			if s == "once" || s == "always" || s == "deny" {
				return s
			}
			return "deny"
		}
		return "" // fall back to notify-send actions
	case "darwin":
		script := fmt.Sprintf(`set r to button returned of (display dialog %q buttons {"Keep blocked","Allow once","Always"} default button "Allow once" with title "DenyOut")
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
$r = [System.Windows.MessageBox]::Show(%q, 'DenyOut', 'YesNoCancel', 'Question')
# Yes=Allow once, No=Always, Cancel=Deny
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
	return ""
}
