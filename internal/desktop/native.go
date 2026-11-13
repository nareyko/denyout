package desktop

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

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
