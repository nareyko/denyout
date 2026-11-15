//go:build linux

package desktop

import (
	"os"
	"os/exec"
	"strings"
)

// probeScreenLocked reports locked state when a signal is available.
// ok=false means "unknown — use idle only".
func probeScreenLocked() (locked bool, ok bool) {
	if sid := strings.TrimSpace(os.Getenv("XDG_SESSION_ID")); sid != "" {
		out, err := exec.Command("loginctl", "show-session", sid, "-p", "LockedHint", "--value").CombinedOutput()
		if err == nil {
			v := strings.TrimSpace(strings.ToLower(string(out)))
			if v == "yes" || v == "true" || v == "1" {
				return true, true
			}
			if v == "no" || v == "false" || v == "0" {
				return false, true
			}
		}
	}
	// Fallback: GNOME / freedesktop ScreenSaver GetActive (boolean reply).
	for _, dest := range []string{
		"org.freedesktop.ScreenSaver",
		"org.gnome.ScreenSaver",
	} {
		out, err := exec.Command(
			"dbus-send", "--session", "--print-reply=literal", "--dest="+dest,
			"/org/freedesktop/ScreenSaver", dest+".GetActive",
		).CombinedOutput()
		if err != nil {
			// GNOME path sometimes uses /org/gnome/ScreenSaver
			out, err = exec.Command(
				"dbus-send", "--session", "--print-reply=literal", "--dest="+dest,
				"/org/gnome/ScreenSaver", dest+".GetActive",
			).CombinedOutput()
		}
		if err != nil {
			continue
		}
		s := strings.ToLower(string(out))
		if strings.Contains(s, "true") || strings.Contains(s, "boolean 1") {
			return true, true
		}
		if strings.Contains(s, "false") || strings.Contains(s, "boolean 0") {
			return false, true
		}
	}
	return false, false
}
