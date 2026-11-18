//go:build linux

package desktop

import (
	"os"
	"os/exec"
	"strings"
)

// probeCmd runs a probe command and returns combined output (test seam).
var probeCmd = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// parseLockedHint parses `loginctl show-session -p LockedHint --value` output.
func parseLockedHint(out string) (locked, ok bool) {
	switch strings.TrimSpace(strings.ToLower(out)) {
	case "yes", "true", "1":
		return true, true
	case "no", "false", "0":
		return false, true
	}
	return false, false
}

// parseScreenSaverActive parses a dbus-send GetActive reply.
func parseScreenSaverActive(out string) (locked, ok bool) {
	s := strings.ToLower(out)
	if strings.Contains(s, "true") || strings.Contains(s, "boolean 1") {
		return true, true
	}
	if strings.Contains(s, "false") || strings.Contains(s, "boolean 0") {
		return false, true
	}
	return false, false
}

func probeLoginctlLocked() (locked, ok bool) {
	sid := strings.TrimSpace(os.Getenv("XDG_SESSION_ID"))
	if sid == "" {
		return false, false
	}
	out, err := probeCmd("loginctl", "show-session", sid, "-p", "LockedHint", "--value")
	if err != nil {
		return false, false
	}
	return parseLockedHint(string(out))
}

func dbusScreenSaverActive(dest, path string) ([]byte, error) {
	return probeCmd("dbus-send", "--session", "--print-reply=literal", "--dest="+dest,
		path, dest+".GetActive")
}

// probeScreenLocked reports locked state when a signal is available.
// ok=false means "unknown — use idle only".
func probeScreenLocked() (locked bool, ok bool) {
	if l, k := probeLoginctlLocked(); k {
		return l, true
	}
	// Fallback: GNOME / freedesktop ScreenSaver GetActive (boolean reply).
	for _, dest := range []string{
		"org.freedesktop.ScreenSaver",
		"org.gnome.ScreenSaver",
	} {
		out, err := dbusScreenSaverActive(dest, "/org/freedesktop/ScreenSaver")
		if err != nil {
			// GNOME path sometimes uses /org/gnome/ScreenSaver
			out, err = dbusScreenSaverActive(dest, "/org/gnome/ScreenSaver")
		}
		if err != nil {
			continue
		}
		if l, k := parseScreenSaverActive(string(out)); k {
			return l, true
		}
	}
	return false, false
}
