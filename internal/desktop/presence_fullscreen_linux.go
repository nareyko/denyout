//go:build linux

package desktop

import (
	"encoding/json"
	"os/exec"
	"strings"
)

// probeFullscreen reports whether the active window looks fullscreen.
// ok=false means unknown — leave the previous notify.Fullscreen flag alone.
func probeFullscreen() (fullscreen bool, ok bool) {
	if fs, ok := probeFullscreenX11(); ok {
		return fs, true
	}
	if fs, ok := probeFullscreenHyprland(); ok {
		return fs, true
	}
	return false, false
}

func probeFullscreenX11() (bool, bool) {
	if _, err := exec.LookPath("xprop"); err != nil {
		return false, false
	}
	root, err := exec.Command("xprop", "-root", "_NET_ACTIVE_WINDOW").CombinedOutput()
	if err != nil {
		return false, false
	}
	// Example: _NET_ACTIVE_WINDOW(WINDOW): window id # 0x3c00007
	fields := strings.Fields(string(root))
	var wid string
	for i := len(fields) - 1; i >= 0; i-- {
		if strings.HasPrefix(fields[i], "0x") || strings.HasPrefix(fields[i], "0X") {
			wid = fields[i]
			break
		}
	}
	if wid == "" || wid == "0x0" || wid == "0x00" {
		return false, true // known: no active window / desktop
	}
	st, err := exec.Command("xprop", "-id", wid, "_NET_WM_STATE").CombinedOutput()
	if err != nil {
		return false, false
	}
	s := string(st)
	if strings.Contains(s, "not found") {
		return false, true
	}
	return strings.Contains(s, "_NET_WM_STATE_FULLSCREEN"), true
}

func probeFullscreenHyprland() (bool, bool) {
	if _, err := exec.LookPath("hyprctl"); err != nil {
		return false, false
	}
	out, err := exec.Command("hyprctl", "activewindow", "-j").CombinedOutput()
	if err != nil || len(out) == 0 {
		return false, false
	}
	var w struct {
		Fullscreen int  `json:"fullscreen"`
		Client     bool `json:"fullscreenClient"`
	}
	if err := json.Unmarshal(out, &w); err != nil {
		// Hyprland may return fullscreen as bool in some versions — soft parse.
		s := strings.ToLower(string(out))
		if strings.Contains(s, `"fullscreen":true`) || strings.Contains(s, `"fullscreen":1`) ||
			strings.Contains(s, `"fullscreen":2`) || strings.Contains(s, `"fullscreen":3`) {
			return true, true
		}
		if strings.Contains(s, `"fullscreen":false`) || strings.Contains(s, `"fullscreen":0`) {
			return false, true
		}
		return false, false
	}
	return w.Fullscreen > 0 || w.Client, true
}
