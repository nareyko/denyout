//go:build linux

package desktop

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
)

// probeFullscreen reports whether the active window looks fullscreen.
// ok=false means unknown — caller must not pretend fullscreen quiet is active.
//
// Order: X11 → GNOME Shell Eval → GNOME Introspect → Hyprland → Sway.
// On locked-down GNOME Wayland, Eval/Introspect are often denied; ok stays false
// and Settings must say detection is unavailable (Stay quiet while away still works).
func probeFullscreen() (fullscreen bool, ok bool) {
	if fs, ok := probeFullscreenX11(); ok {
		return fs, true
	}
	if fs, ok := probeFullscreenGnomeEval(); ok {
		return fs, true
	}
	if fs, ok := probeFullscreenGnomeIntrospect(); ok {
		return fs, true
	}
	if fs, ok := probeFullscreenHyprland(); ok {
		return fs, true
	}
	if fs, ok := probeFullscreenSway(); ok {
		return fs, true
	}
	return false, false
}

func probeFullscreenX11() (bool, bool) {
	if _, err := exec.LookPath("xprop"); err != nil {
		return false, false
	}
	// On pure Wayland, xprop often only sees XWayland clients — still useful when it works.
	root, err := exec.Command("xprop", "-root", "_NET_ACTIVE_WINDOW").CombinedOutput()
	if err != nil {
		return false, false
	}
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

var gnomeEvalRe = regexp.MustCompile(`^\(\s*(true|false)\s*,\s*'([^']*)'\s*\)`)

func probeFullscreenGnomeEval() (bool, bool) {
	if _, err := exec.LookPath("gdbus"); err != nil {
		return false, false
	}
	// Requires unsafe Shell Eval (often disabled). When allowed, works on Mutter Wayland.
	script := `Boolean(global.display.focus_window && global.display.focus_window.is_fullscreen())`
	out, err := exec.Command("gdbus", "call", "--session",
		"--dest", "org.gnome.Shell",
		"--object-path", "/org/gnome/Shell",
		"--method", "org.gnome.Shell.Eval",
		script,
	).CombinedOutput()
	if err != nil {
		return false, false
	}
	return parseGnomeShellEval(string(out))
}

// parseGnomeShellEval parses gdbus Eval output: (true, 'true'|'false') or (false, ”) when denied.
func parseGnomeShellEval(out string) (fullscreen bool, ok bool) {
	s := strings.TrimSpace(out)
	m := gnomeEvalRe.FindStringSubmatch(s)
	if m == nil {
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "(false") {
			return false, false
		}
		if strings.Contains(low, "'true'") {
			return true, true
		}
		if strings.Contains(low, "'false'") {
			return false, true
		}
		return false, false
	}
	if !strings.EqualFold(m[1], "true") {
		return false, false // Eval disabled / error
	}
	switch strings.ToLower(strings.TrimSpace(m[2])) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func probeFullscreenGnomeIntrospect() (bool, bool) {
	if _, err := exec.LookPath("gdbus"); err != nil {
		return false, false
	}
	out, err := exec.Command("gdbus", "call", "--session",
		"--dest", "org.gnome.Shell.Introspect",
		"--object-path", "/org/gnome/Shell/Introspect",
		"--method", "org.gnome.Shell.Introspect.GetWindows",
	).CombinedOutput()
	if err != nil {
		// AccessDenied on stock GNOME — unknown, not "not fullscreen".
		return false, false
	}
	return parseGnomeIntrospectWindows(string(out))
}

// parseGnomeIntrospectWindows finds a focused window and reads fullscreen-ish keys.
func parseGnomeIntrospectWindows(out string) (fullscreen bool, ok bool) {
	low := strings.ToLower(out)
	if strings.Contains(low, "accessdenied") || strings.Contains(low, "not allowed") {
		return false, false
	}
	blocks := splitGdbusDictBlocks(out)
	if len(blocks) == 0 {
		if strings.Contains(out, "a{ta{sv}}") {
			return false, true
		}
		if focusedHint(low) {
			return fullscreenHint(low), true
		}
		return false, false
	}
	for _, b := range blocks {
		bl := strings.ToLower(b)
		if !focusedHint(bl) {
			continue
		}
		return fullscreenHint(bl), true
	}
	return false, true
}

func splitGdbusDictBlocks(out string) []string {
	parts := strings.Split(out, "uint64")
	if len(parts) <= 1 {
		parts = strings.Split(out, "}, {")
	}
	var blocks []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		blocks = append(blocks, p)
	}
	return blocks
}

func focusedHint(low string) bool {
	return strings.Contains(low, `'has-focus': <true>`) ||
		strings.Contains(low, `"has-focus": <true>`) ||
		strings.Contains(low, `'has-focus': true`) ||
		strings.Contains(low, `'focus': <true>`) ||
		strings.Contains(low, `'is-focused': <true>`) ||
		strings.Contains(low, "has-focus': <true>")
}

func fullscreenHint(low string) bool {
	return strings.Contains(low, `'is-fullscreen': <true>`) ||
		strings.Contains(low, `'fullscreen': <true>`) ||
		strings.Contains(low, `"is-fullscreen": <true>`) ||
		strings.Contains(low, `'is-fullscreen': true`) ||
		strings.Contains(low, `'fullscreen': true`)
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

func probeFullscreenSway() (bool, bool) {
	if _, err := exec.LookPath("swaymsg"); err != nil {
		return false, false
	}
	out, err := exec.Command("swaymsg", "-t", "get_tree").CombinedOutput()
	if err != nil || len(out) == 0 {
		return false, false
	}
	return parseSwayTreeFullscreen(out)
}

func parseSwayTreeFullscreen(out []byte) (bool, bool) {
	var root swayNode
	if err := json.Unmarshal(out, &root); err != nil {
		return false, false
	}
	fs, found := findSwayFocusedFullscreen(&root)
	if !found {
		return false, true
	}
	return fs, true
}

type swayNode struct {
	Focused        bool       `json:"focused"`
	FullscreenMode int        `json:"fullscreen_mode"`
	Nodes          []swayNode `json:"nodes"`
	FloatingNodes  []swayNode `json:"floating_nodes"`
}

func findSwayFocusedFullscreen(n *swayNode) (fullscreen bool, found bool) {
	if n == nil {
		return false, false
	}
	if n.Focused {
		return n.FullscreenMode != 0, true
	}
	for i := range n.Nodes {
		if fs, ok := findSwayFocusedFullscreen(&n.Nodes[i]); ok {
			return fs, true
		}
	}
	for i := range n.FloatingNodes {
		if fs, ok := findSwayFocusedFullscreen(&n.FloatingNodes[i]); ok {
			return fs, true
		}
	}
	return false, false
}
