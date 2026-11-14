package notify

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
)

var (
	mu sync.Mutex
	enabled = true
	level = "normal" // quiet | normal | detailed
)

// Kind is an OS-toast category. Only whitelisted kinds may reach the desktop.
type Kind string

const (
	KindKeepRepeat Kind = "keep_repeat"
	KindAllowUndo Kind = "allow_undo"
	KindProtectResumed Kind = "protect_resumed"
	KindProtectFailed Kind = "protect_failed"
)

// AllowedKind reports whether kind may emit an OS notification.
func AllowedKind(kind Kind) bool {
	switch kind {
	case KindKeepRepeat, KindAllowUndo, KindProtectResumed, KindProtectFailed:
		return true
	default:
		return false
	}
}

// SetEnabled turns OS notifications on or off (desktop preference).
// When off, maps to Quiet behavior for Emit filtering.
func SetEnabled(on bool) {
	mu.Lock()
	enabled = on
	if !on && level == "normal" {
		level = "quiet"
	}
	if on && level == "quiet" {
		level = "normal"
	}
	mu.Unlock()
}

// SetLevel sets Quiet / Normal / Detailed (case-insensitive).
func SetLevel(s string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quiet":
		level = "quiet"
		enabled = true // dialogs still on; OS filtered
	case "detailed":
		level = "detailed"
		enabled = true
	default:
		level = "normal"
		enabled = true
	}
}

// Level returns the current notification level.
func Level() string {
	mu.Lock()
	defer mu.Unlock()
	return level
}

// Enabled reports whether notifications are on (legacy bool; Quiet still "enabled").
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled && level != "quiet"
}

func levelAllows(kind Kind) bool {
	switch level {
	case "quiet":
		return kind == KindProtectFailed
	default: // normal, detailed
		return AllowedKind(kind)
	}
}

// Emit shows an OS notification only for a whitelisted kind (and when level allows).
func Emit(kind Kind, title, body string) {
	mu.Lock()
	ok := levelAllows(kind)
	mu.Unlock()
	if !ok {
		return
	}
	if title == "" {
		title = "DenyOut"
	}
	if err := beeep.Notify(title, body, ""); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
}

// Action is a button on an actionable OS toast (Linux notify-send).
type Action struct {
	ID string // returned when chosen
	Label string
}

// EmitAction shows a whitelisted toast with optional action buttons.
// On Linux with notify-send, waits up to wait and returns the action id (or "").
// Elsewhere (or on failure) falls back to Emit and returns "".
// onAction is called asynchronously with the chosen id when non-empty.
func EmitAction(kind Kind, title, body string, wait time.Duration, actions []Action, onAction func(id string)) {
	mu.Lock()
	ok := levelAllows(kind)
	mu.Unlock()
	if !ok {
		return
	}
	if title == "" {
		title = "DenyOut"
	}
	if wait <= 0 {
		wait = 10 * time.Second
	}
	if runtime.GOOS == "linux" && len(actions) > 0 {
		if _, err := exec.LookPath("notify-send"); err == nil {
			go func() {
				id := runNotifySendActions(title, body, wait, actions)
				if id != "" && onAction != nil {
					onAction(id)
				}
			}()
			return
		}
	}
	Emit(kind, title, body)
}

func runNotifySendActions(title, body string, wait time.Duration, actions []Action) string {
	args := []string{
		"--app-name=DenyOut",
		"--urgency=normal",
		fmt.Sprintf("--expire-time=%d", int(wait.Milliseconds())),
		"--wait",
	}
	for _, a := range actions {
		args = append(args, "--action="+a.ID+"="+a.Label)
	}
	args = append(args, title, body)
	cmd := exec.Command("notify-send", args...)
	done := make(chan string, 1)
	go func() {
		out, err := cmd.Output()
		if err != nil {
			done <- ""
			return
		}
		done <- strings.TrimSpace(string(out))
	}()
	select {
	case id := <-done:
		return id
	case <-time.After(wait + 2*time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ""
	}
}

// Info is a no-op. Status / teaching / Protect on-off nags must not use OS toasts;
// use Emit with a whitelist kind, or in-app UI only.
func Info(title, body string) {
	_ = title
	_ = body
}

// Deny is a no-op for passive OS banners. Hard-block HITL uses the decision dialog
// (or transitional notify-send actions in postblock until that lands).
func Deny(host string, reasons []string, redactedURL ...string) {
	_ = host
	_ = reasons
	_ = redactedURL
}

// HumanReasons turns stable reason codes into plain-language copy.
func HumanReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "Your agent tried to reach something outside the allowlist."
	}
	var parts []string
	for _, r := range reasons {
		switch r {
		case "host_not_allowed":
			parts = append(parts, "That site is not on your allowed list.")
		case "host_denied":
			parts = append(parts, "This site is on your deny list.")
		case "threat_list":
			parts = append(parts, "This site is on a known phishing or malware list.")
		case "secret_in_url", "secret_in_header", "secret_in_body":
			parts = append(parts, "Blocked a link that looked like it contained a secret.")
		case "canary_detected":
			parts = append(parts, "A canary/test secret was found in the request.")
		case "unsafe_ip":
			parts = append(parts, "The destination looked like a private or metadata address.")
		case "port_not_allowed":
			parts = append(parts, "That network port is not allowed.")
		case "rate_limited":
			parts = append(parts, "Too many requests in a short time.")
		default:
			parts = append(parts, r)
		}
	}
	return strings.Join(parts, " ")
}
