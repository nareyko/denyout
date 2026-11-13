package notify

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gen2brain/beeep"
)

var (
	mu      sync.Mutex
	enabled = true
)

// SetEnabled turns OS notifications on or off (desktop preference).
func SetEnabled(on bool) {
	mu.Lock()
	enabled = on
	mu.Unlock()
}

// Enabled reports whether notifications are on.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled
}

// Deny shows a plain-language OS notification for a blocked request.
// host and reasons must already be safe to show (no raw secrets).
func Deny(host string, reasons []string) {
	mu.Lock()
	on := enabled
	mu.Unlock()
	if !on {
		return
	}
	if host == "" {
		host = "a website"
	}
	title := "DenyOut blocked a request"
	body := fmt.Sprintf("Blocked connection to %s.\n%s", host, HumanReasons(reasons))
	if err := beeep.Notify(title, body, ""); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
}

// AskNotify informs the user that a new site was blocked under Ask mode.
// Action buttons are OS-dependent; users can Allow from Settings.
func AskNotify(host string) {
	mu.Lock()
	on := enabled
	mu.Unlock()
	if !on {
		return
	}
	if host == "" {
		host = "a website"
	}
	title := "DenyOut: new site blocked"
	body := fmt.Sprintf("%s is not allowed yet. Open DenyOut Settings to Allow once or Always.", host)
	if err := beeep.Notify(title, body, ""); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
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
		case "secret_in_url":
			parts = append(parts, "The link looked like it contained a secret.")
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
