package notify

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gen2brain/beeep"
)

// AskAction is the user's choice from an Ask notification or allow page.
type AskAction string

const (
	AskOnce   AskAction = "once"
	AskAlways AskAction = "always"
	AskDeny   AskAction = "deny"
)

// AskHandler is invoked when the user picks an action (may be nil).
type AskHandler func(host string, action AskAction)

// AskOptions controls Ask UX.
type AskOptions struct {
	Host     string
	OpenURL  string // localhost allow page; opened as primary click target
	OnAction AskHandler
}

// Ask prompts for Allow once / Always / Deny.
// Linux: notify-send actions when available; always opens OpenURL when set.
// Other OS: notification + OpenURL (buttons on the allow page).
func Ask(opts AskOptions) {
	mu.Lock()
	on := enabled
	mu.Unlock()
	if !on {
		return
	}
	host := opts.Host
	if host == "" {
		host = "a website"
	}

	if opts.OpenURL != "" {
		go openURL(opts.OpenURL)
	}

	title := "DenyOut: allow this site?"
	body := fmt.Sprintf("%s was blocked (Ask mode).\nAllow once, Always, or Deny.", host)

	if runtime.GOOS == "linux" {
		if action, ok := askNotifySend(title, body); ok {
			if opts.OnAction != nil {
				opts.OnAction(host, action)
			}
			return
		}
	}

	if err := beeep.Notify(title, body+"\nUse the DenyOut window to choose.", ""); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
}

// AskNotify is the legacy entry used when only a host is known (opens nothing).
func AskNotify(host string) {
	Ask(AskOptions{Host: host})
}

func askNotifySend(title, body string) (AskAction, bool) {
	if _, err := exec.LookPath("notify-send"); err != nil {
		return "", false
	}
	cmd := exec.Command("notify-send",
		"--app-name=DenyOut",
		"--urgency=normal",
		"--expire-time=120000",
		"--wait",
		"--action=once=Allow once",
		"--action=always=Always",
		"--action=deny=Deny",
		title,
		body,
	)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	a := AskAction(strings.TrimSpace(string(out)))
	switch a {
	case AskOnce, AskAlways, AskDeny:
		return a, true
	default:
		return "", false
	}
}

func openURL(u string) {
	time.Sleep(150 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}
