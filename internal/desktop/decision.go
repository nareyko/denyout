package desktop

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Decision actions returned by presenters / native dialogs.
const (
	DecisionKeep       = "keep"
	DecisionAllow      = "allow"
	DecisionLater      = "later"
	DecisionOpen       = "open"
	DecisionKeepTimed  = "keep_timed:"  // suffix duration e.g. keep_timed:1h
	DecisionAllowTimed = "allow_timed:" // suffix duration
)

// DecisionPrompt is one hard-block decision (compact dialog / in-app modal).
type DecisionPrompt struct {
	ID      string
	Host    string
	Reason  string
	Why     string
	URL     string
	Timeout time.Duration
	Taught  bool
}

// DecisionPresenter shows a compact decision UI and returns an action string.
// nil → native zenity/kdialog fallback.
type DecisionPresenter func(p DecisionPrompt) string

var (
	decisionPresMu sync.Mutex
	decisionPres   DecisionPresenter
)

// SetDecisionPresenter registers the in-app (Wails) decision UI. Pass nil to clear.
func SetDecisionPresenter(fn DecisionPresenter) {
	decisionPresMu.Lock()
	decisionPres = fn
	decisionPresMu.Unlock()
}

func getDecisionPresenter() DecisionPresenter {
	decisionPresMu.Lock()
	defer decisionPresMu.Unlock()
	return decisionPres
}

func decisionTimeout(a *App) time.Duration {
	a.mu.Lock()
	sec := a.state.DecisionTimeoutSec
	a.mu.Unlock()
	if sec <= 0 {
		return 15 * time.Second
	}
	return time.Duration(sec) * time.Second
}

func reaskInterval(a *App) time.Duration {
	a.mu.Lock()
	sec := a.state.ReaskIntervalSec
	a.mu.Unlock()
	if sec <= 0 {
		return time.Minute
	}
	return time.Duration(sec) * time.Second
}

var (
	promptThrottleMu sync.Mutex
	promptLastAt     = map[string]time.Time{}
	ignoreCount      = map[string]int{}
)

func shouldThrottlePrompt(key string, every time.Duration) bool {
	promptThrottleMu.Lock()
	defer promptThrottleMu.Unlock()
	last, ok := promptLastAt[key]
	if ok && time.Since(last) < every {
		return true
	}
	promptLastAt[key] = time.Now()
	return false
}

func notePromptIgnore(key string) int {
	promptThrottleMu.Lock()
	defer promptThrottleMu.Unlock()
	ignoreCount[key]++
	return ignoreCount[key]
}

func clearPromptIgnore(key string) {
	promptThrottleMu.Lock()
	delete(ignoreCount, key)
	promptThrottleMu.Unlock()
}

func (a *App) presentHardBlockDecision(p DecisionPrompt) string {
	if p.Timeout <= 0 {
		p.Timeout = decisionTimeout(a)
	}
	if p.ID == "" {
		p.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if fn := getDecisionPresenter(); fn != nil {
		return fn(p)
	}
	return nativeDecisionDialog(p)
}

func decisionBody(p DecisionPrompt) string {
	var b strings.Builder
	b.WriteString(p.Host)
	b.WriteByte('\n')
	b.WriteString(p.Why)
	if p.URL != "" {
		b.WriteByte('\n')
		b.WriteString(p.URL)
	}
	b.WriteString("\n\n")
	if !p.Taught {
		b.WriteString("This is how DenyOut protects you. Choose Keep blocked, Allow this site, or Decide later.\n")
	} else {
		b.WriteString("Keep blocked, Allow this site, or Decide later.\n")
	}
	return b.String()
}

// PresentDecisionNative shows the compact OS decision dialog (exported for Wails fallback).
func PresentDecisionNative(p DecisionPrompt) string {
	return nativeDecisionDialog(p)
}

// nativeDecisionDialog is the compact OS dialog when the main window is not presenting.
func nativeDecisionDialog(p DecisionPrompt) string {
	title := "DenyOut blocked something"
	text := decisionBody(p)
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	done := make(chan string, 1)
	go func() {
		done <- nativeDecisionDialogSync(title, text)
	}()
	select {
	case a := <-done:
		if a == "" {
			return DecisionLater
		}
		return a
	case <-time.After(timeout):
		return DecisionLater
	}
}

func nativeDecisionDialogSync(title, text string) string {
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(zenity, "--list",
				"--title="+title,
				"--text="+text,
				"--column=Choice",
				"--hide-header",
				"--width=480",
				"--height=320",
				"Keep blocked",
				"Keep blocked for 15 minutes",
				"Keep blocked for 1 hour",
				"Allow this site",
				"Allow for 15 minutes",
				"Allow for 1 hour",
				"Decide later",
				"Open DenyOut",
			)
			out, err := cmd.Output()
			if err != nil {
				return DecisionLater
			}
			return mapDecisionLabel(strings.TrimSpace(string(out)))
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			// menu returns selected tag
			cmd := exec.Command(kdialog, "--title", title, "--menu", text,
				"keep", "Keep blocked",
				"keep_15m", "Keep blocked for 15 minutes",
				"keep_1h", "Keep blocked for 1 hour",
				"allow", "Allow this site",
				"allow_15m", "Allow for 15 minutes",
				"allow_1h", "Allow for 1 hour",
				"later", "Decide later",
				"open", "Open DenyOut",
			)
			out, err := cmd.Output()
			if err != nil {
				return DecisionLater
			}
			return mapDecisionTag(strings.TrimSpace(string(out)))
		}
	case "darwin":
		script := fmt.Sprintf(`set r to button returned of (display dialog %q buttons {"Decide later","Allow this site","Keep blocked"} default button "Decide later" with title %q)
return r`, text, title)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return DecisionLater
		}
		return mapDecisionLabel(strings.TrimSpace(string(out)))
	}
	// Last resort: Keep vs Allow (cancel = later)
	if nativeConfirm(title, text+"\n\nAllow this site?", "Allow this site", "Keep blocked") {
		return DecisionAllow
	}
	return DecisionKeep
}

func mapDecisionLabel(s string) string {
	switch s {
	case "Keep blocked":
		return DecisionKeep
	case "Keep blocked for 15 minutes":
		return DecisionKeepTimed + "15m"
	case "Keep blocked for 1 hour":
		return DecisionKeepTimed + "1h"
	case "Allow this site":
		return DecisionAllow
	case "Allow for 15 minutes":
		return DecisionAllowTimed + "15m"
	case "Allow for 1 hour":
		return DecisionAllowTimed + "1h"
	case "Open DenyOut":
		return DecisionOpen
	case "Decide later", "":
		return DecisionLater
	default:
		return mapDecisionTag(s)
	}
}

func mapDecisionTag(s string) string {
	switch s {
	case "keep":
		return DecisionKeep
	case "keep_15m":
		return DecisionKeepTimed + "15m"
	case "keep_1h":
		return DecisionKeepTimed + "1h"
	case "allow":
		return DecisionAllow
	case "allow_15m":
		return DecisionAllowTimed + "15m"
	case "allow_1h":
		return DecisionAllowTimed + "1h"
	case "open":
		return DecisionOpen
	default:
		return DecisionLater
	}
}

func parseTimedSuffix(action, prefix string) (time.Duration, bool) {
	if !strings.HasPrefix(action, prefix) {
		return 0, false
	}
	switch strings.TrimPrefix(action, prefix) {
	case "15m":
		return 15 * time.Minute, true
	case "1h":
		return time.Hour, true
	case "tomorrow":
		// Until local tomorrow 00:00 — approximate 24h for v1.
		return 24 * time.Hour, true
	default:
		return 0, false
	}
}
