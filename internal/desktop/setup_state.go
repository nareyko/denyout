package desktop

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// reconcileAutostart keeps login-launch files aligned with setup + preference.
func (a *App) reconcileAutostart() {
	a.mu.Lock()
	done := a.state.SetupDone
	want := a.state.Autostart
	a.mu.Unlock()
	reg := AutostartRegistered()
	if !done {
		if !reg {
			return
		}
		AppendDesktopLog("INFO autostart: removing leftover login entry before setup completes")
		_ = UnregisterAutostart()
		a.mu.Lock()
		a.state.Autostart = false
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		return
	}
	// After setup: preference On but missing .desktop (failed register / manual delete).
	if want && !reg {
		AppendDesktopLog("INFO autostart: repairing missing login entry")
		if err := RegisterAutostart(); err != nil {
			AppendDesktopLog("WARN autostart repair: %v", err)
			a.mu.Lock()
			a.state.Autostart = false
			st := a.state
			a.mu.Unlock()
			_ = SaveState(st)
		}
		return
	}
	if !want && reg {
		AppendDesktopLog("INFO autostart: removing login entry (preference Off)")
		_ = UnregisterAutostart()
	}
}

// normalizePersistedState fixes disk prefs that fight Safe-desktop UX.
func (a *App) normalizePersistedState() {
	a.mu.Lock()
	changed := false
	// Only auto-ack UX v2 for non–Agents-only installs. Whole-PC Agents users keep
	// NeedsUXv2Migration so the in-app modal can offer Switch to Protect computer.
	if a.state.SetupDone && !a.state.UXv2Migrated &&
		normalizePolicyProfile(a.state.PolicyProfile) != PolicyProfileAgent {
		a.state.UXv2Migrated = true
		changed = true
	}
	if a.state.SetupDone && !a.state.AutostartAsked {
		a.state.AutostartAsked = true
		changed = true
	}
	if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse && a.state.AskMode {
		a.state.AskMode = false
		changed = true
	}
	if strings.TrimSpace(a.state.NotifyLevel) == "" {
		if a.state.Notify {
			a.state.NotifyLevel = "normal"
		} else {
			a.state.NotifyLevel = "quiet"
		}
		changed = true
	} else {
		// Keep Notify bool aligned with level.
		want := a.state.NotifyLevel != "quiet"
		if a.state.Notify != want {
			a.state.Notify = want
			changed = true
		}
	}
	st := a.state
	a.mu.Unlock()
	if changed {
		_ = SaveState(st)
	}
	applyNotifyPrefs(st)
}

// maybeAskAutostart offers login launch once. kind: protect | agents | off.
func (a *App) maybeAskAutostart(kind string) {
	a.mu.Lock()
	asked := a.state.AutostartAsked
	a.mu.Unlock()
	if asked {
		return
	}
	yes := true
	if dialogToolkitAvailable() {
		body := "Start DenyOut automatically when you log in?\n\nRecommended so DenyOut is ready after reboot."
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "protect", "safe", "computer":
			body = "Start DenyOut automatically when you log in?\n\nRecommended so DenyOut can restore Protect after reboot when it was left on (Quit turns Protect off)."
		case "agents":
			body = "Start DenyOut automatically when you log in?\n\nRecommended so DenyOut is ready for My agents after reboot. Everyday browsing stays unprotected until you turn on Protect computer."
		}
		yes = nativeConfirm(
			"DenyOut",
			body,
			"Yes, start at login",
			"Not now",
		)
	}
	a.mu.Lock()
	a.state.AutostartAsked = true
	a.state.Autostart = yes
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if yes {
		if err := RegisterAutostart(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: autostart: %v\n", err)
		}
	}
}

// maybePromptCrashLeftovers asks after unexpected quit with recorded wrap PIDs.
func (a *App) maybePromptCrashLeftovers() {
	a.mu.Lock()
	pids := append([]int(nil), a.state.WrapPIDs...)
	a.mu.Unlock()
	alive := livingPIDs(pids)
	if len(alive) == 0 {
		if len(pids) > 0 {
			a.mu.Lock()
			a.state.WrapPIDs = nil
			st := a.state
			a.mu.Unlock()
			_ = SaveState(st)
		}
		return
	}
	stop := nativeConfirm(
		"DenyOut",
		"DenyOut closed unexpectedly. Some wrapped agents may still be running without protection.\n\nStop leftover processes?",
		"Stop leftovers",
		"Ignore",
	)
	if stop {
		for _, pid := range alive {
			proc, err := os.FindProcess(pid)
			if err == nil && proc != nil {
				_ = proc.Kill()
			}
		}
		notify.Info("DenyOut", "Stopped leftover agent processes.")
	}
	a.mu.Lock()
	a.state.WrapPIDs = nil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
}

func livingPIDs(pids []int) []int {
	var out []int
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if runtime.GOOS != "windows" {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
				out = append(out, pid)
				continue
			}
		}
		proc, err := os.FindProcess(pid)
		if err != nil || proc == nil {
			continue
		}
		if err := proc.Signal(syscall.Signal(0)); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// maybeNotNowNudge sends one soft remind after Not now.
func (a *App) maybeNotNowNudge() {
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if st.NotNowReminded || st.NotNowAt == "" || st.ProtectionOn {
		return
	}
	t, err := time.Parse(time.RFC3339, st.NotNowAt)
	if err != nil {
		return
	}
	if time.Since(t) < 36*time.Hour {
		return
	}
	// Intentional Off after Not now: no OS nag (Home/tray stay truthful).
	a.mu.Lock()
	a.state.NotNowReminded = true
	st2 := a.state
	a.mu.Unlock()
	_ = SaveState(st2)
}
