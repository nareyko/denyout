package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// runFirstRunWizard shows Protect computer / Protect AI agents / Not now.
// Headless / no dialog toolkit -> mark setup done Off (CLI path).
func (a *App) runFirstRunWizard() {
	if runtime.GOOS == "linux" && !dialogToolkitAvailable() {
		a.finishSetupNotNow("Install zenity (or kdialog) for the desktop setup dialog, or use: denyout profile create")
		return
	}
	choice := nativeFirstRunChoice()
	switch choice {
	case "computer":
		a.mu.Lock()
		a.state.SetupDone = true
		a.state.PolicyProfile = PolicyProfileBrowse
		a.state.AskMode = false
		a.state.Notify = true
		a.state.UXv2Migrated = true
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		a.maybeAskAutostart()
		if err := a.enableSafeDesktop(); err != nil {
			notify.Emit(notify.KindProtectFailed, "DenyOut", "Could not turn on Protect computer (admin may be required). You can retry from the tray.")
			a.showYourSetup("off")
		} else {
			a.showYourSetup("safe")
		}
	case "agents":
		a.mu.Lock()
		a.state.SetupDone = true
		a.state.PolicyProfile = PolicyProfileBrowse
		a.state.AskMode = false
		a.state.Notify = true
		a.state.UXv2Migrated = true
		a.state.ProtectionOn = false
		a.state.Scope = ScopeOff
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		a.maybeAskAutostart()
		a.showYourSetup("agents")
		go func() {
			if a.opts.OpenUI != nil {
				a.RequestOpenUI("profiles-new")
				return
			}
			a.wizardNewAgent(true)
		}()
	default: // not now / cancel
		a.finishSetupNotNow("")
		a.maybeAskAutostart()
		a.showYourSetup("off")
	}
}

func (a *App) finishSetupNotNow(extra string) {
	a.mu.Lock()
	a.state.SetupDone = true
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	a.state.Notify = true
	a.state.UXv2Migrated = true
	a.state.ProtectionOn = false
	a.state.Scope = ScopeOff
	a.state.NotNowAt = time.Now().UTC().Format(time.RFC3339)
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	msg := "You can turn protection on anytime from the DenyOut tray."
	if extra != "" {
		msg = extra + "\n" + msg
	}
	notify.Info("DenyOut", msg)
}

// showYourSetup explains current mode once after first-run / install.
func (a *App) showYourSetup(mode string) {
	a.mu.Lock()
	if a.state.YourSetupShown {
		a.mu.Unlock()
		return
	}
	a.state.YourSetupShown = true
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	text := YourSetupText(mode)
	if dialogToolkitAvailable() {
		// Q2: offer Open DenyOut once (primary); Got it dismisses without opening.
		if nativeConfirm("DenyOut - Your setup", text, "Open DenyOut", "Got it") {
			a.RequestOpenUI("home")
		}
		return
	}
	notify.Info("DenyOut - Your setup", text)
}

// YourSetupText is shared EN copy for native + Wails Your setup (Q6).
func YourSetupText(mode string) string {
	var status string
	switch mode {
	case "safe":
		status = "You are protected.\nBrowse as usual - we'll only interrupt for clear risks."
	case "agents":
		status = "Protect computer is off for now.\nUse My agents for AI tools, or turn on Protect computer from Home or the tray."
	default:
		status = "Protection is off.\nTurn on Protect computer from Home or the tray when you are ready."
	}
	return status + "\n\n" +
		"- When something is blocked: Keep blocked or Allow this site.\n" +
		"- Open DenyOut (Home) to see if you are protected and what was blocked.\n" +
		"- If Protect failed, open Problems.\n\n" +
		"Privacy: decisions stay on this computer."
}

func nativeFirstRunChoice() string {
	title := "DenyOut"
	text := "How should DenyOut protect this computer?\n\n" +
		"- Protect computer - Safe desktop: internet works as usual; blocks suspicious links.\n" +
		"- Protect AI agents - wrap a program (python, Cursor agent, ...); rest of PC unchanged.\n" +
		"- Not now - leave off; open the tray later."
	switch runtime.GOOS {
	case "linux":
		if zenity, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(zenity, "--question",
				"--title="+title,
				"--text="+text,
				"--ok-label=Protect computer",
				"--cancel-label=Not now",
				"--extra-button=Protect AI agents",
				"--width=520",
			)
			out, err := cmd.CombinedOutput()
			s := strings.TrimSpace(string(out))
			if strings.Contains(s, "Protect AI agents") {
				return "agents"
			}
			if err == nil {
				return "computer"
			}
			return "notnow"
		}
		if kdialog, err := exec.LookPath("kdialog"); err == nil {
			err := exec.Command(kdialog, "--yesnocancel", text,
				"--yes-label", "Protect computer",
				"--no-label", "Protect AI agents",
				"--cancel-label", "Not now",
				"--title", title,
			).Run()
			code := 2
			if err == nil {
				code = 0
			} else if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
			switch code {
			case 0:
				return "computer"
			case 1:
				return "agents"
			default:
				return "notnow"
			}
		}
	case "darwin":
		script := fmt.Sprintf(`set r to button returned of (display dialog %q buttons {"Not now","Protect AI agents","Protect computer"} default button "Protect computer" with title %q)
return r`, text, title)
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "notnow"
		}
		s := strings.TrimSpace(string(out))
		switch {
		case strings.Contains(s, "AI agents"):
			return "agents"
		case strings.Contains(s, "computer"):
			return "computer"
		default:
			return "notnow"
		}
	}
	return "notnow"
}

func (a *App) maybeAskAutostart() {
	a.mu.Lock()
	asked := a.state.AutostartAsked
	a.mu.Unlock()
	if asked {
		return
	}
	yes := true
	if dialogToolkitAvailable() {
		yes = nativeConfirm(
			"DenyOut",
			"Start DenyOut automatically when you log in?\n\nRecommended so Protect computer stays on after reboot.",
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

// maybeMigrateUXv2 offers Safe desktop switch for old Agents-only defaults.
func (a *App) maybeMigrateUXv2() {
	a.mu.Lock()
	need := a.state.NeedsUXv2Migration()
	a.mu.Unlock()
	if !need {
		return
	}
	switchToSafe := true
	if dialogToolkitAvailable() {
		switchToSafe = nativeConfirm(
			"DenyOut update",
			"Earlier DenyOut versions defaulted to Agents only on the whole computer (messengers and many sites can break).\n\n"+
				"Switch to Safe desktop? (Recommended - web works; agents use wrap profiles.)\n\n"+
				"Choose Keep Agents only only if you still want whole-PC allowlist mode.",
			"Switch to Safe desktop",
			"Keep Agents only",
		)
	}
	a.mu.Lock()
	a.state.UXv2Migrated = true
	if switchToSafe {
		a.state.PolicyProfile = PolicyProfileBrowse
		a.state.AskMode = false
	}
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	_ = SaveState(st)
	if switchToSafe {
		notify.Info("DenyOut", "Switched to Protect computer. Use My agents for AI tools.")
		if wasOn {
			a.restartActiveProtector()
		}
	} else {
		notify.Info("DenyOut", "Keeping Agents only on the whole computer.")
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

// enableSafeDesktop turns on Computer + Safe desktop (browse, no host Ask).
func (a *App) enableSafeDesktop() error {
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	return a.enableComputerFromTray()
}

func (a *App) switchToSafeDesktopFromTray() {
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	a.state.ActiveProfileID = ""
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	_ = SaveState(st)
	if wasOn {
		a.restartActiveProtector()
	} else {
		_ = a.enableComputerFromTray()
	}
}
