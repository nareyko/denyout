package desktop

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// runFirstRunWizard shows Protect computer / Protect AI agents / Not now.
// Headless / no dialog toolkit -> mark setup done Off (CLI path).
func (a *App) runFirstRunWizard() {
	if runtime.GOOS == "linux" && !dialogToolkitAvailable() {
		_ = a.finishSetupNotNow("Install zenity (or kdialog) for the desktop setup dialog, or use: denyout profile create")
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
		a.maybeAskAutostart("protect")
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
		a.maybeAskAutostart("agents")
		a.showYourSetup("agents")
		go func() {
			// Wails already opens New agent from the frontend — do not re-emit
			// profiles-new (that resets the form while the user is typing).
			if a.opts.SkipNativeYourSetup {
				return
			}
			if a.opts.OpenUI != nil {
				a.RequestOpenUI("profiles-new")
				return
			}
			a.wizardNewAgent(true)
		}()
	default: // not now / cancel
		_ = a.finishSetupNotNow("")
		a.maybeAskAutostart("off")
		a.showYourSetup("off")
	}
}

func (a *App) finishSetupNotNow(extra string) error {
	// Peek-mode Protect may already be live — best-effort unload before claiming Off.
	// If admin Remove fails (cancelled pkexec / no helper), still clear leave-on so
	// Not now cannot trap the user in Needs attention.
	if err := a.stopProtectionErr(); err != nil {
		AppendDesktopLog("WARN setup Not now unload: %v (clearing Off intent anyway)", err)
	}
	a.mu.Lock()
	a.state.SetupDone = true
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	// Keep chatty choice if set; otherwise Quiet (new default).
	if strings.TrimSpace(a.state.NotifyLevel) == "" {
		a.state.NotifyLevel = "quiet"
	}
	a.state.Notify = a.state.NotifyLevel != "quiet"
	a.state.UXv2Migrated = true
	// Explicit Off: clear leave-on intent so Home/Problems do not stay on Needs attention.
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.state.Scope = ScopeOff
	a.state.ProtectPausedUntil = ""
	a.state.ProtectPauseLast = ""
	a.state.NotNowAt = time.Now().UTC().Format(time.RFC3339)
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	applyNotifyPrefs(st)
	msg := "You can turn protection on anytime from the DenyOut tray."
	if extra != "" {
		msg = extra + "\n" + msg
	}
	notify.Info("DenyOut", msg)
	return nil
}

// ensureSetupDoneAfterProtect finishes first-run when Protect was turned on during peek
// (Settings/Problems/Home before the mode modal completed).
func (a *App) ensureSetupDoneAfterProtect(mode string) {
	a.mu.Lock()
	need := !a.state.SetupDone
	a.mu.Unlock()
	if !need {
		return
	}
	a.completeSetupSideEffects()
	a.showYourSetup(mode)
}

// showYourSetup explains current mode once after first-run / install.
func (a *App) showYourSetup(mode string) {
	a.mu.Lock()
	if a.state.YourSetupShown {
		a.mu.Unlock()
		return
	}
	autostartOn := a.state.Autostart
	quietAway := !a.state.QuietWhileAwayOff
	text := YourSetupText(mode, autostartOn, false, quietAway)
	if a.opts.SkipNativeYourSetup {
		// Wails shows Your setup when setup_done && !your_setup_shown.
		// Do not mark shown here — MarkYourSetupShown runs on dismiss.
		// Persist mode so snapshot copy is Agents/Off/Safe, not live uiMode.
		a.state.PendingYourSetup = mode
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		// Agents path already opens profiles-new; do not steal focus to Home.
		if a.opts.OpenUI != nil && mode != "agents" {
			a.RequestOpenUI("home")
		}
		return
	}
	a.state.YourSetupShown = true
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

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
// autostart must reflect the real login-launch preference after RegisterAutostart.
// unhealthy: Protect intent is broken — never claim "You are protected."
// quietWhileAway: Stay quiet while away preference (default on).
func YourSetupText(mode string, autostart bool, unhealthy bool, quietWhileAway bool) string {
	var status string
	if unhealthy {
		switch mode {
		case "agents", "agents_only":
			status = "Agents only needs your attention.\nOpen Problems to fix it, then come back to Home."
		case "session":
			status = "Session protection needs your attention.\nOpen Problems to fix it, then come back to Home."
		default:
			status = "Protect needs your attention.\nOpen Problems to fix it, then come back to Home."
		}
	} else {
		switch mode {
		case "safe":
			status = "You are protected.\nBrowse as usual - we'll only interrupt for clear risks."
		case "agents_only":
			status = "Agents only is on for the whole computer.\nEveryday browsing is not protected like Protect computer — switch from Home or Settings when you want that."
		case "session":
			status = "Session protection is on.\nThis is a limited session proxy — switch to Protect computer from Home for everyday browsing."
		case "agents":
			status = "Protect computer is off for now.\nUse My agents for AI tools, or turn on Protect computer from Home or the tray."
		default:
			status = "Protection is off.\nTurn on Protect computer from Home or the tray when you are ready."
		}
	}
	homeBullet := "- Open DenyOut (Home) to see if you are protected and what was blocked.\n"
	switch mode {
	case "agents_only":
		homeBullet = "- Open DenyOut (Home) to see Agents only status and what was blocked.\n"
	case "session":
		homeBullet = "- Open DenyOut (Home) to see Session status and what was blocked.\n"
	case "agents", "off":
		homeBullet = "- Open DenyOut (Home) for mode status and what was blocked.\n"
	}
	blockBullet := "- When something is blocked while you are here: Keep blocked or Allow this site.\n"
	if quietWhileAway {
		blockBullet += "- Stay quiet while away is on: Ask and block dialogs stay off while locked or idle (about 5 minutes); soft OS banners stay off while away (Protect failed and tray-hidden on window close can still show). One summary when you return. Everything is in History.\n"
	} else {
		blockBullet += "- Stay quiet while away is off — Ask/block dialogs can still appear while locked or idle (about 5 minutes). Soft OS banners still follow How chatty / System banners (Quiet keeps them off except Protect failed and the tray-hidden hint). Everything is in History.\n"
	}
	blockBullet += "- Respect fullscreen (Settings → Advanced) separately avoids Ask/block dialogs and soft OS banners while a fullscreen app is in front (Protect failed and tray-hidden on window close can still show).\n"
	body := status + "\n\n" +
		blockBullet +
		homeBullet +
		"- If Protect or Agents only failed, open Problems.\n\n"
	if autostart {
		body += "DenyOut will open when you log in. You can turn that off in Settings.\n\n"
	} else {
		body += "Login launch is off. You can turn it on in Settings → Autostart.\n\n"
	}
	return body + "Privacy: decisions stay on this computer."
}

// completeSetupSideEffects marks first-run finished.
// Native tray: D9=C enables login autostart. Wails: leave Off until Settings (in-app consent).
func (a *App) completeSetupSideEffects() {
	wails := a.opts.SkipNativeYourSetup
	a.mu.Lock()
	a.state.SetupDone = true
	a.state.AutostartAsked = true
	a.state.UXv2Migrated = true
	if wails {
		a.state.Autostart = false
	} else {
		a.state.Autostart = true
	}
	// Preserve onboarding chatty choice; empty → Quiet (Presence wave).
	if strings.TrimSpace(a.state.NotifyLevel) == "" {
		a.state.NotifyLevel = "quiet"
	}
	a.state.Notify = a.state.NotifyLevel != "quiet"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	applyNotifyPrefs(st)
	if wails {
		_ = UnregisterAutostart() // clear any leftover login entry
		return
	}
	if err := RegisterAutostart(); err != nil {
		AppendDesktopLog("WARN autostart after setup: %v", err)
		a.mu.Lock()
		a.state.Autostart = false
		stFail := a.state
		a.mu.Unlock()
		_ = SaveState(stFail)
	}
}

// ProtectConfirmText is the DenyOut confirm before Off→On (D5/D12).
func ProtectConfirmText(helperOK bool) (title, body string) {
	title = "Turn on Protect computer?"
	if helperOK {
		body = "DenyOut will set system network rules.\n\n" +
			"Your system should not ask for a password (helper already installed).\n\n" +
			"Continue?"
		return title, body
	}
	body = "Your system will ask for a password so DenyOut can set network rules " +
		"and a local certificate.\n\n" +
		"If install succeeds, DenyOut can restore protection after restart without asking again " +
		"on platforms that support the helper. Until then, each turn-on may ask for a password.\n\n" +
		"Continue?"
	return title, body
}

func nativeFirstRunChoice() string {
	title := "DenyOut"
	text := "How should DenyOut protect this computer?\n\n" +
		"- Protect computer - Safe desktop: internet works as usual. Blocks suspicious links. Needs your computer password once.\n" +
		"- Protect AI agents - wrap a program (python, Cursor agent, ...). Rest of PC unchanged. No admin password.\n" +
		"- Not now - leave off. Open the tray later."
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

// enableSafeDesktop turns on Computer + Safe desktop (browse, no host Ask).
func (a *App) enableSafeDesktop() error {
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	needSetup := !a.state.SetupDone
	hadSession := a.session != nil
	hadProxyd := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	var err error
	if hadSession {
		// Do not restartActiveProtector — that would keep ScopeSession.
		err = a.switchToSafeDesktopFromTray()
	} else if hadProxyd {
		// Profile flip (e.g. Agents only → Protect) must restart proxyd so
		// DENYOUT_POLICY_PROFILE matches the snapshot.
		err = a.restartActiveProtector()
	} else {
		err = a.enableComputerFromTray()
	}
	if err != nil {
		// D6: first-run password cancel keeps setup pending (mode modal again).
		// Also drop leave-on so Needs attention does not trap behind the setup modal.
		if needSetup {
			a.mu.Lock()
			a.state.SetupDone = false
			a.state.ProtectionOn = false
			a.state.ComputerEnabled = false
			if a.proxyd == nil && a.session == nil {
				a.state.Scope = ScopeOff
			}
			stFail := a.state
			a.mu.Unlock()
			_ = SaveState(stFail)
		}
		return err
	}
	if needSetup {
		LogEvent("setup_choice", map[string]any{"choice": "protect"})
		a.completeSetupSideEffects()
		a.showYourSetup("safe")
	}
	return nil
}

func (a *App) switchToSafeDesktopFromTray() error {
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	a.state.ActiveProfileID = ""
	hadSession := a.session != nil
	hadProxyd := a.proxyd != nil
	a.mu.Unlock()
	// Session → Protect must not restartActiveProtector (that keeps ScopeSession).
	var err error
	if hadSession {
		a.stopSession()
		a.mu.Lock()
		a.state.Scope = ScopeComputer
		a.state.PolicyProfile = PolicyProfileBrowse
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		err = a.enableComputerFromTray()
	} else {
		a.mu.Lock()
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		if hadProxyd {
			err = a.restartActiveProtector()
		} else {
			err = a.enableComputerFromTray()
		}
	}
	if err != nil {
		return err
	}
	a.ensureSetupDoneAfterProtect("safe")
	return nil
}
