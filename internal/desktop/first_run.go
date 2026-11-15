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
	// Peek-mode Protect may already be live — unload before claiming Off.
	if err := a.stopProtectionErr(); err != nil {
		return err
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
		blockBullet += "- Stay quiet while away is on: Ask and block dialogs stay off while locked or idle (about 5 minutes). One summary when you return. Everything is in History.\n"
	} else {
		blockBullet += "- Stay quiet while away is off — Ask and block dialogs can still appear while locked or idle. Everything is in History.\n"
	}
	blockBullet += "- Respect fullscreen (Settings → Advanced) separately avoids dialogs while a fullscreen app is in front.\n"
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

// UIOnboardingNotNow finishes setup with protection Off (D8 — no later nudges).
func (a *App) UIOnboardingNotNow() error {
	if err := a.finishSetupNotNow(""); err != nil {
		return fmt.Errorf("Could not turn Protect off before Not now: %w", err)
	}
	a.mu.Lock()
	a.state.NotNowReminded = true
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	a.completeSetupSideEffects()
	a.showYourSetup("off")
	return nil
}

// UIOnboardingAgents finishes setup Off and opens the new-agent flow (D7).
func (a *App) UIOnboardingAgents() error {
	a.mu.Lock()
	a.state.ProtectionOn = false
	a.state.Scope = ScopeOff
	a.state.ComputerEnabled = false
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.AskMode = false
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	a.completeSetupSideEffects()
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
	return nil
}

// UIResetSetup returns the user to first-run mode choice (D20).
func (a *App) UIResetSetup() error {
	// Must fully unload Protect before clearing setup flags — never claim Off while
	// nft/pf / proxyd may still be live (e.g. cancelled ElevateRemove).
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	a.mu.Lock()
	a.state.SetupDone = false
	a.state.YourSetupShown = false
	a.state.PendingYourSetup = ""
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.state.Scope = ScopeOff
	a.state.Autostart = false
	a.state.AutostartAsked = false
	a.state.ProtectPausedUntil = ""
	a.state.ProtectPauseLast = ""
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	_ = UnregisterAutostart()
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("home")
	}
	return nil
}

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
			body = "Start DenyOut automatically when you log in?\n\nRecommended so Protect computer stays on after reboot."
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

// maybeMigrateUXv2 offers Safe desktop switch for old Agents-only defaults.
func (a *App) maybeMigrateUXv2() {
	a.mu.Lock()
	need := a.state.NeedsUXv2Migration()
	a.mu.Unlock()
	if !need {
		return
	}
	// Wails owns the prompt (snapshot needs_uxv2_migration + UIMigrateUXv2).
	// Do not silent-switch without zenity or steal focus with a native dialog.
	if a.opts.OpenUI != nil {
		return
	}
	switchToSafe := true
	if dialogToolkitAvailable() {
		switchToSafe = nativeConfirm(
			"DenyOut update",
			"Earlier DenyOut versions defaulted to Agents only on the whole computer (messengers and many sites can break).\n\n"+
				"Switch to Safe desktop? (Recommended - web works. Agents use wrap profiles.)\n\n"+
				"Choose Keep Agents only only if you still want whole-PC allowlist mode.",
			"Switch to Safe desktop",
			"Keep Agents only",
		)
	}
	_ = a.applyUXv2Migration(switchToSafe)
}

// UIMigrateUXv2 finishes the Wails/legacy Agents→Protect prompt.
func (a *App) UIMigrateUXv2(switchToSafe bool) error {
	a.mu.Lock()
	need := a.state.NeedsUXv2Migration()
	a.mu.Unlock()
	if !need {
		return nil
	}
	return a.applyUXv2Migration(switchToSafe)
}

func (a *App) applyUXv2Migration(switchToSafe bool) error {
	a.mu.Lock()
	prevMigrated := a.state.UXv2Migrated
	prevProfile := a.state.PolicyProfile
	prevAsk := a.state.AskMode
	a.state.UXv2Migrated = true
	if switchToSafe {
		a.state.PolicyProfile = PolicyProfileBrowse
		a.state.AskMode = false
	}
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if switchToSafe {
		if wasOn {
			if err := a.restartActiveProtector(); err != nil {
				a.mu.Lock()
				a.state.UXv2Migrated = prevMigrated
				a.state.PolicyProfile = prevProfile
				a.state.AskMode = prevAsk
				stFail := a.state
				a.mu.Unlock()
				_ = SaveState(stFail)
				return err
			}
		}
		notify.Info("DenyOut", "Switched to Protect computer. Use My agents for AI tools.")
		return nil
	}
	notify.Info("DenyOut", "Keeping Agents only on the whole computer.")
	return nil
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
