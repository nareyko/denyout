package desktop

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
)

func (a *App) startComputer() error {
	a.mu.Lock()
	if a.session != nil || a.proxyd != nil {
		// Idempotent: restore/retry while already running is OK (not a failure).
		a.mu.Unlock()
		return nil
	}
	// Browse (Protect computer) never uses whole-PC host Ask.
	ask := a.state.AskMode && normalizePolicyProfile(a.state.PolicyProfile) != PolicyProfileBrowse
	wizard := a.wizardURL
	control := a.controlURL
	a.status = "Starting..."
	a.mu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		a.setStatus("Error")
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	caDir := CADir()
	if _, err := proxy.LoadOrCreatePersistentCA(caDir); err != nil {
		a.setStatus("Error")
		return err
	}
	caPath := caDir + "/ca.crt"

	uid, _ := hostguard.CurrentUID()
	a.mu.Lock()
	allowQUIC := a.state.AllowBrowserQUIC
	a.mu.Unlock()
	if err := hostguard.ElevateApply(port, caPath, uid, allowQUIC); err != nil {
		a.setStatus("Needs admin")
		// Test/CI elevate skip is not a user password cancel — do not sticky Off (unavailable).
		if !hostguard.IsElevateDisabled(err) {
			a.mu.Lock()
			a.state.ComputerAvailable = false
			st := a.state
			a.mu.Unlock()
			_ = SaveState(st)
			RecordError("hostguard.ElevateApply", err.Error())
		} else {
			AppendDesktopLog("INFO ElevateApply skipped (test/CI): %v", err)
			LogEvent("elevate_skipped", map[string]any{"reason": "test_ci", "err": err.Error()})
		}
		return err
	}
	// Chrome/Electron use NSS, not only the system trust store.
	if err := hostguard.TrustCAForUserBrowsers(caPath); err != nil {
		AppendDesktopLog("WARN browser CA trust (NSS): %v - Chrome may show SSL errors", err)
	} else {
		AppendDesktopLog("INFO browser CA trusted in user NSS DB")
	}

	self, err := hostguard.SelfExe()
	if err != nil {
		_ = hostguard.ElevateRemove(port, uid)
		a.setStatus("Error")
		return err
	}
	args := []string{
		"hostctl", "proxyd",
		"--port", strconv.Itoa(port),
		"--ca-dir", caDir,
	}
	if ask {
		args = append(args, "--ask")
	}
	if control != "" {
		args = append(args, "--control-url", control)
	}
	if wizard != "" {
		args = append(args, "--allow-base", strings.TrimRight(wizard, "/"))
	}
	cmd := exec.Command(self, args...)
	// Detached process group: hostguard/proxyd lifecycle is owned by ElevateRemove on Quit unload.
	cmd.Stdout = nil
	cmd.Stderr = nil
	detachCmd(cmd)
	env := os.Environ()
	a.mu.Lock()
	allows := liveAllowHostsLocked(a.state)
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	if len(allows) > 0 {
		env = append(env, "DENYOUT_ALWAYS_ALLOW="+strings.Join(allows, ","))
	}
	env = append(env, "DENYOUT_POLICY_PROFILE="+profile)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		_ = hostguard.ElevateRemove(port, uid)
		a.setStatus("Error")
		return err
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.mu.Lock()
	a.proxyd = cmd
	a.proxyPort = port
	a.state.Scope = ScopeComputer
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.ComputerAvailable = true
	a.status = "Computer"
	st := a.state
	a.mu.Unlock()
	// Drop stale Last blocked from old IP-literal policy (Safe browse now allows public IPs).
	if normalizePolicyProfile(profile) == PolicyProfileBrowse && isIPLiteral(st.LastDenyHost) {
		st.LastDenyHost = ""
		st.LastDenyURL = ""
		st.LastDenySummary = ""
		st.LastDenyProcess = ""
		a.mu.Lock()
		a.state.LastDenyHost = ""
		a.state.LastDenyURL = ""
		a.state.LastDenySummary = ""
		a.state.LastDenyProcess = ""
		a.mu.Unlock()
	}
	_ = SaveState(st)
	ClearLastError()

	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		if a.proxyd == cmd {
			a.proxyd = nil
			a.proxyPort = 0
			a.state.ComputerEnabled = false
			// Keep ProtectionOn so restore / Problems "Needs attention" still
			// reflect leave-on intent after an unexpected proxyd exit.
			if a.status == "Computer" {
				a.status = "Needs attention"
			}
			st := a.state
			a.mu.Unlock()
			_ = SaveState(st)
			return
		}
		a.mu.Unlock()
	}()
	return nil
}

// stopComputerOpts stops computer-mode proxyd.
// If elevateRemove is false, only kills proxyd - next ElevateApply replaces nft/pf
// in one admin prompt (avoid Remove+Apply = two passwords).
// When elevateRemove is true and Remove fails (password cancelled), returns error
// and leaves leave-on state intact so Quit can abort (D19).
func (a *App) stopComputerOpts(keepRestore, elevateRemove bool) error {
	a.mu.Lock()
	cmd := a.proxyd
	port := a.proxyPort
	hadProxyd := cmd != nil
	// Remove even if proxyd already exited (rules can linger after crash).
	shouldRemove := elevateRemove && (hadProxyd ||
		(a.state.Scope == ScopeComputer && (a.state.ProtectionOn || a.state.ComputerEnabled)))
	wasProtectionOn := a.state.ProtectionOn
	wasComputerEnabled := a.state.ComputerEnabled
	wasScope := a.state.Scope
	a.proxyd = nil
	if hadProxyd {
		a.proxyPort = 0
	}
	a.state.ComputerEnabled = false
	if !keepRestore && a.state.Scope == ScopeComputer {
		a.state.ProtectionOn = false
	}
	if a.session == nil {
		a.status = "Off"
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = cmd.Process.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	// Only tear down hostguard when leaving computer mode for real.
	// Session mode also stores proxyPort - must not trigger ElevateRemove/pkexec.
	if shouldRemove {
		uid, _ := hostguard.CurrentUID()
		// Snapshot QUIC drops before Remove deletes the nft table (otherwise counters vanish).
		logQuicDropStats("protect_off")
		if err := hostguard.ElevateRemove(port, uid); err != nil {
			// Restore leave-on so we do not pretend Protect is gone (D19).
			a.mu.Lock()
			a.state.ProtectionOn = wasProtectionOn
			a.state.ComputerEnabled = wasComputerEnabled
			a.state.Scope = wasScope
			if wasProtectionOn {
				a.status = "Needs admin"
			}
			st2 := a.state
			a.mu.Unlock()
			_ = SaveState(st2)
			return err
		}
	}
	return nil
}

func (a *App) stopAll() {
	_ = a.stopComputerOpts(true, false) // keep rules; caller may re-Apply once
	a.stopSessionKeep(true)
	a.setStatus("Off")
}

// stopAllKeepRestore stops live protectors but leaves ProtectionOn for next login
// (used on SIGTERM / tray ctx cancel so logout does not prompt for Remove).
func (a *App) stopAllKeepRestore() {
	a.stopAll()
}

func (a *App) stopProtection() {
	_ = a.stopProtectionErr()
}

func (a *App) stopProtectionErr() error {
	if err := a.stopComputerOpts(false, true); err != nil {
		return err
	}
	a.stopSession()
	a.mu.Lock()
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.status = "Off"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogEvent("protect_off", map[string]any{"source": "ui"})
	return nil
}

// quitUnload fully tears down protection and clears leave-on state so the next
// login does not auto-restore. Used by every Quit path (no leave-on).
// Prefer helper; if password is required and the user cancels, return error and
// do not exit — never leave half-running protection with tray gone.
func (a *App) quitUnload() error {
	return a.stopProtectionErr()
}

// trayQuitChoice confirms full unload when quitting the tray.
// Returns "off" or "" (cancel). Keep-protection-on was removed (Quit always unloads).
func (a *App) trayQuitChoice() string {
	wrapsRunning := a.runningWrapCount() > 0
	a.mu.Lock()
	hasProxyd := a.proxyd != nil
	hasSession := a.session != nil
	unhealthy := problemsUnhealthyLocked(a)
	// Inline currentMode (already hold a.mu — do not call currentMode()).
	mode := ModeOff
	if hasProxyd {
		mode = ModeComputer
	} else if hasSession {
		mode = ModeSession
	}
	agentsIntent := normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileAgent
	on := hasProxyd || hasSession || a.state.ProtectionOn || a.state.ComputerEnabled || unhealthy
	a.mu.Unlock()
	if !on && !wrapsRunning {
		return "off" // nothing live — exit
	}
	body := "Quit turns off protection and stops My agents wraps.\n\nCancel keeps DenyOut running."
	primary := "Turn off protection and quit"
	switch {
	case unhealthy && mode == ModeOff:
		if agentsIntent {
			body = "Agents only is not running. Quit clears restore intent.\n\nCancel keeps DenyOut open."
			primary = "Clear intent and quit"
		} else {
			body = "Protect is not running. Quit clears restore intent.\n\nCancel keeps DenyOut open."
			primary = "Clear intent and quit"
		}
	case !on && wrapsRunning:
		body = "Quit stops My agents wraps.\n\nCancel keeps DenyOut running."
		primary = "Stop agents and quit"
	case mode == ModeComputer && agentsIntent:
		body = "Quit turns off Agents only and stops My agents wraps. Everyday browsing was already unprotected.\n\nCancel keeps DenyOut running."
		primary = "Turn off Agents only and quit"
	case hasSession && !hasProxyd:
		body = "Quit turns off Session protection and stops My agents wraps.\n\nCancel keeps DenyOut running."
		primary = "Turn off Session protection and quit"
	}
	if !nativeConfirm("Quit DenyOut?", body, primary, "Cancel") {
		return ""
	}
	return "off"
}

func (a *App) setStatus(s string) {
	a.mu.Lock()
	a.status = s
	a.mu.Unlock()
}

func (a *App) allowHostOnce(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	a.mu.Lock()
	sess := a.session
	on := a.proxyd != nil || sess != nil
	a.mu.Unlock()
	if !on {
		return fmt.Errorf("protection is off")
	}
	if sess != nil {
		sess.AllowHost(host, "user_once")
		LogBlock("allow_once", map[string]any{"host": host, "scope": "session", "source": "ui"})
		return nil
	}
	// proxyd has no ephemeral AllowOnce IPC — use a 1h timed allow (not permanent Always).
	a.addTimedAllow(host, time.Hour)
	LogBlock("allow_once", map[string]any{"host": host, "scope": "timed_1h", "source": "ui"})
	return nil
}

func (a *App) allowHostAlways(host string) error {
	// persistAlwaysHost also restarts proxyd / updates session when protection is on.
	return a.persistAlwaysHostFrom(host, "ui")
}

func (a *App) enableComputerFromTray() error {
	if a.currentMode() == ModeComputer {
		// Already live: "Try again" must restart when unhealthy (CA missing, status error),
		// not silently succeed while chrome stays Needs attention.
		a.mu.Lock()
		unhealthy := problemsUnhealthyLocked(a)
		a.mu.Unlock()
		if unhealthy {
			return a.restartActiveProtector()
		}
		a.clearProtectPause()
		return nil
	}
	a.stopSession()
	a.mu.Lock()
	a.state.ComputerAvailable = true // user explicitly retries
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if err := a.startComputer(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		a.setStatus("Needs admin")
		a.mu.Lock()
		if !hostguard.IsElevateDisabled(err) {
			a.state.ComputerAvailable = false
		}
		a.state.ProtectionOn = false
		a.state.Scope = ScopeOff
		stFail := a.state
		a.mu.Unlock()
		_ = SaveState(stFail)
		if !hostguard.IsElevateDisabled(err) {
			notify.Emit(notify.KindProtectFailed, "DenyOut", "A password window should have appeared. If you cancelled it, protection stayed Off. Open DenyOut -> Problems, or try Protect computer again.")
		}
		return err
	}
	a.clearProtectPause()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	AppendDesktopLog("INFO computer mode on profile=%s", profile)
	LogEvent("protect_on", map[string]any{"source": "enable", "profile": profile})
	if !certutilAvailable() {
		AppendDesktopLog("INFO hint: install libnss3-tools (certutil) for Chrome/Chromium trust")
	}
	if !clipboardAvailable() {
		AppendDesktopLog("INFO hint: install wl-clipboard for Copy last error")
	}
	// Success: Home/tray status only - no OS "You're protected" toast (notifications whitelist).
	return nil
}

// activeProtectPausedUntil returns until if still in the future; empty if expired/invalid.
func activeProtectPausedUntil(until string) string {
	until = strings.TrimSpace(until)
	if until == "" {
		return ""
	}
	exp, err := time.Parse(time.RFC3339, until)
	if err != nil || !time.Now().Before(exp) {
		return ""
	}
	return until
}

// clearProtectPause drops a scheduled auto-resume after the user turns Protect on.
func (a *App) clearProtectPause() {
	a.mu.Lock()
	changed := false
	if a.state.ProtectPausedUntil != "" {
		a.state.ProtectPausedUntil = ""
		changed = true
	}
	// Drop stale "forever" so Home/Settings stop saying "Off until you turn it on"
	// after Protect is back on.
	if a.state.ProtectPauseLast == "forever" {
		a.state.ProtectPauseLast = ""
		changed = true
	}
	if !changed {
		a.mu.Unlock()
		return
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
}

func (a *App) enableSessionFromTray() error {
	if a.currentMode() == ModeSession {
		return nil
	}
	_ = a.stopComputerOpts(false, true) // leaving computer -> Remove once
	if err := a.startSession(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		a.setStatus("Error")
		return err
	}
	return nil
}

func (a *App) stopProtectionFromTray() {
	a.mu.Lock()
	leaveOn := a.state.ProtectionOn || a.state.ComputerEnabled
	paused := activeProtectPausedUntil(a.state.ProtectPausedUntil) != "" || a.state.ProtectPauseLast == "forever"
	a.mu.Unlock()
	if a.currentMode() == ModeOff && !leaveOn {
		// Already paused / forever-off: reopen PauseModal so duration can change.
		if paused && a.opts.OpenUI != nil {
			a.RequestOpenUI("pause")
		}
		return
	}
	// Wails: open in-app PauseModal (Cancel keeps Protect on). Avoid silent 1h when zenity missing.
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("pause")
		return
	}
	choice, ok := a.chooseProtectPause()
	if !ok {
		return // user cancelled — leave protection on
	}
	a.stopProtection()
	a.applyProtectPauseChoice(choice)
	// Intentional Off: no OS nag - Home/tray show status.
}

// chooseProtectPause asks how long to leave Protect off.
// ok=false means the user cancelled (do not turn protection off).
// choice "forever" means until manual On (empty ProtectPausedUntil).
func (a *App) chooseProtectPause() (choice string, ok bool) {
	a.mu.Lock()
	last := a.state.ProtectPauseLast
	a.mu.Unlock()
	def := "1h"
	if last != "" {
		def = last
	}
	title := "DenyOut - Turn off / pause"
	text := "How long should Protect stay off?\n(Cancel keeps protection on. Default: " + def + ".)"
	if runtime.GOOS == "linux" {
		if zenity, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.Command(zenity, "--list",
				"--title="+title,
				"--text="+text,
				"--column=Choice",
				"--hide-header",
				"--width=420",
				"--height=300",
				"15 minutes",
				"1 hour",
				"About 24 hours",
				"Until I turn it on",
			)
			out, err := cmd.Output()
			if err != nil {
				return "", false
			}
			label := strings.TrimSpace(string(out))
			if label == "" {
				return "", false
			}
			return mapPauseLabel(label, def), true
		}
	}
	return def, true
}

func mapPauseLabel(s, def string) string {
	switch s {
	case "15 minutes":
		return "15m"
	case "1 hour":
		return "1h"
	case "About 24 hours", "Until tomorrow": // legacy zenity label
		return "tomorrow"
	case "Until I turn it on":
		return "forever"
	default:
		return def
	}
}

func (a *App) applyProtectPauseChoice(choice string) {
	a.mu.Lock()
	a.state.ProtectPauseLast = choice
	var until string
	switch choice {
	case "15m":
		until = time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)
	case "1h":
		until = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	case "tomorrow":
		until = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	default: // forever
		until = ""
	}
	a.state.ProtectPausedUntil = until
	// Drop frozen Your setup "protected" copy — live mode is Off after pause.
	a.state.PendingYourSetup = ""
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogEvent("protect_pause", map[string]any{"choice": choice, "until": until})
	LogEvent("protect_off", map[string]any{"source": "pause", "choice": choice})
}

func (a *App) restartActiveProtector() error {
	a.mu.Lock()
	scope := a.state.Scope
	on := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	if !on {
		return nil
	}
	a.stopAll() // computer: no ElevateRemove; session: stop in-process
	a.mu.Lock()
	a.state.ProtectionOn = true
	a.state.Scope = scope
	a.mu.Unlock()
	switch scope {
	case ScopeComputer:
		if err := a.startComputer(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: restart computer failed: %v - staying Off\n", err)
			a.mu.Lock()
			a.state.ProtectionOn = false
			a.state.ComputerEnabled = false
			a.state.Scope = ScopeOff
			stFail := a.state
			a.mu.Unlock()
			_ = SaveState(stFail)
			a.setStatus("Needs admin")
			notify.Emit(notify.KindProtectFailed, "DenyOut", "Could not restart Protect computer - staying Off. Retry from Open DenyOut or the tray.")
			return err
		}
		a.clearProtectPause()
		return nil
	case ScopeSession:
		// Session is not a user-facing restore target after UX v2.
		return a.startSession()
	default:
		if err := a.startComputer(); err != nil {
			a.mu.Lock()
			a.state.ProtectionOn = false
			a.state.ComputerEnabled = false
			a.state.Scope = ScopeOff
			stFail := a.state
			a.mu.Unlock()
			_ = SaveState(stFail)
			a.setStatus("Needs admin")
			return err
		}
		a.clearProtectPause()
		return nil
	}
}

// clearLegacySessionScope drops persisted ScopeSession on boot (no silent Session restore).
func (a *App) clearLegacySessionScope() {
	a.mu.Lock()
	if a.state.Scope != ScopeSession {
		a.mu.Unlock()
		return
	}
	AppendDesktopLog("INFO restore: ignoring legacy session scope (no silent Session)")
	a.state.Scope = ScopeOff
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.legacySessionNote =
		"Earlier Session mode was cleared. Turn on Protect computer from Home when you want browsing protection."
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	LogEvent("restore_skipped", map[string]any{"reason": "legacy_session"})
}

// restoreProtection is unused for silent leave-on; Protect is offered via UIReadyRestore / native confirm.
// Kept for tests that still exercise elevate-skip failure paths via direct call.
func (a *App) restoreProtection() {
	a.clearLegacySessionScope()
	a.mu.Lock()
	on := a.state.ProtectionOn || a.state.ComputerEnabled
	scope := a.state.Scope
	a.mu.Unlock()
	if !on {
		return
	}
	if scope == "" {
		scope = ScopeComputer
	}
	AppendDesktopLog("INFO restore scope=%s profile=%s", scope, normalizePolicyProfile(a.state.PolicyProfile))
	if scope != ScopeComputer {
		return
	}
	if err := a.startComputer(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: restore computer failed: %v - staying Off\n", err)
		a.mu.Lock()
		a.state.ProtectionOn = false
		a.state.Scope = ScopeOff
		if !hostguard.IsElevateDisabled(err) {
			a.state.ComputerAvailable = false
			RecordError("restore.computer", err.Error())
		} else {
			AppendDesktopLog("INFO restore ElevateApply skipped (test/CI): %v", err)
			LogEvent("elevate_skipped", map[string]any{"reason": "test_ci", "source": "restore"})
		}
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		if !hostguard.IsElevateDisabled(err) {
			notify.Emit(notify.KindProtectFailed, "DenyOut", "A password window should have appeared. If you cancelled it, protection stayed Off. Try Protect computer again from Open DenyOut or the tray.")
		}
	}
}
