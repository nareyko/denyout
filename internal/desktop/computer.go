package desktop

import (
	"fmt"
	"net"
	"os"
	"os/exec"
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
		a.mu.Unlock()
		return fmt.Errorf("protection is already on")
	}
	ask := a.state.AskMode
	wizard := a.wizardURL
	control := a.controlURL
	a.status = "Starting…"
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
	if err := hostguard.ElevateApply(port, caPath, uid); err != nil {
		a.setStatus("Needs admin")
		a.mu.Lock()
		a.state.ComputerAvailable = false
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		RecordError("hostguard.ElevateApply", err.Error())
		return err
	}
	// Chrome/Electron use NSS, not only the system trust store.
	if err := hostguard.TrustCAForUserBrowsers(caPath); err != nil {
		AppendDesktopLog("WARN browser CA trust (NSS): %v — Chrome may show SSL errors", err)
	} else {
		AppendDesktopLog("INFO browser CA trusted in user NSS DB")
	}

	self, err := os.Executable()
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	env := os.Environ()
	a.mu.Lock()
	if len(a.state.AlwaysAllowHosts) > 0 {
		env = append(env, "DENYOUT_ALWAYS_ALLOW="+strings.Join(a.state.AlwaysAllowHosts, ","))
	}
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
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
	_ = SaveState(st)

	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		if a.proxyd == cmd {
			a.proxyd = nil
			a.proxyPort = 0
			a.state.ComputerEnabled = false
			if a.status == "Computer" {
				a.status = "Off"
			}
		}
		a.mu.Unlock()
	}()
	return nil
}

// stopComputerOpts stops computer-mode proxyd.
// If elevateRemove is false, only kills proxyd — next ElevateApply replaces nft/pf
// in one admin prompt (avoid Remove+Apply = two passwords).
func (a *App) stopComputerOpts(keepRestore, elevateRemove bool) {
	a.mu.Lock()
	cmd := a.proxyd
	port := a.proxyPort
	hadProxyd := cmd != nil
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
	// Session mode also stores proxyPort — must not trigger ElevateRemove/pkexec.
	if elevateRemove && hadProxyd && port > 0 {
		uid, _ := hostguard.CurrentUID()
		_ = hostguard.ElevateRemove(port, uid)
	}
}

func (a *App) stopAll() {
	a.stopComputerOpts(true, false) // keep rules; caller may re-Apply once
	a.stopSessionKeep(true)
	a.setStatus("Off")
}

// stopAllKeepRestore stops live protectors but leaves ProtectionOn for next login (Quit leave-on).
func (a *App) stopAllKeepRestore() {
	a.stopAll()
}

func (a *App) stopProtection() {
	a.stopComputerOpts(false, true) // user turned off → one Remove prompt
	a.stopSession()
	a.mu.Lock()
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.status = "Off"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
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
		return nil
	}
	// proxyd: once without IPC to live engine → persist + restart
	return a.allowHostAlways(host)
}

func (a *App) allowHostAlways(host string) error {
	if err := a.persistAlwaysHost(host); err != nil {
		return err
	}
	a.mu.Lock()
	sess := a.session
	wasProxy := a.proxyd != nil
	a.mu.Unlock()
	if sess != nil {
		return nil
	}
	if wasProxy {
		// Kill proxyd only; ElevateApply replaces redirect in one password.
		a.stopComputerOpts(true, false)
		return a.startComputer()
	}
	return nil
}

func (a *App) enableComputerFromTray() error {
	if a.currentMode() == ModeComputer {
		notify.Info("DenyOut", "Already protecting whole computer.")
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
		a.state.ComputerAvailable = false
		a.state.ProtectionOn = false
		a.state.Scope = ScopeOff
		stFail := a.state
		a.mu.Unlock()
		_ = SaveState(stFail)
		notify.Info("DenyOut", "Admin failed — protection stays Off. Tray → Protect computer to retry, or Help & logs.")
		return err
	}
	AppendDesktopLog("INFO computer mode on profile=%s", normalizePolicyProfile(a.state.PolicyProfile))
	if !certutilAvailable() {
		AppendDesktopLog("INFO hint: install libnss3-tools (certutil) for Chrome/Chromium trust")
	}
	if !clipboardAvailable() {
		AppendDesktopLog("INFO hint: install wl-clipboard for Copy last error")
	}
	notify.Info("DenyOut", "Protect computer is on ("+policyProfileLabel(a.state.PolicyProfile)+").")
	return nil
}

func (a *App) enableSessionFromTray() error {
	if a.currentMode() == ModeSession {
		notify.Info("DenyOut", "Already in session mode.")
		return nil
	}
	a.stopComputerOpts(false, true) // leaving computer → Remove once
	if err := a.startSession(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		a.setStatus("Error")
		return err
	}
	notify.Info("DenyOut", "Session mode: apps that use system proxy. Browsers may ignore it.")
	return nil
}

func (a *App) stopProtectionFromTray() {
	if a.currentMode() == ModeOff {
		notify.Info("DenyOut", "Protection is already off. (Running agents are separate — use My agents → Stop.)")
		return
	}
	a.stopProtection()
	notify.Info("DenyOut", "Protect computer is off. Running agents (if any) keep going — Stop them from My agents.")
}

func (a *App) restartActiveProtector() {
	a.mu.Lock()
	scope := a.state.Scope
	on := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	if !on {
		return
	}
	a.stopAll() // computer: no ElevateRemove; session: stop in-process
	a.mu.Lock()
	a.state.ProtectionOn = true
	a.state.Scope = scope
	a.mu.Unlock()
	switch scope {
	case ScopeComputer:
		if err := a.startComputer(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: restart computer failed: %v — staying Off\n", err)
			a.setStatus("Needs admin")
			notify.Info("DenyOut", "Could not restart Protect computer — staying Off. Retry from the tray.")
		}
	case ScopeSession:
		// Session is not a user-facing restore target after UX v2.
		_ = a.startSession()
	default:
		if err := a.startComputer(); err != nil {
			a.setStatus("Needs admin")
		}
	}
}

func (a *App) restoreProtection() {
	a.mu.Lock()
	on := a.state.ProtectionOn || a.state.ComputerEnabled
	scope := a.state.Scope
	a.mu.Unlock()
	if !on {
		return
	}
	// Migrate legacy session preference → Off (no morning Session surprise).
	if scope == ScopeSession {
		AppendDesktopLog("INFO restore: ignoring legacy session scope (no silent Session)")
		a.mu.Lock()
		a.state.Scope = ScopeOff
		a.state.ProtectionOn = false
		a.state.ComputerEnabled = false
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.Info("DenyOut", "Previous Session mode was cleared. Use Protect computer (Safe desktop) when ready.")
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
		fmt.Fprintf(os.Stderr, "denyout desktop: restore computer failed: %v — staying Off\n", err)
		RecordError("restore.computer", err.Error())
		a.mu.Lock()
		a.state.ComputerAvailable = false
		a.state.ProtectionOn = false
		a.state.Scope = ScopeOff
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.Info("DenyOut", "Admin failed — protection stays Off. Tray → Protect computer to retry.")
	}
}
