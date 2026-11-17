package desktop

import (
	"fmt"
	"runtime"
	"strings"
)

// UITestProtection returns plain-language Protect status for the in-app UI.
func (a *App) UITestProtection() string {
	return a.testProtectionMessage()
}

// UISetBlockBrowserQUIC toggles dropping UDP/443 while Protect is on (default on).
// When Protect is live, re-applies hostguard so nft/pf match the new choice.
func (a *App) UISetBlockBrowserQUIC(on bool) error {
	a.mu.Lock()
	a.state.AllowBrowserQUIC = !on
	live := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	LogEvent("block_quic_setting", map[string]any{"block": on, "live": live})
	if live {
		if err := a.restartActiveProtector(); err != nil {
			return fmt.Errorf("Saved, but could not refresh Protect rules: %w", err)
		}
	}
	return nil
}

// UISetTunDataplane toggles experimental UDP/443 via denyout0 (Linux; default off).
// When Protect is live, restarts the protector so tun-start/stop matches.
func (a *App) UISetTunDataplane(on bool) error {
	if runtime.GOOS != "linux" && on {
		return fmt.Errorf("UDP via DenyOut TUN is Linux-only")
	}
	a.mu.Lock()
	a.state.TunDataplane = on
	if !on {
		a.state.QuicMITM = false
	}
	live := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	LogEvent("tun_dataplane_setting", map[string]any{"on": on, "live": live})
	if live {
		if err := a.restartActiveProtector(); err != nil {
			return fmt.Errorf("Saved, but could not refresh Protect: %w", err)
		}
	}
	return nil
}

// UISetQuicMITM toggles experimental HTTP/3 MITM (Linux; default off; needs TunDataplane).
func (a *App) UISetQuicMITM(on bool) error {
	if runtime.GOOS != "linux" && on {
		return fmt.Errorf("HTTP/3 MITM is Linux-only")
	}
	a.mu.Lock()
	if on && !a.state.TunDataplane {
		a.mu.Unlock()
		return fmt.Errorf("enable TunDataplane first (UDP via DenyOut TUN)")
	}
	a.state.QuicMITM = on
	live := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	LogEvent("quic_mitm_setting", map[string]any{"on": on, "live": live})
	if live && a.state.TunDataplane {
		if err := a.restartActiveProtector(); err != nil {
			return fmt.Errorf("Saved, but could not refresh Protect: %w", err)
		}
	}
	return nil
}

// UIStopProtectionWithChoice turns protection Off using an in-app pause choice
// (15m|1h|tomorrow|forever). Used by Wails so Cancel can stay in the window.
func (a *App) UIStopProtectionWithChoice(choice string) error {
	a.mu.Lock()
	leaveOn := a.state.ProtectionOn || a.state.ComputerEnabled
	live := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	choice = strings.TrimSpace(choice)
	switch choice {
	case "15m", "1h", "tomorrow", "forever":
	default:
		choice = "1h"
	}
	// Already Off (paused / forever): still apply a new duration from PauseModal.
	if a.currentMode() == ModeOff && !leaveOn {
		a.applyProtectPauseChoice(choice)
		return nil
	}
	// Protector dead but leave-on intent remains (Needs attention): clear intent
	// without ElevateRemove — cancel-password must not trap the user in unhealthy.
	if !live {
		a.mu.Lock()
		a.state.ProtectionOn = false
		a.state.ComputerEnabled = false
		a.state.Scope = ScopeOff
		a.state.PendingYourSetup = ""
		a.status = "Off"
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		a.applyProtectPauseChoice(choice)
		return nil
	}
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	a.applyProtectPauseChoice(choice)
	return nil
}

// UISetAutostart toggles login autostart for denyout (GUI) when available.
func (a *App) UISetAutostart(on bool) error {
	a.mu.Lock()
	if !a.state.SetupDone {
		a.mu.Unlock()
		return fmt.Errorf("finish first-run setup before changing autostart")
	}
	a.state.Autostart = on
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if on {
		if err := RegisterAutostart(); err != nil {
			a.mu.Lock()
			a.state.Autostart = false
			stFail := a.state
			a.mu.Unlock()
			_ = SaveState(stFail)
			return err
		}
		return nil
	}
	return UnregisterAutostart()
}

// UIEnableSafeDesktop turns on Protect computer.
func (a *App) UIEnableSafeDesktop() error {
	return a.enableSafeDesktop()
}

// UIEnableAgentsOnly turns on Agents only (whole PC) - caller must confirm in UI.
func (a *App) UIEnableAgentsOnly() error {
	return a.enableAgentsOnlyWholePC()
}

// UISwitchSafe switches from Agents only back to Safe desktop.
func (a *App) UISwitchSafe() error {
	return a.switchToSafeDesktopFromTray()
}

// UIStopProtection turns protection Off (asks pause duration on desktop).
func (a *App) UIStopProtection() error {
	if a.currentMode() == ModeOff {
		return nil
	}
	choice, ok := a.chooseProtectPause()
	if !ok {
		return nil // cancelled — leave protection on
	}
	if err := a.stopProtectionErr(); err != nil {
		return err
	}
	a.applyProtectPauseChoice(choice)
	return nil
}

// UIRetryProtect retries the intended Protect path.
// Broken Agents only keeps PolicyProfileAgent (does not silently flip to browse).
func (a *App) UIRetryProtect() error {
	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	if profile == PolicyProfileAgent {
		if err := a.enableComputerFromTray(); err != nil {
			return err
		}
		a.ensureSetupDoneAfterProtect("agents_only")
		return nil
	}
	return a.enableSafeDesktop()
}

// enableAgentsOnlyWholePC is the confirmed path (UI already confirmed).
func (a *App) enableAgentsOnlyWholePC() error {
	// Wails already confirmed the risk — force-stop wraps (no second native dialog).
	a.stopAllWrapsOpts("Agents only on whole PC - stopping wraps", true)
	a.mu.Lock()
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.AskMode = true
	a.state.ActiveProfileID = ""
	hadSession := a.session != nil
	hadProxyd := a.proxyd != nil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	var err error
	// Session → Agents only must not restartActiveProtector (that keeps ScopeSession).
	if hadSession {
		a.stopSession()
		a.mu.Lock()
		a.state.Scope = ScopeComputer
		a.state.PolicyProfile = PolicyProfileAgent
		a.state.AskMode = true
		st = a.state
		a.mu.Unlock()
		_ = SaveState(st)
		err = a.enableComputerFromTray()
	} else if hadProxyd {
		err = a.restartActiveProtector()
	} else {
		err = a.enableComputerFromTray()
	}
	if err != nil {
		return err
	}
	a.ensureSetupDoneAfterProtect("agents_only")
	return nil
}
