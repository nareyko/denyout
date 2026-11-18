package desktop

import (
	"fmt"

	"github.com/nareyko/denyout/internal/notify"
)

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
	LogEvent("setup_choice", map[string]any{"choice": "not_now"})
	a.completeSetupSideEffects()
	// Not now installs nothing, so there is no result to verify: skip the final screen.
	a.mu.Lock()
	a.state.YourSetupShown = true
	a.state.PendingYourSetup = ""
	st = a.state
	a.mu.Unlock()
	_ = SaveState(st)
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
	LogEvent("setup_choice", map[string]any{"choice": "agents"})
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
	_ = a.unregisterAutostart()
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("home")
	}
	return nil
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
