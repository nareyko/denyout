package desktop

import (
	"fmt"
	"os"

	"github.com/nareyko/denyout/internal/notify"
)

// Install performs silent desktop setup: Safe desktop preference, autostart,
// detach tray. Elevation happens at most once inside the tray process
// (restoreProtection) — never Apply+Remove+Apply from the installer.
func Install(opts Options) error {
	_ = opts
	st := LoadState()
	st.SetupDone = true
	st.Notify = true
	st.AskMode = false
	st.PolicyProfile = PolicyProfileBrowse
	st.UXv2Migrated = true
	st.ComputerAvailable = true
	st.Scope = ScopeComputer
	st.ProtectionOn = true
	st.ComputerEnabled = true
	st.Autostart = true
	st.AutostartAsked = true
	if err := SaveState(st); err != nil {
		return err
	}
	notify.SetEnabled(true)

	if err := RegisterAutostart(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout install: autostart: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "denyout install: login autostart registered")
	}

	fmt.Fprintln(os.Stderr, "denyout install: stopping previous tray/proxyd (if any)…")
	StopPreviousInstances()

	if err := DetachDesktop(); err != nil {
		return fmt.Errorf("start tray: %w", err)
	}

	fmt.Fprintln(os.Stderr, "denyout install: tray started — approve admin once if prompted (stays Off on failure; no Session fallback)")
	fmt.Fprintf(os.Stderr, "denyout install: done (scope=%s profile=%s protection_on=%v)\n", st.Scope, st.PolicyProfile, st.ProtectionOn)
	return nil
}
