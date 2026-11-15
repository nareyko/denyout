package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nareyko/denyout/internal/notify"
)

// Install performs user-space desktop setup only: prefs for later Protect,
// stop old instances, detach tray/UI. Does NOT enable Protect, does NOT
// elevate, and does NOT register autostart until the user finishes mode choice
// (see completeSetupSideEffects).
//
// Re-install / upgrade (SetupDone already true): keep setup + soft prefs
// (notify level, Stay quiet, Respect fullscreen, …); still force Protect Off
// and clear a stale last-error so Problems is not stuck on a fixed elevate bug.
func Install(opts Options) error {
	_ = opts
	st, err := installPrepareState()
	if err != nil {
		return err
	}
	upgrade := st.SetupDone

	if !upgrade {
		// Login launch is registered only after mode choice (completeSetupSideEffects).
		// Drop any leftover entry from a previous install so Settings matches Off.
		_ = UnregisterAutostart()
	}

	fmt.Fprintln(os.Stderr, "denyout install: stopping previous tray/proxyd (if any)...")
	StopPreviousInstances()
	if dir := DefaultInstallDir(); dir != "" {
		WarnStaleBinariesOnPATH(dir)
	}

	if !desktopBinaryPresent() {
		fmt.Fprintln(os.Stderr, "denyout install: warning - denyout (GUI) not found next to denyout-cli")
		fmt.Fprintln(os.Stderr, "  Home window needs denyout (Wails). Without it you only get the tray + system dialogs.")
		fmt.Fprintln(os.Stderr, "  Build: CGO_ENABLED=1 go build -tags 'wails,production,webkit2_41' -o ~/.local/bin/denyout ./cmd/denyout")
	}

	if err := DetachDesktopOpen(); err != nil {
		return fmt.Errorf("start tray: %w", err)
	}

	if upgrade {
		fmt.Fprintln(os.Stderr, "denyout install: upgrade — keeping your setup; protection off until you turn it on")
	} else {
		fmt.Fprintln(os.Stderr, "denyout install: started (protection off until you choose)")
	}
	fmt.Fprintf(os.Stderr, "denyout install: done (scope=%s profile=%s protection_on=%v setup_done=%v)\n",
		st.Scope, st.PolicyProfile, st.ProtectionOn, st.SetupDone)
	return nil
}

// installPrepareState shapes desktop.json for Install (also used by tests).
func installPrepareState() (State, error) {
	prev := LoadState()
	upgrade := prev.SetupDone

	st := prev
	if !upgrade {
		st.SetupDone = false
		st.Notify = true
		st.AskMode = false
		st.PolicyProfile = PolicyProfileBrowse
		st.UXv2Migrated = true
		st.Autostart = false
		st.AutostartAsked = false
		st.YourSetupShown = false
		st.PendingYourSetup = ""
	} else {
		st.SetupDone = true
		st.UXv2Migrated = true
		if st.PolicyProfile == "" {
			st.PolicyProfile = PolicyProfileBrowse
		}
	}
	st.ComputerAvailable = true
	st.Scope = ScopeOff
	st.ProtectionOn = false
	st.ComputerEnabled = false
	if err := SaveState(st); err != nil {
		return st, err
	}
	ClearLastError()
	notify.SetEnabled(true)
	applyNotifyPrefs(st)
	return st, nil
}

func desktopBinaryPresent() bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	base := filepath.Base(self)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if strings.EqualFold(name, "denyout") {
		return true
	}
	cand := filepath.Join(filepath.Dir(self), "denyout")
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return true
	}
	return false
}
