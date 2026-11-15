package desktop

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nareyko/denyout/internal/notify"
)

// Install performs user-space desktop setup only: prefs for later Protect,
// stop old instances, detach tray/UI. Does NOT enable Protect, does NOT
// elevate, and does NOT register autostart until the user finishes mode choice
// (see completeSetupSideEffects).
func Install(opts Options) error {
	_ = opts
	st := LoadState()
	st.SetupDone = false
	st.Notify = true
	st.AskMode = false
	st.PolicyProfile = PolicyProfileBrowse
	st.UXv2Migrated = true
	st.ComputerAvailable = true
	st.Scope = ScopeOff
	st.ProtectionOn = false
	st.ComputerEnabled = false
	st.Autostart = false
	st.AutostartAsked = false
	st.YourSetupShown = false
	st.PendingYourSetup = ""
	if err := SaveState(st); err != nil {
		return err
	}
	notify.SetEnabled(true)
	// Login launch is registered only after mode choice (completeSetupSideEffects).
	// Drop any leftover entry from a previous install so Settings matches Off.
	_ = UnregisterAutostart()

	fmt.Fprintln(os.Stderr, "denyout install: stopping previous tray/proxyd (if any)...")
	StopPreviousInstances()
	if dir := DefaultInstallDir(); dir != "" {
		WarnStaleBinariesOnPATH(dir)
	}

	if !desktopBinaryPresent() {
		fmt.Fprintln(os.Stderr, "denyout install: warning - denyout-desktop not found next to denyout")
		fmt.Fprintln(os.Stderr, "  Home window needs denyout-desktop (Wails). Without it you only get the tray + system dialogs.")
		fmt.Fprintln(os.Stderr, "  Build: CGO_ENABLED=1 go build -tags 'wails,production,webkit2_41' -o ~/.local/bin/denyout-desktop ./cmd/denyout-desktop")
	}

	if err := DetachDesktopOpen(); err != nil {
		return fmt.Errorf("start tray: %w", err)
	}

	fmt.Fprintln(os.Stderr, "denyout install: started (protection off until you choose)")
	fmt.Fprintf(os.Stderr, "denyout install: done (scope=%s profile=%s protection_on=%v setup_done=%v)\n",
		st.Scope, st.PolicyProfile, st.ProtectionOn, st.SetupDone)
	return nil
}

func desktopBinaryPresent() bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	dir := filepath.Dir(self)
	cand := filepath.Join(dir, "denyout-desktop")
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return true
	}
	return false
}
