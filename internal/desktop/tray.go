package desktop

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gogpu/systray"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/protectstate"
)

func (a *App) trayEnableProtectComputer() {
	// Wails: open Home turn-on confirm (same copy as in-app). Avoid native zenity mismatch.
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("enable-protect")
		return
	}
	title, body := ProtectConfirmText(hostguard.HelperAvailable())
	if dialogToolkitAvailable() {
		if !nativeConfirm(title, body, "Continue", "Cancel") {
			return
		}
	}
	_ = a.enableSafeDesktop()
}

// RunTray runs the system tray until ctx is cancelled or Quit.
func (a *App) RunTray(ctx context.Context) error {
	return a.runTray(ctx)
}

func (a *App) runTray(ctx context.Context) error {
	tray := systray.New()
	tray.SetIcon(iconIdlePNG)
	tray.SetTooltip("DenyOut - Off")
	tray.SetAppName("DenyOut")

	// Left-click: Problems when Protect is broken or threat lists need a refresh; else Home.
	tray.OnClick(func() { go a.trayLeftClick() })

	menu := systray.NewMenu()
	statusItem := menu.Add("Off", nil)
	statusItem.SetDisabled(true)
	menu.AddSeparator()

	// Open first: on GNOME/AppIndicator left-click often opens the menu instead of
	// OnClick — make Home one click from the menu.
	menu.Add("Open DenyOut...", func() {
		go a.RequestOpenUI("home")
	})
	menu.AddSeparator()

	computerItem := menu.Add("Protect computer", func() {
		go a.trayEnableProtectComputer()
	})
	menu.Add("My agents...", func() {
		go a.myAgentsMenu()
	})
	offItem := menu.Add("Off", func() {
		a.stopProtectionFromTray()
	})
	menu.AddSeparator()

	snooze1h := menu.Add("Snooze notifications 1 hour", func() {
		go func() { _ = a.UISetNotifySnooze("1h") }()
	})
	snoozeTomorrow := menu.Add("Snooze until 8:00 tomorrow", func() {
		go func() { _ = a.UISetNotifySnooze("tomorrow") }()
	})
	clearSnooze := menu.Add("Clear notification snooze", func() {
		go func() { _ = a.UISetNotifySnooze("clear") }()
	})
	menu.AddSeparator()

	menu.Add("Quit DenyOut", func() { a.trayQuit(tray) })

	// Notify once when protection transitions into degraded (proxy lost, redirect pulled).
	degradeTracker := &protectstate.Tracker{OnDegraded: func(tr protectstate.Transition) {
		notify.Emit(notify.KindProtectFailed, "Protection is degraded", tr.Message)
	}}

	tray.SetMenu(menu)
	tray.Show()

	ti := trayItems{status: statusItem, computer: computerItem, off: offItem, snooze1h: snooze1h, snoozeTomorrow: snoozeTomorrow, clearSnooze: clearSnooze}
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				a.stopAllKeepRestore()
				a.stopAllWrapsOpts("", true)
				a.stopProtect()
				tray.Remove()
				return
			case <-t.C:
				a.trayTick(tray, ti, degradeTracker)
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready - left-click opens DenyOut (on some Linux desktops left-click opens the menu — use Open DenyOut…)")
	errCh := make(chan error, 1)
	go func() { errCh <- tray.Run() }()

	select {
	case <-ctx.Done():
		a.stopAllKeepRestore()
		a.stopAllWrapsOpts("", true)
		a.stopProtect()
		tray.Remove()
		return nil
	case err := <-errCh:
		a.stopAllKeepRestore()
		a.stopAllWrapsOpts("", true)
		a.stopProtect()
		return err
	}
}

func checkedLabel(base string, on bool) string {
	if on {
		return base + " ✓"
	}
	return base
}

func userModeLabel(mode, profile string) string {
	switch mode {
	case ModeComputer:
		if normalizePolicyProfile(profile) == PolicyProfileBrowse {
			return "Protected"
		}
		return "Agents only"
	case ModeSession:
		return "Session"
	default:
		return "Off"
	}
}

type trayItems struct {
	status, computer, off, snooze1h, snoozeTomorrow, clearSnooze *systray.MenuItem
}

func (a *App) trayLeftClick() {
	a.mu.Lock()
	alert := problemsUnhealthyLocked(a)
	threatWarn := a.threatNeedsAttentionLocked()
	a.mu.Unlock()
	if alert || threatWarn {
		a.RequestOpenUI("problems")
		return
	}
	a.RequestOpenUI("home")
}

func (a *App) trayQuit(tray *systray.SystemTray) {
	// Wails: in-app quit modal (works without zenity). Native fallback otherwise.
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("quit")
		return
	}
	choice := a.trayQuitChoice()
	if choice == "" {
		return // cancel
	}
	notify.CloseAll()
	// Quit always fully unloads (password if helper is not installed).
	if err := a.quitUnload(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: quit cancelled or failed: %v\n", err)
		return
	}
	a.stopAllWrapsOpts("Quit", true)
	a.stopProtect()
	tray.Remove()
	os.Exit(0)
}

// trayTick snapshots app state and applies the pure trayView to the tray.
func (a *App) trayTick(tray *systray.SystemTray, ti trayItems, degradeTracker *protectstate.Tracker) {
	mode := a.currentMode()
	a.mu.Lock()
	st := a.status
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	avail := a.state.ComputerAvailable
	pauseUntil := activeProtectPausedUntil(a.state.ProtectPausedUntil)
	pauseLast := a.state.ProtectPauseLast
	leaveOn := a.state.ProtectionOn || a.state.ComputerEnabled
	pres := protectResultLocked(a)
	needsAttention := pres.NeedsAttention
	threatWarn := a.threatNeedsAttentionLocked()
	unread := a.state.AwayUnreadBlocks
	snoozeUntil := activeNotifySnoozeUntil(a.state.NotifySnoozeUntil)
	a.mu.Unlock()
	a.pollPresenceOnce()
	degradeTracker.Observe(pres)

	in := trayInputs{
		Mode: mode, Profile: profile, Avail: avail, PauseUntil: pauseUntil,
		PauseLast: pauseLast, LeaveOn: leaveOn, NeedsAttention: needsAttention,
		ThreatWarn: threatWarn, Unread: unread, SnoozeUntil: snoozeUntil,
		Status: st, Now: time.Now(),
	}
	in.QuietPhrase = a.quietReason()
	if !needsAttention {
		in.UndoActive = a.undoOfferActive()
	}
	in.WrapsRunning = a.runningWrapCount() > 0
	applyTrayModel(trayView(in), tray, ti)
}
