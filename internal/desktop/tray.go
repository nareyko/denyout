package desktop

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gogpu/systray"

	"github.com/nareyko/denyout/internal/notify"
)

func (a *App) runTray(ctx context.Context) error {
	tray := systray.New()
	tray.SetIcon(iconIdlePNG)
	tray.SetTooltip("DenyOut — Off")
	tray.SetAppName("DenyOut")

	menu := systray.NewMenu()
	statusItem := menu.Add("Status: Off", nil)
	statusItem.SetDisabled(true)
	lastItem := menu.Add("Last block: none", nil)
	lastItem.SetDisabled(true)
	learningItem := menu.Add("Learning: none", func() {
		go a.pinLearningFromTray()
	})
	menu.AddSeparator()

	computerItem := menu.Add("Protect computer", func() {
		_ = a.enableSafeDesktop()
	})
	myAgentsItem := menu.Add("My agents…", func() {
		go a.myAgentsMenu()
	})
	_ = myAgentsItem
	agentsOnlyItem := menu.Add("Agents only (whole PC)…", func() {
		go a.confirmAgentsOnlyWholePC()
	})
	safeBackItem := menu.Add("Switch to Safe desktop", func() {
		a.switchToSafeDesktopFromTray()
	})
	offItem := menu.Add("Off", func() {
		a.stopProtectionFromTray()
	})
	menu.AddSeparator()

	menu.Add("Open activity…", func() {
		go a.nativeShowActivity()
	})
	menu.Add("Always-allow list…", func() {
		go a.nativeManageAlwaysAllow()
	})
	menu.Add("Undo last always-allow", func() {
		a.undoLastAlwaysAllow()
	})
	resumeAskItem := menu.Add("Resume asks", func() {
		if a.asks != nil {
			a.asks.ClearPause()
		}
		a.mu.Lock()
		a.state.AskPausedUntil = ""
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.Info("DenyOut", "Asks resumed.")
	})
	menu.AddSeparator()

	notifyItem := menu.Add("Notifications", func() {
		a.mu.Lock()
		a.state.Notify = !a.state.Notify
		on := a.state.Notify
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.SetEnabled(on)
	})
	menu.Add("Help & logs…", func() {
		go a.helpAndLogs()
	})
	menu.Add("Copy last error", func() {
		copyLastErrorOrPrint()
	})
	menu.Add("Test protection…", func() {
		go a.testProtection()
	})
	menu.AddSeparator()

	ver := a.opts.Version
	if ver == "" {
		ver = "dev"
	}
	verItem := menu.Add("DenyOut "+ver, nil)
	verItem.SetDisabled(true)

	menu.Add("Quit DenyOut", func() {
		// Quit leave-on: keep ProtectionOn so next login restores Computer.
		a.stopAllKeepRestore()
		a.stopAllWrapsOpts("Quit", true)
		a.stopProtect()
		tray.Remove()
		os.Exit(0)
	})

	tray.SetMenu(menu)
	tray.Show()

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
				mode := a.currentMode()
				a.mu.Lock()
				st := a.status
				last := a.lastDeny
				notifyOn := a.state.Notify
				profile := normalizePolicyProfile(a.state.PolicyProfile)
				avail := a.state.ComputerAvailable
				askPaused := a.state.AskPaused() || (a.asks != nil && a.asks.Paused())
				a.mu.Unlock()

				label := userModeLabel(mode, profile)
				if mode == ModeOff && !avail {
					label = "Off (computer unavailable)"
				}
				statusItem.SetLabel("Status: " + label)
				if last == "" {
					lastItem.SetLabel("Last block: none")
				} else {
					lastItem.SetLabel("Last block: " + truncate(last, 40))
				}
				learningItem.SetLabel(a.learningMenuLabel())

				computerItem.SetLabel(checkedLabel("Protect computer", mode == ModeComputer && profile == PolicyProfileBrowse))
				computerItem.SetDisabled(mode == ModeComputer && profile == PolicyProfileBrowse)
				agentsOnlyItem.SetLabel(checkedLabel("Agents only (whole PC)…", mode == ModeComputer && profile == PolicyProfileAgent))
				safeBackItem.SetDisabled(!(mode == ModeComputer && profile == PolicyProfileAgent))
				offItem.SetLabel(checkedLabel("Off", mode == ModeOff))
				offItem.SetDisabled(mode == ModeOff)

				notifyItem.SetLabel(checkedLabel("Notifications", notifyOn))
				resumeAskItem.SetDisabled(!askPaused)

				tray.SetTooltip("DenyOut — " + label)

				switch {
				case strings.Contains(strings.ToLower(st), "error"), strings.Contains(st, "Needs"):
					tray.SetIcon(iconAlertPNG)
				case mode != ModeOff || a.runningWrapCount() > 0:
					tray.SetIcon(iconOnPNG)
				default:
					tray.SetIcon(iconIdlePNG)
				}
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready — Protect computer / My agents / Off")
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
		return policyProfileLabel(profile)
	case ModeSession:
		// Hidden as user mode; show honestly if somehow active.
		return "Limited (session)"
	default:
		return "Off"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
