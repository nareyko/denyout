package desktop

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gogpu/systray"
)

// RunTray runs the system tray until ctx is cancelled or Quit.
func (a *App) RunTray(ctx context.Context) error {
	return a.runTray(ctx)
}

func (a *App) runTray(ctx context.Context) error {
	tray := systray.New()
	tray.SetIcon(iconIdlePNG)
	tray.SetTooltip("DenyOut - Off")
	tray.SetAppName("DenyOut")

	// Left-click: Home, or History when needs attention / last deny pending review.
	tray.OnClick(func() {
		go func() {
			a.mu.Lock()
			alert := problemsUnhealthyLocked(a) || a.state.LastDenyHost != "" && !a.state.ProtectionOn
			pause := a.state.ProtectPausedUntil != ""
			a.mu.Unlock()
			if alert {
				a.RequestOpenUI("activity")
				return
			}
			if pause {
				a.RequestOpenUI("home")
				return
			}
			a.RequestOpenUI("home")
		}()
	})

	menu := systray.NewMenu()
	statusItem := menu.Add("Off", nil)
	statusItem.SetDisabled(true)
	menu.AddSeparator()

	computerItem := menu.Add("Protect computer", func() {
		_ = a.enableSafeDesktop()
	})
	menu.Add("My agents...", func() {
		go a.myAgentsMenu()
	})
	offItem := menu.Add("Off", func() {
		a.stopProtectionFromTray()
	})
	menu.AddSeparator()

	menu.Add("Open DenyOut...", func() {
		go a.RequestOpenUI("home")
	})
	menu.AddSeparator()

	menu.Add("Quit DenyOut", func() {
		// Full unload: hostguard Remove (one admin prompt if rules present) + exit.
		a.quitUnload()
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
				profile := normalizePolicyProfile(a.state.PolicyProfile)
				avail := a.state.ComputerAvailable
				pauseUntil := a.state.ProtectPausedUntil
				needsAttention := problemsUnhealthyLocked(a)
				a.mu.Unlock()

				label := userModeLabel(mode, profile)
				if mode == ModeOff && pauseUntil != "" {
					label = "Paused"
					if t, err := time.Parse(time.RFC3339, pauseUntil); err == nil {
						label = "Paused until " + t.Local().Format("15:04")
					}
				} else if mode == ModeOff && !avail {
					label = "Off (unavailable)"
				}
				if needsAttention {
					label = "Needs attention"
				}
				statusItem.SetLabel(label)

				computerItem.SetLabel(checkedLabel("Protect computer", mode == ModeComputer && profile == PolicyProfileBrowse))
				computerItem.SetDisabled(mode == ModeComputer && profile == PolicyProfileBrowse)
				offItem.SetLabel(checkedLabel("Off", mode == ModeOff && pauseUntil == ""))
				offItem.SetDisabled(mode == ModeOff)

				tray.SetTooltip("DenyOut - " + label)

				switch {
				case needsAttention, strings.Contains(strings.ToLower(st), "error"), strings.Contains(st, "Needs"):
					tray.SetIcon(iconAlertPNG)
				case mode != ModeOff || a.runningWrapCount() > 0:
					tray.SetIcon(iconOnPNG)
				default:
					tray.SetIcon(iconIdlePNG)
				}
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready - left-click opens DenyOut")
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
		return "Limited (session)"
	default:
		return "Off"
	}
}
