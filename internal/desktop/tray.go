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
	menu.AddSeparator()

	computerItem := menu.Add("Computer", func() {
		_ = a.enableComputerFromTray()
	})
	sessionItem := menu.Add("Session (proxy)", func() {
		_ = a.enableSessionFromTray()
	})
	offItem := menu.Add("Off", func() {
		a.stopProtectionFromTray()
	})
	menu.AddSeparator()

	menu.Add("Open activity…", func() {
		u := a.activityPageURL()
		if u == "" {
			notify.Info("DenyOut", "Activity page not ready yet.")
			return
		}
		openBrowser(u)
	})
	menu.Add("Open diagnostics…", func() {
		openLogsOrPrint()
	})
	menu.Add("Copy last error", func() {
		copyLastErrorOrPrint()
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
		fmt.Fprintf(os.Stderr, "denyout desktop: notifications=%v\n", on)
	})
	askItem := menu.Add("Ask before new sites", func() {
		a.mu.Lock()
		a.state.AskMode = !a.state.AskMode
		ask := a.state.AskMode
		st := a.state
		wasOn := a.proxyd != nil || a.session != nil
		a.mu.Unlock()
		_ = SaveState(st)
		fmt.Fprintf(os.Stderr, "denyout desktop: ask_mode=%v\n", ask)
		if wasOn {
			a.restartActiveProtector()
		}
	})
	browseItem := menu.Add("Advanced: Browse profile", func() {
		a.mu.Lock()
		if normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse {
			a.state.PolicyProfile = PolicyProfileAgent
		} else {
			a.state.PolicyProfile = PolicyProfileBrowse
		}
		profile := a.state.PolicyProfile
		st := a.state
		wasOn := a.proxyd != nil || a.session != nil
		a.mu.Unlock()
		_ = SaveState(st)
		AppendDesktopLog("INFO policy_profile=%s", profile)
		notify.Info("DenyOut", "Policy profile: "+profile)
		if wasOn {
			a.restartActiveProtector()
		}
	})
	menu.AddSeparator()
	menu.Add("Advanced: protect shell", func() {
		a.mu.Lock()
		a.state.PreferredAgent = "shell"
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		if err := a.startProtect(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		}
	})
	menu.Add("Stop protected program", func() {
		a.stopProtect()
	})
	if a.opts.WebUI && a.wizardURL != "" {
		menu.AddSeparator()
		menu.Add("Open web settings…", func() {
			openBrowser(a.wizardURL)
		})
	}
	menu.AddSeparator()
	menu.Add("Quit DenyOut", func() {
		a.stopProtection()
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
				// Signal / reinstall: stop processes but keep ProtectionOn for next restore.
				// (Quit menu still calls stopProtection() to clear restore preference.)
				a.stopAll()
				a.stopProtect()
				tray.Remove()
				return
			case <-t.C:
				mode := a.currentMode()
				a.mu.Lock()
				st := a.status
				last := a.lastDeny
				notifyOn := a.state.Notify
				askOn := a.state.AskMode
				browseOn := normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse
				avail := a.state.ComputerAvailable
				a.mu.Unlock()

				label := modeLabel(mode)
				if mode == ModeOff && !avail {
					label = "Off (computer unavailable)"
				}
				statusItem.SetLabel("Status: " + label)
				if last == "" {
					lastItem.SetLabel("Last block: none")
				} else {
					lastItem.SetLabel("Last block: " + last)
				}

				computerItem.SetLabel(checkedLabel("Computer", mode == ModeComputer))
				computerItem.SetDisabled(mode == ModeComputer)
				sessionItem.SetLabel(checkedLabel("Session (proxy)", mode == ModeSession))
				sessionItem.SetDisabled(mode == ModeSession)
				offItem.SetLabel(checkedLabel("Off", mode == ModeOff))
				offItem.SetDisabled(mode == ModeOff)

				notifyItem.SetLabel(checkedLabel("Notifications", notifyOn))
				askItem.SetLabel(checkedLabel("Ask before new sites", askOn))
				browseItem.SetLabel(checkedLabel("Advanced: Browse profile", browseOn))

				tray.SetTooltip("DenyOut — " + modeLabel(mode))

				switch {
				case strings.Contains(strings.ToLower(st), "error"), strings.Contains(st, "Needs"):
					tray.SetIcon(iconAlertPNG)
				case mode != ModeOff:
					tray.SetIcon(iconOnPNG)
				default:
					tray.SetIcon(iconIdlePNG)
				}
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready — Computer / Session / Activity / Quit")
	errCh := make(chan error, 1)
	go func() { errCh <- tray.Run() }()

	select {
	case <-ctx.Done():
		a.stopAll()
		a.stopProtect()
		tray.Remove()
		return nil
	case err := <-errCh:
		a.stopAll()
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
