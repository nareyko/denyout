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
	tray.SetTooltip("DenyOut")
	tray.SetAppName("DenyOut")

	menu := systray.NewMenu()
	statusItem := menu.Add("Status: Off", nil)
	statusItem.SetDisabled(true)
	lastItem := menu.Add("Last block: none", nil)
	lastItem.SetDisabled(true)
	menu.AddSeparator()

	menu.Add("Protect whole computer", func() {
		a.enableComputerFromTray()
	})
	menu.Add("Protect this session (proxy)", func() {
		a.enableSessionFromTray()
	})
	menu.Add("Turn protection off", func() {
		a.stopProtection()
	})
	menu.AddSeparator()

	menu.Add("Settings: toggle notifications", func() {
		a.mu.Lock()
		a.state.Notify = !a.state.Notify
		on := a.state.Notify
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.SetEnabled(on)
		fmt.Fprintf(os.Stderr, "denyout desktop: notifications=%v\n", on)
	})
	menu.Add("Settings: toggle Ask before new sites", func() {
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
	menu.Add("Open logs…", func() {
		openLogsOrPrint()
	})
	menu.Add("Copy last error", func() {
		copyLastErrorOrPrint()
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
				a.stopProtection()
				a.stopProtect()
				tray.Remove()
				return
			case <-t.C:
				a.mu.Lock()
				st := a.status
				last := a.lastDeny
				on := a.session != nil || a.proxyd != nil
				scope := a.state.Scope
				avail := a.state.ComputerAvailable
				a.mu.Unlock()
				label := st
				if on && scope == ScopeSession {
					label = "Session (proxy)"
				}
				if on && scope == ScopeComputer {
					label = "Computer"
				}
				if !avail && !on {
					label = "Off (computer unavailable)"
				}
				statusItem.SetLabel("Status: " + label)
				if last == "" {
					lastItem.SetLabel("Last block: none")
				} else {
					lastItem.SetLabel("Last block: " + last)
				}
				switch {
				case strings.Contains(strings.ToLower(st), "error"), strings.Contains(st, "Needs"):
					tray.SetIcon(iconAlertPNG)
				case on:
					tray.SetIcon(iconOnPNG)
				default:
					tray.SetIcon(iconIdlePNG)
				}
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready — Computer / Session / Logs / Quit")
	errCh := make(chan error, 1)
	go func() { errCh <- tray.Run() }()

	select {
	case <-ctx.Done():
		a.stopProtection()
		a.stopProtect()
		tray.Remove()
		return nil
	case err := <-errCh:
		a.stopProtection()
		a.stopProtect()
		return err
	}
}
