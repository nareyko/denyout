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

func (a *App) runTray(ctx context.Context, wizardURL string) error {
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

	menu.Add("Protect this computer", func() {
		if err := a.startComputer(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
			a.setStatus("Needs admin")
		}
	})
	menu.Add("Turn protection off", func() {
		a.stopComputer()
	})
	menu.AddSeparator()
	menu.Add("Settings…", func() {
		openBrowser(wizardURL)
	})
	menu.Add("Advanced: protect a program…", func() {
		openBrowser(wizardURL + "#advanced")
	})
	menu.Add("Stop protected program", func() {
		a.stopProtect()
	})
	menu.AddSeparator()
	menu.Add("Quit DenyOut", func() {
		a.stopComputer()
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
				a.stopComputer()
				a.stopProtect()
				tray.Remove()
				return
			case <-t.C:
				a.mu.Lock()
				st := a.status
				last := a.lastDeny
				on := a.session != nil
				a.mu.Unlock()
				statusItem.SetLabel("Status: " + st)
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
				_ = notify.Enabled()
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready — Protect this computer / Settings / Quit")
	errCh := make(chan error, 1)
	go func() { errCh <- tray.Run() }()

	select {
	case <-ctx.Done():
		a.stopComputer()
		a.stopProtect()
		tray.Remove()
		return nil
	case err := <-errCh:
		a.stopComputer()
		a.stopProtect()
		return err
	}
}
