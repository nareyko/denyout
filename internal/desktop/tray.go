package desktop

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gogpu/systray"

	"github.com/nareyko/denyout/internal/notify"
)

func (a *App) runTray(ctx context.Context, wizardURL string) error {
	tray := systray.New()
	tray.SetIcon(iconPNG)
	tray.SetTooltip("DenyOut")
	tray.SetAppName("DenyOut")

	menu := systray.NewMenu()
	statusItem := menu.Add("Status: Idle", nil)
	statusItem.SetDisabled(true)
	lastItem := menu.Add("Last block: none", nil)
	lastItem.SetDisabled(true)
	menu.AddSeparator()

	menu.Add("Protect now", func() {
		if err := a.startProtect(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		}
	})
	menu.Add("Stop protected agent", func() {
		a.stopProtect()
	})
	menu.AddSeparator()
	menu.Add("Open setup…", func() {
		openBrowser(wizardURL)
	})
	menu.Add("Toggle notifications", func() {
		a.mu.Lock()
		a.state.Notify = !a.state.Notify
		on := a.state.Notify
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		notify.SetEnabled(on)
		fmt.Fprintf(os.Stderr, "denyout desktop: notifications=%v\n", on)
	})
	menu.AddSeparator()
	menu.Add("Quit DenyOut", func() {
		a.stopProtect()
		tray.Remove()
		os.Exit(0)
	})

	tray.SetMenu(menu)
	tray.Show()

	// Refresh status labels periodically.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				a.stopProtect()
				tray.Remove()
				return
			case <-t.C:
				a.mu.Lock()
				st := a.status
				last := a.lastDeny
				a.mu.Unlock()
				statusItem.SetLabel("Status: " + st)
				if last == "" {
					lastItem.SetLabel("Last block: none")
				} else {
					lastItem.SetLabel("Last block: " + last)
				}
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "denyout desktop: tray ready — Protect now / Open setup / Quit")
	errCh := make(chan error, 1)
	go func() { errCh <- tray.Run() }()

	select {
	case <-ctx.Done():
		a.stopProtect()
		tray.Remove()
		return nil
	case err := <-errCh:
		a.stopProtect()
		return err
	}
}
