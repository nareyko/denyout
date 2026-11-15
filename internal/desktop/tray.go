package desktop

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gogpu/systray"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
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
	tray.OnClick(func() {
		go func() {
			a.mu.Lock()
			alert := problemsUnhealthyLocked(a)
			threatWarn := a.threatNeedsAttentionLocked()
			a.mu.Unlock()
			if alert || threatWarn {
				a.RequestOpenUI("problems")
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
		go a.trayEnableProtectComputer()
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

	menu.Add("Quit DenyOut", func() {
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
		// Quit always fully unloads (password OK if needed).
		if err := a.quitUnload(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: quit cancelled or failed: %v\n", err)
			return
		}
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
				pauseUntil := activeProtectPausedUntil(a.state.ProtectPausedUntil)
				pauseLast := a.state.ProtectPauseLast
				leaveOn := a.state.ProtectionOn || a.state.ComputerEnabled
				needsAttention := problemsUnhealthyLocked(a)
				threatWarn := a.threatNeedsAttentionLocked()
				unread := a.state.AwayUnreadBlocks
				snoozeUntil := activeNotifySnoozeUntil(a.state.NotifySnoozeUntil)
				a.mu.Unlock()
				a.pollPresenceOnce()

				snooze1h.SetDisabled(snoozeUntil != "")
				snoozeTomorrow.SetDisabled(snoozeUntil != "")
				clearSnooze.SetDisabled(snoozeUntil == "")

				label := userModeLabel(mode, profile)
				paused := mode == ModeOff && (pauseUntil != "" || pauseLast == "forever")
				agentsIntent := profile == PolicyProfileAgent
				pausePrefix := ""
				if agentsIntent {
					pausePrefix = "Agents only "
				}
				if mode == ModeOff && pauseUntil != "" {
					label = pausePrefix + "Paused"
					if t, err := time.Parse(time.RFC3339, pauseUntil); err == nil {
						local := t.Local()
						// Prefer 12h clock to match typical chrome toLocaleTimeString.
						if local.Format("2006-01-02") == time.Now().Local().Format("2006-01-02") {
							label = pausePrefix + "paused until " + local.Format("3:04 PM")
						} else {
							label = pausePrefix + "paused until " + local.Format("Jan 2, 3:04 PM")
						}
					}
				} else if mode == ModeOff && pauseLast == "forever" {
					if agentsIntent {
						label = "Agents only off until you turn it on"
					} else {
						label = "Off until you turn it on"
					}
				} else if mode == ModeOff && !avail {
					label = "Off (unavailable)"
				}
				if needsAttention {
					label = "Needs attention"
				}
				// Threat-list warn stays in the tooltip (chrome keeps Protected + warn pill).
				statusItem.SetLabel(label)

				computerItem.SetLabel(checkedLabel("Protect computer", mode == ModeComputer && profile == PolicyProfileBrowse))
				computerItem.SetDisabled(mode == ModeComputer && profile == PolicyProfileBrowse)
				// Needs attention is ModeOff with leave-on intent — Off must stay
				// clickable so PauseModal can clear broken Protect (same as Home).
				offNoun := "Protect"
				switch {
				case mode == ModeComputer && profile == PolicyProfileAgent:
					offNoun = "Agents only"
				case mode == ModeSession:
					offNoun = "Session protection"
				case agentsIntent && (paused || mode == ModeOff):
					offNoun = "Agents only"
				}
				if paused {
					offItem.SetLabel("Change " + offNoun + " pause…")
					offItem.SetDisabled(false)
				} else if needsAttention && mode == ModeOff {
					// Match Home/Jump: Clear intent only when Protect is not live.
					if agentsIntent {
						offItem.SetLabel("Clear Agents only intent…")
					} else {
						offItem.SetLabel("Clear Protect intent…")
					}
					offItem.SetDisabled(false)
				} else if needsAttention || (mode == ModeOff && leaveOn) {
					offItem.SetLabel("Pause / turn off " + offNoun + "…")
					offItem.SetDisabled(false)
				} else if mode != ModeOff {
					// Match Home / Settings / Jump: live protector → pause wording, not bare "Off".
					offItem.SetLabel("Pause / turn off " + offNoun + "…")
					offItem.SetDisabled(false)
				} else {
					offItem.SetLabel(checkedLabel("Off", true))
					offItem.SetDisabled(true)
				}

				tooltip := "DenyOut - " + label
				statusExtra := ""
				if snoozeUntil != "" {
					tooltip += " · snoozed"
					statusExtra += " · snoozed"
				}
				if unread > 0 {
					if unread == 1 {
						tooltip += " · 1 quiet"
						statusExtra += " · 1 quiet"
					} else {
						tooltip += fmt.Sprintf(" · %d quiet", unread)
						statusExtra += fmt.Sprintf(" · %d quiet", unread)
					}
				}
				// Mirror chrome mode pill: keep both snoozed and quiet when both apply.
				if !needsAttention && statusExtra != "" {
					statusItem.SetLabel(label + statusExtra)
				}
				tray.SetTooltip(tooltip)

				wrapsRunning := a.runningWrapCount() > 0
				switch {
				case needsAttention, strings.Contains(strings.ToLower(st), "error"), strings.Contains(st, "Needs"):
					tray.SetIcon(iconAlertPNG)
				case mode != ModeOff:
					// Threat-list warn keeps the on icon (chrome: mode pill + warn chip).
					tray.SetIcon(iconOnPNG)
					if threatWarn {
						tray.SetTooltip(tooltip + " · Threat lists need a refresh")
					}
				case threatWarn:
					tray.SetIcon(iconIdlePNG)
					tray.SetTooltip(tooltip + " · Threat lists need a refresh")
				case wrapsRunning:
					// Protect computer is Off — don't imply whole-PC Protect with the on icon.
					tray.SetIcon(iconIdlePNG)
					if !paused && !needsAttention && !threatWarn {
						if mode == ModeOff && !avail {
							// Match chrome: unavailable wins, agents still visible.
							statusItem.SetLabel("Off (unavailable) · agents running")
							tip := "DenyOut - Off (unavailable) · agents running"
							if unread > 0 {
								tip += fmt.Sprintf(" · %d quiet", unread)
							}
							tray.SetTooltip(tip)
						} else if mode == ModeOff && pauseUntil == "" && pauseLast != "forever" {
							tip := "DenyOut - Off · agents running"
							if unread > 0 {
								tip += fmt.Sprintf(" · %d quiet", unread)
							}
							tray.SetTooltip(tip)
							statusItem.SetLabel("Off · agents running")
						}
					}
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
		return "Session"
	default:
		return "Off"
	}
}
