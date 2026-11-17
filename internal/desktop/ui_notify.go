package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// UISetNotify toggles notifications (legacy bool -> Quiet / Normal).
func (a *App) UISetNotify(on bool) error {
	if on {
		return a.UISetNotifyLevel("normal")
	}
	return a.UISetNotifyLevel("quiet")
}

// UISetNotifyUIFocused tells the notify package whether the main window is
// focused so non-critical OS toasts stay silent while the user is looking.
// Focus also counts as user activity (clears Away idle).
func (a *App) UISetNotifyUIFocused(on bool) {
	notify.SetUIFocused(on)
	if on {
		a.noteUserActivity()
	} else {
		a.syncAwayNotify()
	}
}

// UISetQuietWhileAway toggles Stay quiet while away (locked/idle).
func (a *App) UISetQuietWhileAway(on bool) error {
	a.mu.Lock()
	a.state.QuietWhileAwayOff = !on
	st := a.state
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	a.syncAwayNotify()
	return nil
}

// UIClearAwayUnread clears the tray "waiting" count (digest dismiss / History).
func (a *App) UIClearAwayUnread() error {
	a.clearAwayUnread()
	return nil
}

// UIDismissAwayDigest dismisses the return digest and clears unread.
func (a *App) UIDismissAwayDigest() error {
	a.clearAwayUnread()
	return nil
}

// awayDigestViewLocked builds AwayDigestView while a.mu is held (GetUISnapshot).
func (a *App) awayDigestViewLocked() *AwayDigestView {
	if !a.awayDigestPending() {
		return nil
	}
	total := a.state.AwayUnreadBlocks
	if total <= 0 {
		return nil
	}
	waiting := a.state.AwayUnreadWaiting
	if waiting < 0 {
		waiting = 0
	}
	if waiting > total {
		waiting = total
	}
	blocks := total - waiting
	hosts := append([]string(nil), a.state.AwayUnreadHosts...)
	if len(hosts) > 5 {
		hosts = hosts[:5]
	}
	waitHosts := append([]string(nil), a.state.AwayUnreadWaitingHosts...)
	if len(waitHosts) > 5 {
		waitHosts = waitHosts[:5]
	}
	return &AwayDigestView{
		Pending:      true,
		Blocks:       blocks,
		Waiting:      waiting,
		Hosts:        hosts,
		WaitingHosts: waitHosts,
	}
}

// UISetNotifyLevel sets quiet | normal | detailed.
func (a *App) UISetNotifyLevel(level string) error {
	a.mu.Lock()
	a.state.NotifyLevel = strings.ToLower(strings.TrimSpace(level))
	if a.state.NotifyLevel == "" {
		a.state.NotifyLevel = "quiet"
	}
	a.state.Notify = a.state.NotifyLevel != "quiet"
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

func activeNotifySnoozeUntil(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || !time.Now().Before(t) {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// UISetNotifySnooze sets temporary OS quiet: "1h" | "tomorrow" | "clear" | "".
// Protection stays on; Ask/Decision in-app still work when Present.
func (a *App) UISetNotifySnooze(choice string) error {
	choice = strings.ToLower(strings.TrimSpace(choice))
	var until time.Time
	switch choice {
	case "", "clear", "off", "none":
		until = time.Time{}
	case "1h", "1hour", "hour":
		until = time.Now().Add(time.Hour)
	case "tomorrow", "until_tomorrow", "until-tomorrow":
		now := time.Now()
		// Local next calendar day 08:00 (after night window).
		y, m, d := now.Date()
		until = time.Date(y, m, d+1, 8, 0, 0, 0, now.Location())
		if !until.After(now) {
			until = until.Add(24 * time.Hour)
		}
	default:
		return fmt.Errorf("Unknown snooze choice")
	}
	a.mu.Lock()
	if until.IsZero() {
		a.state.NotifySnoozeUntil = ""
	} else {
		a.state.NotifySnoozeUntil = until.UTC().Format(time.RFC3339)
	}
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetQuietOvernight toggles no sound at night (default on).
func (a *App) UISetQuietOvernight(on bool) error {
	a.mu.Lock()
	a.state.QuietOvernightOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSoundOnlyAnswer toggles sound only when you must answer (default on).
func (a *App) UISetSoundOnlyAnswer(on bool) error {
	a.mu.Lock()
	a.state.SoundOnlyAnswerOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSystemBanners toggles Allow system banners (protect_failed still passes when off).
func (a *App) UISetSystemBanners(on bool) error {
	a.mu.Lock()
	a.state.SystemBannersOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetRespectFullscreen toggles Respect fullscreen / games (default on).
func (a *App) UISetRespectFullscreen(on bool) error {
	a.mu.Lock()
	a.state.RespectFullscreenOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetSilentWhenOpen toggles silent OS while DenyOut is open (default on).
func (a *App) UISetSilentWhenOpen(on bool) error {
	a.mu.Lock()
	a.state.SilentWhenOpenOff = !on
	st := a.state
	a.mu.Unlock()
	applyNotifyPrefs(st)
	return SaveState(st)
}

// UISetDecisionTimeoutSec sets hard-block decision countdown (seconds).
func (a *App) UISetDecisionTimeoutSec(sec int) error {
	if sec < 5 {
		sec = 5
	}
	if sec > 120 {
		sec = 120
	}
	a.mu.Lock()
	a.state.DecisionTimeoutSec = sec
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UISetReaskIntervalSec sets re-ask / keep-repeat throttle (seconds).
func (a *App) UISetReaskIntervalSec(sec int) error {
	if sec < 15 {
		sec = 15
	}
	if sec > 3600 {
		sec = 3600
	}
	a.mu.Lock()
	a.state.ReaskIntervalSec = sec
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}
