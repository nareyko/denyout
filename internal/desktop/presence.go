package desktop

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

const awayIdleAfter = 5 * time.Minute

// awayUnreadKind classifies a suppressed Away event for the return digest.
type awayUnreadKind string

const (
	awayUnreadBlock   awayUnreadKind = "block"   // auto-kept / keep-repeat
	awayUnreadWaiting awayUnreadKind = "waiting" // hard-block Decide later
)

// Presence / Away (notify-presence wave Phase B+C).
// Stay quiet while away (default on): no Ask/Decision popups; tray unread grows.
// Return: one in-app digest when Present again with unread.
type presence struct {
	mu            sync.Mutex
	lastActivity  time.Time
	screenLocked  bool
	away          bool // last computed, for notify.SetAway edge updates
	digestPending bool // Armed on Away→Present when unread > 0
	softOpenSent  bool // Soft OS Open once per return cycle
	fsDetectOK    bool // last probeFullscreen ok (honest Settings)
	fsActive      bool // last known fullscreen when fsDetectOK
}

func (a *App) initPresence() {
	a.presence.mu.Lock()
	a.presence.lastActivity = time.Now()
	a.presence.mu.Unlock()
	a.syncAwayNotify()
}

// noteUserActivity records that the user is interacting with the UI.
func (a *App) noteUserActivity() {
	a.presence.mu.Lock()
	a.presence.lastActivity = time.Now()
	wasLocked := a.presence.screenLocked
	a.presence.mu.Unlock()
	if wasLocked {
		// Unlock often arrives as activity before LockedHint clears.
		a.setScreenLocked(false)
	} else {
		a.syncAwayNotify()
	}
}

func (a *App) setScreenLocked(on bool) {
	a.presence.mu.Lock()
	a.presence.screenLocked = on
	if !on {
		a.presence.lastActivity = time.Now()
	}
	a.presence.mu.Unlock()
	a.syncAwayNotify()
}

func (a *App) stayQuietWhileAway() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.state.QuietWhileAwayOff
}

// isAway reports whether DenyOut should suppress Ask/Decision and grow tray unread.
func (a *App) isAway() bool {
	a.mu.Lock()
	off := a.state.QuietWhileAwayOff
	a.mu.Unlock()
	if off {
		return false
	}
	return a.awaySignals()
}

// isAwayLocked is isAway while the caller already holds a.mu.
func (a *App) isAwayLocked() bool {
	if a.state.QuietWhileAwayOff {
		return false
	}
	return a.awaySignals()
}

func (a *App) awaySignals() bool {
	a.presence.mu.Lock()
	locked := a.presence.screenLocked
	idle := time.Since(a.presence.lastActivity) >= awayIdleAfter
	a.presence.mu.Unlock()
	return locked || idle
}

func (a *App) syncAwayNotify() {
	away := a.isAway()
	a.presence.mu.Lock()
	prev := a.presence.away
	a.presence.away = away
	a.presence.mu.Unlock()
	if prev == away {
		return
	}
	notify.SetAway(away)
	if away {
		// Entering Away: next return may soft-open again.
		a.presence.mu.Lock()
		a.presence.softOpenSent = false
		a.presence.mu.Unlock()
		return
	}
	// Away → Present: arm return digest if something waited.
	a.armQuietReturnDigest()
}

// armQuietReturnDigest marks a return summary when quiet items waited (Away or fullscreen).
func (a *App) armQuietReturnDigest() {
	if a.awayUnreadCount() <= 0 {
		return
	}
	a.presence.mu.Lock()
	a.presence.digestPending = true
	a.presence.mu.Unlock()
	a.maybeSoftOpenReturn()
}

func (a *App) maybeSoftOpenReturn() {
	a.presence.mu.Lock()
	if a.presence.softOpenSent || !a.presence.digestPending {
		a.presence.mu.Unlock()
		return
	}
	a.presence.softOpenSent = true
	a.presence.mu.Unlock()

	// Quiet → tray + in-app only. Soft Open only when Normal+ and UI not in front.
	if notify.Level() == "quiet" || notify.UIFocused() {
		return
	}
	n := a.awayUnreadCount()
	if n <= 0 {
		return
	}
	body := "Quiet items waiting — switch to DenyOut to review."
	if n == 1 {
		body = "1 quiet item waiting. Switch to DenyOut."
	} else if n > 1 {
		body = fmt.Sprintf("%d quiet items waiting. Switch to DenyOut.", n)
	}
	notify.EmitAction(notify.KindOpenApp, "DenyOut", body, 12*time.Second,
		[]notify.Action{{ID: "open", Label: "Open"}},
		func(id string) {
			if id == "open" {
				a.RequestOpenUI("home")
			}
		},
	)
}

func appendAwayHost(list *[]string, host string) {
	if host == "" {
		return
	}
	for _, h := range *list {
		if h == host {
			return
		}
	}
	*list = append(*list, host)
	if len(*list) > 20 {
		*list = (*list)[len(*list)-20:]
	}
}

func (a *App) noteAwayUnread(host string, kind awayUnreadKind) {
	host = strings.TrimSpace(host)
	if kind == "" {
		kind = awayUnreadBlock
	}
	a.mu.Lock()
	a.state.AwayUnreadBlocks++
	if kind == awayUnreadWaiting {
		a.state.AwayUnreadWaiting++
		appendAwayHost(&a.state.AwayUnreadWaitingHosts, host)
	} else {
		appendAwayHost(&a.state.AwayUnreadHosts, host)
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
}

func (a *App) awayUnreadCount() int {
	a.mu.Lock()
	n := a.state.AwayUnreadBlocks
	a.mu.Unlock()
	if n < 0 {
		return 0
	}
	return n
}

func (a *App) awayDigestPending() bool {
	a.presence.mu.Lock()
	defer a.presence.mu.Unlock()
	return a.presence.digestPending
}

func (a *App) clearAwayUnread() {
	a.mu.Lock()
	a.state.AwayUnreadBlocks = 0
	a.state.AwayUnreadWaiting = 0
	a.state.AwayUnreadHosts = nil
	a.state.AwayUnreadWaitingHosts = nil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	a.presence.mu.Lock()
	a.presence.digestPending = false
	a.presence.mu.Unlock()
}

// pollPresenceOnce refreshes lock hint + away flag (tray ticker / tests).
func (a *App) pollPresenceOnce() {
	if locked, ok := probeScreenLocked(); ok {
		a.setScreenLocked(locked)
	} else {
		a.syncAwayNotify()
	}
	a.pollFullscreenOnce()
}

// pollFullscreenOnce updates notify.Fullscreen when a detector is available.
// Leaving fullscreen with quiet unread arms the same return digest as Away→Present.
// When detection is unavailable, clear fullscreen so we do not fake quiet.
func (a *App) pollFullscreenOnce() {
	fs, ok := probeFullscreen()
	a.presence.mu.Lock()
	a.presence.fsDetectOK = ok
	a.presence.fsActive = ok && fs
	a.presence.mu.Unlock()
	if !ok {
		if notify.Fullscreen() {
			notify.SetFullscreen(false)
		}
		return
	}
	was := notify.Fullscreen()
	notify.SetFullscreen(fs)
	if was && !fs {
		a.armQuietReturnDigest()
	}
}

// fullscreenDetectOK reports whether the last poll could see fullscreen state.
func (a *App) fullscreenDetectOK() bool {
	a.presence.mu.Lock()
	defer a.presence.mu.Unlock()
	return a.presence.fsDetectOK
}

// sessionLooksWayland is used for honest Settings copy (not probe order).
func sessionLooksWayland() bool {
	if strings.EqualFold(os.Getenv("XDG_SESSION_TYPE"), "wayland") {
		return true
	}
	return strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
}

// isFullscreenQuiet: Respect fullscreen is on and a fullscreen app is in front.
// Suppress Ask/Decision steal-focus; tray unread grows (like Away).
func (a *App) isFullscreenQuiet() bool {
	return notify.Fullscreen() && notify.RespectFullscreen()
}
