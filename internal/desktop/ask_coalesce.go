package desktop

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

const askDenySuppress = 30 * time.Second
const ipNotifyEvery = 2 * time.Minute
const askTimeout = 2 * time.Minute
const askStormWindow = 5 * time.Minute
const askStormCount = 3
const askPauseDefault = 15 * time.Minute

type askCall struct {
	wg     sync.WaitGroup
	action string
}

// askFlight coalesces Ask per host, serializes dialogs globally, supports pause.
type askFlight struct {
	mu          sync.Mutex
	pending     map[string]*askCall
	suppress    map[string]time.Time
	ipLast      map[string]time.Time
	global      sync.Mutex // one Ask UI at a time
	askTimes    []time.Time
	pausedUntil time.Time
}

func newAskFlight() *askFlight {
	return &askFlight{
		pending:  make(map[string]*askCall),
		suppress: make(map[string]time.Time),
		ipLast:   make(map[string]time.Time),
	}
}

func (f *askFlight) SetPaused(d time.Duration) {
	f.mu.Lock()
	f.pausedUntil = time.Now().Add(d)
	f.mu.Unlock()
}

func (f *askFlight) ClearPause() {
	f.mu.Lock()
	f.pausedUntil = time.Time{}
	f.mu.Unlock()
}

func (f *askFlight) Paused() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Before(f.pausedUntil)
}

func (f *askFlight) PauseRemaining() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := time.Until(f.pausedUntil)
	if d < 0 {
		return 0
	}
	return d
}

func (f *askFlight) Do(host string, fn func() string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "deny"
	}
	f.mu.Lock()
	if time.Now().Before(f.pausedUntil) {
		f.mu.Unlock()
		return "deny"
	}
	if t, ok := f.suppress[host]; ok && time.Now().Before(t) {
		f.mu.Unlock()
		return "deny"
	}
	if c, ok := f.pending[host]; ok {
		f.mu.Unlock()
		c.wg.Wait()
		return c.action
	}
	c := &askCall{}
	c.wg.Add(1)
	f.pending[host] = c
	f.mu.Unlock()

	f.global.Lock()
	action := fn()
	f.global.Unlock()

	if action == "" {
		action = "deny"
	}
	c.action = action

	f.mu.Lock()
	delete(f.pending, host)
	if action == "deny" {
		f.suppress[host] = time.Now().Add(askDenySuppress)
	} else {
		delete(f.suppress, host)
	}
	// Ask storm tracking
	now := time.Now()
	f.askTimes = append(f.askTimes, now)
	cut := now.Add(-askStormWindow)
	n := 0
	for _, t := range f.askTimes {
		if t.After(cut) {
			f.askTimes[n] = t
			n++
		}
	}
	f.askTimes = f.askTimes[:n]
	storm := len(f.askTimes) >= askStormCount
	f.mu.Unlock()
	c.wg.Done()

	if storm {
		go maybeOfferAskPause(f)
	}
	return action
}

var askPauseOfferMu sync.Mutex
var askPauseOfferedAt time.Time

func maybeOfferAskPause(f *askFlight) {
	askPauseOfferMu.Lock()
	if time.Since(askPauseOfferedAt) < askStormWindow {
		askPauseOfferMu.Unlock()
		return
	}
	askPauseOfferedAt = time.Now()
	askPauseOfferMu.Unlock()
	if nativeConfirm(
		"DenyOut",
		"Many permission prompts in a short time.\n\nPause asks for 15 minutes? New sites stay blocked until you resume.",
		"Pause asks",
		"Keep asking",
	) {
		f.SetPaused(askPauseDefault)
		notify.Info("DenyOut", "Asks paused for 15 minutes. New sites stay blocked. Resume from Settings -> Advanced.")
	}
}

func (f *askFlight) notifyIPBlocked(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	now := time.Now()
	f.mu.Lock()
	if t, ok := f.ipLast[host]; ok && now.Sub(t) < ipNotifyEvery {
		f.mu.Unlock()
		return
	}
	f.ipLast[host] = now
	f.mu.Unlock()
	notify.Info("DenyOut blocked a direct IP",
		host+"\nConnections by raw IP are blocked in this mode. Prefer Protect computer for everyday apps.")
}

func (a *App) coalescedAsk(host, reason string) string {
	return a.coalescedAskProfile(host, reason, "")
}

func (a *App) coalescedAskProfile(host, reason, profileName string) string {
	if a.asks == nil {
		a.asks = newAskFlight()
	}
	if a.state.AskPaused() || a.asks.Paused() {
		return "deny"
	}
	if net.ParseIP(strings.TrimSpace(host)) != nil {
		a.asks.notifyIPBlocked(host)
		return "deny"
	}
	return a.asks.Do(host, func() string {
		return askViaToastThenDialog(host, reason, profileName)
	})
}
