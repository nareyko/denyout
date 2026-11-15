package desktop

import (
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

func testAppPresence() *App {
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	applyNotifyPrefs(a.state)
	a.initPresence()
	return a
}

func TestAwayIdleSuppressesDecision(t *testing.T) {
	a := testAppPresence()
	if a.isAway() {
		t.Fatal("fresh app must not be Away")
	}
	a.presence.mu.Lock()
	a.presence.lastActivity = time.Now().Add(-awayIdleAfter - time.Second)
	a.presence.mu.Unlock()
	a.syncAwayNotify()
	if !a.isAway() {
		t.Fatal("expected Away after idle")
	}
	if !notify.Away() {
		t.Fatal("notify package should see Away")
	}
	act := a.presentHardBlockDecision(DecisionPrompt{
		Host:   "evil.example",
		Reason: "threat_list",
		Why:    "test",
	})
	if act != DecisionLater {
		t.Fatalf("action=%q", act)
	}
	if a.awayUnreadCount() < 1 {
		t.Fatal("expected unread")
	}
}

func TestAwayAskReturnsDeny(t *testing.T) {
	a := testAppPresence()
	a.setScreenLocked(true)
	if !a.isAway() {
		t.Fatal("locked => Away")
	}
	got := a.coalescedAskProfile("new.example", "host_not_allowed", "Agent", "p1")
	if got != AskDeny {
		t.Fatalf("got %q", got)
	}
	if a.awayUnreadCount() < 1 {
		t.Fatal("expected unread")
	}
}

func TestQuietWhileAwayOffDisablesAway(t *testing.T) {
	a := testAppPresence()
	a.setScreenLocked(true)
	if !a.isAway() {
		t.Fatal("want Away")
	}
	if err := a.UISetQuietWhileAway(false); err != nil {
		t.Fatal(err)
	}
	if a.isAway() {
		t.Fatal("quiet while away off => not Away")
	}
	_ = a.UISetQuietWhileAway(true)
}

func TestNoteUserActivityClearsAway(t *testing.T) {
	a := testAppPresence()
	a.presence.mu.Lock()
	a.presence.lastActivity = time.Now().Add(-awayIdleAfter - time.Minute)
	a.presence.mu.Unlock()
	a.syncAwayNotify()
	if !a.isAway() {
		t.Fatal("want Away")
	}
	a.noteUserActivity()
	if a.isAway() {
		t.Fatal("activity should clear idle Away")
	}
}

func TestClearAwayUnread(t *testing.T) {
	a := testAppPresence()
	a.noteAwayUnread("a.example", awayUnreadBlock)
	a.noteAwayUnread("b.example", awayUnreadWaiting)
	if a.awayUnreadCount() < 2 {
		t.Fatal(a.awayUnreadCount())
	}
	_ = a.UIClearAwayUnread()
	if a.awayUnreadCount() != 0 {
		t.Fatal(a.awayUnreadCount())
	}
}

func TestReturnArmsAwayDigest(t *testing.T) {
	a := testAppPresence()
	a.setScreenLocked(true)
	a.noteAwayUnread("evil.example", awayUnreadBlock)
	a.noteAwayUnread("ask.example", awayUnreadWaiting)
	if a.awayDigestPending() {
		t.Fatal("digest must not arm while still Away")
	}
	a.setScreenLocked(false)
	if !a.awayDigestPending() {
		t.Fatal("return with unread should arm digest")
	}
	a.mu.Lock()
	view := a.awayDigestViewLocked()
	a.mu.Unlock()
	if view == nil || !view.Pending {
		t.Fatal("expected digest view")
	}
	if view.Blocks != 1 || view.Waiting != 1 {
		t.Fatalf("blocks=%d waiting=%d", view.Blocks, view.Waiting)
	}
	if len(view.Hosts) != 1 || view.Hosts[0] != "evil.example" {
		t.Fatalf("block hosts=%v", view.Hosts)
	}
	if len(view.WaitingHosts) != 1 || view.WaitingHosts[0] != "ask.example" {
		t.Fatalf("waiting hosts=%v", view.WaitingHosts)
	}
	_ = a.UIDismissAwayDigest()
	if a.awayDigestPending() || a.awayUnreadCount() != 0 {
		t.Fatal("dismiss should clear digest + unread")
	}
}

func TestReturnNoDigestWithoutUnread(t *testing.T) {
	a := testAppPresence()
	a.setScreenLocked(true)
	a.setScreenLocked(false)
	if a.awayDigestPending() {
		t.Fatal("empty return must not show digest")
	}
}

func TestNotifySnoozeOneHour(t *testing.T) {
	a := testAppPresence()
	if err := a.UISetNotifySnooze("1h"); err != nil {
		t.Fatal(err)
	}
	if !notify.Snoozed() {
		t.Fatal("expected snooze active")
	}
	a.mu.Lock()
	until := a.state.NotifySnoozeUntil
	a.mu.Unlock()
	if until == "" {
		t.Fatal("expected persisted snooze")
	}
	if err := a.UISetNotifySnooze("clear"); err != nil {
		t.Fatal(err)
	}
	if notify.Snoozed() {
		t.Fatal("cleared")
	}
}

func TestSystemBannersAndSilentPrefs(t *testing.T) {
	a := testAppPresence()
	if err := a.UISetSystemBanners(false); err != nil {
		t.Fatal(err)
	}
	if notify.BannersAllowed() {
		t.Fatal("banners should be off")
	}
	if err := a.UISetSilentWhenOpen(false); err != nil {
		t.Fatal(err)
	}
	if notify.SilentWhenOpen() {
		t.Fatal("silent when open should be off")
	}
	_ = a.UISetSystemBanners(true)
	_ = a.UISetSilentWhenOpen(true)
	_ = a.UISetQuietOvernight(true)
	_ = a.UISetSoundOnlyAnswer(true)
	_ = a.UISetRespectFullscreen(true)
}

func TestFullscreenQuietSuppressesDecision(t *testing.T) {
	a := testAppPresence()
	_ = a.UISetRespectFullscreen(true)
	notify.SetFullscreen(true)
	defer notify.SetFullscreen(false)
	if !a.isFullscreenQuiet() {
		t.Fatal("want fullscreen quiet")
	}
	act := a.presentHardBlockDecision(DecisionPrompt{
		Host:   "game.example",
		Reason: "threat_list",
		Why:    "test",
	})
	if act != DecisionLater {
		t.Fatalf("action=%q", act)
	}
	if a.awayUnreadCount() < 1 {
		t.Fatal("expected unread while fullscreen quiet")
	}
	if a.awayDigestPending() {
		t.Fatal("digest should wait until leaving fullscreen")
	}
	notify.SetFullscreen(false)
	a.armQuietReturnDigest()
	if !a.awayDigestPending() {
		t.Fatal("leaving fullscreen with unread should arm return digest")
	}
}

func TestUndoBannerThrottleSameHost(t *testing.T) {
	a := testAppPresence()
	undoBannerMu.Lock()
	undoBannerHost = ""
	undoBannerAt = time.Time{}
	undoBannerMu.Unlock()
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetFullscreen(false)
	notify.SetBannersAllowed(true)

	calls := 0
	a.emitAllowUndoBanner("same.example", "first", func() { calls++ })
	a.emitAllowUndoBanner("same.example", "second", func() { calls++ })
	undoBannerMu.Lock()
	host := undoBannerHost
	undoBannerMu.Unlock()
	if host != "same.example" {
		t.Fatalf("host=%q", host)
	}
	// Second call must be throttled (no second EmitAction wait). calls stay 0 until Undo clicked.
	_ = calls
	a.emitAllowUndoBanner("other.example", "other", nil)
	undoBannerMu.Lock()
	host = undoBannerHost
	undoBannerMu.Unlock()
	if host != "other.example" {
		t.Fatalf("other host should refresh throttle: %q", host)
	}
}
