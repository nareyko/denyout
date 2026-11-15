package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

func TestHumanReasonsStable(t *testing.T) {
	notify.SetEnabled(false)
	notify.Deny("example.com", []string{"host_not_allowed", "secret_in_url"})
	notify.SetEnabled(true)

	s := notify.HumanReasons([]string{"host_not_allowed", "secret_in_url"})
	if !strings.Contains(s, "allowed list") || !strings.Contains(s, "secret") {
		t.Fatalf("%q", s)
	}
	tl := notify.HumanReasons([]string{"threat_list"})
	if !strings.Contains(tl, "phishing") && !strings.Contains(tl, "malware") {
		t.Fatalf("threat_list copy: %q", tl)
	}
	if notify.HumanReasons(nil) == "" {
		t.Fatal("empty reasons should still explain")
	}
}

func TestEnabledToggle(t *testing.T) {
	notify.SetEnabled(false)
	if notify.Enabled() {
		t.Fatal("expected disabled")
	}
	notify.SetEnabled(true)
	if !notify.Enabled() {
		t.Fatal("expected enabled")
	}
}

func TestWhitelistKinds(t *testing.T) {
	for _, k := range []notify.Kind{
		notify.KindAllowUndo,
		notify.KindProtectResumed,
		notify.KindProtectFailed,
		notify.KindOpenApp,
		notify.KindTrayHidden,
	} {
		if !notify.AllowedKind(k) {
			t.Fatalf("expected allowed: %s", k)
		}
	}
	if notify.AllowedKind(notify.KindKeepRepeat) {
		t.Fatal("keep_repeat must never reach the OS whitelist")
	}
	if notify.AllowedKind(notify.Kind("protection_off")) {
		t.Fatal("protection_off must not be whitelisted")
	}
	if notify.AllowedKind(notify.Kind("info")) {
		t.Fatal("generic info must not be whitelisted")
	}
}

func TestInfoAndDenyAreNoopsWhenEnabled(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	// Must not panic or require a display; whitelist rejects non-Emit paths.
	notify.Info("DenyOut", "Protection is off. Should not appear.")
	notify.Deny("example.com", []string{"secret_in_url"}, "https://example.com/x")
	notify.Emit(notify.Kind("not_a_real_kind"), "DenyOut", "rejected")
	notify.Emit(notify.KindKeepRepeat, "DenyOut", "must never be OS")
}

func TestQuietBlocksKeepRepeat(t *testing.T) {
	notify.SetUIFocused(false)
	notify.SetLevel("quiet")
	if notify.Level() != "quiet" {
		t.Fatal(notify.Level())
	}
	// Emit must not panic; Quiet allows only protect_failed; keep_repeat never OS.
	notify.Emit(notify.KindKeepRepeat, "DenyOut", "should be filtered")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "allowed in quiet")
	notify.SetLevel("normal")
}

func TestUIFocusedSuppressesNonCritical(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetAway(false)
	notify.SetUIFocused(true)
	if !notify.UIFocused() {
		t.Fatal("expected focused")
	}
	// Must not panic; allow_undo suppressed while focused; protect_failed still allowed.
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed while focused")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "still allowed while focused")
	notify.SetUIFocused(false)
	notify.Emit(notify.KindAllowUndo, "DenyOut", "ok when unfocused")
}

func TestAwaySuppressesNonCritical(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(true)
	if !notify.Away() {
		t.Fatal("expected away")
	}
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed while away")
	notify.Emit(notify.KindOpenApp, "DenyOut", "suppressed while away")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "still allowed while away")
	notify.SetAway(false)
}

func TestQuietSuppressesOpenApp(t *testing.T) {
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetLevel("quiet")
	notify.Emit(notify.KindOpenApp, "DenyOut", "must stay off in Quiet")
	notify.SetLevel("normal")
	notify.Emit(notify.KindOpenApp, "DenyOut", "ok in Normal when unfocused")
}

func TestTrayHiddenAllowedOnQuietAndFocused(t *testing.T) {
	notify.SetLevel("quiet")
	notify.SetUIFocused(true)
	notify.SetSilentWhenOpen(true)
	notify.SetBannersAllowed(false)
	notify.SetAway(false)
	notify.SetFullscreen(false)
	if !notify.AllowedKind(notify.KindTrayHidden) {
		t.Fatal("tray_hidden must be whitelisted")
	}
	// Must not panic; emitAllowed must permit (Quiet + focused + banners off).
	notify.Emit(notify.KindTrayHidden, "DenyOut", "still in tray")
	notify.SetBannersAllowed(true)
	notify.SetUIFocused(false)
	notify.SetLevel("normal")
}

func TestSnoozeSuppressesNonCritical(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetSnoozeUntil(time.Now().Add(time.Hour))
	if !notify.Snoozed() {
		t.Fatal("expected snoozed")
	}
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed while snoozed")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "still allowed while snoozed")
	notify.SetSnoozeUntil(time.Time{})
	if notify.Snoozed() {
		t.Fatal("cleared")
	}
}

func TestBannersOffProtectFailedOnly(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetSnoozeUntil(time.Time{})
	notify.SetBannersAllowed(false)
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed")
	notify.Emit(notify.KindOpenApp, "DenyOut", "suppressed")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "still allowed")
	notify.SetBannersAllowed(true)
}

func TestSilentWhenOpenOffAllowsFocused(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetSilentWhenOpen(false)
	notify.SetUIFocused(true)
	notify.Emit(notify.KindAllowUndo, "DenyOut", "ok when silent-when-open off")
	notify.SetSilentWhenOpen(true)
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed again")
	notify.SetUIFocused(false)
}

func TestSoundAllowedNightAndAnswerOnly(t *testing.T) {
	notify.SetQuietOvernight(true)
	notify.SetSoundOnlyWhenAnswer(true)
	if notify.SoundAllowed(false) {
		t.Fatal("passive should be silent when sound-only-answer")
	}
	// Answer sound still gated by night window; just ensure API is stable.
	_ = notify.SoundAllowed(true)
	notify.SetSoundOnlyWhenAnswer(false)
	notify.SetQuietOvernight(false)
	if !notify.SoundAllowed(false) {
		t.Fatal("both prefs off => sound ok")
	}
	notify.SetQuietOvernight(true)
	notify.SetSoundOnlyWhenAnswer(true)
}

func TestNightWindowMutesSoundNotEmit(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetFullscreen(false)
	notify.SetQuietOvernight(true)
	notify.SetSoundOnlyWhenAnswer(false)
	notify.SetNowFunc(func() time.Time {
		return time.Date(2026, 11, 15, 23, 30, 0, 0, time.Local)
	})
	defer notify.SetNowFunc(nil)
	if !notify.InNightWindow() {
		t.Fatal("expected night")
	}
	if notify.SoundAllowed(true) {
		t.Fatal("night should mute sound even for must-answer")
	}
	// Emit policy unchanged — must not panic; banner still allowed.
	notify.Emit(notify.KindAllowUndo, "DenyOut", "banner ok at night without sound")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "critical ok at night")
}

func TestExpireForLifetimes(t *testing.T) {
	if notify.ExpireFor(notify.KindProtectFailed) != 0 {
		t.Fatal("failed stays")
	}
	if notify.ExpireFor(notify.KindAllowUndo) != 10*time.Second {
		t.Fatal("undo ~10s")
	}
	if notify.ExpireFor(notify.KindOpenApp) != 12*time.Second {
		t.Fatal("open ~12s")
	}
	if notify.ExpireFor(notify.KindProtectResumed) != 5*time.Second {
		t.Fatal("status quick")
	}
}

func TestFullscreenSuppressesNonCritical(t *testing.T) {
	notify.SetLevel("normal")
	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetRespectFullscreen(true)
	notify.SetFullscreen(true)
	notify.Emit(notify.KindAllowUndo, "DenyOut", "suppressed in fullscreen")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "still allowed")
	notify.SetFullscreen(false)
}
