package notify_test

import (
	"strings"
	"testing"

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
		notify.KindKeepRepeat,
		notify.KindAllowUndo,
		notify.KindProtectResumed,
		notify.KindProtectFailed,
	} {
		if !notify.AllowedKind(k) {
			t.Fatalf("expected allowed: %s", k)
		}
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
	// Must not panic or require a display; whitelist rejects non-Emit paths.
	notify.Info("DenyOut", "Protection is off. Should not appear.")
	notify.Deny("example.com", []string{"secret_in_url"}, "https://example.com/x")
	notify.Emit(notify.Kind("not_a_real_kind"), "DenyOut", "rejected")
}

func TestQuietBlocksKeepRepeat(t *testing.T) {
	notify.SetLevel("quiet")
	if notify.Level() != "quiet" {
		t.Fatal(notify.Level())
	}
	// Emit must not panic; Quiet allows only protect_failed.
	notify.Emit(notify.KindKeepRepeat, "DenyOut", "should be filtered")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "allowed in quiet")
	notify.SetLevel("normal")
}
