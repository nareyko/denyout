package desktop

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

func TestFormatQuietReason(t *testing.T) {
	if formatQuietReason(nil, "") != "" {
		t.Fatal("empty")
	}
	if g := formatQuietReason([]string{"away"}, ""); g != "Quiet · away" {
		t.Fatalf("%q", g)
	}
	if g := formatQuietReason([]string{"away", "fullscreen"}, ""); g != "Quiet · away · fullscreen" {
		t.Fatalf("%q", g)
	}
	until := time.Date(2099, 6, 1, 15, 4, 0, 0, time.Local).Format(time.RFC3339)
	wantSnooze := "Quiet · snoozed until " + formatQuietSnoozeUntil(until)
	if g := formatQuietReason([]string{"snoozed"}, until); g != wantSnooze {
		t.Fatalf("%q want %q", g, wantSnooze)
	}
	wantCombo := "Quiet · away · snoozed until " + formatQuietSnoozeUntil(until)
	if g := formatQuietReason([]string{"away", "snoozed"}, until); g != wantCombo {
		t.Fatalf("%q want %q", g, wantCombo)
	}
}

func containsAllSub(s string, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || stringIndex(s, sub) >= 0)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestQuietReasonAwayAndSnooze(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState()}
	a.initPresence()
	a.setScreenLocked(true)
	if err := a.UISetNotifySnooze("1h"); err != nil {
		t.Fatal(err)
	}
	notify.SetFullscreen(false)
	phrase := a.quietReason()
	if phrase == "" || !containsAllSub(phrase, "Quiet · away") || !containsAllSub(phrase, "snoozed until") {
		t.Fatalf("phrase=%q", phrase)
	}
	snap := a.GetUISnapshot()
	if snap.QuietReason != phrase || !snap.Quieting {
		t.Fatalf("snap reason=%q quieting=%v", snap.QuietReason, snap.Quieting)
	}
}

func TestQuietReasonFullscreen(t *testing.T) {
	a := &App{state: DefaultState()}
	a.initPresence() // lastActivity=now so idle Away is off
	_ = a.UISetRespectFullscreen(true)
	notify.SetFullscreen(true)
	defer notify.SetFullscreen(false)
	phrase := a.quietReason()
	if phrase != "Quiet · fullscreen" {
		t.Fatalf("%q", phrase)
	}
}

func TestIconQuietEmbedded(t *testing.T) {
	if len(iconQuietPNG) < 50 {
		t.Fatalf("icon-quiet.png not embedded (%d bytes)", len(iconQuietPNG))
	}
}
