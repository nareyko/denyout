package desktop

import (
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/run"
)

func TestClearProtectPause(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.ProtectPausedUntil = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	a.clearProtectPause()
	if a.state.ProtectPausedUntil != "" {
		t.Fatalf("pause still set: %q", a.state.ProtectPausedUntil)
	}
}

func TestSnapshotHidesPauseWhileProtected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_STATE_HOME", dir)
	pause := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// Intent-only (proxyd dead): keep pause visible so Home/Settings stay honest.
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.Scope = ScopeComputer
	a.state.PolicyProfile = PolicyProfileBrowse
	a.state.ProtectPausedUntil = pause
	snap := a.GetUISnapshot()
	if snap.ProtectPausedUntil == "" {
		t.Fatal("expected pause kept when ProtectionOn intent but protector not live")
	}
	if !snap.ProtectionOn {
		t.Fatal("expected protection_on from ProtectionOn flag")
	}

	// Live session: pause must hide (manual turn-on supersedes schedule).
	a2 := &App{state: DefaultState(), status: "Session", wraps: map[string]*wrapProc{}, session: &run.Session{}}
	a2.state.SetupDone = true
	a2.state.ProtectionOn = true
	a2.state.ProtectPausedUntil = pause
	snap2 := a2.GetUISnapshot()
	if snap2.ProtectPausedUntil != "" {
		t.Fatalf("expected pause hidden while live session, got %q", snap2.ProtectPausedUntil)
	}
}

func TestUIModeRequiresLiveProxyd(t *testing.T) {
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.PolicyProfile = PolicyProfileBrowse
	if uiModeLocked(a) != "off" {
		t.Fatalf("without proxyd mode=%s want off", uiModeLocked(a))
	}
	if !problemsUnhealthyLocked(a) {
		t.Fatal("intended On without proxyd should be unhealthy")
	}
}

func TestSnapshotClearsExpiredAskPause(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_STATE_HOME", dir)
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a.state.SetupDone = true
	a.state.AskPausedUntil = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	a.asks.SetPaused(time.Hour) // stale in-memory pause must clear with expired disk until
	snap := a.GetUISnapshot()
	if snap.AskPaused {
		t.Fatal("expected ask_paused false after expired until")
	}
	if snap.AskPausedUntil != "" {
		t.Fatalf("expected empty ask_paused_until, got %q", snap.AskPausedUntil)
	}
	if a.state.AskPausedUntil != "" {
		t.Fatalf("expected disk ask pause cleared, got %q", a.state.AskPausedUntil)
	}
	if a.asks.Paused() {
		t.Fatal("expected in-memory ask pause cleared")
	}
}
