package desktop

import (
	"testing"
	"time"
)

func TestTrayView(t *testing.T) {
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.Local)
	today := now.Add(2 * time.Hour)
	later := now.Add(48 * time.Hour)
	base := func(f func(*trayInputs)) trayInputs {
		in := trayInputs{Mode: ModeOff, Profile: PolicyProfileBrowse, Avail: true, Now: now}
		if f != nil {
			f(&in)
		}
		return in
	}
	cases := []struct {
		name                   string
		in                     trayInputs
		status, tip, off, comp string
		icon                   trayIcon
		offDis, compDis        bool
	}{
		{"off", base(nil), "Off", "DenyOut - Off", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"off leave-on", base(func(i *trayInputs) { i.LeaveOn = true }), "Off", "DenyOut - Off", "Pause / turn off Protect…", "Protect computer", trayIconIdle, false, false},
		{"unavailable", base(func(i *trayInputs) { i.Avail = false }), "Off (unavailable)", "DenyOut - Off (unavailable)", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"protected", base(func(i *trayInputs) { i.Mode = ModeComputer }), "Protected", "DenyOut - Protected", "Pause / turn off Protect…", "Protect computer ✓", trayIconOn, false, true},
		{"agents only live", base(func(i *trayInputs) { i.Mode = ModeComputer; i.Profile = PolicyProfileAgent }), "Agents only", "DenyOut - Agents only", "Pause / turn off Agents only…", "Protect computer", trayIconOn, false, false},
		{"session", base(func(i *trayInputs) { i.Mode = ModeSession }), "Session", "DenyOut - Session", "Pause / turn off Session protection…", "Protect computer", trayIconOn, false, false},
		{"paused today", base(func(i *trayInputs) { i.PauseUntil = today.UTC().Format(time.RFC3339) }), "paused until " + today.Format("15:04"), "DenyOut - paused until " + today.Format("15:04"), "Change Protect pause…", "Protect computer", trayIconIdle, false, false},
		{"paused later agents", base(func(i *trayInputs) { i.Profile = PolicyProfileAgent; i.PauseUntil = later.UTC().Format(time.RFC3339) }), "Agents only paused until " + later.Format("Jan 2, 15:04"), "DenyOut - Agents only paused until " + later.Format("Jan 2, 15:04"), "Change Agents only pause…", "Protect computer", trayIconIdle, false, false},
		{"paused bad time", base(func(i *trayInputs) { i.PauseUntil = "garbage" }), "Paused", "DenyOut - Paused", "Change Protect pause…", "Protect computer", trayIconIdle, false, false},
		{"paused bad time agents", base(func(i *trayInputs) { i.PauseUntil = "garbage"; i.Profile = PolicyProfileAgent }), "Agents only Paused", "DenyOut - Agents only Paused", "Change Agents only pause…", "Protect computer", trayIconIdle, false, false},
		{"forever", base(func(i *trayInputs) { i.PauseLast = "forever" }), "Off until you turn it on", "DenyOut - Off until you turn it on", "Change Protect pause…", "Protect computer", trayIconIdle, false, false},
		{"forever agents", base(func(i *trayInputs) { i.PauseLast = "forever"; i.Profile = PolicyProfileAgent }), "Agents only off until you turn it on", "DenyOut - Agents only off until you turn it on", "Change Agents only pause…", "Protect computer", trayIconIdle, false, false},
		{"needs attention", base(func(i *trayInputs) {
			i.NeedsAttention = true
			i.LeaveOn = true
			i.QuietPhrase = "away"
			i.Unread = 3
			i.UndoActive = true
		}), "Needs attention", "DenyOut - Needs attention", "Clear Protect intent…", "Protect computer", trayIconAlert, false, false},
		{"needs attention agents", base(func(i *trayInputs) { i.NeedsAttention = true; i.Profile = PolicyProfileAgent }), "Needs attention", "DenyOut - Needs attention", "Clear Agents only intent…", "Protect computer", trayIconAlert, false, false},
		{"needs attention live", base(func(i *trayInputs) { i.NeedsAttention = true; i.Mode = ModeComputer }), "Needs attention", "DenyOut - Needs attention", "Pause / turn off Protect…", "Protect computer ✓", trayIconAlert, false, true},
		{"status error", base(func(i *trayInputs) { i.Mode = ModeComputer; i.Status = "Some Error" }), "Protected", "DenyOut - Protected", "Pause / turn off Protect…", "Protect computer ✓", trayIconAlert, false, true},
		{"status Needs", base(func(i *trayInputs) { i.Status = "Needs password" }), "Off", "DenyOut - Off", "Off ✓", "Protect computer", trayIconAlert, true, false},
		{"quiet one", base(func(i *trayInputs) { i.Mode = ModeComputer; i.QuietPhrase = "away"; i.Unread = 1 }), "Protected · away · 1 quiet", "DenyOut - Protected · away · 1 quiet", "Pause / turn off Protect…", "Protect computer ✓", trayIconQuiet, false, true},
		{"quiet many undo threat", base(func(i *trayInputs) {
			i.Mode = ModeComputer
			i.QuietPhrase = "fullscreen"
			i.Unread = 5
			i.UndoActive = true
			i.ThreatWarn = true
		}), "Protected · fullscreen · 5 quiet · Undo", "DenyOut - Protected · fullscreen · 5 quiet · Undo available — open DenyOut · Threat lists need a refresh", "Pause / turn off Protect…", "Protect computer ✓", trayIconQuiet, false, true},
		{"snooze fallback", base(func(i *trayInputs) { i.Mode = ModeSession; i.SnoozeUntil = "x" }), "Session · snoozed", "DenyOut - Session · snoozed", "Pause / turn off Session protection…", "Protect computer", trayIconOn, false, false},
		{"on threat", base(func(i *trayInputs) { i.Mode = ModeSession; i.ThreatWarn = true }), "Session", "DenyOut - Session · Threat lists need a refresh", "Pause / turn off Session protection…", "Protect computer", trayIconOn, false, false},
		{"idle threat", base(func(i *trayInputs) { i.ThreatWarn = true; i.WrapsRunning = true }), "Off", "DenyOut - Off · Threat lists need a refresh", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"idle unread undo", base(func(i *trayInputs) { i.Unread = 2; i.UndoActive = true }), "Off · 2 quiet · Undo", "DenyOut - Off · 2 quiet · Undo available — open DenyOut", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"agents running", base(func(i *trayInputs) { i.WrapsRunning = true }), "Off · agents running", "DenyOut - Off · agents running", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"agents running snooze quiet", base(func(i *trayInputs) { i.WrapsRunning = true; i.SnoozeUntil = "x"; i.Unread = 1 }), "Off · agents running · snoozed · 1 quiet", "DenyOut - Off · agents running · snoozed · 1 quiet", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"agents running unavailable", base(func(i *trayInputs) { i.WrapsRunning = true; i.Avail = false; i.Unread = 4 }), "Off (unavailable) · agents running · 4 quiet", "DenyOut - Off (unavailable) · agents running · 4 quiet", "Off ✓", "Protect computer", trayIconIdle, true, false},
		{"agents running but paused", base(func(i *trayInputs) { i.WrapsRunning = true; i.PauseLast = "forever" }), "Off until you turn it on", "DenyOut - Off until you turn it on", "Change Protect pause…", "Protect computer", trayIconIdle, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := trayView(c.in)
			if m.StatusLabel != c.status || m.Tooltip != c.tip || m.OffLabel != c.off || m.ComputerLabel != c.comp ||
				m.Icon != c.icon || m.OffDisabled != c.offDis || m.ComputerOff != c.compDis {
				t.Fatalf("got %+v", m)
			}
		})
	}
}

func TestTrayViewSnoozeItems(t *testing.T) {
	m := trayView(trayInputs{Mode: ModeOff, Now: time.Now()})
	if m.Snooze1hOff || m.SnoozeTomorrowOff || !m.ClearSnoozeOff {
		t.Fatalf("%+v", m)
	}
	m = trayView(trayInputs{Mode: ModeOff, SnoozeUntil: "x", Now: time.Now()})
	if !m.Snooze1hOff || !m.SnoozeTomorrowOff || m.ClearSnoozeOff {
		t.Fatalf("%+v", m)
	}
}

func TestTrayIconBytes(t *testing.T) {
	for _, i := range []trayIcon{trayIconIdle, trayIconOn, trayIconQuiet, trayIconAlert} {
		if len(trayIconBytes(i)) == 0 {
			t.Fatal(i)
		}
	}
}
