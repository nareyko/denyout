package desktop

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/protectstate"
)

const deskPID = 500

func auditEv(ts int64, verb string, lowers bool, peer hostguard.PeerInfo) hostguard.AuditEvent {
	return hostguard.AuditEvent{TS: ts, Verb: verb, Mutating: true, Result: hostguard.AuditOK, Lowers: lowers, Peer: peer}
}

var (
	selfPeer    = hostguard.PeerInfo{PID: deskPID, UID: 1000, Exe: "/home/u/.local/bin/denyout", ExeClass: hostguard.ExeUserInstall, Trusted: true}
	shellPeer   = hostguard.PeerInfo{PID: 901, PPID: 900, UID: 1000, Exe: "/usr/bin/nc", Comm: "nc", ExeClass: hostguard.ExeOther}
	trustedElse = hostguard.PeerInfo{PID: 902, PPID: 900, UID: 1000, Exe: "/usr/lib/denyout/denyout-cli", ExeClass: hostguard.ExeSystem, Trusted: true}
)

func TestEvaluateAudit(t *testing.T) {
	evs := []hostguard.AuditEvent{
		auditEv(10, "apply", false, selfPeer),
		auditEv(20, "remove", true, shellPeer),
		auditEv(30, "remove", true, selfPeer),
	}
	v := evaluateAudit(evs, 0, deskPID)
	if v.maxTS != 30 || v.restoredTS != 10 || v.suspicious == nil || v.suspicious.TS != 20 || v.reason != "untrusted_exe" {
		t.Fatalf("%+v", v)
	}
	if v := evaluateAudit(evs, 20, deskPID); v.suspicious != nil {
		t.Fatalf("events at or below the watermark are already judged: %+v", v)
	}
	// A trusted binary that is not the desktop (or its direct child) is suspicious too.
	v = evaluateAudit([]hostguard.AuditEvent{auditEv(5, "teardown", true, hostguard.PeerInfo{PID: 77, PPID: 76, ExeClass: hostguard.ExeSystem, Trusted: true})}, 0, deskPID)
	if v.suspicious == nil || v.reason != "not_from_desktop" {
		t.Fatalf("%+v", v)
	}
	if v := evaluateAudit(nil, 0, deskPID); v.suspicious != nil || v.maxTS != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestTamperMessageSanitizesPeer(t *testing.T) {
	ev := auditEv(time.Date(2026, 11, 18, 10, 11, 12, 0, time.Local).UnixNano(), "remove", true,
		hostguard.PeerInfo{PID: 31, Exe: "/tmp/\x1b[31mevil\n" + strings.Repeat("x", 100)})
	ti := newTamperInfo(ev, "untrusted_exe")
	if strings.ContainsAny(ti.view.Message, "\x1b\n") || len(ti.view.Exe) > 49 {
		t.Fatalf("%q", ti.view.Message)
	}
	ev.Peer = hostguard.PeerInfo{PID: 8, Exe: "/usr/bin/nc"}
	if got := newTamperInfo(ev, "x").view.Message; got != "Protect was changed by nc (pid 8) at 10:11:12." {
		t.Fatalf("%q", got)
	}
	ev.Peer = hostguard.PeerInfo{PID: 8, Comm: "sh"}
	if !strings.Contains(newTamperInfo(ev, "x").view.Message, "by sh (pid 8)") {
		t.Fatal("comm fallback")
	}
	ev.Peer = hostguard.PeerInfo{PID: 8}
	if !strings.Contains(newTamperInfo(ev, "x").view.Message, "an unknown program (pid 8)") {
		t.Fatal("unknown fallback")
	}
}

func newTamperApp(t *testing.T, live bool) *App {
	t.Helper()
	a := NewApp(Options{Version: "test", NoTray: true})
	a.state.ProtectionOn, a.state.ComputerEnabled = true, true
	if live {
		a.proxyd = &exec.Cmd{} // only its non-nil-ness is read
		t.Cleanup(func() { a.mu.Lock(); a.proxyd = nil; a.mu.Unlock() })
	}
	return a
}

type fakeTail struct {
	events []hostguard.AuditEvent
	calls  int
	err    error
}

func (f *fakeTail) fetch(n int) (hostguard.AuditTail, error) {
	f.calls++
	return hostguard.AuditTail{Events: f.events}, f.err
}

func TestTamperPollNoHelperCallWhenProtectOff(t *testing.T) {
	a := newTamperApp(t, false)
	f := &fakeTail{events: []hostguard.AuditEvent{auditEv(1, "remove", true, shellPeer)}}
	a.tamperPollOnce(f.fetch, deskPID)
	if f.calls != 0 || a.tamper != nil {
		t.Fatalf("calls=%d tamper=%v", f.calls, a.tamper)
	}
}

func TestTamperPollFlagsOnlyNewSuspiciousEvents(t *testing.T) {
	a := newTamperApp(t, true)
	// History from before this Protect session, including an old suspicious event.
	f := &fakeTail{events: []hostguard.AuditEvent{
		auditEv(1, "remove", true, shellPeer),
		auditEv(2, "apply", false, selfPeer),
	}}
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper != nil {
		t.Fatal("history before Protect On must not be judged")
	}
	// The desktop's own lowering call (user pressed Off) is fine.
	f.events = append(f.events, auditEv(3, "fail-policy", true, selfPeer))
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper != nil {
		t.Fatal("own change flagged")
	}
	// A trusted binary run from the desktop's direct child is also fine.
	child := trustedElse
	child.PPID = deskPID
	f.events = append(f.events, auditEv(4, "tun-stop", true, child))
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper != nil {
		t.Fatal("trusted direct child flagged")
	}
	// Another program switches Protect off.
	f.events = append(f.events, auditEv(time.Date(2020, 1, 2, 1, 8, 7, 0, time.Local).UnixNano(), "remove", true, shellPeer))
	a.tamperPollOnce(f.fetch, deskPID)
	a.mu.Lock()
	tv := tamperViewLocked(a)
	res := protectResultLocked(a)
	snapAlert := problemsUnhealthyLocked(a)
	a.mu.Unlock()
	if tv == nil || tv.Message != "Protect was changed by nc (pid 901) at 01:08:07." || tv.Verb != "remove" || tv.Reason != "untrusted_exe" {
		t.Fatalf("%+v", tv)
	}
	if res.State != protectstate.NeedsAttention || res.Reason != protectstate.ReasonTampered || res.Message != tv.Message || !snapAlert {
		t.Fatalf("state: %+v", res)
	}
	snap := a.GetUISnapshot()
	if snap.Tamper == nil || !snap.ProblemsAlert || a.GetProblems().Tamper == nil || !a.GetProblems().Unhealthy {
		t.Fatalf("UI payloads: %+v", snap.Tamper)
	}
	// Re-polling the same trail neither duplicates nor clears the note.
	first := a.tamper.ts
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper == nil || a.tamper.ts != first {
		t.Fatal("note changed on an idempotent poll")
	}
	// The desktop re-applying protection clears it.
	f.events = append(f.events, auditEv(time.Now().UnixNano(), "apply", false, selfPeer))
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper != nil {
		t.Fatal("restore by the desktop must clear the note")
	}
	if a.GetUISnapshot().Tamper != nil {
		t.Fatal("snapshot still shows the note")
	}
}

func TestTamperPollSessionRestartKeepsUnrestoredNoteAndClearsAfterApply(t *testing.T) {
	a := newTamperApp(t, true)
	ti := newTamperInfo(auditEv(50, "remove", true, shellPeer), "untrusted_exe")
	a.tamper = &ti
	f := &fakeTail{events: []hostguard.AuditEvent{auditEv(40, "apply", false, selfPeer), auditEv(50, "remove", true, shellPeer)}}
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper == nil {
		t.Fatal("note lost without a restore")
	}
	// Protect stops and starts again: the poller re-initialises and sees the new apply.
	a.mu.Lock()
	a.proxyd = nil
	a.mu.Unlock()
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamperInit {
		t.Fatal("poller must re-initialise after Protect stops")
	}
	a.mu.Lock()
	a.proxyd = &exec.Cmd{}
	a.mu.Unlock()
	f.events = append(f.events, auditEv(60, "apply", false, selfPeer))
	a.tamperPollOnce(f.fetch, deskPID)
	if a.tamper != nil {
		t.Fatal("apply after the change must clear the note")
	}
}

func TestTamperPollHelperErrorsAreQuiet(t *testing.T) {
	a := newTamperApp(t, true)
	f := &fakeTail{err: errors.New("helper unavailable")}
	a.tamperPollOnce(f.fetch, deskPID)
	if f.calls != 1 || a.tamper != nil || a.tamperInit {
		t.Fatalf("calls=%d tamper=%v init=%v", f.calls, a.tamper, a.tamperInit)
	}
}

func TestUIDismissTamper(t *testing.T) {
	a := newTamperApp(t, true)
	ti := newTamperInfo(auditEv(5, "remove", true, shellPeer), "untrusted_exe")
	a.tamper = &ti
	a.UIDismissTamper()
	a.UIDismissTamper() // idempotent
	if a.tamper != nil || protectResultLocked(a).Reason == protectstate.ReasonTampered {
		t.Fatal("not dismissed")
	}
}

// Without a tamper note the snapshot reasons are exactly what they were before.
func TestNoTamperKeepsStateUntouched(t *testing.T) {
	a := newTamperApp(t, true)
	a.mu.Lock()
	r := protectResultLocked(a)
	a.mu.Unlock()
	if r.Reason == protectstate.ReasonTampered || a.GetUISnapshot().Tamper != nil {
		t.Fatalf("%+v", r)
	}
}
