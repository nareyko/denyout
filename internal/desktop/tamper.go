package desktop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
)

// Owner-uid detection (docs/10-security-boundaries.md, docs/design-security-open-decisions.md 1.D).
//
// The root helper records every mutating request with the peer's pid and executable. While
// Protect is on, the desktop polls that trail and, when a request that LOWERS protection
// (remove, teardown, fail-policy open, tun-stop, uninstall, redirect moved) did not come from
// the desktop itself, raises a notification and a Needs attention reason ("tampered").
// This is detection after the fact, not prevention: a process running as the owner uid can
// still switch Protect off; the user finds out within one poll interval.

// tamperPollEvery is the audit-tail poll period while Protect is on (one local socket call).
const tamperPollEvery = 5 * time.Second

// TamperView is the UI payload for an unacknowledged suspicious change.
type TamperView struct {
	Message string `json:"message"`
	Verb    string `json:"verb"`
	Exe     string `json:"exe"`
	PID     int    `json:"pid"`
	Time    string `json:"time"`   // local HH:MM:SS
	Reason  string `json:"reason"` // untrusted_exe | not_from_desktop
}

type tamperInfo struct {
	ts   int64
	view TamperView
}

// tamperExeName is the peer program name safe to show: basename of the exe, else comm.
func tamperExeName(p hostguard.PeerInfo) string {
	name := filepath.Base(p.Exe)
	if p.Exe == "" || name == "." || name == "/" {
		name = p.Comm
	}
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
		if b.Len() >= 48 {
			break
		}
	}
	if b.Len() == 0 {
		return "an unknown program"
	}
	return b.String()
}

// newTamperInfo describes a suspicious event (message: "Protect was changed by <exe> (pid N) at <time>.").
func newTamperInfo(ev hostguard.AuditEvent, reason string) tamperInfo {
	name := tamperExeName(ev.Peer)
	when := time.Unix(0, ev.TS).Local().Format("15:04:05")
	return tamperInfo{ts: ev.TS, view: TamperView{
		Message: fmt.Sprintf("Protect was changed by %s (pid %d) at %s.", name, ev.Peer.PID, when),
		Verb:    ev.Verb, Exe: name, PID: ev.Peer.PID, Time: when, Reason: reason,
	}}
}

// auditVerdict is the pure outcome of evaluating one audit-tail reply.
type auditVerdict struct {
	maxTS      int64
	suspicious *hostguard.AuditEvent // newest suspicious event after the watermark
	reason     string
	restoredTS int64 // newest successful apply made by the desktop itself (any age)
}

// evaluateAudit scans events (oldest first). Only events newer than watermark can be
// suspicious (older ones were already judged); restoredTS looks at all of them so a
// restore done by the desktop clears an older tamper note.
func evaluateAudit(events []hostguard.AuditEvent, watermark int64, desktopPID int) auditVerdict {
	var v auditVerdict
	for i := range events {
		ev := events[i]
		if ev.TS > v.maxTS {
			v.maxTS = ev.TS
		}
		if ev.Verb == "apply" && ev.Result == hostguard.AuditOK && ev.Peer.FromDesktop(desktopPID) && ev.TS > v.restoredTS {
			v.restoredTS = ev.TS
		}
		if ev.TS <= watermark {
			continue
		}
		if r := hostguard.SuspiciousReason(ev, desktopPID); r != "" {
			e := ev
			v.suspicious, v.reason = &e, r
		}
	}
	return v
}

// startTamperWatch polls the helper's audit trail while Protect is on.
func (a *App) startTamperWatch(ctx context.Context) {
	go func() {
		t := time.NewTicker(tamperPollEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !hostguard.ElevateDisabledByEnv() { // tests/CI never talk to a helper
					a.tamperPollOnce(hostguard.HelperAuditTail, os.Getpid())
				}
			}
		}
	}()
}

// tamperPollOnce runs one poll. fetch and desktopPID are injected for tests. It does
// nothing (and makes no helper call) unless Protect is live (a.proxyd != nil).
func (a *App) tamperPollOnce(fetch func(n int) (hostguard.AuditTail, error), desktopPID int) {
	a.mu.Lock()
	live := a.proxyd != nil
	if !live {
		a.tamperInit = false // next live poll starts from "now" again
	}
	a.mu.Unlock()
	if !live {
		return
	}
	tail, err := fetch(200)
	if err != nil {
		return // helper missing/older: nothing to watch
	}
	a.mu.Lock()
	if !a.tamperInit {
		// Start after the desktop's own Protect On apply: history from before this
		// Protect session is not judged.
		a.tamperMark = evaluateAudit(tail.Events, 1<<62, desktopPID).restoredTS
		if a.tamperMark == 0 {
			a.tamperMark = evaluateAudit(tail.Events, 1<<62, desktopPID).maxTS
		}
		a.tamperInit = true
	}
	v := evaluateAudit(tail.Events, a.tamperMark, desktopPID)
	if v.maxTS > a.tamperMark {
		a.tamperMark = v.maxTS
	}
	if a.tamper != nil && v.restoredTS > a.tamper.ts {
		a.tamper = nil // the desktop re-applied after the change
	}
	var raised *tamperInfo
	if v.suspicious != nil && v.suspicious.TS > v.restoredTS {
		ti := newTamperInfo(*v.suspicious, v.reason)
		a.tamper = &ti
		raised = &ti
	}
	a.mu.Unlock()
	if raised != nil {
		// Never log command lines or payloads: only the validated verb and peer facts.
		LogEvent("protect_tamper", map[string]any{"verb": raised.view.Verb, "exe": raised.view.Exe, "pid": raised.view.PID, "reason": raised.view.Reason})
		notify.Emit(notify.KindProtectFailed, "Protect was changed", raised.view.Message+" Open DenyOut to restore protection.")
	}
}

// tamperViewLocked returns the current note (caller holds a.mu); nil when none.
func tamperViewLocked(a *App) *TamperView {
	if a.tamper == nil {
		return nil
	}
	v := a.tamper.view
	return &v
}

// tamperNoteLocked is the protectstate TamperNote input.
func tamperNoteLocked(a *App) (bool, string) {
	if a.tamper == nil {
		return false, ""
	}
	return true, a.tamper.view.Message
}

// UIDismissTamper acknowledges the note without restoring ("It was me").
func (a *App) UIDismissTamper() {
	a.mu.Lock()
	had := a.tamper != nil
	a.tamper = nil
	a.mu.Unlock()
	if had {
		LogEvent("protect_tamper_dismissed", nil)
	}
}

func (a *App) clearTamper() {
	a.mu.Lock()
	a.tamper = nil
	a.mu.Unlock()
}
