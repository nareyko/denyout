package desktop

import (
	"context"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// startTimedRulesWorker expires timed allow/deny and Protect pause.
func (a *App) startTimedRulesWorker(ctx context.Context) {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		a.sweepTimedRules()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.sweepTimedRules()
			}
		}
	}()
}

func (a *App) sweepTimedRules() {
	now := time.Now()
	a.mu.Lock()
	var expiredAllows []TimedRule
	var expiredDenies []TimedRule
	aliveAllows := a.state.TimedAllows[:0]
	for _, r := range a.state.TimedAllows {
		exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil || !now.Before(exp) {
			expiredAllows = append(expiredAllows, r)
			continue
		}
		aliveAllows = append(aliveAllows, r)
	}
	a.state.TimedAllows = aliveAllows

	aliveDenies := a.state.TimedDenies[:0]
	for _, r := range a.state.TimedDenies {
		exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil || !now.Before(exp) {
			// Timed deny ended -> silent back to policy (no dialog).
			expiredDenies = append(expiredDenies, r)
			continue
		}
		aliveDenies = append(aliveDenies, r)
	}
	a.state.TimedDenies = aliveDenies

	pauseUntil := a.state.ProtectPausedUntil
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	for _, r := range expiredAllows {
		LogBlock("timed_allow_expire", map[string]any{"host": r.Host, "until": r.ExpiresAt})
	}
	for _, r := range expiredDenies {
		LogBlock("timed_deny_expire", map[string]any{"host": r.Host, "reason": r.Reason, "until": r.ExpiresAt})
	}

	if len(expiredAllows) > 0 {
		// Drop temporary allows from proxyd + in-process session + wraps.
		a.mu.Lock()
		wasProxy := a.proxyd != nil
		stillLive := map[string]bool{}
		for _, h := range liveAllowHostsLocked(a.state) {
			stillLive[h] = true
		}
		a.mu.Unlock()
		if wasProxy {
			_ = a.stopComputerOpts(true, false)
			if err := a.startComputer(); err != nil {
				AppendDesktopLog("WARN timed-allow expiry rebind: %v", err)
			}
		}
		for _, r := range expiredAllows {
			host := strings.TrimSpace(r.Host)
			if host == "" {
				continue
			}
			if !stillLive[strings.ToLower(host)] {
				a.revokeHostEverywhere(host)
			}
			notify.Info("DenyOut", "Temporary allow ended for "+host)
		}
	}

	if pauseUntil == "" {
		return
	}
	exp, err := time.Parse(time.RFC3339, pauseUntil)
	if err != nil || now.Before(exp) {
		return
	}
	// User may have turned Protect on during the pause — only resume + toast when still off.
	if a.currentMode() == ModeComputer {
		a.clearProtectPause()
		return
	}
	// Clear pause only after a successful resume. Failed password/admin must not
	// look like a deliberate Off (Home/Settings would drop the Paused label).
	if err := a.enableComputerFromTray(); err != nil {
		// Do not invent a new 1h pause the user never picked. Clear the expired
		// schedule so Home shows Off + Turn on (not a fake "Paused until…").
		a.clearProtectPause()
		notify.Emit(notify.KindProtectFailed, "DenyOut",
			"Could not resume Protect automatically. Turn on from Home when ready.")
		return
	}
	a.mu.Lock()
	agents := normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileAgent
	a.mu.Unlock()
	resumed := "Protect computer is on again.\nUndo to pause again."
	if agents {
		resumed = "Agents only is on again.\nUndo to pause again."
	}
	ttl := notify.ExpireFor(notify.KindProtectResumed)
	if ttl <= 0 {
		ttl = undoOfferDefaultResume
	}
	// Pass 29: Undo only in-app (no OS --action=undo). Open window so the strip is visible.
	a.armUndoOffer(undoOfferResumePause, "", resumed, ttl, func() {
		a.stopProtectionFromTray()
	})
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("home")
	}
}
