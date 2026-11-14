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
		host := strings.TrimSpace(r.Host)
		if host == "" {
			continue
		}
		// Timed allow ended -> ask again (decision dialog).
		go a.handlePostBlockDeny(host, []string{"host_denied"}, "")
	}

	if pauseUntil == "" {
		return
	}
	exp, err := time.Parse(time.RFC3339, pauseUntil)
	if err != nil || now.Before(exp) {
		return
	}
	a.mu.Lock()
	a.state.ProtectPausedUntil = ""
	st2 := a.state
	a.mu.Unlock()
	_ = SaveState(st2)
	if err := a.enableComputerFromTray(); err != nil {
		return
	}
	notify.EmitAction(notify.KindProtectResumed, "DenyOut",
		"Protection is on again.\nUndo to pause again.", 15*time.Second,
		[]notify.Action{{ID: "undo", Label: "Undo"}},
		func(id string) {
			if id != "undo" {
				return
			}
			// Re-open pause presets (same as intentional Off).
			choice := a.chooseProtectPause()
			a.stopProtection()
			a.applyProtectPauseChoice(choice)
		},
	)
}
