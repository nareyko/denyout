package desktop

import (
	"context"
	"fmt"
	"time"

	"github.com/nareyko/denyout/internal/threatlists"
)

// startThreatPollWorker periodically refreshes due threat feeds so Settings
// "Update every (hours)" is real, not only honored on Protect start / Refresh now.
func (a *App) startThreatPollWorker(ctx context.Context) {
	go func() {
		// First pass soon after launch (never-downloaded feeds are always due).
		t := time.NewTimer(45 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.pollThreatListsOnce()
				t.Reset(30 * time.Minute)
			}
		}
	}()
}

func (a *App) pollThreatListsOnce() {
	st := a.ensureThreatStore(false)
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	u := &threatlists.Updater{Store: st}
	res := u.RefreshEnabled(ctx, false)
	changed := false
	for _, r := range res {
		if r.Skipped {
			continue
		}
		if r.OK {
			changed = true
			AppendDesktopLog("INFO threatlist poll %s: %d entries", r.ID, r.Entries)
		} else if r.Error != "" {
			AppendDesktopLog("WARN threatlist poll %s: %s", r.ID, r.Error)
		}
	}
	if !changed {
		return
	}
	a.syncThreatChecker(st)
	if err := a.rebindThreatsIfProtectOn(); err != nil {
		AppendDesktopLog("WARN threatlist rebind after poll: %v", err)
	}
}

// ensureThreatStore opens (or reuses) Book C cache.
// When forceRefresh is true, also refreshes enabled feeds (Protect start / Refresh now).
func (a *App) ensureThreatStore(forceRefresh bool) *threatlists.Store {
	a.mu.Lock()
	if a.threats != nil && !forceRefresh {
		st := a.threats
		a.mu.Unlock()
		return st
	}
	a.mu.Unlock()

	if !forceRefresh {
		st, err := threatlists.OpenDefault()
		if err != nil {
			AppendDesktopLog("WARN threatlists unavailable: %v", err)
			return nil
		}
		a.mu.Lock()
		a.threats = st
		a.mu.Unlock()
		return st
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	att, err := threatlists.OpenAndRefresh(ctx, true)
	if err != nil {
		AppendDesktopLog("WARN threatlists open: %v", err)
		st, err2 := threatlists.OpenDefault()
		if err2 != nil {
			AppendDesktopLog("WARN threatlists unavailable: %v", err2)
			return nil
		}
		a.mu.Lock()
		a.threats = st
		a.mu.Unlock()
		return st
	}
	for _, r := range att.Refresh {
		if r.Skipped {
			continue
		}
		if r.OK {
			AppendDesktopLog("INFO threatlist %s: %d entries", r.ID, r.Entries)
		} else if r.Error != "" {
			AppendDesktopLog("WARN threatlist %s: %s", r.ID, r.Error)
		}
	}
	a.mu.Lock()
	a.threats = att.Store
	a.mu.Unlock()
	return att.Store
}

func (a *App) threatChecker() *threatlists.Store {
	return a.ensureThreatStore(false)
}

// ThreatNeedsAttention is true when all enabled feeds are stale > 7 days.
func (a *App) ThreatNeedsAttention() bool {
	st := a.threatChecker()
	if st == nil {
		return false
	}
	return (&threatlists.Updater{Store: st}).NeedsAttention()
}

// threatNeedsAttentionLocked uses the already-open store (caller holds a.mu).
// Never call ensureThreatStore here — that would re-lock and deadlock.
func (a *App) threatNeedsAttentionLocked() bool {
	if a.threats == nil {
		return false
	}
	return (&threatlists.Updater{Store: a.threats}).NeedsAttention()
}

func threatAttachLogSummary(st *threatlists.Store) string {
	if st == nil {
		return "none"
	}
	s := st.Status()
	n := 0
	for _, f := range s.Feeds {
		if f.Active {
			n += f.EntryCount
		}
	}
	return fmt.Sprintf("%d active entries", n)
}
