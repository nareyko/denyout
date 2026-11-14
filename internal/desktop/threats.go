package desktop

import (
	"context"
	"fmt"
	"time"

	"github.com/nareyko/denyout/internal/threatlists"
)

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
