package desktop

import (
	"fmt"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

func (a *App) pinLearningUI(id string) {
	p, err := LoadProfile(id)
	if err != nil {
		notify.Info("DenyOut", err.Error())
		return
	}
	if len(p.PendingOnce) == 0 {
		notify.Info("DenyOut", "Nothing to pin for "+p.Name)
		return
	}
	action, ok := nativeListPick(
		"DenyOut - Pin learning",
		fmt.Sprintf("%s learned %d site(s). Pin permanently?", p.Name, len(p.PendingOnce)),
		[]string{
			"Pin all",
			"Discard pending",
			"Keep learning (leave pending)",
			"Cancel",
		},
	)
	if !ok || action == "Cancel" {
		return
	}
	switch action {
	case "Pin all":
		hosts := append([]string{}, p.PendingOnce...)
		p.PinPending(nil)
		// Default after Pin: keep learning No (owner lock).
		p.Learning.Enabled = false
		if err := SaveProfile(p); err != nil {
			notify.Info("DenyOut", err.Error())
			return
		}
		a.applyPinnedLive(id, hosts)
		notify.Info("DenyOut", fmt.Sprintf("Pinned %d site(s) for %s. Learning off - turn on again in profile if needed.", len(hosts), p.Name))
	case "Discard pending":
		p.DiscardPending()
		if err := SaveProfile(p); err != nil {
			notify.Info("DenyOut", err.Error())
			return
		}
		notify.Info("DenyOut", "Discarded pending sites for "+p.Name)
	case "Keep learning (leave pending)":
		notify.Info("DenyOut", "Left pending sites for "+p.Name)
	}
}

func (a *App) applyPinnedLive(id string, hosts []string) {
	a.mu.Lock()
	wp := a.wraps[id]
	a.mu.Unlock()
	if wp != nil && wp.sess != nil {
		for _, h := range hosts {
			wp.sess.AllowHost(h, "user_always")
		}
	}
}

// maybeLearningNudge reminds after learning window.
func (a *App) maybeLearningNudge() {
	list, err := ListProfiles()
	if err != nil {
		return
	}
	for _, p := range list {
		if !p.Learning.Enabled || len(p.PendingOnce) == 0 || p.Learning.StartedAt == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, p.Learning.StartedAt)
		if err != nil {
			continue
		}
		hours := p.Learning.DurationHours
		if hours <= 0 {
			hours = 24
		}
		if time.Since(t) < time.Duration(hours)*time.Hour {
			continue
		}
		notify.Info("DenyOut",
			fmt.Sprintf("%s learning window ended - %d site(s) waiting. Open DenyOut -> My agents to Pin...", p.Name, len(p.PendingOnce)))
		// Nudge once: push started_at forward so we don't spam.
		p.Learning.StartedAt = time.Now().UTC().Format(time.RFC3339)
		_ = SaveProfile(p)
		return
	}
}

// UndoAlwaysAllow removes last always host if present (Always Undo).
func (a *App) undoLastAlwaysAllow() {
	a.mu.Lock()
	hosts := a.state.AlwaysAllowHosts
	if len(hosts) == 0 {
		a.mu.Unlock()
		notify.Info("DenyOut", "Always-allow list is empty.")
		return
	}
	last := hosts[len(hosts)-1]
	a.mu.Unlock()
	a.removeAlwaysHost(last)
	notify.Info("DenyOut", "Undid always-allow: "+last)
}

func (a *App) testProtection() {
	notify.Info("DenyOut", "Test: open a browser and visit a normal site. If Protect computer is on, it should work. A clear block shows Keep blocked / Allow this site for 15 seconds.")
}
