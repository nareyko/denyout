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
		// Match Wails UIPinLearning: keep Learning on for future Allow-once hosts.
		if err := SaveProfile(p); err != nil {
			notify.Info("DenyOut", err.Error())
			return
		}
		a.applyPinnedLive(id, hosts)
		notify.Info("DenyOut", fmt.Sprintf("Pinned %d site(s) for %s.", len(hosts), p.Name))
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

func (a *App) testProtectionMessage() string {
	a.mu.Lock()
	unhealthy := problemsUnhealthyLocked(a)
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	if unhealthy {
		if profile == PolicyProfileAgent {
			return "Agents only did not stay on. Use Try Agents only again on Home or Problems."
		}
		return "Protect did not start correctly. Use Try Protect computer again on Home or Problems."
	}
	mode := a.currentMode()
	switch {
	case mode == ModeComputer && profile == PolicyProfileBrowse:
		return "Protect computer is on. Browse as usual - a clear block shows Keep blocked / Allow this site."
	case mode == ModeComputer:
		return "Agents only is on for the whole PC. Everyday browsing is not covered - use My agents or switch to Protect computer."
	case mode == ModeSession:
		return "Session protection is on (limited proxy). Prefer Protect computer from Home for everyday browsing."
	case a.runningWrapCount() > 0:
		return "Protect computer is off, but a wrapped agent is running. Start Protect computer from Home for everyday browsing."
	default:
		return "Protection is off. Turn on Protect computer from Home, then browse as usual."
	}
}
