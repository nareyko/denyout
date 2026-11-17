package desktop

import (
	"fmt"
	"strings"
)

// ListProfileViews returns profiles with running state.
func (a *App) ListProfileViews() ([]ProfileView, error) {
	list, err := ListProfiles()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ProfileView, 0, len(list))
	for _, p := range list {
		v := ProfileView{AgentProfile: p}
		if w, ok := a.wraps[p.ID]; ok && w != nil && w.cmd != nil && w.cmd.Process != nil {
			v.Running = true
			v.PID = w.cmd.Process.Pid
		}
		out = append(out, v)
	}
	return out, nil
}

// UISaveProfile saves a profile definition.
func (a *App) UISaveProfile(p AgentProfile) error {
	// Keep RequireIsolation and Sandbox aligned (UI checkbox must not leave sandbox=srt).
	if !p.RequireIsolation {
		p.Sandbox = ""
	} else if strings.TrimSpace(p.Sandbox) == "" {
		p.Sandbox = "srt"
	}
	if err := SaveProfile(p); err != nil {
		return err
	}
	return a.reapplyRunningProfile(p.ID)
}

// reapplyRunningProfile restarts a live wrap so disk profile changes take effect.
func (a *App) reapplyRunningProfile(id string) error {
	a.mu.Lock()
	_, running := a.wraps[id]
	a.mu.Unlock()
	if !running {
		return nil
	}
	a.stopProfile(id)
	return a.startProfile(id)
}

// ListAllowPacks returns curated Book A starter packs.
func (a *App) ListAllowPacks() ([]AllowPack, error) {
	return ListAllowPacks()
}

// UIApplyAllowPack merges a pack into a profile (idempotent) and saves.
func (a *App) UIApplyAllowPack(profileID, packID string) ([]string, error) {
	p, err := LoadProfile(profileID)
	if err != nil {
		return nil, err
	}
	added, err := ApplyPack(&p, packID)
	if err != nil {
		return nil, err
	}
	if err := SaveProfile(p); err != nil {
		return nil, err
	}
	if err := a.reapplyRunningProfile(profileID); err != nil {
		return added, err
	}
	if len(added) > 0 {
		LogBlock("pack_allow", map[string]any{"profile_id": profileID, "pack_id": packID, "hosts": added})
	}
	return added, nil
}

// UIUndoAllowPack removes pack-owned hosts from a profile and saves.
func (a *App) UIUndoAllowPack(profileID, packID string) ([]string, error) {
	p, err := LoadProfile(profileID)
	if err != nil {
		return nil, err
	}
	removed, err := UndoPack(&p, packID)
	if err != nil {
		return nil, err
	}
	if err := SaveProfile(p); err != nil {
		return nil, err
	}
	if err := a.reapplyRunningProfile(profileID); err != nil {
		return removed, err
	}
	if len(removed) > 0 {
		LogBlock("pack_undo", map[string]any{"profile_id": profileID, "pack_id": packID, "hosts": removed})
	}
	return removed, nil
}

// UISuggestAllowPack returns a pack id suggestion for name/command (may be empty).
func (a *App) UISuggestAllowPack(name string, command []string) string {
	return SuggestPackID(name, command)
}

// UIDeleteProfile deletes a profile and stops wrap if running.
func (a *App) UIDeleteProfile(id string) error {
	a.stopProfile(id)
	return DeleteProfile(id)
}

// UIStartProfile starts a wrap profile.
func (a *App) UIStartProfile(id string) error {
	return a.startProfile(id)
}

// UIStopProfile stops a running wrap.
func (a *App) UIStopProfile(id string) {
	a.stopProfile(id)
}

// UIPinLearning pins pending hosts for a profile.
func (a *App) UIPinLearning(id string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	if len(p.PendingOnce) == 0 {
		return fmt.Errorf("nothing to pin for %s", p.Name)
	}
	hosts := append([]string{}, p.PendingOnce...)
	p.PinPending(nil)
	// Keep Learning on so future Allow-once hosts can still be collected.
	if err := SaveProfile(p); err != nil {
		return err
	}
	a.applyPinnedLive(id, hosts)
	return nil
}

// UIDiscardLearning discards pending once hosts and revokes them on a live wrap.
func (a *App) UIDiscardLearning(id string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	return a.discardLearningPending(id, &p)
}

// discardLearningPending clears pending Allow-once hosts and revokes them on a
// live wrap so Discard's "stay blocked this run" promise holds (Wails + tray).
func (a *App) discardLearningPending(id string, p *AgentProfile) error {
	if p == nil {
		return fmt.Errorf("profile required")
	}
	hosts := append([]string{}, p.PendingOnce...)
	p.DiscardPending()
	if err := SaveProfile(*p); err != nil {
		return err
	}
	for _, h := range hosts {
		a.revokeWrapHostLive(id, h, false)
	}
	return nil
}
