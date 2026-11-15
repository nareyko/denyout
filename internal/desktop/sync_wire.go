package desktop

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/cloudsync"
)

// SyncResult is the outcome of a pull/push attempt.
type SyncResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Pushed  bool   `json:"pushed"`
	Pulled  bool   `json:"pulled"`
}

// UISyncNow pulls remote config, merges last-write-wins with local, applies winner, pushes if needed.
// Signed-out or sync-disabled -> local-only message, no network upload.
func (a *App) UISyncNow() (SyncResult, error) {
	a.mu.Lock()
	acc := accountViewLocked(a)
	cli := a.accountClientLocked()
	cli.Token = a.state.AccountToken
	a.mu.Unlock()

	if !acc.SignedIn {
		return SyncResult{OK: true, Message: "Local only - sign in to sync settings."}, nil
	}
	if !acc.SyncEnabled {
		return SyncResult{OK: true, Message: "Sync is turned off - settings stay on this computer."}, nil
	}

	threat := a.threatSyncPrefs()
	packs := collectAppliedPackIDs()
	a.mu.Lock()
	localDoc := ExportSyncDocument(a.state, threat, packs)
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := cli.GetConfig(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	remote, err := cloudsync.Unmarshal(raw)
	if err != nil {
		return SyncResult{}, fmt.Errorf("remote config: %w", err)
	}

	emptyRemote := remote.UpdatedAt.IsZero() &&
		remote.Settings.NotifyLevel == "" &&
		len(remote.Settings.AlwaysAllowHosts) == 0 &&
		remote.Settings.BlockPhishing == nil
	if emptyRemote {
		return a.pushLocalDoc(ctx, cli, localDoc, true)
	}

	if remote.UpdatedAt.After(localDoc.UpdatedAt) {
		if err := a.applyRemoteDocument(remote); err != nil {
			return SyncResult{}, err
		}
		return SyncResult{OK: true, Message: "Pulled cloud settings (newer on server).", Pulled: true}, nil
	}

	if localDoc.UpdatedAt.Equal(remote.UpdatedAt) {
		localDoc.UpdatedAt = time.Now().UTC()
	}
	return a.pushLocalDoc(ctx, cli, localDoc, false)
}

func (a *App) pushLocalDoc(ctx context.Context, cli *cloudsync.Client, doc cloudsync.Document, firstPush bool) (SyncResult, error) {
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	raw, err := cloudsync.Marshal(doc)
	if err != nil {
		return SyncResult{}, err
	}
	if err := cli.PutConfig(ctx, raw); err != nil {
		return SyncResult{}, err
	}
	a.mu.Lock()
	a.state.ConfigUpdatedAt = doc.UpdatedAt.UTC().Format(time.RFC3339)
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	msg := "Pushed local settings to the cloud."
	if firstPush {
		msg = "Uploaded settings to the cloud (first sync)."
	}
	return SyncResult{OK: true, Message: msg, Pushed: true}, nil
}

func (a *App) applyRemoteDocument(doc cloudsync.Document) error {
	a.mu.Lock()
	ApplySyncSettings(&a.state, doc.Settings)
	a.state.ConfigUpdatedAt = doc.UpdatedAt.UTC().Format(time.RFC3339)
	st := a.state
	prefs, haveThreat := ThreatPrefsFromSettings(doc.Settings)
	needRebind := a.proxyd != nil || a.session != nil
	hosts := append([]string(nil), a.state.AlwaysAllowHosts...)
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	applyNotifyPrefs(st)
	var threatErr error
	if haveThreat {
		if err := a.UISetBlockPhishing(prefs.BlockPhishing); err != nil {
			threatErr = err
		}
		if err := a.UISetBlockMalware(prefs.BlockMalware); err != nil {
			threatErr = err
		}
		if err := a.UISetBlockStronger(prefs.BlockStronger); err != nil {
			threatErr = err
		}
		if prefs.ThreatPollHours > 0 {
			if err := a.UISetThreatPollHours(prefs.ThreatPollHours); err != nil {
				threatErr = err
			}
		}
	}
	// Always-allow hosts must hit live Protect — disk-only merge left proxyd stale.
	if needRebind {
		if err := a.restartActiveProtector(); err != nil {
			AppendDesktopLog("WARN sync rebind after pull: %v", err)
			return fmt.Errorf("synced settings, but Protect could not reload allows: %w", err)
		}
	}
	if threatErr != nil {
		AppendDesktopLog("WARN sync threat prefs: %v", threatErr)
		return fmt.Errorf("synced settings, but threat lists could not fully apply: %w", threatErr)
	}
	for _, h := range hosts {
		a.allowHostOnRunningWraps(h)
	}
	return nil
}

func (a *App) threatSyncPrefs() ThreatSyncPrefs {
	v := a.GetThreatLists()
	return ThreatSyncPrefs{
		BlockPhishing:   v.BlockPhishing,
		BlockMalware:    v.BlockMalware,
		BlockStronger:   v.BlockStronger,
		ThreatPollHours: v.PollHours,
	}
}

func collectAppliedPackIDs() []string {
	list, err := ListProfiles()
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range list {
		for _, ap := range p.AppliedPacks {
			id := strings.TrimSpace(ap.ID)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
