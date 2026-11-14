package desktop

import (
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/cloudsync"
)

// ThreatSyncPrefs are Book C toggles exported into the sync blob (not full feed cache).
type ThreatSyncPrefs struct {
	BlockPhishing   bool
	BlockMalware    bool
	BlockStronger   bool
	ThreatPollHours int
}

// ExportSyncDocument builds a cloudsync.Document from local desktop state (+ threat prefs).
// Does not include audit events, secrets, account tokens, or update-check tip fields.
func ExportSyncDocument(st State, threat ThreatSyncPrefs, packIDs []string) cloudsync.Document {
	phish, mal, strong := threat.BlockPhishing, threat.BlockMalware, threat.BlockStronger
	return cloudsync.Document{
		SchemaVersion: cloudsync.SchemaVersion,
		UpdatedAt:     syncUpdatedAt(st),
		Settings: cloudsync.Settings{
			NotifyLevel:            effectiveNotifyLevel(st),
			DecisionTimeoutSec:     effectiveDecisionTimeoutSec(st),
			ReaskIntervalSec:       effectiveReaskIntervalSec(st),
			AlwaysAllowHosts:       append([]string(nil), st.AlwaysAllowHosts...),
			RememberedKeeps:        append([]string(nil), st.RememberedKeeps...),
			RememberedSignalAllows: append([]string(nil), st.RememberedSignalAllows...),
			BlockPhishing:          &phish,
			BlockMalware:           &mal,
			BlockStronger:          &strong,
			ThreatPollHours:        threat.ThreatPollHours,
			SensitiveSinksEnabled:  cloneBoolPtr(st.SensitiveSinksEnabled),
			SensitiveWritesEnabled: cloneBoolPtr(st.SensitiveWritesEnabled),
			BodyPureA:              st.BodyPureA,
			AntiChunkEnabled:       st.AntiChunkEnabled,
			AppliedPackIDs:         append([]string(nil), packIDs...),
		},
	}
}

// ApplySyncSettings merges cloud settings into local state (settings fields only).
// Caller persists State and applies threat prefs separately via UISetBlock*.
func ApplySyncSettings(st *State, s cloudsync.Settings) {
	if st == nil {
		return
	}
	if s.NotifyLevel != "" {
		st.NotifyLevel = s.NotifyLevel
		st.Notify = s.NotifyLevel != "quiet"
	}
	if s.DecisionTimeoutSec > 0 {
		st.DecisionTimeoutSec = s.DecisionTimeoutSec
	}
	if s.ReaskIntervalSec > 0 {
		st.ReaskIntervalSec = s.ReaskIntervalSec
	}
	if s.AlwaysAllowHosts != nil {
		st.AlwaysAllowHosts = append([]string(nil), s.AlwaysAllowHosts...)
	}
	if s.RememberedKeeps != nil {
		st.RememberedKeeps = append([]string(nil), s.RememberedKeeps...)
	}
	if s.RememberedSignalAllows != nil {
		st.RememberedSignalAllows = append([]string(nil), s.RememberedSignalAllows...)
	}
	if s.SensitiveSinksEnabled != nil {
		st.SensitiveSinksEnabled = cloneBoolPtr(s.SensitiveSinksEnabled)
	}
	if s.SensitiveWritesEnabled != nil {
		st.SensitiveWritesEnabled = cloneBoolPtr(s.SensitiveWritesEnabled)
	}
	st.BodyPureA = s.BodyPureA
	st.AntiChunkEnabled = s.AntiChunkEnabled
}

// ThreatPrefsFromSettings extracts Book C toggles from sync settings.
func ThreatPrefsFromSettings(s cloudsync.Settings) (prefs ThreatSyncPrefs, ok bool) {
	if s.BlockPhishing == nil && s.BlockMalware == nil && s.BlockStronger == nil && s.ThreatPollHours == 0 {
		return prefs, false
	}
	ok = true
	if s.BlockPhishing != nil {
		prefs.BlockPhishing = *s.BlockPhishing
	}
	if s.BlockMalware != nil {
		prefs.BlockMalware = *s.BlockMalware
	}
	if s.BlockStronger != nil {
		prefs.BlockStronger = *s.BlockStronger
	}
	prefs.ThreatPollHours = s.ThreatPollHours
	return prefs, ok
}

func syncUpdatedAt(st State) time.Time {
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(st.ConfigUpdatedAt)); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
