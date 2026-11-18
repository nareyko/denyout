package appstate

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/cloudsync"
	"github.com/nareyko/denyout/internal/protectstate"
)

// ThreatSyncPrefs are Book C toggles exported into the sync blob (not full feed cache).
type ThreatSyncPrefs struct {
	BlockPhishing    bool
	BlockMalware     bool
	BlockStronger    bool
	BlockAdsTrackers bool
	ThreatPollHours  int
}

// ExportSyncDocument builds a cloudsync.Document from local desktop state (+ threat prefs).
// Does not include audit events, secrets, account tokens, or update-check tip fields.
func ExportSyncDocument(st State, threat ThreatSyncPrefs, packIDs []string) cloudsync.Document {
	phish, mal, strong, ads := threat.BlockPhishing, threat.BlockMalware, threat.BlockStronger, threat.BlockAdsTrackers
	return cloudsync.Document{
		SchemaVersion: cloudsync.SchemaVersion,
		UpdatedAt:     syncUpdatedAt(st),
		Settings: cloudsync.Settings{
			NotifyLevel:            EffectiveNotifyLevel(st),
			DecisionTimeoutSec:     EffectiveDecisionTimeoutSec(st),
			ReaskIntervalSec:       EffectiveReaskIntervalSec(st),
			AlwaysAllowHosts:       append([]string(nil), st.AlwaysAllowHosts...),
			RememberedKeeps:        append([]string(nil), st.RememberedKeeps...),
			RememberedSignalAllows: append([]string(nil), st.RememberedSignalAllows...),
			BlockPhishing:          &phish,
			BlockMalware:           &mal,
			BlockStronger:          &strong,
			BlockAdsTrackers:       &ads,
			ThreatPollHours:        threat.ThreatPollHours,
			SensitiveSinksEnabled:  cloneBoolPtr(st.SensitiveSinksEnabled),
			SensitiveWritesEnabled: cloneBoolPtr(st.SensitiveWritesEnabled),
			BodyPureA:              st.BodyPureA,
			AntiChunkEnabled:       st.AntiChunkEnabled,
			FailPolicy:             exportFailPolicy(st),
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
		st.DecisionTimeoutSec = clampInt(s.DecisionTimeoutSec, 1, 3600)
	}
	if s.ReaskIntervalSec > 0 {
		st.ReaskIntervalSec = clampInt(s.ReaskIntervalSec, 1, 86400)
	}
	// Remote lists are untrusted input: validate shape and size so a hostile or
	// buggy sync server cannot inject wildcard / junk allow entries.
	if s.AlwaysAllowHosts != nil {
		st.AlwaysAllowHosts = sanitizeSyncHosts(s.AlwaysAllowHosts)
	}
	if s.RememberedKeeps != nil {
		st.RememberedKeeps = capStrings(s.RememberedKeeps, 500, 253)
	}
	if s.RememberedSignalAllows != nil {
		st.RememberedSignalAllows = capStrings(s.RememberedSignalAllows, 500, 253)
	}
	if s.SensitiveSinksEnabled != nil {
		st.SensitiveSinksEnabled = cloneBoolPtr(s.SensitiveSinksEnabled)
	}
	if s.SensitiveWritesEnabled != nil {
		st.SensitiveWritesEnabled = cloneBoolPtr(s.SensitiveWritesEnabled)
	}
	// Remote sync may only keep or tighten these protections: an absent field
	// decodes as false and must never silently switch them off.
	st.BodyPureA = st.BodyPureA || s.BodyPureA
	st.AntiChunkEnabled = st.AntiChunkEnabled || s.AntiChunkEnabled
	// fail_policy: the remote may only tighten ("closed"). "open", an absent field or
	// any junk is ignored, so a hostile or stale blob can never reopen a strict machine.
	if p, ok := protectstate.ParseFailPolicy(s.FailPolicy); ok && p == protectstate.FailClosed {
		st.FailPolicy = string(protectstate.FailClosed)
	}
}

// exportFailPolicy exports only the strict value; "open"/default is the baseline and
// never needs to be pushed.
func exportFailPolicy(st State) string {
	if NormalizeFailPolicy(st.FailPolicy) == string(protectstate.FailClosed) {
		return string(protectstate.FailClosed)
	}
	return ""
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func capStrings(in []string, maxN, maxLen int) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > maxLen {
			continue
		}
		out = append(out, v)
		if len(out) >= maxN {
			break
		}
	}
	return out
}

var syncHostRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)

// sanitizeSyncHosts keeps plain DNS host names only (no wildcards, schemes,
// ports, IP literals or bare TLDs), max 500 entries.
func sanitizeSyncHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) > 253 || !syncHostRE.MatchString(h) || net.ParseIP(h) != nil {
			continue
		}
		out = append(out, h)
		if len(out) >= 500 {
			break
		}
	}
	return out
}

// ThreatPrefsFromSettings extracts Book C toggles from sync settings.
func ThreatPrefsFromSettings(s cloudsync.Settings) (prefs ThreatSyncPrefs, ok bool) {
	if s.BlockPhishing == nil && s.BlockMalware == nil && s.BlockStronger == nil && s.BlockAdsTrackers == nil && s.ThreatPollHours == 0 {
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
	if s.BlockAdsTrackers != nil {
		prefs.BlockAdsTrackers = *s.BlockAdsTrackers
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

// EffectiveNotifyLevel resolves the notification level (legacy Notify bool fallback).
func EffectiveNotifyLevel(st State) string {
	if strings.TrimSpace(st.NotifyLevel) != "" {
		return st.NotifyLevel
	}
	if st.Notify {
		return "normal"
	}
	return "quiet"
}

// EffectiveDecisionTimeoutSec is the Ask decision timeout (default 15s).
func EffectiveDecisionTimeoutSec(st State) int {
	if st.DecisionTimeoutSec > 0 {
		return st.DecisionTimeoutSec
	}
	return 15
}

// EffectiveReaskIntervalSec is the re-ask interval (default 60s).
func EffectiveReaskIntervalSec(st State) int {
	if st.ReaskIntervalSec > 0 {
		return st.ReaskIntervalSec
	}
	return 60
}
