// Package appstate is the persisted desktop preference model (State), its defaults and
// atomic load/save. It has no UI, tray or proxy dependencies.
package appstate

import (
	"encoding/json"
	"github.com/nareyko/denyout/internal/appdata"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Protection scope.
const (
	ScopeOff      = ""
	ScopeComputer = "computer" // hostguard transparent + system CA (admin)
	ScopeSession  = "session"  // internal fallback only - not a user-facing mode
)

// Policy profiles.
const (
	PolicyProfileAgent  = "agent"  // Agents only - default-deny allowlist
	PolicyProfileBrowse = "browse" // Safe desktop - web OK, scanners on
)

// NormalizePolicyProfile maps any input to a known profile (default: browse).
func NormalizePolicyProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case PolicyProfileAgent:
		return PolicyProfileAgent
	default:
		return PolicyProfileBrowse
	}
}

// State is persisted desktop preferences.
type State struct {
	// SchemaVersion is the on-disk schema version (see migrate.go). 0 = file written
	// before versioning; LoadState migrates it forward and SaveState stamps it.
	SchemaVersion int    `json:"schema_version,omitempty"`
	SetupDone     bool   `json:"setup_done"`
	Notify        bool   `json:"notify"`
	NotifyLevel   string `json:"notify_level,omitempty"` // quiet | normal | detailed
	// QuietWhileAwayOff: when true, Ask/Decision still appear while locked/idle.
	// Default false = stay quiet while away (Presence wave).
	QuietWhileAwayOff bool `json:"quiet_while_away_off,omitempty"`
	// AwayUnreadBlocks / AwayUnreadHosts: suppressed prompts while Away (tray count).
	AwayUnreadBlocks int      `json:"away_unread_blocks,omitempty"`
	AwayUnreadHosts  []string `json:"away_unread_hosts,omitempty"` // auto-kept / block quiet hosts
	// AwayUnreadWaiting: subset of AwayUnreadBlocks that were hard-block "Decide later" while Away.
	AwayUnreadWaiting      int      `json:"away_unread_waiting,omitempty"`
	AwayUnreadWaitingHosts []string `json:"away_unread_waiting_hosts,omitempty"`
	// NotifySnoozeUntil: RFC3339; non-critical OS banners muted until then (Protect stays on).
	NotifySnoozeUntil string `json:"notify_snooze_until,omitempty"`
	// QuietOvernightOff: default false = no sound at night (22:00–08:00).
	QuietOvernightOff bool `json:"quiet_overnight_off,omitempty"`
	// SoundOnlyAnswerOff: default false = sound only when Ask/Decision / Protect failed.
	SoundOnlyAnswerOff bool `json:"sound_only_answer_off,omitempty"`
	// SystemBannersOff: Advanced master; protect_failed still allowed (L7).
	SystemBannersOff bool `json:"system_banners_off,omitempty"`
	// RespectFullscreenOff: default false = respect fullscreen/games.
	RespectFullscreenOff bool `json:"respect_fullscreen_off,omitempty"`
	// SilentWhenOpenOff: default false = stay silent in the system when DenyOut is open.
	SilentWhenOpenOff bool `json:"silent_when_open_off,omitempty"`
	// AllowBrowserQUIC: when true, Protect does not drop UDP/443 (HTTP/3 may bypass MITM).
	// Default false = block QUIC so browsers fall back to TCP that DenyOut can inspect.
	AllowBrowserQUIC bool `json:"allow_browser_quic,omitempty"`
	// TunDataplane: experimental Linux UDP/443 via denyout0 (G3–G5). Default false;
	// also enabled when DENYOUT_TUN_E2E=1. Prefer VM dogfood before flipping on a laptop.
	TunDataplane bool `json:"tun_dataplane,omitempty"`
	// QuicMITM: experimental HTTP/3 decrypt (G6 Q2). Default false; requires TunDataplane
	// (or DENYOUT_TUN_E2E) and DENYOUT_QUIC_MITM=1 or this pref. Cursor hosts stay drop/sight.
	QuicMITM           bool        `json:"quic_mitm,omitempty"`
	AskMode            bool        `json:"ask_mode"`
	PolicyProfile      string      `json:"policy_profile,omitempty"` // browse (Safe desktop) | agent (Agents only)
	ActiveProfileID    string      `json:"active_profile_id,omitempty"`
	Scope              string      `json:"scope,omitempty"`
	ProtectionOn       bool        `json:"protection_on"`
	ComputerEnabled    bool        `json:"computer_enabled"`
	ComputerAvailable  bool        `json:"computer_available"`
	Autostart          bool        `json:"autostart"`
	AutostartAsked     bool        `json:"autostart_asked"`
	UXv2Migrated       bool        `json:"ux_v2_migrated"`
	NotNowReminded     bool        `json:"not_now_reminded"`
	NotNowAt           string      `json:"not_now_at,omitempty"` // RFC3339
	PreferredAgent     string      `json:"preferred_agent,omitempty"`
	CustomCommand      string      `json:"custom_command,omitempty"`
	AlwaysAllowHosts   []string    `json:"always_allow_hosts,omitempty"`
	LastDenyHost       string      `json:"last_deny_host,omitempty"`
	LastDenySummary    string      `json:"last_deny_summary,omitempty"`
	LastDenyURL        string      `json:"last_deny_url,omitempty"`        // redacted
	LastDenyProcess    string      `json:"last_deny_process,omitempty"`    // e.g. wrap:<profileID>
	AskPausedUntil     string      `json:"ask_paused_until,omitempty"`     // RFC3339
	WrapPIDs           []int       `json:"wrap_pids,omitempty"`            // for crash leftover detection
	RememberedKeeps    []string    `json:"remembered_keeps,omitempty"`     // host|reason after Keep forever
	TimedDenies        []TimedRule `json:"timed_denies,omitempty"`         // keep blocked until ExpiresAt
	TimedAllows        []TimedRule `json:"timed_allows,omitempty"`         // allow until ExpiresAt
	DecisionTimeoutSec int         `json:"decision_timeout_sec,omitempty"` // default 15
	ReaskIntervalSec   int         `json:"reask_interval_sec,omitempty"`   // default 60
	ProtectPausedUntil string      `json:"protect_paused_until,omitempty"` // RFC3339; empty = not paused
	ProtectPauseLast   string      `json:"protect_pause_last,omitempty"`   // last Off duration choice
	PostBlockTaught    bool        `json:"post_block_taught,omitempty"`
	YourSetupShown     bool        `json:"your_setup_shown,omitempty"`
	// PendingYourSetup is "safe"|"agents"|"agents_only"|"off" until MarkYourSetupShown (Wails modal copy).
	PendingYourSetup string   `json:"pending_your_setup,omitempty"`
	DismissedTips    []string `json:"dismissed_tips,omitempty"` // tip ids closed forever
	// Program update tip (public manifest; no account).
	UpdateManifestURL      string `json:"update_manifest_url,omitempty"` // empty -> default denyout.com URL
	UpdateAvailableVersion string `json:"update_available_version,omitempty"`
	UpdateAvailableURL     string `json:"update_available_url,omitempty"`
	UpdateAvailableNotes   string `json:"update_available_notes,omitempty"`
	UpdateCheckedAt        string `json:"update_checked_at,omitempty"` // RFC3339
	// Cloud sync (opt-in when signed in) - local copy of syncable prefs.
	RememberedSignalAllows []string `json:"remembered_signal_allows,omitempty"` // host|signal_type
	SensitiveSinksEnabled  *bool    `json:"sensitive_sinks_enabled,omitempty"`  // nil = default ON when feature ships
	SensitiveWritesEnabled *bool    `json:"sensitive_writes_enabled,omitempty"`
	BodyPureA              bool     `json:"body_pure_a,omitempty"`
	AntiChunkEnabled       bool     `json:"anti_chunk_enabled,omitempty"`
	ConfigUpdatedAt        string   `json:"config_updated_at,omitempty"` // RFC3339 for sync LWW
	// Optional denyout.com account (never required for Protect).
	AccountAPIBase string `json:"account_api_base,omitempty"`
	AccountEmail   string `json:"account_email,omitempty"`
	AccountToken   string `json:"account_token,omitempty"` // local session; not synced to cloud blob
	SyncEnabled    bool   `json:"sync_enabled,omitempty"`
	SyncEnabledSet bool   `json:"sync_enabled_set,omitempty"` // distinguish default vs user choice
}

// TimedRule is a temporary allow or deny for a host (optional reason key).
type TimedRule struct {
	Host      string `json:"host"`
	Reason    string `json:"reason,omitempty"` // for denies: post-block reason
	ExpiresAt string `json:"expires_at"`       // RFC3339
}

var stateMu sync.Mutex

// DefaultState returns first-run defaults (Safe desktop UX).
func DefaultState() State {
	return State{
		Notify:            false,
		NotifyLevel:       "quiet", // new installs: OS almost silent (History + tray)
		AskMode:           false,   // Safe desktop: no host Ask
		PolicyProfile:     PolicyProfileBrowse,
		ComputerAvailable: true,
		Autostart:         true,
	}
}

// LoadState reads desktop state (defaults if missing).
func LoadState() State {
	st := DefaultState()
	b, err := os.ReadFile(appdata.StatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	migrate(&st, b)
	return st
}

func jsonHasKey(b []byte, key string) bool {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return false
	}
	_, ok := raw[key]
	return ok
}

// SaveState writes desktop state.
func SaveState(st State) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	if st.SchemaVersion < CurrentSchemaVersion { // never downgrade a newer file's stamp
		st.SchemaVersion = CurrentSchemaVersion
	}
	path := appdata.StatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

// writeFileAtomic writes via a unique temp file in the same directory, fsyncs,
// then renames, so a crash never leaves a truncated state/config file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// AskPaused reports whether host-Ask dialogs are paused.
func (st State) AskPaused() bool {
	if st.AskPausedUntil == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, st.AskPausedUntil)
	if err != nil {
		return false
	}
	return time.Now().Before(t)
}

// NeedsUXv2Migration is true for pre-Safe-desktop installs still on agent without migration ack.
func (st State) NeedsUXv2Migration() bool {
	return st.SetupDone && !st.UXv2Migrated && NormalizePolicyProfile(st.PolicyProfile) == PolicyProfileAgent
}

// PostBlockKey is the stable key of a (host, reason) post-block decision.
func PostBlockKey(host, reason string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strings.TrimSpace(reason)
}

// RememberedKeep reports whether the user chose to keep a block (persisted or timed).
func (st State) RememberedKeep(host, reason string) bool {
	key := PostBlockKey(host, reason)
	for _, k := range st.RememberedKeeps {
		if k == key {
			return true
		}
	}
	now := time.Now()
	for _, t := range st.TimedDenies {
		if PostBlockKey(t.Host, t.Reason) != key {
			continue
		}
		exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
		if err == nil && now.Before(exp) {
			return true
		}
	}
	return false
}
