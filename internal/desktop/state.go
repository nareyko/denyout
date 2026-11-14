package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Protection scope.
const (
	ScopeOff = ""
	ScopeComputer = "computer" // hostguard transparent + system CA (admin)
	ScopeSession = "session" // internal fallback only - not a user-facing mode
)

// State is persisted desktop preferences.
type State struct {
	SetupDone bool `json:"setup_done"`
	Notify bool `json:"notify"`
	NotifyLevel string `json:"notify_level,omitempty"` // quiet | normal | detailed
	AskMode bool `json:"ask_mode"`
	PolicyProfile string `json:"policy_profile,omitempty"` // browse (Safe desktop) | agent (Agents only)
	ActiveProfileID string `json:"active_profile_id,omitempty"`
	Scope string `json:"scope,omitempty"`
	ProtectionOn bool `json:"protection_on"`
	ComputerEnabled bool `json:"computer_enabled"`
	ComputerAvailable bool `json:"computer_available"`
	Autostart bool `json:"autostart"`
	AutostartAsked bool `json:"autostart_asked"`
	UXv2Migrated bool `json:"ux_v2_migrated"`
	NotNowReminded bool `json:"not_now_reminded"`
	NotNowAt string `json:"not_now_at,omitempty"` // RFC3339
	PreferredAgent string `json:"preferred_agent,omitempty"`
	CustomCommand string `json:"custom_command,omitempty"`
	AlwaysAllowHosts []string `json:"always_allow_hosts,omitempty"`
	LastDenyHost string `json:"last_deny_host,omitempty"`
	LastDenySummary string `json:"last_deny_summary,omitempty"`
	LastDenyURL string `json:"last_deny_url,omitempty"` // redacted
	AskPausedUntil string `json:"ask_paused_until,omitempty"` // RFC3339
	WrapPIDs []int `json:"wrap_pids,omitempty"` // for crash leftover detection
	RememberedKeeps []string `json:"remembered_keeps,omitempty"` // host|reason after Keep forever
	TimedDenies []TimedRule `json:"timed_denies,omitempty"` // keep blocked until ExpiresAt
	TimedAllows []TimedRule `json:"timed_allows,omitempty"` // allow until ExpiresAt
	DecisionTimeoutSec int `json:"decision_timeout_sec,omitempty"` // default 15
	ReaskIntervalSec int `json:"reask_interval_sec,omitempty"` // default 60
	ProtectPausedUntil string `json:"protect_paused_until,omitempty"` // RFC3339; empty = not paused
	ProtectPauseLast string `json:"protect_pause_last,omitempty"` // last Off duration choice
	PostBlockTaught bool `json:"post_block_taught,omitempty"`
	YourSetupShown bool `json:"your_setup_shown,omitempty"`
	DismissedTips []string `json:"dismissed_tips,omitempty"` // tip ids closed forever
	// Program update tip (public manifest; no account).
	UpdateManifestURL string `json:"update_manifest_url,omitempty"` // empty -> default denyout.com URL
	UpdateAvailableVersion string `json:"update_available_version,omitempty"`
	UpdateAvailableURL string `json:"update_available_url,omitempty"`
	UpdateAvailableNotes string `json:"update_available_notes,omitempty"`
	UpdateCheckedAt string `json:"update_checked_at,omitempty"` // RFC3339
	// Cloud sync (opt-in when signed in) - local copy of syncable prefs.
	RememberedSignalAllows []string `json:"remembered_signal_allows,omitempty"` // host|signal_type
	SensitiveSinksEnabled *bool `json:"sensitive_sinks_enabled,omitempty"` // nil = default ON when feature ships
	SensitiveWritesEnabled *bool `json:"sensitive_writes_enabled,omitempty"`
	BodyPureA bool `json:"body_pure_a,omitempty"`
	AntiChunkEnabled bool `json:"anti_chunk_enabled,omitempty"`
	ConfigUpdatedAt string `json:"config_updated_at,omitempty"` // RFC3339 for sync LWW
	// Optional denyout.com account (never required for Protect).
	AccountAPIBase string `json:"account_api_base,omitempty"`
	AccountEmail string `json:"account_email,omitempty"`
	AccountToken string `json:"account_token,omitempty"` // local session; not synced to cloud blob
	SyncEnabled bool `json:"sync_enabled,omitempty"`
	SyncEnabledSet bool `json:"sync_enabled_set,omitempty"` // distinguish default vs user choice
}

// TimedRule is a temporary allow or deny for a host (optional reason key).
type TimedRule struct {
	Host string `json:"host"`
	Reason string `json:"reason,omitempty"` // for denies: post-block reason
	ExpiresAt string `json:"expires_at"` // RFC3339
}

var stateMu sync.Mutex

// DefaultState returns first-run defaults (Safe desktop UX).
func DefaultState() State {
	return State{
		Notify: true,
		AskMode: false, // Safe desktop: no host Ask
		PolicyProfile: PolicyProfileBrowse,
		ComputerAvailable: true,
		Autostart: true,
	}
}

// StatePath returns the desktop state file path.
func StatePath() string {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "denyout-desktop.json"
		}
		cfg = filepath.Join(home, ".config")
	}
	return filepath.Join(cfg, "denyout", "desktop.json")
}

// ProfilesDir is ~/.config/denyout/profiles.
func ProfilesDir() string {
	return filepath.Join(filepath.Dir(StatePath()), "profiles")
}

// CADir is the persistent desktop CA directory.
func CADir() string {
	return filepath.Join(filepath.Dir(StatePath()), "ca")
}

// LoadState reads desktop state (defaults if missing).
func LoadState() State {
	st := DefaultState()
	b, err := os.ReadFile(StatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	if st.Scope == "" && st.ComputerEnabled {
		st.Scope = ScopeComputer
		st.ProtectionOn = true
	}
	if !jsonHasKey(b, "computer_available") {
		st.ComputerAvailable = true
	}
	if !jsonHasKey(b, "autostart") && !st.AutostartAsked {
		st.Autostart = true
	}
	// Legacy empty profile -> was agent; migration dialog handles switch to browse.
	if strings.TrimSpace(st.PolicyProfile) == "" {
		st.PolicyProfile = PolicyProfileAgent
	}
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
	path := StatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
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
	return st.SetupDone && !st.UXv2Migrated && normalizePolicyProfile(st.PolicyProfile) == PolicyProfileAgent
}
