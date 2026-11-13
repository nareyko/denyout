package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Protection scope.
const (
	ScopeOff      = ""
	ScopeComputer = "computer" // hostguard transparent + system CA (admin)
	ScopeSession  = "session"  // local proxy + env (no admin)
)

// State is persisted desktop preferences.
type State struct {
	SetupDone         bool     `json:"setup_done"`
	Notify            bool     `json:"notify"`
	AskMode           bool     `json:"ask_mode"`
	Scope             string   `json:"scope,omitempty"`              // computer | session | empty
	ProtectionOn      bool     `json:"protection_on"`               // restore on login
	ComputerEnabled   bool     `json:"computer_enabled"`            // legacy / mirror of scope=computer+on
	ComputerAvailable bool     `json:"computer_available"`          // false after elevation fail until retry
	PreferredAgent    string   `json:"preferred_agent,omitempty"`   // advanced: claude|cursor|shell|custom
	CustomCommand     string   `json:"custom_command,omitempty"`
	AlwaysAllowHosts  []string `json:"always_allow_hosts,omitempty"`
	LastDenyHost      string   `json:"last_deny_host,omitempty"`
	LastDenySummary   string   `json:"last_deny_summary,omitempty"`
}

var stateMu sync.Mutex

// DefaultState returns first-run defaults.
func DefaultState() State {
	return State{
		Notify:            true,
		AskMode:           false,
		ComputerAvailable: true,
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

// CADir is the persistent desktop CA directory.
func CADir() string {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join("denyout-ca")
		}
		cfg = filepath.Join(home, ".config")
	}
	return filepath.Join(cfg, "denyout", "ca")
}

// LoadState reads desktop state (defaults if missing).
func LoadState() State {
	st := DefaultState()
	b, err := os.ReadFile(StatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	// Migrate older state: computer_enabled without scope.
	if st.Scope == "" && st.ComputerEnabled {
		st.Scope = ScopeComputer
		st.ProtectionOn = true
	}
	// Older files lacked computer_available — treat as available.
	if !jsonHasComputerAvailable(b) {
		st.ComputerAvailable = true
	}
	return st
}

func jsonHasComputerAvailable(b []byte) bool {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return false
	}
	_, ok := raw["computer_available"]
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
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
