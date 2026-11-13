package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// State is persisted desktop preferences (first-run wizard, notifications).
type State struct {
	SetupDone       bool   `json:"setup_done"`
	Notify          bool   `json:"notify"`
	PreferredAgent  string `json:"preferred_agent,omitempty"` // claude|cursor|shell|custom
	CustomCommand   string `json:"custom_command,omitempty"`
	LastDenyHost    string `json:"last_deny_host,omitempty"`
	LastDenySummary string `json:"last_deny_summary,omitempty"`
}

var stateMu sync.Mutex

// DefaultState returns first-run defaults.
func DefaultState() State {
	return State{Notify: true}
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

// LoadState reads desktop state (defaults if missing).
func LoadState() State {
	st := DefaultState()
	b, err := os.ReadFile(StatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	return st
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
