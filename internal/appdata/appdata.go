// Package appdata resolves the per-user locations DenyOut Desktop stores its files in.
// It has no dependencies on the rest of the app so any package can use it.
package appdata

import (
	"os"
	"path/filepath"
)

// StatePath returns the desktop state file path (~/.config/denyout/desktop.json).
func StatePath() string {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "denyout.json"
		}
		cfg = filepath.Join(home, ".config")
	}
	return filepath.Join(cfg, "denyout", "desktop.json")
}

// ConfigDir is the directory that holds the state file.
func ConfigDir() string { return filepath.Dir(StatePath()) }

// ProfilesDir is ~/.config/denyout/profiles.
func ProfilesDir() string { return filepath.Join(ConfigDir(), "profiles") }

// CADir is the persistent desktop CA directory.
func CADir() string { return filepath.Join(ConfigDir(), "ca") }
