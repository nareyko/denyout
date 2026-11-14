package threatlists

import (
	"os"
	"path/filepath"
)

// DefaultDir returns XDG state dir for threat list cache:
// $XDG_STATE_HOME/denyout/threatlists (or ~/.local/state/denyout/threatlists).
func DefaultDir() string {
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join("denyout-threatlists")
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "denyout", "threatlists")
}
