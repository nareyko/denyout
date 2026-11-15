package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the whole package under a temp XDG tree so async SaveState
// / logging after t.Setenv Cleanup cannot rewrite the developer dogfood home.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "denyout-desktop-test-xdg-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("HOME", dir)
	_ = os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	_ = os.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
