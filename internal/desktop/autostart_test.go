//go:build linux

package desktop_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestRegisterAutostartLinux(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// XDG paths under HOME for this test user
	if err := desktop.RegisterAutostart(); err != nil {
		t.Fatal(err)
	}
	desktopFile := filepath.Join(home, ".config", "autostart", "denyout.desktop")
	b, err := os.ReadFile(desktopFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "desktop") || !strings.Contains(string(b), "Exec=") {
		t.Fatalf("unexpected desktop entry:\n%s", b)
	}
	unit := filepath.Join(home, ".config", "systemd", "user", "denyout-desktop.service")
	if _, err := os.Stat(unit); err != nil {
		t.Fatalf("missing user unit: %v", err)
	}
}
