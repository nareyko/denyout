package desktop

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

// TestMain isolates the whole package under a temp XDG tree so async SaveState
// / logging after t.Setenv Cleanup cannot rewrite the developer dogfood home.
// Also stubs notify-send (no --wait hang) and CloseAll so Undo/OpenApp tests
// do not leave DenyOut banners in the desktop notification shade.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "denyout-test-xdg-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("HOME", dir)
	_ = os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	_ = os.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	// Never block desktop tests on pkexec/sudo GUI (local or CI).
	_ = os.Setenv("DENYOUT_TEST_NO_ELEVATE", "1")

	stub := filepath.Join(dir, "bin")
	if err := os.MkdirAll(stub, 0o755); err != nil {
		panic(err)
	}
	ns := filepath.Join(stub, "notify-send")
	if err := os.WriteFile(ns, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		panic(err)
	}
	_ = os.Setenv("PATH", stub+string(os.PathListSeparator)+os.Getenv("PATH"))

	code := m.Run()
	notify.CloseAll()
	if n := countDenyOutNotifySend(); n > 0 {
		notify.CloseAll()
		if countDenyOutNotifySend() > 0 {
			_, _ = os.Stderr.WriteString("denyout desktop tests: DenyOut notify-send leftovers after CloseAll\n")
			_ = os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func countDenyOutNotifySend() int {
	out, err := exec.Command("ps", "-eo", "args=").Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "notify-send") || !strings.Contains(line, "--app-name=DenyOut") {
			continue
		}
		if strings.Contains(line, "pgrep") || strings.Contains(line, "pkill") || strings.Contains(line, "ps -eo") {
			continue
		}
		n++
	}
	return n
}
