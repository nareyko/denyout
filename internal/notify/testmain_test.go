package notify_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

// TestMain installs a no-hang notify-send stub on PATH and sweeps any leftovers.
// Real --wait toasts must not survive the notify package test suite into the desktop shade.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "denyout-notify-test-*")
	if err != nil {
		panic(err)
	}
	stub := filepath.Join(dir, "notify-send")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		panic(err)
	}
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	code := m.Run()
	notify.CloseAll()
	if leftover := countDenyOutNotifySend(); leftover > 0 {
		notify.CloseAll()
		if countDenyOutNotifySend() > 0 {
			_, _ = os.Stderr.WriteString("denyout notify tests: DenyOut notify-send leftovers after CloseAll\n")
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
