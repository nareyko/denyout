package notify

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCloseAllKillsTrackedProcess(t *testing.T) {
	cmd := exec.Command("sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	trackWaitProc(cmd.Process)
	CloseAll()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// killed or exited
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("tracked process still alive after CloseAll")
	}
}

func TestCloseAllPkillFallbackLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pkill fallback is Linux-only")
	}
	if _, err := exec.LookPath("pkill"); err != nil {
		t.Skip("pkill not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "notify-send")
	// Hang like a real --wait toast so CloseAll must pkill it.
	// Do not `exec sleep` — that replaces argv and drops --app-name=DenyOut from the cmdline.
	body := "#!/bin/sh\nsleep 120\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, "--app-name=DenyOut", "DenyOut", "test orphan")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	// Do not track — simulate orphan reparented after parent exit.
	time.Sleep(50 * time.Millisecond)
	CloseAll()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("orphan notify-send still alive after CloseAll pkill")
	}
}
