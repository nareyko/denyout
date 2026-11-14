package desktop_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestRecordErrorAndReadLast(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

	desktop.RecordError("test.kind", "boom detail line")
	got := desktop.ReadLastError()
	if !strings.Contains(got, "test.kind") || !strings.Contains(got, "boom detail line") {
		t.Fatalf("last-error.txt=%q", got)
	}
	b, err := os.ReadFile(desktop.DesktopLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ERROR [test.kind]") {
		t.Fatalf("desktop.log=%s", b)
	}
}

func TestOpenLogsWritesReadme(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

	// OpenLogs may fail to launch a GUI opener in CI; still writes README.
	_ = desktop.OpenLogs()
	b, err := os.ReadFile(desktop.ReadmePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "last-error.txt") || !strings.Contains(string(b), "audit.jsonl") {
		t.Fatalf("README=%s", b)
	}
}
