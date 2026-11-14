package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAutostartExecLine(t *testing.T) {
	desktop := filepath.Join("/opt", "denyout-desktop")
	if got := autostartExecLine(desktop); got != desktop {
		t.Fatalf("desktop binary: got %q", got)
	}
	cli := filepath.Join("/opt", "denyout")
	want := cli + " desktop"
	if got := autostartExecLine(cli); got != want {
		t.Fatalf("cli binary: got %q want %q", got, want)
	}
}

func TestDesktopLaunchArgs(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "denyout")
	bin, args := desktopLaunchArgs(self)
	if bin != self || len(args) != 1 || args[0] != "desktop" {
		t.Fatalf("without sibling: bin=%q args=%v", bin, args)
	}
	sib := filepath.Join(dir, "denyout-desktop")
	if runtime.GOOS == "windows" {
		sib += ".exe"
	}
	if err := os.WriteFile(sib, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	bin, args = desktopLaunchArgs(self)
	if bin != sib || len(args) != 0 {
		t.Fatalf("with sibling: bin=%q args=%v", bin, args)
	}
}
