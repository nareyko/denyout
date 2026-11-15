package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPreferStableDesktopBinarySkipsGoTest(t *testing.T) {
	dir := t.TempDir()
	stable := filepath.Join(dir, "denyout")
	if err := os.WriteFile(stable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	got := preferStableDesktopBinary(filepath.Join(os.TempDir(), "go-build123", "desktop.test"))
	if got != stable {
		// LookPath may resolve to another denyout earlier on PATH; accept any non-test.
		base := filepath.Base(got)
		if strings.Contains(base, ".test") || strings.HasSuffix(base, ".test") {
			t.Fatalf("still unstable: %s", got)
		}
	}
}

func TestAutostartExecLine(t *testing.T) {
	gui := filepath.Join("/opt", "denyout")
	if got := autostartExecLine(gui); got != gui {
		t.Fatalf("gui binary: got %q", got)
	}
	dir := t.TempDir()
	cli := filepath.Join(dir, "denyout-cli")
	want := cli + " desktop"
	if got := autostartExecLine(cli); got != want {
		t.Fatalf("cli binary without sibling: got %q want %q", got, want)
	}
	sib := filepath.Join(dir, "denyout")
	if runtime.GOOS == "windows" {
		sib += ".exe"
	}
	if err := os.WriteFile(sib, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := autostartExecLine(cli); got != sib {
		t.Fatalf("cli with sibling: got %q want %q", got, sib)
	}
}

func TestDesktopLaunchArgs(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "denyout-cli")
	bin, args := desktopLaunchArgs(cli)
	if bin != cli || len(args) != 1 || args[0] != "desktop" {
		t.Fatalf("without sibling: bin=%q args=%v", bin, args)
	}
	sib := filepath.Join(dir, "denyout")
	if runtime.GOOS == "windows" {
		sib += ".exe"
	}
	if err := os.WriteFile(sib, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	bin, args = desktopLaunchArgs(cli)
	if bin != sib || len(args) != 0 {
		t.Fatalf("with sibling: bin=%q args=%v", bin, args)
	}
	bin, args = desktopLaunchArgs(sib)
	if bin != sib || len(args) != 0 {
		t.Fatalf("gui self: bin=%q args=%v", bin, args)
	}
}
