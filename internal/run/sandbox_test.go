package run_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/run"
)

func TestWrapSandboxPassthrough(t *testing.T) {
	argv, env, clean, err := run.WrapSandbox("", []string{"echo", "hi"}, "http://127.0.0.1:9")
	defer clean()
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 2 || argv[0] != "echo" {
		t.Fatalf("%v", argv)
	}
	if len(env) != 0 {
		t.Fatalf("env=%v", env)
	}
}

func TestWrapSandboxSRTFailClosed(t *testing.T) {
	// Ensure srt is not found via empty PATH.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))
	_, _, clean, err := run.WrapSandbox("srt", []string{"true"}, "http://127.0.0.1:9")
	defer clean()
	if err == nil {
		t.Fatal("expected fail closed when srt missing")
	}
	if !strings.Contains(err.Error(), "srt") {
		t.Fatalf("%v", err)
	}
}

func TestWrapSandboxSRTPresent(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "srt")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	argv, env, clean, err := run.WrapSandbox("srt", []string{"true"}, "http://127.0.0.1:9191")
	defer clean()
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != fake || argv[1] != "--settings" {
		t.Fatalf("%v", argv)
	}
	found := false
	for _, e := range env {
		if strings.HasPrefix(e, "HTTP_PROXY=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("env=%v", env)
	}
}
