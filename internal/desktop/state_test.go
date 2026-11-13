package desktop_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestLoadStateMigratesComputerEnabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "denyout", "desktop.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// Legacy shape: no scope / computer_available.
	legacy := []byte(`{"setup_done":true,"notify":true,"ask_mode":false,"computer_enabled":true}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	st := desktop.LoadState()
	if st.Scope != desktop.ScopeComputer {
		t.Fatalf("scope=%q want computer", st.Scope)
	}
	if !st.ProtectionOn {
		t.Fatal("expected protection_on after migrate")
	}
	if !st.ComputerAvailable {
		t.Fatal("legacy file without computer_available should default available")
	}
}

func TestLoadStateRespectsComputerUnavailable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	st := desktop.DefaultState()
	st.SetupDone = true
	st.ComputerAvailable = false
	st.Scope = desktop.ScopeSession
	st.ProtectionOn = true
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}
	got := desktop.LoadState()
	if got.ComputerAvailable {
		t.Fatal("expected computer_available=false to persist")
	}
	if got.Scope != desktop.ScopeSession {
		t.Fatalf("scope=%q", got.Scope)
	}
}

func TestDefaultState(t *testing.T) {
	st := desktop.DefaultState()
	if !st.Notify || st.AskMode || !st.ComputerAvailable {
		t.Fatalf("%+v", st)
	}
}
