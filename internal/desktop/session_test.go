package desktop_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestLegacySessionClearedOnRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	st := desktop.DefaultState()
	st.SetupDone = true
	st.UXv2Migrated = true
	st.Scope = desktop.ScopeSession
	st.ProtectionOn = true
	st.ComputerAvailable = false
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- desktop.Run(ctx, desktop.Options{NoTray: true, Version: "test"})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := desktop.LoadState()
		if !got.ProtectionOn && got.Scope != desktop.ScopeSession {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("desktop did not exit")
			}
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	cancel()
	t.Fatalf("expected legacy session cleared, got %+v", desktop.LoadState())
}
