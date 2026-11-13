package desktop_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestSessionEnvWrittenOnRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	st := desktop.DefaultState()
	st.SetupDone = true
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

	deadline := time.Now().Add(8 * time.Second)
	envPath := filepath.Join(home, ".config", "denyout", "session-env")
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(envPath)
		if err == nil && strings.Contains(string(b), "HTTP_PROXY=http://127.0.0.1:") {
			linuxEnv := filepath.Join(home, ".config", "environment.d", "90denyout.conf")
			if _, err := os.Stat(linuxEnv); err != nil {
				t.Fatalf("missing environment.d drop-in: %v", err)
			}
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("desktop did not exit after cancel (session stop hang?)")
			}
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	cancel()
	t.Fatal("session-env not written after restore")
}
