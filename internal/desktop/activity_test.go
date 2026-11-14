package desktop_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestControlReadyAndSessionRestore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

	st := desktop.DefaultState()
	st.SetupDone = true
	st.Scope = desktop.ScopeSession
	st.ProtectionOn = true
	st.LastDenyHost = "blocked.example"
	st.LastDenySummary = "host not allowed"
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- desktop.Run(ctx, desktop.Options{
			NoTray:        true,
			Version:       "test",
			ControlListen: addr,
		})
	}()

	base := "http://" + addr
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	resp, err := http.Get(base + "/ready")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ready map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	if ready["ok"] != true {
		t.Fatalf("ready=%+v", ready)
	}

	// Activity HTML must be gone.
	aresp, err := http.Get(base + "/activity")
	if err == nil {
		aresp.Body.Close()
		if aresp.StatusCode == 200 {
			t.Fatal("web /activity must not be served")
		}
	}

	// Bootstrap continues after /ready (restore clears legacy Session). Poll state.
	var got desktop.State
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got = desktop.LoadState()
		if got.LastDenyHost == "blocked.example" && got.SetupDone {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got.LastDenyHost != "blocked.example" {
		t.Fatalf("hydrate last_deny path=%s got=%+v", desktop.StatePath(), got)
	}
	// Legacy Session scope must not silently restore - cleared to Off.
	if got.Scope == desktop.ScopeSession && got.ProtectionOn {
		t.Fatalf("legacy session must not stay on after restore, got %+v", got)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("desktop did not exit")
	}
}
