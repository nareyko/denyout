package desktop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestWizardAPISetup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

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
			NoTray: true,
			NoOpen: true,
			Listen: addr,
		})
	}()

	base := "http://" + addr
	var last error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				last = nil
				break
			}
		} else {
			last = err
		}
		time.Sleep(30 * time.Millisecond)
	}
	if last != nil {
		t.Fatalf("wizard up: %v", last)
	}

	body := []byte(`{"agent":"claude","notify":true}`)
	resp, err := http.Post(base+"/api/setup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setup status=%d", resp.StatusCode)
	}

	st := desktop.LoadState()
	if !st.SetupDone || st.PreferredAgent != "claude" || !st.Notify {
		t.Fatalf("state=%+v", st)
	}

	sresp, err := http.Get(base + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var status map[string]any
	if err := json.NewDecoder(sresp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status["setup_done"] != true || status["agent"] != "claude" {
		t.Fatalf("%v", status)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("desktop did not exit")
	}
}

func TestSplitCommandViaProtectSetup(t *testing.T) {
	// Custom agent command is persisted through setup API.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = desktop.Run(ctx, desktop.Options{NoTray: true, NoOpen: true, Listen: addr})
	}()

	base := "http://" + addr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/api/status"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	payload := []byte(`{"agent":"custom","custom_command":"echo hello","notify":false}`)
	resp, err := http.Post(base+"/api/setup", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	st := desktop.LoadState()
	if st.PreferredAgent != "custom" || st.CustomCommand != "echo hello" || st.Notify {
		t.Fatalf("%+v", st)
	}
	cancel()
}
