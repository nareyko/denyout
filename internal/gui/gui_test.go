package gui_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/proxy"
)

func TestGUIAPI(t *testing.T) {
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
		errCh <- gui.Run(ctx, gui.Options{
			Version:     "test",
			TLSMode:     proxy.TLSIntercept,
			Listen:      addr,
			OpenBrowser: false,
		})
	}()

	base := "http://" + addr
	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get(base + "/api/status")
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("gui never came up: %v", err)
	}
	defer resp.Body.Close()

	var st map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st["mode"] != "enforce" || st["preset"] != "models" {
		t.Fatalf("status=%v", st)
	}

	resp2, err := http.Post(base+"/api/wrap/start", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("wrap start: %s %s", resp2.Status, body)
	}
	var st2 map[string]any
	if err := json.Unmarshal(body, &st2); err != nil {
		t.Fatal(err)
	}
	if st2["running"] != true {
		t.Fatalf("expected running: %s", body)
	}

	resp3, err := http.Post(base+"/api/check", "application/json", strings.NewReader(`{"url":"https://api.anthropic.com/"}`))
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if !strings.Contains(string(b3), `"verdict":"allow"`) {
		t.Fatalf("check allow: %s", b3)
	}

	resp4, err := http.Post(base+"/api/wrap/stop", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()

	cancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("gui did not exit")
	}
}
