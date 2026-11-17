package gui_test

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/proxy"
)

func TestCheckRejectsOversizedBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = gui.Run(ctx, gui.Options{Version: "test", TLSMode: proxy.TLSIntercept, Listen: addr})
	}()
	base := "http://" + addr
	for i := 0; i < 100; i++ {
		if r, err := http.Get(base + "/api/status"); err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	big := `{"url":"https://example.com/` + strings.Repeat("a", 200<<10) + `"}`
	resp, err := http.Post(base+"/api/check", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: status %d, want 400", resp.StatusCode)
	}
}
