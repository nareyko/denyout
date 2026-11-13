package serve_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/serve"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "denyout.yaml")
	content := `apiVersion: denyout/v1
kind: Config
mode: enforce
preset: models
tls:
  mode: intercept
  session_ca: true
listen:
  host: 127.0.0.1
  port: 0
audit:
  stdout: false
  jsonl_path: ""
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServeProxyAndHealth(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir)
	proxyAddr := freeAddr(t)
	healthAddr := freeAddr(t)
	metricsAddr := freeAddr(t)
	caDir := filepath.Join(dir, "ca")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve.Run(ctx, serve.Options{
			ConfigPath:    cfg,
			Listen:        proxyAddr,
			HealthListen:  healthAddr,
			MetricsListen: metricsAddr,
			CADir:         caDir,
			Version:       "test",
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + healthAddr + "/readyz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && string(body) == "ready\n" {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("status=%d body=%q", resp.StatusCode, body)
		} else {
			lastErr = err
		}
		time.Sleep(30 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("health not ready: %v", lastErr)
	}

	mresp, err := http.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(mresp.Body)
	mresp.Body.Close()
	if mresp.StatusCode != 200 || !strings.Contains(string(mb), "denyout_up 1") {
		t.Fatalf("metrics: %s %s", mresp.Status, mb)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Fatalf("expected CA cert: %v", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit")
	}
}

func TestServeKillSwitch(t *testing.T) {
	t.Setenv("DENYOUT_KILL", "1")
	err := serve.Run(context.Background(), serve.Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
		Version:    "test",
	})
	if err == nil || !strings.Contains(err.Error(), "DENYOUT_KILL") {
		t.Fatalf("want kill error, got %v", err)
	}
}

func TestServeRequiresConfig(t *testing.T) {
	err := serve.Run(context.Background(), serve.Options{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("want config required, got %v", err)
	}
}
