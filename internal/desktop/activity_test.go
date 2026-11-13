package desktop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/desktop"
)

func TestActivityAPIsAndModeNoOp(t *testing.T) {
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
		resp, err := http.Get(base + "/activity")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}

	// Wait until session mode is live.
	var status map[string]any
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/api/desktop/status")
		if err == nil {
			_ = json.NewDecoder(resp.Body).Decode(&status)
			resp.Body.Close()
			if status["mode"] == "session" {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	if status["mode"] != "session" {
		cancel()
		t.Fatalf("expected session mode, got %+v", status)
	}
	if status["last_deny_host"] != "blocked.example" {
		t.Fatalf("hydrate last_deny: %+v", status)
	}

	// Same-mode switch is a no-op (must not error / flip off).
	body := []byte(`{"mode":"session"}`)
	resp, err := http.Post(base+"/api/desktop/mode", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("mode status=%d", resp.StatusCode)
	}
	var modeOut map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&modeOut); err != nil {
		t.Fatal(err)
	}
	if modeOut["mode"] != "session" {
		t.Fatalf("noop mode=%v", modeOut)
	}

	auditPath := desktop.AuditLogPath()
	_ = os.MkdirAll(filepath.Dir(auditPath), 0o755)
	line := `{"schema_version":1,"event_id":"e1","ts":"2026-01-01T00:00:00Z","session_id":"s","verdict":"deny","reasons":["host_not_allowed"],"mode":"enforce","network":{"dest_host":"evil.test","dest_port":443},"policy_hash":"x","denyout_version":"test"}` + "\n"
	if err := os.WriteFile(auditPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	dresp, err := http.Get(base + "/api/desktop/denials?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	var denials struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(dresp.Body).Decode(&denials); err != nil {
		t.Fatal(err)
	}
	if len(denials.Events) != 1 || denials.Events[0].Network.DestHost != "evil.test" {
		t.Fatalf("denials=%+v", denials.Events)
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
