package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureTunAfterProtectOnSkipsByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("DENYOUT_TUN_E2E", "")

	ensureTunAfterProtectOn(1000)

	b, err := os.ReadFile(EventsLogPath())
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["type"] == "tun_start_skipped" {
			saw = true
			if rec["reason"] != "flag_off" || rec["phase"] != "T0" {
				t.Fatalf("%+v", rec)
			}
		}
		if rec["type"] == "tun_start" {
			t.Fatal("must not emit tun_start when flag off")
		}
	}
	if !saw {
		t.Fatalf("missing tun_start_skipped\n%s", b)
	}
}

func TestLogQuicDropStatsEmitsSourceAndTunStop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	logQuicDropStats("test_protect_off")

	b, err := os.ReadFile(EventsLogPath())
	if err != nil {
		t.Fatal(err)
	}
	var sawQuic, sawTunStats, sawTunStop bool
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		switch rec["type"] {
		case "quic_drop_stats":
			sawQuic = true
			if rec["source"] != "nft" {
				t.Fatalf("quic source=%v want nft (T0 path)", rec["source"])
			}
			if rec["reason"] != "test_protect_off" {
				t.Fatalf("reason=%v", rec["reason"])
			}
		case "tun_drop_stats":
			sawTunStats = true
			if rec["source"] != "tun" {
				t.Fatalf("tun source=%v", rec["source"])
			}
			if rec["present"] != false {
				t.Fatalf("stub must be present=false: %+v", rec)
			}
		case "tun_stop":
			sawTunStop = true
			if rec["enabled"] != false {
				t.Fatalf("tun_stop must stay disabled: %+v", rec)
			}
		}
	}
	if !sawQuic || !sawTunStats || !sawTunStop {
		t.Fatalf("missing events quic=%v tun_stats=%v tun_stop=%v\n%s", sawQuic, sawTunStats, sawTunStop, b)
	}
}
