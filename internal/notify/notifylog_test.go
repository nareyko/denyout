package notify_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

func TestNotifyLogQuietSuppressesOpenApp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.jsonl")
	notify.SetLogPath(path)
	t.Cleanup(func() { notify.SetLogPath("") })

	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetFullscreen(false)
	notify.SetSnoozeUntil(time.Time{})
	notify.SetLevel("quiet")
	notify.Emit(notify.KindOpenApp, "DenyOut", "suppressed in Quiet")

	rec := lastNotifyLine(t, path)
	if rec["shown"] != false {
		t.Fatalf("shown=%v want false", rec["shown"])
	}
	if rec["reason"] != "quiet" {
		t.Fatalf("reason=%v want quiet", rec["reason"])
	}
	if rec["kind"] != "open_app" {
		t.Fatalf("kind=%v", rec["kind"])
	}
}

func TestNotifyLogProtectFailedShown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.jsonl")
	notify.SetLogPath(path)
	t.Cleanup(func() { notify.SetLogPath("") })

	notify.SetUIFocused(false)
	notify.SetAway(false)
	notify.SetBannersAllowed(true)
	notify.SetFullscreen(false)
	notify.SetSnoozeUntil(time.Time{})
	notify.SetLevel("quiet")
	notify.Emit(notify.KindProtectFailed, "DenyOut", "allowed in Quiet")

	rec := lastNotifyLine(t, path)
	if rec["shown"] != true {
		t.Fatalf("shown=%v want true", rec["shown"])
	}
	if reason, _ := rec["reason"].(string); reason != "" {
		t.Fatalf("reason=%q want empty", reason)
	}
	if rec["kind"] != "protect_failed" {
		t.Fatalf("kind=%v", rec["kind"])
	}
}

func lastNotifyLine(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		last = sc.Text()
	}
	if last == "" {
		t.Fatal("expected a JSONL line")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(last), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}
