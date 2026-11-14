package desktop_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/desktop"
)

func TestListDenialsFilters(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	path := desktop.AuditLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	sink, err := audit.Open(path, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.Event{
		Verdict: "deny",
		Reasons: []string{"secret_in_url"},
		Network: audit.Network{DestHost: "evil.example", DestPort: 443},
		HTTP: &audit.HTTPInfo{Path: "/x", QueryRedacted: "api_key=***"},
		Process: "proxyd",
	}
	if err := sink.Log(ev); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	a := desktop.NewApp(desktop.Options{Version: "test", NoTray: true})
	rows, err := a.ListDenials(desktop.DenialQuery{Search: "evil", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].Host != "evil.example" {
		t.Fatalf("host=%s", rows[0].Host)
	}
	if rows[0].URL == "" || rows[0].Why == "" {
		t.Fatalf("want url+why: %+v", rows[0])
	}
	b, _ := json.Marshal(rows[0])
	if len(b) < 10 {
		t.Fatal(string(b))
	}

	snap := a.GetUISnapshot()
	if snap.BlockedToday < 1 {
		t.Fatalf("blocked_today=%d want >=1", snap.BlockedToday)
	}
}
