package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
)

func TestLogJSONLRequiredFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	s, err := audit.Open(path, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Log(audit.Event{
		SessionID:  "s1",
		Verdict:    "deny",
		Reasons:    []string{"secret_in_url"},
		Mode:       "enforce",
		Network:    audit.Network{DestHost: "evil.example", DestPort: 443},
		PolicyHash: "sha256:abc",
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(b)
	for _, need := range []string{`"schema_version":1`, `"event_id":`, `"session_id":"s1"`, `"verdict":"deny"`, `"policy_hash":"sha256:abc"`} {
		if !strings.Contains(line, need) {
			t.Fatalf("missing %s in %s", need, line)
		}
	}
	if strings.Contains(line, "sk-") {
		t.Fatal("unexpected secret material")
	}

	evs, err := audit.RecentDenials(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Verdict != "deny" {
		t.Fatalf("RecentDenials=%v", evs)
	}
}

func TestRotateAndTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := audit.Open(path, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	// ~300+ bytes per event → rotate after a few lines, then keep headroom for a final deny.
	s.SetMaxBytes(900)
	for i := 0; i < 20; i++ {
		if err := s.Log(audit.Event{
			SessionID:  "s1",
			Verdict:    "allow",
			Reasons:    []string{"ok"},
			Mode:       "enforce",
			Network:    audit.Network{DestHost: "ok.example", DestPort: 443},
			PolicyHash: "sha256:abc",
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	baks := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			baks++
		}
	}
	if baks < 1 {
		t.Fatalf("expected rotated .bak after bulk allows, entries=%v", entries)
	}
	s.SetMaxBytes(-1) // keep final deny in the active file
	if err := s.Log(audit.Event{
		SessionID:  "s1",
		Verdict:    "deny",
		Reasons:    []string{"host_not_allowed"},
		Mode:       "enforce",
		Network:    audit.Network{DestHost: "evil.example", DestPort: 443},
		PolicyHash: "sha256:abc",
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	all, err := audit.TailEvents(path, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("expected events in current file after rotate")
	}
	denies, err := audit.TailEvents(path, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range denies {
		if ev.Network.DestHost == "evil.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("deny missing in tail: %+v", denies)
	}
}
