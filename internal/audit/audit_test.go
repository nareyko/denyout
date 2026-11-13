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
