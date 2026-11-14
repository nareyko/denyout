package audit_test

import (
	"encoding/json"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
)

func TestEventPolicyProfileJSON(t *testing.T) {
	ev := audit.Event{
		SessionID:     "sess-1",
		Verdict:       "deny",
		Reasons:       []string{"host_not_allowed"},
		PolicyProfile: "agent",
		Process:       "proxyd",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["policy_profile"] != "agent" {
		t.Fatalf("policy_profile=%v", got["policy_profile"])
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}
	if got["process"] != "proxyd" {
		t.Fatalf("process=%v", got["process"])
	}
}
