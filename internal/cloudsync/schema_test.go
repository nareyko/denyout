package cloudsync

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalRoundTrip(t *testing.T) {
	phish := true
	doc := Document{
		SchemaVersion: SchemaVersion,
		UpdatedAt:     time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
		Settings: Settings{
			NotifyLevel:            "normal",
			AlwaysAllowHosts:       []string{"api.openai.com"},
			RememberedKeeps:        []string{"evil.example|secret_shape"},
			RememberedSignalAllows: []string{"api.github.com|auth_to_host"},
			BlockPhishing:          &phish,
			ThreatPollHours:        24,
		},
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Settings.NotifyLevel != "normal" || len(got.Settings.AlwaysAllowHosts) != 1 {
		t.Fatalf("%+v", got)
	}
	if got.Settings.BlockPhishing == nil || !*got.Settings.BlockPhishing {
		t.Fatal("phishing")
	}
}

func TestUnmarshalFutureSchemaRejected(t *testing.T) {
	_, err := Unmarshal([]byte(`{"schema_version":99,"settings":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("%v", err)
	}
}

func TestMergeLWW(t *testing.T) {
	older := Document{UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Settings: Settings{NotifyLevel: "quiet"}}
	newer := Document{UpdatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Settings: Settings{NotifyLevel: "detailed"}}
	if MergeLWW(older, newer).Settings.NotifyLevel != "detailed" {
		t.Fatal("want remote")
	}
	if MergeLWW(newer, older).Settings.NotifyLevel != "detailed" {
		t.Fatal("want local newer")
	}
}

func TestNeverSyncDocumented(t *testing.T) {
	if len(NeverSync) < 4 {
		t.Fatal("NeverSync too short")
	}
	joined := strings.Join(NeverSync, " ")
	for _, need := range []string{"audit", "canary", "account_tokens"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing %s in %v", need, NeverSync)
		}
	}
}
