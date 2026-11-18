package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/cloudsync"
)

func TestMigrateV1ToV2AddsFailPolicyEmpty(t *testing.T) {
	st := loadFixture(t, "desktop_v1_plain.json")
	if st.SchemaVersion != 2 || CurrentSchemaVersion != 2 {
		t.Fatalf("version %d", st.SchemaVersion)
	}
	if st.FailPolicy != "" {
		t.Fatalf("v1 files must read as the default (open), got %q", st.FailPolicy)
	}
	// Existing fields survive and nothing else is touched.
	if !st.SetupDone || st.Autostart || !st.ProtectionOn || st.Scope != ScopeComputer {
		t.Fatalf("fields changed by migration: %+v", st)
	}
}

func TestMigrateV1HandEditedValuesNeverLoosen(t *testing.T) {
	if st := loadFixture(t, "desktop_v1_hand_edited_strict.json"); st.FailPolicy != "closed" {
		t.Errorf("strict alias must canonicalise to closed, got %q", st.FailPolicy)
	}
	if st := loadFixture(t, "desktop_v1_garbage_policy.json"); st.FailPolicy != "closed" {
		t.Errorf("unrecognised value must fail safe to closed, got %q", st.FailPolicy)
	}
}

func TestV2FileRoundTripsAndOmitsDefault(t *testing.T) {
	st := loadFixture(t, "desktop_v2_open.json")
	if st.SchemaVersion != 2 || st.FailPolicy != "open" {
		t.Fatalf("%+v", st)
	}
	st.FailPolicy = "closed"
	if err := SaveState(st); err != nil {
		t.Fatal(err)
	}
	if again := LoadState(); again.FailPolicy != "closed" || again.SchemaVersion != 2 {
		t.Fatalf("round trip: %+v", again)
	}
	st.FailPolicy = ""
	_ = SaveState(st)
	b, _ := os.ReadFile(appStatePath())
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	if _, ok := raw["fail_policy"]; ok {
		t.Error("empty fail_policy must be omitted from the file")
	}
}

func TestNewerFileKeepsVersionAndPolicy(t *testing.T) {
	// A newer file (v3) with an unknown policy shape keeps its version; the value is still
	// normalised on read so it cannot loosen anything.
	st := loadFixtureBytes(t, `{"schema_version":3,"fail_policy":"closed"}`)
	if st.SchemaVersion != 3 || st.FailPolicy != "closed" {
		t.Fatalf("%+v", st)
	}
}

func loadFixtureBytes(t *testing.T, s string) State {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p := appStatePath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadState()
}

func TestNormalizeFailPolicy(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "  ": "", "open": "open", "OPEN": "open", "soft": "open", "fail-open": "open",
		"closed": "closed", "Strict": "closed", "fail-closed": "closed", "nope": "closed", "0": "closed",
	} {
		if got := NormalizeFailPolicy(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

// ---- cloud sync can only tighten ----

func TestSyncCanOnlyTightenFailPolicy(t *testing.T) {
	cases := []struct {
		local, remote, want string
	}{
		{"", "closed", "closed"},
		{"open", "closed", "closed"},
		{"closed", "closed", "closed"},
		{"closed", "open", "closed"}, // remote must never reopen
		{"closed", "", "closed"},     // absent field must never reopen
		{"closed", "soft", "closed"},
		{"closed", "garbage", "closed"},
		{"", "open", ""},
		{"open", "open", "open"},
		{"", "strict", "closed"}, // alias of closed: still only a tightening
	}
	for _, c := range cases {
		st := &State{FailPolicy: c.local}
		ApplySyncSettings(st, cloudsync.Settings{FailPolicy: c.remote})
		if st.FailPolicy != c.want {
			t.Errorf("local=%q remote=%q: got %q want %q", c.local, c.remote, st.FailPolicy, c.want)
		}
	}
}

func TestSyncExportOnlyStrictFailPolicy(t *testing.T) {
	if d := ExportSyncDocument(State{FailPolicy: "closed"}, ThreatSyncPrefs{}, nil); d.Settings.FailPolicy != "closed" {
		t.Errorf("closed not exported: %q", d.Settings.FailPolicy)
	}
	for _, p := range []string{"", "open"} {
		if d := ExportSyncDocument(State{FailPolicy: p}, ThreatSyncPrefs{}, nil); d.Settings.FailPolicy != "" {
			t.Errorf("%q must not be exported, got %q", p, d.Settings.FailPolicy)
		}
	}
}

func TestSyncJSONCannotOpenViaDocument(t *testing.T) {
	var doc cloudsync.Document
	raw := `{"schema_version":1,"settings":{"fail_policy":"open"}}`
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	st := &State{FailPolicy: "closed"}
	ApplySyncSettings(st, doc.Settings)
	if st.FailPolicy != "closed" {
		t.Fatalf("remote doc reopened a strict machine: %q", st.FailPolicy)
	}
}
