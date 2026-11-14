package desktop

import (
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/cloudsync"
)

func TestExportApplyRoundTrip(t *testing.T) {
	sinks := true
	st := DefaultState()
	st.NotifyLevel = "detailed"
	st.AlwaysAllowHosts = []string{"api.openai.com"}
	st.RememberedKeeps = []string{"bad.example|secret_shape"}
	st.RememberedSignalAllows = []string{"api.github.com|auth_to_host"}
	st.SensitiveSinksEnabled = &sinks
	st.BodyPureA = true
	st.ConfigUpdatedAt = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)

	doc := ExportSyncDocument(st, ThreatSyncPrefs{
		BlockPhishing: true, BlockMalware: true, ThreatPollHours: 12,
	}, []string{"cursor-starter"})

	raw, err := cloudsync.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cloudsync.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	var st2 State
	ApplySyncSettings(&st2, got.Settings)
	if st2.NotifyLevel != "detailed" || !st2.Notify {
		t.Fatalf("notify %+v", st2)
	}
	if len(st2.AlwaysAllowHosts) != 1 || st2.AlwaysAllowHosts[0] != "api.openai.com" {
		t.Fatalf("hosts %+v", st2.AlwaysAllowHosts)
	}
	if len(st2.RememberedSignalAllows) != 1 || !st2.BodyPureA {
		t.Fatalf("signals/body %+v", st2)
	}
	if st2.SensitiveSinksEnabled == nil || !*st2.SensitiveSinksEnabled {
		t.Fatal("sinks")
	}
	prefs, ok := ThreatPrefsFromSettings(got.Settings)
	if !ok || !prefs.BlockPhishing || prefs.ThreatPollHours != 12 {
		t.Fatalf("%+v", prefs)
	}
	if len(got.Settings.AppliedPackIDs) != 1 {
		t.Fatal("packs")
	}
}

func TestExportOmitsAccountishFields(t *testing.T) {
	st := DefaultState()
	st.UpdateAvailableURL = "https://evil.example/should-not-sync"
	st.LastDenyURL = "https://x/?sk=secret"
	doc := ExportSyncDocument(st, ThreatSyncPrefs{}, nil)
	raw, _ := cloudsync.Marshal(doc)
	s := string(raw)
	for _, bad := range []string{"should-not-sync", "sk=secret", "last_deny"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaked %q into sync blob: %s", bad, s)
		}
	}
}
