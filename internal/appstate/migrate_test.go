package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) State {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p := appStatePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadState()
}

func TestMigrateLegacyV0(t *testing.T) {
	st := loadFixture(t, "desktop_v0_legacy.json")
	if st.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("version %d", st.SchemaVersion)
	}
	if st.Scope != ScopeComputer || !st.ProtectionOn {
		t.Errorf("computer_enabled legacy not migrated: scope=%q on=%v", st.Scope, st.ProtectionOn)
	}
	if !st.ComputerAvailable || !st.Autostart {
		t.Errorf("missing-key defaults not applied: %+v", st)
	}
	if st.PolicyProfile != PolicyProfileAgent {
		t.Errorf("empty legacy profile must read as agent, got %q", st.PolicyProfile)
	}
	if st.DecisionTimeoutSec != 30 || !st.BodyPureA || len(st.AlwaysAllowHosts) != 1 {
		t.Errorf("fields lost in migration: %+v", st)
	}
}

func TestMigratePlainV0KeepsExplicitValues(t *testing.T) {
	st := loadFixture(t, "desktop_v0_plain.json")
	if st.ComputerAvailable || st.Autostart {
		t.Errorf("explicit false values must survive: %+v", st)
	}
	if st.PolicyProfile != PolicyProfileBrowse || st.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("got %+v", st)
	}
}

func TestSaveStampsVersionAndRoundTrips(t *testing.T) {
	st := loadFixture(t, "desktop_v0_legacy.json")
	if err := SaveState(st); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(appStatePath())
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if v, _ := raw["schema_version"].(float64); int(v) != CurrentSchemaVersion {
		t.Errorf("schema_version not written: %v", raw["schema_version"])
	}
	again := LoadState()
	if again.PolicyProfile != PolicyProfileAgent || again.Scope != ScopeComputer || again.DecisionTimeoutSec != 30 {
		t.Errorf("second load differs: %+v", again)
	}
}

func TestNewerVersionLoadedAsIsAndNotDowngraded(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p := appStatePath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(`{"schema_version":99,"computer_available":false,"policy_profile":"browse"}`), 0o600)
	st := LoadState()
	if st.SchemaVersion != 99 || st.ComputerAvailable {
		t.Errorf("newer file must not be rewritten by migrations: %+v", st)
	}
	if err := SaveState(st); err != nil {
		t.Fatal(err)
	}
	if LoadState().SchemaVersion != 99 {
		t.Error("save must not downgrade schema_version")
	}
}
