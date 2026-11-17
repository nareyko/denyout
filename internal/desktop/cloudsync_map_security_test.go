package desktop

import (
	"testing"

	"github.com/nareyko/denyout/internal/cloudsync"
)

func TestApplySyncSettingsRejectsHostileInput(t *testing.T) {
	st := &State{BodyPureA: true, AntiChunkEnabled: true}
	ApplySyncSettings(st, cloudsync.Settings{
		AlwaysAllowHosts:   []string{"ok.example.com", "*.evil.com", "http://x.com", "1.2.3.4", "com", "a b.com", "EVIL.org"},
		DecisionTimeoutSec: 999999,
	})
	want := map[string]bool{"ok.example.com": true, "evil.org": true}
	if len(st.AlwaysAllowHosts) != 2 {
		t.Fatalf("hosts=%v", st.AlwaysAllowHosts)
	}
	for _, h := range st.AlwaysAllowHosts {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
	if st.DecisionTimeoutSec != 3600 {
		t.Errorf("timeout not clamped: %d", st.DecisionTimeoutSec)
	}
	if !st.BodyPureA || !st.AntiChunkEnabled {
		t.Error("remote sync must not disable protections")
	}
}
