package desktop_test

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestDefaultStateSafeDesktop(t *testing.T) {
	st := desktop.DefaultState()
	if st.PolicyProfile != desktop.PolicyProfileBrowse {
		t.Fatalf("default profile=%q want browse", st.PolicyProfile)
	}
	if st.AskMode {
		t.Fatal("Safe desktop default must not enable host Ask")
	}
}

func TestProfilePinPending(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	p := desktop.NewAgentProfile("Bot", []string{"python", "app.py"})
	p.AddPendingOnce("api.example.com")
	p.AddPendingOnce("api.example.com") // dedupe
	if len(p.PendingOnce) != 1 {
		t.Fatalf("pending=%v", p.PendingOnce)
	}
	p.PinPending(nil)
	if len(p.PendingOnce) != 0 || len(p.ExtraAllow) != 1 {
		t.Fatalf("after pin pending=%v allow=%v", p.PendingOnce, p.ExtraAllow)
	}
	if err := desktop.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := desktop.LoadProfile(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Bot" || len(got.ExtraAllow) != 1 {
		t.Fatalf("%+v", got)
	}
	got.DiscardPending()
	got.AddPendingOnce("tmp.example")
	got.DiscardPending()
	if len(got.PendingOnce) != 0 {
		t.Fatal(got.PendingOnce)
	}
}

func TestNormalizeProfileName(t *testing.T) {
	if desktop.NormalizeProfileName("") != "Agent 1" {
		t.Fatal("empty")
	}
	long := make([]rune, 50)
	for i := range long {
		long[i] = 'a'
	}
	n := desktop.NormalizeProfileName(string(long))
	if len([]rune(n)) != 40 {
		t.Fatalf("len=%d", len([]rune(n)))
	}
}

func TestNeedsUXv2Migration(t *testing.T) {
	st := desktop.DefaultState()
	st.SetupDone = true
	st.UXv2Migrated = false
	st.PolicyProfile = desktop.PolicyProfileAgent
	if !st.NeedsUXv2Migration() {
		t.Fatal("expected migration")
	}
	st.UXv2Migrated = true
	if st.NeedsUXv2Migration() {
		t.Fatal("migrated")
	}
}
