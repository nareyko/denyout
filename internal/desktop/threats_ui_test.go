package desktop

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/threatlists"
)

func TestGetThreatListsDefaults(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	v := a.GetThreatLists()
	if v.PollHours != threatlists.DefaultPollHours {
		t.Fatalf("poll: %d", v.PollHours)
	}
	if !v.BlockPhishing || !v.BlockMalware {
		t.Fatalf("defaults should be on: %+v", v)
	}
	if v.BlockStronger {
		t.Fatal("Stronger must default off")
	}
	if v.StrongerWarning == "" {
		t.Fatal("stronger warning copy required")
	}
	if len(v.Feeds) != 3 {
		t.Fatalf("want phishing+malware+stronger rows, got %d: %+v", len(v.Feeds), v.Feeds)
	}
	if v.ProductExceptions < 15 || len(v.ProductExceptionHosts) != v.ProductExceptions {
		t.Fatalf("product exceptions: n=%d hosts=%d", v.ProductExceptions, len(v.ProductExceptionHosts))
	}
	if len(v.AdvancedFeeds) != 3 {
		t.Fatalf("want 3 advanced feeds, got %d", len(v.AdvancedFeeds))
	}
	for _, f := range v.AdvancedFeeds {
		if f.Enabled {
			t.Fatalf("advanced must default off: %+v", f)
		}
	}
	if v.AdvancedWarning == "" {
		t.Fatal("advanced warning required")
	}
}

func TestSetAdvancedRejectsCoreID(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	_ = a.GetThreatLists()
	if err := a.UISetAdvancedThreatFeed(threatlists.IDPhishingArmy, true); err == nil {
		t.Fatal("core id must be rejected")
	}
}

func TestMalwareOffDisablesStronger(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	_ = a.GetThreatLists()
	// Mark stronger enabled without network fetch by writing store directly.
	st := a.ensureThreatStore(false)
	if st == nil {
		t.Fatal("store")
	}
	if err := st.SetEnabled(threatlists.IDHageziTIFMedium, true); err != nil {
		t.Fatal(err)
	}
	// Fake active so UI would show on - then malware off should clear it.
	if err := a.UISetBlockMalware(false); err != nil {
		t.Fatal(err)
	}
	v := a.GetThreatLists()
	if v.BlockMalware || v.BlockStronger {
		t.Fatalf("malware off must clear stronger: %+v", v)
	}
}

func TestSetBlockPhishingOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	_ = a.GetThreatLists()
	if err := a.UISetBlockPhishing(false); err != nil {
		t.Fatal(err)
	}
	v := a.GetThreatLists()
	if v.BlockPhishing {
		t.Fatal("expected off")
	}
	// Persisted under state home
	st, err := threatlists.Open(filepath.Join(dir, "denyout", "threatlists"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Status().Feeds[threatlists.IDPhishingArmy].Enabled {
		t.Fatal("status should persist disabled")
	}
}

func TestSetThreatPollHoursClamped(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	_ = a.GetThreatLists()
	if err := a.UISetThreatPollHours(2); err != nil {
		t.Fatal(err)
	}
	v := a.GetThreatLists()
	if v.PollHours != threatlists.MinPollHours {
		t.Fatalf("got %d", v.PollHours)
	}
}
