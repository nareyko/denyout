package appstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTripAtomic(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	st := DefaultState()
	st.AlwaysAllowHosts = []string{"example.com"}
	if err := SaveState(st); err != nil {
		t.Fatal(err)
	}
	got := LoadState()
	if len(got.AlwaysAllowHosts) != 1 || got.AlwaysAllowHosts[0] != "example.com" {
		t.Fatalf("round trip lost data: %+v", got.AlwaysAllowHosts)
	}
	dir := filepath.Dir(appStatePath())
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if len(e.Name()) > 4 && e.Name()[:5] == ".tmp-" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	if fi, err := os.Stat(appStatePath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state file must be 0600: %v %v", fi, err)
	}
}

func TestPolicyProfileNormalizeAndPostBlockKey(t *testing.T) {
	if NormalizePolicyProfile(" AGENT ") != PolicyProfileAgent || NormalizePolicyProfile("junk") != PolicyProfileBrowse {
		t.Error("NormalizePolicyProfile wrong")
	}
	if PostBlockKey(" Example.COM ", " r ") != "example.com|r" {
		t.Error("PostBlockKey wrong")
	}
	st := State{RememberedKeeps: []string{"a.com|r"}}
	if !st.RememberedKeep("A.com", "r") || st.RememberedKeep("b.com", "r") {
		t.Error("RememberedKeep wrong")
	}
}

func TestCorruptStateFallsBackToDefaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p := appStatePath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte("{broken"), 0o600)
	if got := LoadState(); got.PolicyProfile != PolicyProfileBrowse {
		t.Errorf("corrupt state must yield defaults, got profile %q", got.PolicyProfile)
	}
}
