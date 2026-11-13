package desktop_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	st := desktop.DefaultState()
	st.SetupDone = true
	st.PreferredAgent = "claude"
	st.Notify = true
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}
	path := desktop.StatePath()
	if filepath.Dir(path) != filepath.Join(dir, "denyout") {
		t.Fatalf("path=%s", path)
	}
	got := desktop.LoadState()
	if !got.SetupDone || got.PreferredAgent != "claude" || !got.Notify {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
