package desktop_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestAlwaysAllowRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	st := desktop.DefaultState()
	st.SetupDone = true
	st.AlwaysAllowHosts = []string{"allowed.example"}
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}
	got := desktop.LoadState()
	if len(got.AlwaysAllowHosts) != 1 || got.AlwaysAllowHosts[0] != "allowed.example" {
		t.Fatalf("%+v", got)
	}
}
