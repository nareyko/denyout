package appdata

import (
	"path/filepath"
	"testing"
)

func TestPathsFollowXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	if got := StatePath(); got != "/tmp/xdg/denyout/desktop.json" {
		t.Errorf("StatePath=%q", got)
	}
	if ProfilesDir() != filepath.Join("/tmp/xdg/denyout", "profiles") || CADir() != filepath.Join("/tmp/xdg/denyout", "ca") {
		t.Error("derived dirs wrong")
	}
}
