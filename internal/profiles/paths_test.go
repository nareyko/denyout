package profiles

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/appdata"
)

func TestProfilePathCannotEscape(t *testing.T) {
	for _, id := range []string{"../../etc/x", "a/b", "..", "x\x00y", ""} {
		got := profilePath(id)
		if filepath.Dir(got) != filepath.Clean(appdata.ProfilesDir()) {
			t.Errorf("profilePath(%q)=%q escapes ProfilesDir", id, got)
		}
		if err := DeleteProfile(id); err == nil {
			t.Errorf("DeleteProfile(%q) should fail", id)
		}
	}
	if !ValidProfileID("my-agent_1") || ValidProfileID("../x") {
		t.Error("ValidProfileID wrong")
	}
}
