package desktop

import (
	"testing"

	"github.com/nareyko/denyout/internal/audit"
)

func TestDenialUsefulForUI(t *testing.T) {
	ok := audit.Event{
		Reasons: []string{"threat_list"},
		Network: audit.Network{DestHost: "evil.example"},
	}
	if !denialUsefulForUI(ok) {
		t.Fatal("expected useful")
	}
	empty := audit.Event{Network: audit.Network{DestHost: "evil.example"}}
	if denialUsefulForUI(empty) {
		t.Fatal("empty reasons should be skipped")
	}
	loop := audit.Event{
		Reasons: []string{"host_not_allowed"},
		Network: audit.Network{DestHost: "localhost"},
	}
	if denialUsefulForUI(loop) {
		t.Fatal("localhost should be skipped")
	}
}
