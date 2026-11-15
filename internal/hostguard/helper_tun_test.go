package hostguard_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/tun"
)

func TestTunLocalReplyClosedLoop(t *testing.T) {
	for _, verb := range []string{"tun-start", "tun-stop", "tun-stats"} {
		line, err := hostguard.TunLocalReply(verb)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(line, tun.CapTag) {
			t.Fatalf("%s: %q", verb, line)
		}
		st, err := tun.ParseHelperReply(line)
		if err != nil {
			t.Fatal(err)
		}
		if st.Enabled {
			t.Fatalf("%s must not enable TUN in CI: %q", verb, line)
		}
	}
}

func TestHelperTunCallFallsBackWithoutSocket(t *testing.T) {
	// No /run/denyout-hostguard.sock in unit CI — must still return disabled OK.
	line, err := hostguard.HelperTunCall("tun-stats", 1000)
	if err != nil {
		t.Fatal(err)
	}
	st, err := tun.ParseHelperReply(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.Stats.Present || st.Stats.Source != tun.SourceTUN {
		t.Fatalf("%+v", st.Stats)
	}
}
