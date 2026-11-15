package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

// Guard: until a real tuntap implementation exists, HelperReply must never
// advertise enabled=true (even with DENYOUT_TUN_E2E=1).
func TestHelperReplyNeverEnabledUntilRealDevice(t *testing.T) {
	for _, env := range []string{"", "1"} {
		t.Run("E2E="+env, func(t *testing.T) {
			t.Setenv(tun.EnvE2E, env)
			for _, verb := range []string{"tun-start", "tun-stop", "tun-stats"} {
				line, err := tun.HelperReply(verb)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(line, "enabled=true") {
					t.Fatalf("enabled=true leaked for %s: %q", verb, line)
				}
				st, err := tun.ParseHelperReply(line)
				if err != nil {
					t.Fatal(err)
				}
				if st.Enabled {
					t.Fatalf("Parsed Enabled for %s: %+v", verb, st)
				}
			}
		})
	}
}
