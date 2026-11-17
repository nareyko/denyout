package hostguard

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/privexec"
)

// FuzzParseRequest feeds arbitrary lines (legacy + JSON) to the root-helper parser. It
// must never panic, and any request it accepts must satisfy the invariants the root
// code relies on: owner uid is authoritative, verb is in the closed set, CA path is
// absolute+clean, interface and port pass validation, no control characters survive.
func FuzzParseRequest(f *testing.F) {
	for _, s := range []string{
		"caps 0 0 -", "apply 18443 0 -", "apply 18443 5 - allow_quic",
		"tun-start 0 0 real mitm", "vpn-egress-apply 0 0 wg0",
		"vpn-egress-apply 0 0 wg0;id", "apply 0 0 ../../etc/passwd", "apply 70000 0 -",
		"apply 18443 0 /etc/../etc/shadow", "", "   ", "x", "remove 0 0\x00",
		`{"verb":"apply","port":443,"ca":"-","flags":["allow_quic"]}`,
		`{"verb":"VPN-EGRESS-APPLY","iface":"tailscale0"}`,
		`{"verb":"apply","unknown":1}`, `{"verb":`, `{"verb":"caps"} {"verb":"remove"}`,
		`{"verb":"vpn-egress-apply","iface":"a b"}`, `{"verb":"apply","port":-1,"ca":"/x"}`,
	} {
		f.Add(s)
	}
	const owner = 4242
	f.Fuzz(func(t *testing.T, line string) {
		r, err := ParseRequest(line, owner)
		if err != nil {
			return
		}
		if _, ok := verbs[r.Verb]; !ok {
			t.Fatalf("accepted verb outside closed set: %q", r.Verb)
		}
		if r.UID != owner {
			t.Fatalf("uid not owner: %d", r.UID)
		}
		if r.Verb != strings.ToLower(r.Verb) {
			t.Fatalf("verb not normalised: %q", r.Verb)
		}
		if r.CA != "" && r.CA != "-" && (!filepath.IsAbs(r.CA) || filepath.Clean(r.CA) != r.CA) {
			t.Fatalf("unclean CA accepted: %q", r.CA)
		}
		if r.Iface != "" {
			if err := privexec.ValidIface(r.Iface); err != nil {
				t.Fatalf("bad iface accepted: %q", r.Iface)
			}
		}
		if r.Verb == "apply" {
			if err := privexec.ValidPort(r.Port); err != nil {
				t.Fatalf("bad port accepted: %d", r.Port)
			}
		}
		for _, s := range []string{r.CA, r.Iface} {
			if strings.ContainsAny(s, "\x00\n\r") {
				t.Fatalf("control char in %q", s)
			}
		}
	})
}
