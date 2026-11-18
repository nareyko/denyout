//go:build linux

package hostguard

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

// Characterization of executeHelperRequest / helperTunVerb replies for verbs
// that have no privileged effect on an unprivileged, rule-less test process.

func TestExecuteHelperRequestSafeVerbs(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		prefix  string
		wantErr string
	}{
		{"unknown", Request{Verb: "bogus"}, "", "unknown verb"},
		{"empty", Request{}, "", "unknown verb"},
		{"caps", Request{Verb: "caps"}, "OK", ""},
		{"version", Request{Verb: "version"}, "OK", ""},
		{"fail-status", Request{Verb: "fail-status"}, "OK " + CapFailPolicy, ""},
		{"tun-stats", Request{Verb: "tun-stats"}, "OK " + tun.CapTag, ""},
		{"tun-start-stub", Request{Verb: "tun-start"}, "OK " + tun.CapTag + " enabled=false verb=tun-start", ""},
		{"tun-stop-stub", Request{Verb: "tun-stop"}, "OK " + tun.CapTag + " enabled=false verb=tun-stop", ""},
		{"vpn-egress-remove", Request{Verb: "vpn-egress-remove"}, "OK " + CapVPN + " removed", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := executeHelperRequest(c.req)
			if c.wantErr != "" {
				if err == nil || err.Error() != c.wantErr {
					t.Fatalf("err=%v want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(got, c.prefix) {
				t.Fatalf("reply %q want prefix %q", got, c.prefix)
			}
		})
	}
}

func TestHelperTunVerbUnknownAndStats(t *testing.T) {
	if _, err := helperTunVerb("tun-nope", 1000, false, false); err == nil || !strings.Contains(err.Error(), "unknown helper verb") {
		t.Fatalf("err=%v", err)
	}
	got, err := helperTunVerb("tun-stats", 1000, true, false)
	if err != nil || !strings.HasSuffix(got, "reason=inactive") {
		t.Fatalf("real stats = %q, %v", got, err)
	}
	got, _ = helperTunVerb("tun-stats", 1000, false, false)
	if !strings.HasSuffix(got, "reason=flag_off") {
		t.Fatalf("stub stats = %q", got)
	}
}

func TestHelperTunVerbStopReal(t *testing.T) {
	got, err := helperTunVerb("tun-stop", 1000, true, false)
	if err != nil || got != "OK "+tun.CapTag+" enabled=false verb=tun-stop reason=ok" {
		t.Fatalf("got %q, %v", got, err)
	}
}
