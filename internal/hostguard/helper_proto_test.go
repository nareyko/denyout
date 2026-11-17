package hostguard

import (
	"strings"
	"testing"
)

func TestParseRequestLegacyAndJSON(t *testing.T) {
	const owner = 1000
	ok := []struct {
		line string
		want Request
	}{
		{"caps 0 0 -", Request{Verb: "caps", UID: owner}},
		{"apply 18443 0 -", Request{Verb: "apply", Port: 18443, UID: owner, CA: "-"}},
		{"apply 18443 5 - allow_quic", Request{Verb: "apply", Port: 18443, UID: owner, CA: "-", AllowQUIC: true}},
		{"tun-start 0 0 real mitm", Request{Verb: "tun-start", UID: owner, Real: true, Mitm: true}},
		{"vpn-egress-apply 0 0 wg0", Request{Verb: "vpn-egress-apply", UID: owner, Iface: "wg0"}},
		{`{"verb":"apply","port":443,"ca":"-","flags":["allow_quic"]}`, Request{Verb: "apply", Port: 443, UID: owner, CA: "-", AllowQUIC: true, JSON: true}},
		{`{"verb":"VPN-EGRESS-APPLY","iface":"tailscale0"}`, Request{Verb: "vpn-egress-apply", UID: owner, Iface: "tailscale0", JSON: true}},
	}
	for _, c := range ok {
		got, err := ParseRequest(c.line, owner)
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q:\n got  %+v\n want %+v", c.line, got, c.want)
		}
	}
}

func TestParseRequestRejects(t *testing.T) {
	bad := []string{
		"", "caps", "nope 0 0 -", "apply 0 0 -", "apply 70000 0 -", "apply abc 0 -",
		"vpn-egress-apply 0 0 wg0;id", "vpn-egress-apply 0 0 -", "vpn-egress-apply 0 0 $(id)",
		"apply 18443 0 relative/ca.pem",
		`{"verb":"apply","port":443,"ca":"-","extra":1}`, // unknown field
		`{"verb":"apply"`, `{"verb":"rm"}`, `{"verb":"vpn-egress-apply","iface":"a b"}`,
	}
	for _, l := range bad {
		if _, err := ParseRequest(l, 1000); err == nil {
			t.Errorf("%q must be rejected", l)
		}
	}
}

func TestClientUIDIsNeverTrusted(t *testing.T) {
	r, err := ParseRequest("apply 18443 0 -", 1000)
	if err != nil || r.UID != 1000 {
		t.Fatalf("uid must be the owner: %+v %v", r, err)
	}
	r, _ = ParseRequest("remove 0 4242", 1000)
	if r.UID != 1000 {
		t.Fatal("foreign uid leaked into request")
	}
}

func TestMutatingTable(t *testing.T) {
	for v, want := range map[string]bool{"caps": false, "quic-stats": false, "tun-stats": false, "apply": true, "remove": true, "uninstall-helper": true, "vpn-egress-apply": true} {
		if got := (Request{Verb: v}).Mutating(); got != want {
			t.Errorf("%s mutating=%v want %v", v, got, want)
		}
	}
}

func TestEncodeReply(t *testing.T) {
	if got := encodeReply(Request{}, "OK quic1", nil); got != "OK quic1\n" {
		t.Errorf("legacy ok: %q", got)
	}
	if got := encodeReply(Request{}, "", errString("boom")); got != "ERR boom\n" {
		t.Errorf("legacy err: %q", got)
	}
	if got := encodeReply(Request{JSON: true}, "x", nil); !strings.Contains(got, `"ok":true`) {
		t.Errorf("json ok: %q", got)
	}
	if got := encodeReply(Request{JSON: true}, "", errString("boom")); !strings.Contains(got, `"error":"boom"`) || !strings.Contains(got, `"ok":false`) {
		t.Errorf("json err: %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
