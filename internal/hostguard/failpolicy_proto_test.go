package hostguard

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/protectstate"
)

func TestParseRequestFailPolicy(t *testing.T) {
	const owner = 1000
	ok := []struct {
		line string
		want Request
	}{
		{"apply 18443 0 - 0 fail=closed", Request{Verb: "apply", Port: 18443, UID: owner, CA: "-", FailPolicy: "closed"}},
		{"apply 18443 0 - 1 FAIL=OPEN", Request{Verb: "apply", Port: 18443, UID: owner, CA: "-", AllowQUIC: true, FailPolicy: "open"}},
		{"apply 18443 0 -", Request{Verb: "apply", Port: 18443, UID: owner, CA: "-"}}, // legacy: no change
		{`{"verb":"apply","port":443,"ca":"-","fail_policy":"closed"}`, Request{Verb: "apply", Port: 443, UID: owner, CA: "-", FailPolicy: "closed", JSON: true}},
		{`{"verb":"fail-policy","fail_policy":"open"}`, Request{Verb: "fail-policy", UID: owner, FailPolicy: "open", JSON: true}},
		{"fail-policy 0 0 closed", Request{Verb: "fail-policy", UID: owner, FailPolicy: "closed"}},
		{"fail-status 0 0 -", Request{Verb: "fail-status", UID: owner}},
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
	bad := []string{
		"apply 18443 0 - 0 fail=maybe", "apply 18443 0 - 0 fail=soft", "apply 18443 0 - 0 fail=",
		"fail-policy 0 0 -", "fail-policy 0 0 strict", "fail-policy 0 0",
		`{"verb":"apply","port":443,"ca":"-","fail_policy":"strict"}`,
		`{"verb":"fail-policy"}`, `{"verb":"fail-policy","fail_policy":"OPEN; rm"}`,
		`{"verb":"fail-policy","fail_policy":1}`,
	}
	for _, l := range bad {
		if _, err := ParseRequest(l, owner); err == nil {
			t.Errorf("%q must be rejected", l)
		}
	}
}

func TestFailVerbsMutating(t *testing.T) {
	if !(Request{Verb: "fail-policy"}).Mutating() || (Request{Verb: "fail-status"}).Mutating() {
		t.Fatal("fail-policy must be mutating, fail-status read-only")
	}
}

func TestFailPolicyReplyRoundTrip(t *testing.T) {
	r := FormatFailPolicyReply(protectstate.FailClosed, protectstate.PolicySourceEnv, protectstate.FailOpen)
	st, err := ParseFailPolicyReply(r)
	if err != nil || st.Policy != protectstate.FailClosed || st.Source != protectstate.PolicySourceEnv || st.Configured != protectstate.FailOpen {
		t.Fatalf("%q -> %+v %v", r, st, err)
	}
	r = FormatFailPolicyReply(protectstate.FailOpen, protectstate.PolicySourceDefault, "")
	if st, err = ParseFailPolicyReply(r); err != nil || st.Configured != "" {
		t.Fatalf("%q -> %+v %v", r, st, err)
	}
	for _, bad := range []string{"ERR nope", "OK fail1 policy=weird source=x", "OK"} {
		if _, err := ParseFailPolicyReply(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestHelperStatePersistsFailPolicy(t *testing.T) {
	spec := Spec{ProxyPort: 18443, UID: 1000}
	b, err := encodeHelperStatePolicy(spec, protectstate.FailClosed)
	if err != nil || !strings.Contains(string(b), `"fail_policy":"closed"`) {
		t.Fatalf("%s %v", b, err)
	}
	if p := decodeHelperFailPolicy(b); p != protectstate.FailClosed {
		t.Fatalf("round trip: %q", p)
	}
	// Old files (no field) and tampered values are ignored, never widened.
	old, _ := encodeHelperState(spec)
	if p := decodeHelperFailPolicy(old); p != "" {
		t.Fatalf("legacy file: %q", p)
	}
	if p := decodeHelperFailPolicy([]byte(`{"version":1,"fail_policy":"strict"}`)); p != "" {
		t.Fatalf("tampered: %q", p)
	}
	if p := decodeHelperFailPolicy([]byte(`garbage`)); p != "" {
		t.Fatalf("garbage: %q", p)
	}
	if b, _ := encodeHelperStatePolicy(spec, "bogus"); strings.Contains(string(b), "fail_policy") {
		t.Fatalf("invalid policy must not be written: %s", b)
	}
}

func TestEffectiveFailPolicySource(t *testing.T) {
	t.Setenv("DENYOUT_FAIL_CLOSED", "")
	t.Setenv("DENYOUT_FAIL_POLICY", "")
	defer SetFailPolicy("")
	if p, s := EffectiveFailPolicy(); p != protectstate.FailOpen || s != protectstate.PolicySourceDefault {
		t.Fatalf("%s %s", p, s)
	}
	SetFailPolicy(protectstate.FailClosed)
	if p, s := EffectiveFailPolicy(); p != protectstate.FailClosed || s != protectstate.PolicySourceSetting {
		t.Fatalf("%s %s", p, s)
	}
	t.Setenv("DENYOUT_FAIL_POLICY", "open")
	if p, s := EffectiveFailPolicy(); p != protectstate.FailOpen || s != protectstate.PolicySourceEnv {
		t.Fatalf("%s %s", p, s)
	}
	t.Setenv("DENYOUT_FAIL_CLOSED", "1")
	if p, s := EffectiveFailPolicy(); p != protectstate.FailClosed || s != protectstate.PolicySourceEnvLegacy {
		t.Fatalf("%s %s", p, s)
	}
}

func TestWatchdogLivePolicySwitch(t *testing.T) {
	w := &watchdog{failClosed: true}
	for i := 0; i < 2*watchdogThreshold; i++ {
		if e := w.observe(false); e != "" {
			t.Fatalf("closed: edge %q", e)
		}
	}
	if !w.proxyDown() || !w.closed() {
		t.Fatal("expected down+closed")
	}
	// closed -> open while the proxy is still down: degrade on the very next probe.
	if e := w.setPolicy(false); e != "" {
		t.Fatalf("open switch edge %q", e)
	}
	if e := w.observe(false); e != "degrade" {
		t.Fatalf("want immediate degrade, got %q", e)
	}
	// open -> closed while degraded: put the rules back.
	if e := w.setPolicy(true); e != "reclose" || w.isDegraded() {
		t.Fatalf("want reclose, got %q", e)
	}
	if e := w.observe(false); e != "" {
		t.Fatalf("closed again must not degrade, got %q", e)
	}
	// open -> closed while healthy: nothing to do.
	w2 := &watchdog{}
	if e := w2.setPolicy(true); e != "" {
		t.Fatalf("healthy tighten edge %q", e)
	}
}
