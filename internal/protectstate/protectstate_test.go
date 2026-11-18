package protectstate

import (
	"strings"
	"testing"
)

// legacyUnhealthy / legacyMode are verbatim ports of the pre-refactor desktop logic
// (problemsUnhealthyLocked / uiModeLocked); Compute must match them on every input.
func legacyUnhealthy(in Inputs) bool {
	wantOn := in.Intent || in.ProxydLive || in.SessionLive
	if !wantOn {
		return false
	}
	st := strings.ToLower(in.Status)
	if strings.Contains(st, "error") || strings.Contains(in.Status, "Needs") {
		return true
	}
	if !in.ProxydLive && !in.SessionLive {
		return true
	}
	if in.ProxydLive && in.HelperDegraded {
		return true
	}
	return !in.CAPresent
}

func legacyMode(in Inputs) string {
	if in.ProxydLive {
		if in.AgentsProfile {
			return "agents"
		}
		return "safe"
	}
	if in.SessionLive {
		return "session"
	}
	return "off"
}

func TestComputeMatchesLegacyExhaustive(t *testing.T) {
	b := []bool{false, true}
	statuses := []string{"Off", "Protected", "Session (proxy)", "Error: x", "error", "Needs attention", ""}
	n := 0
	for _, st := range statuses {
		for _, intent := range b {
			for _, px := range b {
				for _, se := range b {
					for _, ag := range b {
						for _, hd := range b {
							for _, ca := range b {
								for _, pa := range b {
									in := Inputs{intent, px, se, ag, st, hd, ca, pa, ""}
									r := Compute(in)
									n++
									if r.NeedsAttention != legacyUnhealthy(in) {
										t.Fatalf("%+v: NeedsAttention=%v legacy=%v", in, r.NeedsAttention, legacyUnhealthy(in))
									}
									if r.Mode != legacyMode(in) {
										t.Fatalf("%+v: Mode=%q legacy=%q", in, r.Mode, legacyMode(in))
									}
									if r.NeedsAttention && r.Message == "" {
										t.Fatalf("%+v: needs attention without reason", in)
									}
									if (r.State == Degraded) != (r.Reason == ReasonHelperDegraded) {
										t.Fatalf("%+v: degraded/reason mismatch %+v", in, r)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d combinations", n)
}

func TestComputeStates(t *testing.T) {
	ok := Inputs{CAPresent: true, Status: "Protected"}
	cases := []struct {
		name string
		mod  func(*Inputs)
		want State
		why  string
	}{
		{"off", func(i *Inputs) {}, Off, ""},
		{"paused", func(i *Inputs) { i.Paused = true }, Paused, ReasonPaused},
		{"protected", func(i *Inputs) { i.ProxydLive = true }, Protected, ""},
		{"agents", func(i *Inputs) { i.ProxydLive, i.AgentsProfile = true, true }, AgentsOnly, ""},
		{"session", func(i *Inputs) { i.SessionLive = true }, Session, ""},
		{"degraded", func(i *Inputs) { i.ProxydLive, i.HelperDegraded = true, true }, Degraded, ReasonHelperDegraded},
		{"intent no proc", func(i *Inputs) { i.Intent = true }, NeedsAttention, ReasonNotRunning},
		{"ca missing", func(i *Inputs) { i.ProxydLive, i.CAPresent = true, false }, NeedsAttention, ReasonCAMissing},
		{"status error", func(i *Inputs) { i.SessionLive, i.Status = true, "Error: boom" }, NeedsAttention, ReasonStatusError},
		{"paused but live wins", func(i *Inputs) { i.Paused, i.ProxydLive = true, true }, Protected, ""},
	}
	for _, c := range cases {
		in := ok
		c.mod(&in)
		r := Compute(in)
		if r.State != c.want || r.Reason != c.why {
			t.Errorf("%s: got %s/%q want %s/%q", c.name, r.State, r.Reason, c.want, c.why)
		}
	}
}

func TestModeLabel(t *testing.T) {
	for m, w := range map[string]string{"safe": "Protected", "agents": "Agents only", "session": "Session", "off": "Off", "x": "Off"} {
		if ModeLabel(m) != w {
			t.Errorf("%s: %s", m, ModeLabel(m))
		}
	}
}

func TestHelperStateDegraded(t *testing.T) {
	for s, w := range map[string]bool{"degraded proxy_down\n": true, "degraded": true, "protected\n": false, "": false, "restored_after_restart": false} {
		if HelperStateDegraded(s) != w {
			t.Errorf("%q", s)
		}
	}
}

func TestFailPolicyFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		env  map[string]string
		def  FailPolicy
		want FailPolicy
	}{
		{nil, "", FailOpen},
		{nil, FailClosed, FailClosed},
		{map[string]string{"DENYOUT_FAIL_CLOSED": "1"}, FailOpen, FailClosed},
		{map[string]string{"DENYOUT_FAIL_CLOSED": "0"}, FailOpen, FailOpen},
		{map[string]string{"DENYOUT_FAIL_POLICY": "closed"}, FailOpen, FailClosed},
		{map[string]string{"DENYOUT_FAIL_POLICY": "OPEN"}, FailClosed, FailOpen},
		{map[string]string{"DENYOUT_FAIL_POLICY": "bogus"}, FailClosed, FailClosed},
		{map[string]string{"DENYOUT_FAIL_CLOSED": "1", "DENYOUT_FAIL_POLICY": "open"}, FailOpen, FailClosed},
	}
	for i, c := range cases {
		if got := FailPolicyFromEnv(env(c.env), c.def); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestTrackerDegradedHook(t *testing.T) {
	var all, deg []Transition
	tr := &Tracker{
		OnTransition: func(x Transition) { all = append(all, x) },
		OnDegraded:   func(x Transition) { deg = append(deg, x) },
	}
	prot := Result{State: Protected}
	dg := Result{State: Degraded, Reason: ReasonHelperDegraded, Message: "m"}
	if _, ch := tr.Observe(dg); ch {
		t.Fatal("first observation must not fire")
	}
	tr.Observe(dg)
	tr.Observe(prot)
	if _, ch := tr.Observe(dg); !ch {
		t.Fatal("protected->degraded must fire")
	}
	tr.Observe(dg)
	if len(deg) != 1 || deg[0].From != Protected || deg[0].Message != "m" {
		t.Fatalf("degraded hook: %+v", deg)
	}
	if len(all) != 2 {
		t.Fatalf("transitions: %+v", all)
	}
}

func TestResolveFailPolicySource(t *testing.T) {
	cases := []struct {
		env     map[string]string
		setting FailPolicy
		want    FailPolicy
		src     string
	}{
		{nil, "", FailOpen, PolicySourceDefault},
		{nil, FailClosed, FailClosed, PolicySourceSetting},
		{nil, "bogus", FailOpen, PolicySourceDefault},
		{map[string]string{"DENYOUT_FAIL_POLICY": "open"}, FailClosed, FailOpen, PolicySourceEnv},
		{map[string]string{"DENYOUT_FAIL_POLICY": "closed"}, FailOpen, FailClosed, PolicySourceEnv},
		{map[string]string{"DENYOUT_FAIL_CLOSED": "1", "DENYOUT_FAIL_POLICY": "open"}, FailOpen, FailClosed, PolicySourceEnvLegacy},
		{map[string]string{"DENYOUT_FAIL_CLOSED": "0"}, FailClosed, FailClosed, PolicySourceSetting},
	}
	for i, c := range cases {
		m := c.env
		p, src := ResolveFailPolicy(func(k string) string { return m[k] }, c.setting)
		if p != c.want || src != c.src {
			t.Errorf("case %d: got %s/%s want %s/%s", i, p, src, c.want, c.src)
		}
	}
}

func TestMessageMentionsPolicy(t *testing.T) {
	deg := Inputs{Intent: true, ProxydLive: true, HelperDegraded: true, CAPresent: true}
	if m := Compute(deg).Message; strings.Contains(m, "setting") {
		t.Fatalf("unknown policy must keep the generic message: %q", m)
	}
	deg.FailPolicy = FailOpen
	if m := Compute(deg).Message; !strings.Contains(m, "keeps the internet working") {
		t.Fatalf("open: %q", m)
	}
	down := Inputs{Intent: true, CAPresent: true, FailPolicy: FailClosed}
	r := Compute(down)
	if r.State != NeedsAttention || !strings.Contains(r.Message, "blocks web traffic") {
		t.Fatalf("closed: %+v", r)
	}
}
