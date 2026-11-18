//go:build linux

package hostguard

import (
	"errors"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/protectstate"
	"github.com/nareyko/denyout/internal/tun"
)

// stubFx replaces every privileged effect with a recorder and restores fx.
func stubFx(t *testing.T) *[]string {
	t.Helper()
	old := fx
	t.Cleanup(func() { fx = old })
	var calls []string
	rec := func(s string) { calls = append(calls, s) }
	fx = helperEffects{
		stopTun:       func() error { rec("stopTun"); return nil },
		removeVPN:     func() error { rec("removeVPN"); return nil },
		applyVPN:      func(i string) error { rec("applyVPN:" + i); return nil },
		apply:         func(s Spec) error { rec("apply"); return nil },
		remove:        func(Spec) error { rec("remove"); return nil },
		teardown:      func(Spec) error { rec("teardown"); return nil },
		uninstall:     func() error { rec("uninstall"); return nil },
		clearApplied:  func() { rec("clearApplied") },
		persist:       func(Spec) { rec("persist") },
		setFailPolicy: func(p protectstate.FailPolicy) { rec("failPolicy:" + string(p)) },
		quicStats:     func() (QUICDropStats, error) { rec("quicStats"); return QUICDropStats{}, nil },
		startTun:      func(tun.StartOpts) error { rec("startTun"); return nil },
		tunSnapshot:   func() (tun.DropStats, bool) { return tun.DropStats{}, false },
		suppressT0:    func(b bool) { rec("suppress:" + map[bool]string{true: "on", false: "off"}[b]) },
		mitmConfig:    func(string) (tun.MITMConfig, error) { rec("mitmConfig"); return tun.MITMConfig{}, errors.New("no ca") },
	}
	return &calls
}

func TestHelperHandlersMatchVerbTable(t *testing.T) {
	for v := range verbs {
		if helperHandlers[v] == nil {
			t.Errorf("verb %q in closed table has no handler", v)
		}
	}
	for v := range helperHandlers {
		if _, ok := verbs[v]; !ok {
			t.Errorf("handler %q is not in the closed verb table", v)
		}
	}
}

func TestExecuteApplySequence(t *testing.T) {
	calls := stubFx(t)
	lastApplyMu.Lock()
	old, oldOK := lastApplySpec, lastApplyOK
	lastApplyMu.Unlock()
	t.Cleanup(func() { lastApplyMu.Lock(); lastApplySpec, lastApplyOK = old, oldOK; lastApplyMu.Unlock() })

	got, err := executeHelperRequest(Request{Verb: "apply", Port: 18443, UID: 1000, CA: "/x", AllowQUIC: true, FailPolicy: "closed"})
	if err != nil || got != "OK quic1" {
		t.Fatalf("got %q, %v", got, err)
	}
	want := "stopTun,apply,failPolicy:closed,persist"
	if strings.Join(*calls, ",") != want {
		t.Fatalf("calls %v want %s", *calls, want)
	}
	lastApplyMu.Lock()
	defer lastApplyMu.Unlock()
	if lastApplySpec.ProxyPort != 18443 || lastApplySpec.UID != 1000 || lastApplySpec.CACert != "/x" || !lastApplySpec.AllowQUIC || !lastApplyOK {
		t.Fatalf("spec = %+v ok=%v", lastApplySpec, lastApplyOK)
	}
}

func TestExecuteApplyFailureLeavesStateAlone(t *testing.T) {
	calls := stubFx(t)
	fx.apply = func(Spec) error { return errors.New("boom") }
	lastApplyMu.Lock()
	lastApplyOK = false
	lastApplyMu.Unlock()
	if _, err := executeHelperRequest(Request{Verb: "apply", Port: 1}); err == nil || err.Error() != "boom" {
		t.Fatalf("err=%v", err)
	}
	if strings.Join(*calls, ",") != "stopTun" {
		t.Fatalf("calls %v", *calls)
	}
	lastApplyMu.Lock()
	defer lastApplyMu.Unlock()
	if lastApplyOK {
		t.Fatal("failed apply must not mark applied")
	}
}

func TestExecuteEndProtectVerbs(t *testing.T) {
	for _, c := range []struct{ verb, last string }{
		{"remove", "remove"}, {"teardown", "teardown"}, {"uninstall-helper", "uninstall"},
	} {
		calls := stubFx(t)
		got, err := executeHelperRequest(Request{Verb: c.verb})
		if err != nil || got != "OK quic1" {
			t.Fatalf("%s: %q %v", c.verb, got, err)
		}
		if want := "clearApplied,stopTun,removeVPN," + c.last; strings.Join(*calls, ",") != want {
			t.Fatalf("%s: calls %v want %s", c.verb, *calls, want)
		}
		fx.remove = func(Spec) error { return errors.New("x") }
		fx.teardown = func(Spec) error { return errors.New("x") }
		fx.uninstall = func() error { return errors.New("x") }
		if _, err := executeHelperRequest(Request{Verb: c.verb}); err == nil {
			t.Fatalf("%s: effect error must propagate", c.verb)
		}
	}
}

func TestExecuteFailPolicyPersistsOnlyWhenApplied(t *testing.T) {
	calls := stubFx(t)
	lastApplyMu.Lock()
	old := lastApplyOK
	lastApplyOK = false
	lastApplyMu.Unlock()
	t.Cleanup(func() { lastApplyMu.Lock(); lastApplyOK = old; lastApplyMu.Unlock() })

	got, err := executeHelperRequest(Request{Verb: "fail-policy", FailPolicy: "open"})
	if err != nil || !strings.HasPrefix(got, "OK "+CapFailPolicy) {
		t.Fatalf("%q %v", got, err)
	}
	if strings.Join(*calls, ",") != "failPolicy:open" {
		t.Fatalf("calls %v", *calls)
	}
	lastApplyMu.Lock()
	lastApplyOK = true
	lastApplyMu.Unlock()
	*calls = nil
	_, _ = executeHelperRequest(Request{Verb: "fail-policy", FailPolicy: "closed"})
	if strings.Join(*calls, ",") != "failPolicy:closed,persist" {
		t.Fatalf("calls %v", *calls)
	}
}

func TestExecuteQUICStatsAndVPN(t *testing.T) {
	stubFx(t)
	got, err := executeHelperRequest(Request{Verb: "quic-stats"})
	if err != nil || !strings.HasPrefix(got, "OK quic1 ") || !strings.Contains(got, "source=nft") {
		t.Fatalf("%q %v", got, err)
	}
	fx.quicStats = func() (QUICDropStats, error) { return QUICDropStats{}, errors.New("nft") }
	if _, err := executeHelperRequest(Request{Verb: "quic-stats"}); err == nil {
		t.Fatal("want error")
	}
	got, _ = executeHelperRequest(Request{Verb: "vpn-egress-apply", Iface: "wg0"})
	if got != "OK "+CapVPN+" applied iface=wg0" {
		t.Fatalf("%q", got)
	}
	fx.applyVPN = func(string) error { return errors.New("x") }
	if _, err := executeHelperRequest(Request{Verb: "vpn-egress-apply", Iface: "wg0"}); err == nil {
		t.Fatal("want error")
	}
}

func TestTunStartReal(t *testing.T) {
	calls := stubFx(t)
	var got tun.StartOpts
	fx.startTun = func(o tun.StartOpts) error { got = o; *calls = append(*calls, "startTun"); return nil }
	lastApplyMu.Lock()
	old := lastApplySpec
	lastApplySpec = Spec{ProxyPort: 7777, CACert: "/ca"}
	lastApplyMu.Unlock()
	t.Cleanup(func() { lastApplyMu.Lock(); lastApplySpec = old; lastApplyMu.Unlock() })

	reply, err := helperTunVerb("tun-start", 1000, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if reply != "OK "+tun.CapTag+" enabled=true verb=tun-start reason=ok tcp=1 mitm=true" {
		t.Fatalf("reply %q", reply)
	}
	if got.UID != 1000 || got.ProxyPort != 7777 || !got.EnableTCP || !got.QUICMITM {
		t.Fatalf("opts %+v", got)
	}
	if want := "mitmConfig,startTun,suppress:on"; strings.Join(*calls, ",") != want {
		t.Fatalf("calls %v want %s", *calls, want)
	}
	// start failure: no suppression
	*calls = nil
	fx.startTun = func(tun.StartOpts) error { return errors.New("tun: boom") }
	if _, err := helperTunVerb("tun-start", 1000, true, false); err == nil {
		t.Fatal("want error")
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "suppress") {
			t.Fatal("must not suppress T0 when start failed")
		}
	}
}

func TestTunStartStubDoesNotTouchRuntime(t *testing.T) {
	calls := stubFx(t)
	reply, err := helperTunVerb("tun-start", 1000, false, false)
	if err != nil || !strings.Contains(reply, "enabled=false") {
		t.Fatalf("%q %v", reply, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("stub start must have no effects: %v", *calls)
	}
}

func TestTunStopAlwaysStopsAndUnsuppresses(t *testing.T) {
	calls := stubFx(t)
	if _, err := helperTunVerb("tun-stop", 1000, false, false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*calls, ",") != "stopTun,suppress:off" {
		t.Fatalf("calls %v", *calls)
	}
}

func TestTunStatsReason(t *testing.T) {
	cases := []struct {
		real, active, want, present bool
		out                         string
	}{
		{false, false, false, false, "flag_off"},
		{false, false, false, true, "flag_off"},
		{true, false, false, true, "ok"},
		{true, false, false, false, "inactive"},
		{false, true, false, false, "flag_off"},
		{false, true, false, true, "ok"},
		{false, false, true, false, "inactive"},
		{false, false, true, true, "ok"},
	}
	for _, c := range cases {
		if got := tunStatsReason(c.real, c.active, c.want, c.present); got != c.out {
			t.Errorf("%+v got %s", c, got)
		}
	}
}
