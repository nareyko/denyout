package desktop

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/cloudsync"
	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/protectstate"
)

func newFailPolicyApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("DENYOUT_FAIL_CLOSED", "")
	t.Setenv("DENYOUT_FAIL_POLICY", "")
	t.Cleanup(func() { hostguard.SetFailPolicy("") })
	return NewApp(Options{Version: "test", NoTray: true})
}

func TestUISetFailPolicyValidatesAndPersists(t *testing.T) {
	a := newFailPolicyApp(t)
	if v := a.GetUISnapshot().FailPolicy; v.Setting != "open" || v.Effective != "open" || v.Source != protectstate.PolicySourceDefault || v.EnvOverride {
		t.Fatalf("default view: %+v", v)
	}
	for _, bad := range []string{"", "soft", "strict", "CLOSED; x", "1"} {
		if err := a.UISetFailPolicy(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if err := a.UISetFailPolicy("closed"); err != nil {
		t.Fatal(err)
	}
	if got := LoadState().FailPolicy; got != "closed" {
		t.Fatalf("not persisted: %q", got)
	}
	if hostguard.ConfiguredFailPolicy() != protectstate.FailClosed {
		t.Fatal("desktop-side policy (sent with the next apply) not updated")
	}
	v := a.GetUISnapshot().FailPolicy
	if v.Setting != "closed" || v.Effective != "closed" || v.Source != protectstate.PolicySourceSetting {
		t.Fatalf("view after set: %+v", v)
	}
	if err := a.UISetFailPolicy(" OPEN "); err != nil {
		t.Fatal(err)
	}
	if LoadState().FailPolicy != "open" || a.GetUISnapshot().FailPolicy.Setting != "open" {
		t.Fatal("switch back to open not applied")
	}
}

func TestFailPolicyViewShowsEnvOverride(t *testing.T) {
	a := newFailPolicyApp(t)
	if err := a.UISetFailPolicy("open"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DENYOUT_FAIL_POLICY", "closed")
	v := a.UIFailPolicy()
	if v.Setting != "open" || v.Effective != "closed" || !v.EnvOverride || !strings.Contains(v.Note, "DENYOUT_FAIL_POLICY") {
		t.Fatalf("%+v", v)
	}
	t.Setenv("DENYOUT_FAIL_CLOSED", "1")
	if v = a.UIFailPolicy(); v.Source != protectstate.PolicySourceEnvLegacy || !strings.Contains(v.Note, "DENYOUT_FAIL_CLOSED") {
		t.Fatalf("%+v", v)
	}
}

func TestFailPolicyViewPrefersHelperReportWhileLive(t *testing.T) {
	a := newFailPolicyApp(t)
	a.mu.Lock()
	a.failHelper = &hostguard.FailPolicyStatus{Policy: protectstate.FailClosed, Source: protectstate.PolicySourceEnv}
	a.mu.Unlock()
	if v := a.UIFailPolicy(); v.Effective != "open" {
		t.Fatalf("helper report must be ignored while Protect is off: %+v", v)
	}
}

func TestRemoteSyncCannotReopenFailPolicy(t *testing.T) {
	a := newFailPolicyApp(t)
	if err := a.UISetFailPolicy("closed"); err != nil {
		t.Fatal(err)
	}
	doc := cloudsync.Document{SchemaVersion: cloudsync.SchemaVersion, Settings: cloudsync.Settings{FailPolicy: "open"}}
	if err := a.applyRemoteDocument(doc); err != nil {
		t.Fatal(err)
	}
	if LoadState().FailPolicy != "closed" || a.UIFailPolicy().Setting != "closed" {
		t.Fatal("remote document reopened the policy")
	}
	// ...but it can tighten.
	if err := a.UISetFailPolicy("open"); err != nil {
		t.Fatal(err)
	}
	doc.Settings.FailPolicy = "closed"
	if err := a.applyRemoteDocument(doc); err != nil {
		t.Fatal(err)
	}
	if LoadState().FailPolicy != "closed" {
		t.Fatal("remote tighten not applied")
	}
}

func TestProtectReasonMentionsPolicy(t *testing.T) {
	a := newFailPolicyApp(t)
	a.mu.Lock()
	a.state.ProtectionOn = true // intent on, nothing running
	a.state.FailPolicy = "closed"
	a.mu.Unlock()
	if r := a.ProtectReason(); !strings.Contains(r, "blocks web traffic") {
		t.Fatalf("closed: %q", r)
	}
	a.mu.Lock()
	a.state.FailPolicy = "open"
	a.mu.Unlock()
	if r := a.ProtectReason(); !strings.Contains(r, "keeps the internet working") {
		t.Fatalf("open: %q", r)
	}
}
