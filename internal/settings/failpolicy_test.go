package settings

import (
	"testing"

	"github.com/nareyko/denyout/internal/appstate"
	"github.com/nareyko/denyout/internal/cloudsync"
)

func TestFailPolicyPrecedence(t *testing.T) {
	cases := []struct {
		name    string
		state   string
		env     map[string]string
		want    string
		source  Source
		envName string
	}{
		{"default", "", nil, "open", SourceDefault, ""},
		{"state closed", "closed", nil, "closed", SourceState, ""},
		{"state open explicit", "open", nil, "open", SourceState, ""},
		{"env policy beats state", "closed", map[string]string{"DENYOUT_FAIL_POLICY": "open"}, "open", SourceEnv, "DENYOUT_FAIL_POLICY"},
		{"env policy closed beats default", "", map[string]string{"DENYOUT_FAIL_POLICY": "closed"}, "closed", SourceEnv, "DENYOUT_FAIL_POLICY"},
		{"legacy beats policy env", "open", map[string]string{"DENYOUT_FAIL_CLOSED": "1", "DENYOUT_FAIL_POLICY": "open"}, "closed", SourceEnv, "DENYOUT_FAIL_CLOSED"},
		{"legacy 0 ignored", "closed", map[string]string{"DENYOUT_FAIL_CLOSED": "0"}, "closed", SourceState, ""},
		{"bad env ignored", "closed", map[string]string{"DENYOUT_FAIL_POLICY": "bogus"}, "closed", SourceState, ""},
		{"garbage state fails safe", "banana", nil, "closed", SourceState, ""},
	}
	for _, c := range cases {
		st := appstate.State{FailPolicy: c.state}
		v := byKey(Resolve(st, envMap(c.env), nil), "fail_policy")
		if v.Value != c.want || v.Source != c.source || (c.envName != "" && v.Env != c.envName) {
			t.Errorf("%s: got %+v want %s/%s/%s", c.name, v, c.want, c.source, c.envName)
		}
		if got := Effective(st, envMap(c.env), nil); got.FailPolicy != c.want {
			t.Errorf("%s: Effective.FailPolicy=%q", c.name, got.FailPolicy)
		}
	}
}

func TestFailPolicyValidateAndSyncTightenOnly(t *testing.T) {
	if errs := Validate(appstate.State{FailPolicy: "closed"}); len(errs) != 0 {
		t.Fatalf("closed must be valid: %v", errs)
	}
	if errs := Validate(appstate.State{FailPolicy: "open"}); len(errs) != 0 {
		t.Fatalf("open must be valid: %v", errs)
	}
	if errs := Validate(appstate.State{FailPolicy: "banana"}); len(errs) != 1 {
		t.Fatalf("banana must be reported once: %v", errs)
	}
	st := appstate.State{FailPolicy: "closed"}
	appstate.ApplySyncSettings(&st, cloudsync.Settings{FailPolicy: "open"})
	if got := Effective(st, nil, nil).FailPolicy; got != "closed" {
		t.Fatalf("sync reopened a strict machine: %q", got)
	}
}
