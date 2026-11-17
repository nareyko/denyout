package settings

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/appstate"
	"github.com/nareyko/denyout/internal/cloudsync"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func byKey(vs []Value, k string) Value {
	for _, v := range vs {
		if v.Key == k {
			return v
		}
	}
	return Value{}
}

func TestPrecedenceFlagEnvStateDefault(t *testing.T) {
	st := appstate.DefaultState()
	st.PolicyProfile = "browse"

	// default: nothing explicit
	v := byKey(Resolve(appstate.State{}, nil, nil), "decision_timeout_sec")
	if v.Value != "15" || v.Source != SourceDefault {
		t.Errorf("default: %+v", v)
	}
	// state beats default
	st.DecisionTimeoutSec = 30
	v = byKey(Resolve(st, nil, nil), "decision_timeout_sec")
	if v.Value != "30" || v.Source != SourceState {
		t.Errorf("state: %+v", v)
	}
	// env beats state
	env := envMap(map[string]string{"DENYOUT_POLICY_PROFILE": "agent"})
	v = byKey(Resolve(st, env, nil), "policy_profile")
	if v.Value != "agent" || v.Source != SourceEnv {
		t.Errorf("env over state: %+v", v)
	}
	// flag beats env
	v = byKey(Resolve(st, env, map[string]string{"policy_profile": "browse"}), "policy_profile")
	if v.Value != "browse" || v.Source != SourceFlag {
		t.Errorf("flag over env: %+v", v)
	}
}

func TestLegacyStateWinsExceptions(t *testing.T) {
	st := appstate.State{UpdateManifestURL: "https://state.example/m.json"}
	env := envMap(map[string]string{"DENYOUT_UPDATE_MANIFEST_URL": "https://env.example/m.json"})
	v := byKey(Resolve(st, env, nil), "update_manifest_url")
	if v.Value != st.UpdateManifestURL || v.Source != SourceState {
		t.Errorf("state must win for update_manifest_url: %+v", v)
	}
	v = byKey(Resolve(appstate.State{}, env, nil), "update_manifest_url")
	if v.Source != SourceEnv {
		t.Errorf("env used when state empty: %+v", v)
	}
}

func TestEnvEnableOnly(t *testing.T) {
	on := appstate.State{TunDataplane: true}
	off := envMap(map[string]string{"DENYOUT_TUN_E2E": "0"})
	if v := byKey(Resolve(on, off, nil), "tun_dataplane"); v.Value != "true" || v.Source != SourceState {
		t.Errorf("env=0 must not switch tun off: %+v", v)
	}
	one := envMap(map[string]string{"DENYOUT_TUN_E2E": "1"})
	if v := byKey(Resolve(appstate.State{}, one, nil), "tun_dataplane"); v.Value != "true" || v.Source != SourceEnv {
		t.Errorf("env=1 enables: %+v", v)
	}
	// Strict "1": "true" is not the legacy gate value.
	tr := envMap(map[string]string{"DENYOUT_TUN_E2E": "true"})
	if v := byKey(Resolve(appstate.State{}, tr, nil), "tun_dataplane"); v.Value != "false" {
		t.Errorf("strict gate accepted 'true': %+v", v)
	}
}

func TestEnvOnlySettingsIgnoreState(t *testing.T) {
	for _, k := range []string{"allow_private", "tls_insecure_upstream"} {
		sp, _ := SpecByKey(k)
		if sp.State {
			t.Errorf("%s must never be state-backed", k)
		}
	}
	env := envMap(map[string]string{"DENYOUT_ALLOW_PRIVATE": "TRUE", "DENYOUT_TLS_INSECURE_UPSTREAM": "1"})
	s := Effective(appstate.State{}, env, nil)
	if !s.AllowPrivate || !s.TLSInsecureUpstream {
		t.Errorf("env bools not parsed: %+v", s)
	}
	if s.SourceOf("allow_private") != SourceEnv {
		t.Error("source")
	}
	if Effective(appstate.State{}, nil, nil).AllowPrivate {
		t.Error("default must be off")
	}
}

func TestSecretsRedacted(t *testing.T) {
	st := appstate.State{AccountToken: "tok-123", AccountEmail: "a@b.c", CustomCommand: "x --key=sk-1", AccountAPIBase: "https://u:p@api.example.com"}
	for _, v := range Resolve(st, nil, nil) {
		d := v.Display()
		for _, bad := range []string{"tok-123", "a@b.c", "sk-1", "u:p@"} {
			if strings.Contains(d, bad) {
				t.Errorf("%s leaks %q: %q", v.Key, bad, d)
			}
		}
	}
	if byKey(Resolve(st, nil, nil), "account_token").Display() != "(set)" {
		t.Error("token should show (set)")
	}
	if byKey(Resolve(appstate.State{}, nil, nil), "account_token").Display() != "" {
		t.Error("unset secret should be empty")
	}
}

func TestSyncCannotLowerBodyScannerProtections(t *testing.T) {
	st := appstate.State{BodyPureA: true, AntiChunkEnabled: true}
	appstate.ApplySyncSettings(&st, cloudsync.Settings{})
	s := Effective(st, nil, nil)
	if !s.BodyPureA || !s.AntiChunkEnabled {
		t.Fatal("remote sync lowered BodyPureA/AntiChunk")
	}
	for _, k := range []string{"body_pure_a", "anti_chunk_enabled"} {
		sp, _ := SpecByKey(k)
		if sp.Env != "" {
			t.Errorf("%s must not have an env override", k)
		}
	}
}

func TestValidate(t *testing.T) {
	if errs := Validate(appstate.DefaultState()); len(errs) != 0 {
		t.Fatalf("defaults invalid: %v", errs)
	}
	bad := appstate.State{
		NotifyLevel: "loud", DecisionTimeoutSec: 99999, ReaskIntervalSec: -1, PolicyProfile: "x",
		Scope: "weird", UpdateManifestURL: "http://x", AccountAPIBase: "ftp://y",
		NotifySnoozeUntil: "yesterday", AlwaysAllowHosts: []string{"*.com", "ok.example.com"},
	}
	errs := Validate(bad)
	if len(errs) != 9 {
		t.Fatalf("want 9 problems, got %d: %v", len(errs), errs)
	}
}

func TestEffectiveFromLegacyFixtureShape(t *testing.T) {
	// A pre-versioning state (no notify_level, notify=true) maps to "normal".
	s := Effective(appstate.State{Notify: true}, nil, nil)
	if s.NotifyLevel != "normal" || s.SourceOf("notify_level") != SourceState {
		t.Errorf("%+v", s)
	}
}

// ---- docs/configuration.md must cover every setting and DENYOUT_* variable ----

func repoRoot(t *testing.T) string {
	t.Helper()
	d, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		d = filepath.Dir(d)
	}
	t.Fatal("repo root not found")
	return ""
}

func TestDocsCoverSettingsAndEnv(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, sp := range Specs {
		if !strings.Contains(doc, "`"+sp.Key+"`") {
			t.Errorf("docs/configuration.md lacks setting %q", sp.Key)
		}
		if sp.Env != "" && !strings.Contains(doc, sp.Env) {
			t.Errorf("docs/configuration.md lacks env %s", sp.Env)
		}
	}
	documented := map[string]bool{}
	for _, e := range OtherEnv {
		documented[e.Name] = true
		if !strings.Contains(doc, e.Name) {
			t.Errorf("docs/configuration.md lacks env %s", e.Name)
		}
	}
	for _, sp := range Specs {
		if sp.Env != "" {
			documented[sp.Env] = true
		}
	}
	re := regexp.MustCompile(`DENYOUT_[A-Z0-9]+(?:_[A-Z0-9]+)*`)
	canary := regexp.MustCompile(`^DENYOUT_CANARY`)
	missing := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "docs") {
			return fs.SkipDir
		}
		if d.IsDir() || !(strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".sh")) || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, _ := os.ReadFile(p)
		for _, name := range re.FindAllString(string(src), -1) {
			if !documented[name] && !canary.MatchString(name) {
				missing[name] = p
			}
		}
		return nil
	})
	for n, p := range missing {
		t.Errorf("env var %s (seen in %s) is not documented in settings.OtherEnv/Specs", n, p)
	}
}
