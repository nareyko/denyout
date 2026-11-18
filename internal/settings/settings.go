// Package settings is the typed, versioned view over every user-tunable DenyOut
// setting. It does not own storage: values live in the desktop state file
// (internal/appstate, schema-versioned there), in environment variables, and in
// command-line flags. This package declares each setting once (Specs), resolves
// the effective value with a fixed precedence, validates the state file, and
// reports where every value came from.
//
// Precedence (highest first): flag > env > state file > built-in default.
// Two documented exceptions keep pre-existing behaviour (Spec.StateWins):
// update_manifest_url and account_api_base, where an explicit state value
// beats the env var.
//
// Security: settings that weaken inspection (tls_insecure_upstream,
// allow_private, ...) are environment-only on purpose - they are never read
// from the state file, so a synced or tampered state cannot enable them.
// body_pure_a and anti_chunk_enabled can only be raised by sync, never lowered
// (enforced in appstate.ApplySyncSettings; asserted by tests here).
package settings

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/appstate"
	"github.com/nareyko/denyout/internal/protectstate"
)

// SchemaVersion is the settings schema this build understands; it equals the
// state-file schema version.
const SchemaVersion = appstate.CurrentSchemaVersion

// Source says where an effective value came from.
type Source string

const (
	SourceDefault Source = "default"
	SourceState   Source = "state"
	SourceEnv     Source = "env"
	SourceFlag    Source = "flag"
)

// Kind is a setting's value type.
type Kind string

const (
	KindBool   Kind = "bool"
	KindInt    Kind = "int"
	KindString Kind = "string"
	KindList   Kind = "list" // comma separated
)

// Spec declares one setting.
type Spec struct {
	Key      string // stable key (also the state-file JSON key when State is set)
	Kind     Kind
	Default  string
	Doc      string
	Security string // security note; empty when none
	Env      string // environment override; empty = none
	Flag     string // CLI flag that sets it, e.g. "--ask"; empty = none
	State    bool   // backed by the desktop state file
	// Secret values are never printed (shown as "(set)").
	Secret bool

	// StateWins keeps legacy behaviour: an explicit state value beats the env var.
	StateWins bool
	// EnvEnableOnly: env can switch the feature on but never off (legacy "=1" gates).
	EnvEnableOnly bool
	// Strict1: for bool env vars only the literal "1" counts (legacy exact match);
	// otherwise "1" and "true" (any case) count.
	Strict1 bool

	get func(appstate.State) (val string, explicit bool)
}

// Value is one resolved setting.
type Value struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source Source `json:"source"`
	Env    string `json:"env,omitempty"`
	Secret bool   `json:"-"`
}

// Display returns the value safe for printing (secrets and URL userinfo redacted).
func (v Value) Display() string {
	if v.Secret {
		if v.Value == "" {
			return ""
		}
		return "(set)"
	}
	if (v.Key == "update_manifest_url" || v.Key == "account_api_base") && v.Value != "" {
		if u, err := url.Parse(v.Value); err == nil && u.User != nil {
			u.User = url.User("redacted")
			return u.String()
		}
	}
	return v.Value
}

func boolStr(b bool) string { return strconv.FormatBool(b) }

func ptrBool(p *bool) (string, bool) {
	if p == nil {
		return "true", false
	}
	return boolStr(*p), true
}

// Specs lists every setting, in display order. Extension point: new state-backed
// settings (e.g. a fail-soft policy flag) are added here as one Spec with a
// getter, then documented automatically by `denyout-cli config show` and
// docs/configuration.md (the docs table is checked against this list by a test).
var Specs = []Spec{
	{Key: "notify_level", Kind: KindString, Default: "quiet", State: true,
		Doc: "OS notification verbosity: quiet | normal | detailed.",
		get: func(s appstate.State) (string, bool) {
			return appstate.EffectiveNotifyLevel(s), s.NotifyLevel != "" || s.Notify
		}},
	{Key: "decision_timeout_sec", Kind: KindInt, Default: "15", State: true,
		Doc: "Seconds an Ask prompt waits before the safe default (1-3600).",
		get: func(s appstate.State) (string, bool) {
			return strconv.Itoa(appstate.EffectiveDecisionTimeoutSec(s)), s.DecisionTimeoutSec > 0
		}},
	{Key: "reask_interval_sec", Kind: KindInt, Default: "60", State: true,
		Doc: "Seconds before the same host is asked about again (1-86400).",
		get: func(s appstate.State) (string, bool) {
			return strconv.Itoa(appstate.EffectiveReaskIntervalSec(s)), s.ReaskIntervalSec > 0
		}},
	{Key: "policy_profile", Kind: KindString, Default: "browse", State: true, Env: "DENYOUT_POLICY_PROFILE",
		Doc: "Whole-device policy: browse (Safe desktop) | agent (Agents only, default-deny). The desktop passes it to the root helper through the env var.",
		get: func(s appstate.State) (string, bool) {
			return appstate.NormalizePolicyProfile(s.PolicyProfile), strings.TrimSpace(s.PolicyProfile) != ""
		}},
	{Key: "ask_mode", Kind: KindBool, Default: "false", State: true, Flag: "--ask",
		Doc: "Prompt for unknown hosts instead of denying them outright.",
		get: func(s appstate.State) (string, bool) { return boolStr(s.AskMode), s.AskMode }},
	{Key: "allow_browser_quic", Kind: KindBool, Default: "false", State: true,
		Doc:      "Do not drop UDP/443; browsers may use HTTP/3.",
		Security: "HTTP/3 bypasses TLS interception; default false drops QUIC so browsers fall back to inspectable TCP.",
		get:      func(s appstate.State) (string, bool) { return boolStr(s.AllowBrowserQUIC), s.AllowBrowserQUIC }},
	{Key: "tun_dataplane", Kind: KindBool, Default: "false", State: true, Env: "DENYOUT_TUN_E2E", EnvEnableOnly: true, Strict1: true,
		Doc: "Experimental Linux UDP/443 data plane via denyout0.",
		get: func(s appstate.State) (string, bool) { return boolStr(s.TunDataplane), s.TunDataplane }},
	{Key: "quic_mitm", Kind: KindBool, Default: "false", State: true, Env: "DENYOUT_QUIC_MITM", EnvEnableOnly: true, Strict1: true,
		Doc: "Experimental HTTP/3 decryption; also needs tun_dataplane.",
		get: func(s appstate.State) (string, bool) { return boolStr(s.QuicMITM), s.QuicMITM }},
	{Key: "body_pure_a", Kind: KindBool, Default: "false", State: true,
		Doc:      "Stricter body scanning mode.",
		Security: "Cloud sync can raise but never lower it.",
		get:      func(s appstate.State) (string, bool) { return boolStr(s.BodyPureA), s.BodyPureA }},
	{Key: "anti_chunk_enabled", Kind: KindBool, Default: "false", State: true,
		Doc:      "Detect secrets split across request chunks.",
		Security: "Cloud sync can raise but never lower it.",
		get:      func(s appstate.State) (string, bool) { return boolStr(s.AntiChunkEnabled), s.AntiChunkEnabled }},
	{Key: "sensitive_sinks_enabled", Kind: KindBool, Default: "true", State: true,
		Doc: "Sensitive-sink detection (nil in the file = on).",
		get: func(s appstate.State) (string, bool) { return ptrBool(s.SensitiveSinksEnabled) }},
	{Key: "sensitive_writes_enabled", Kind: KindBool, Default: "true", State: true,
		Doc: "Sensitive-write detection (nil in the file = on).",
		get: func(s appstate.State) (string, bool) { return ptrBool(s.SensitiveWritesEnabled) }},
	{Key: "fail_policy", Kind: KindString, Default: "open", State: true, Env: "DENYOUT_FAIL_POLICY",
		Doc:      "If DenyOut's proxy stops: open = keep the internet working (default; the redirect is removed, state degraded) | closed = block web traffic until it recovers. Precedence: DENYOUT_FAIL_CLOSED=1 > DENYOUT_FAIL_POLICY > this setting > open. The env vars are read by the root helper; the desktop sends the setting to it (also live, no restart).",
		Security: "Cloud sync can set closed but never open. Env vars can override the setting.",
		get: func(s appstate.State) (string, bool) {
			p := appstate.NormalizeFailPolicy(s.FailPolicy)
			if p == "" {
				return "open", false
			}
			return p, true
		}},
	{Key: "always_allow_hosts", Kind: KindList, Default: "", State: true,
		Doc:      "Hosts the user chose to always allow.",
		Security: "Synced lists are re-validated (plain DNS names only, max 500).",
		get: func(s appstate.State) (string, bool) {
			return strings.Join(s.AlwaysAllowHosts, ","), len(s.AlwaysAllowHosts) > 0
		}},
	{Key: "update_manifest_url", Kind: KindString, Default: "", State: true, Env: "DENYOUT_UPDATE_MANIFEST_URL", StateWins: true,
		Doc:      "Update manifest URL (empty = built-in denyout.com URL).",
		Security: "Must be https.",
		get: func(s appstate.State) (string, bool) {
			return s.UpdateManifestURL, strings.TrimSpace(s.UpdateManifestURL) != ""
		}},
	{Key: "account_api_base", Kind: KindString, Default: "", State: true, Env: "DENYOUT_API_BASE", StateWins: true,
		Doc:      "Cloud account API base (empty = built-in default). The account is optional.",
		Security: "Must be https.",
		get: func(s appstate.State) (string, bool) {
			return s.AccountAPIBase, strings.TrimSpace(s.AccountAPIBase) != ""
		}},
	{Key: "account_email", Kind: KindString, State: true, Secret: true,
		Doc: "Signed-in account email.",
		get: func(s appstate.State) (string, bool) { return s.AccountEmail, s.AccountEmail != "" }},
	{Key: "account_token", Kind: KindString, State: true, Secret: true,
		Doc:      "Local cloud session token.",
		Security: "Never synced, never printed.",
		get:      func(s appstate.State) (string, bool) { return s.AccountToken, s.AccountToken != "" }},
	{Key: "custom_command", Kind: KindString, State: true, Secret: true,
		Doc:      "Custom agent launch command.",
		Security: "May embed credentials; redacted in output.",
		get:      func(s appstate.State) (string, bool) { return s.CustomCommand, s.CustomCommand != "" }},

	// Environment-only settings: deliberately not readable from the state file.
	{Key: "allow_private", Kind: KindBool, Default: "false", Env: "DENYOUT_ALLOW_PRIVATE",
		Doc:      "Allow RFC1918/loopback destinations in the whole-device proxy.",
		Security: "Env only; opens SSRF paths to the local network."},
	{Key: "tls_insecure_upstream", Kind: KindBool, Default: "false", Env: "DENYOUT_TLS_INSECURE_UPSTREAM",
		Doc:      "Skip upstream TLS certificate verification.",
		Security: "Lab use only; disables MITM upstream verification. Env only."},
	{Key: "always_allow_env", Kind: KindList, Default: "", Env: "DENYOUT_ALWAYS_ALLOW",
		Doc:      "Comma-separated hosts appended to the allowlist of the root helper's proxy (set by the desktop).",
		Security: "Env only."},
	{Key: "fail_closed", Kind: KindBool, Default: "false", Env: "DENYOUT_FAIL_CLOSED", Strict1: true,
		Doc:      "Keep redirect rules when the proxy dies (strict) instead of opening after ~6s.",
		Security: "Tightens only."},
	{Key: "kill", Kind: KindBool, Default: "false", Env: "DENYOUT_KILL",
		Doc:      "Refuse to start `denyout-cli serve` (kill switch).",
		Security: "Tightens only."},
}

// SpecByKey returns the spec for key.
func SpecByKey(key string) (Spec, bool) {
	for _, s := range Specs {
		if s.Key == key {
			return s, true
		}
	}
	return Spec{}, false
}

// EnvBool parses an env value: "1" or "true" (any case) is true.
func EnvBool(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true")
}

// EnvList splits a comma separated env value, dropping blanks.
func EnvList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envTruthy(sp Spec, raw string) bool {
	if sp.Strict1 {
		return raw == "1"
	}
	return EnvBool(raw)
}

// Resolve computes the effective value and source of every setting. getenv and
// flags may be nil. flags is keyed by setting Key.
func Resolve(st appstate.State, getenv func(string) string, flags map[string]string) []Value {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	out := make([]Value, 0, len(Specs))
	for _, sp := range Specs {
		v := Value{Key: sp.Key, Value: sp.Default, Source: SourceDefault, Env: sp.Env, Secret: sp.Secret}
		var stateVal string
		var stateSet bool
		if sp.State && sp.get != nil {
			stateVal, stateSet = sp.get(st)
		}
		envVal, envSet := "", false
		if sp.Env != "" {
			if raw := strings.TrimSpace(getenv(sp.Env)); raw != "" {
				switch {
				case sp.Kind == KindBool && sp.EnvEnableOnly:
					if envTruthy(sp, raw) {
						envVal, envSet = "true", true
					}
				case sp.Kind == KindBool:
					envVal, envSet = boolStr(envTruthy(sp, raw)), true
				default:
					envVal, envSet = raw, true
				}
			}
		}
		useState := func() {
			if stateSet {
				v.Value, v.Source = stateVal, SourceState
			}
		}
		useEnv := func() {
			if envSet {
				v.Value, v.Source = envVal, SourceEnv
			}
		}
		// Apply lowest precedence first.
		if sp.StateWins {
			useEnv()
			useState()
		} else {
			useState()
			useEnv()
		}
		if sp.Key == "fail_policy" {
			// Same resolver the helper uses: DENYOUT_FAIL_CLOSED=1 beats DENYOUT_FAIL_POLICY
			// beats the state value beats open.
			pol, src := protectstate.ResolveFailPolicy(getenv, protectstate.FailPolicy(appstate.NormalizeFailPolicy(st.FailPolicy)))
			v.Value = string(pol)
			switch src {
			case protectstate.PolicySourceEnvLegacy:
				v.Source, v.Env = SourceEnv, "DENYOUT_FAIL_CLOSED"
			case protectstate.PolicySourceEnv:
				v.Source = SourceEnv
			case protectstate.PolicySourceSetting:
				v.Source = SourceState
			default:
				v.Source = SourceDefault
			}
		}
		if fv, ok := flags[sp.Key]; ok {
			v.Value, v.Source = fv, SourceFlag
		}
		out = append(out, v)
	}
	return out
}

// Settings is the typed form of the resolved values.
type Settings struct {
	SchemaVersion       int
	NotifyLevel         string
	DecisionTimeoutSec  int
	ReaskIntervalSec    int
	PolicyProfile       string
	FailPolicy          string // open | closed (effective; see fail_policy)
	AskMode             bool
	AllowBrowserQUIC    bool
	TunDataplane        bool
	QuicMITM            bool
	BodyPureA           bool
	AntiChunkEnabled    bool
	SensitiveSinks      bool
	SensitiveWrites     bool
	AlwaysAllowHosts    []string
	UpdateManifestURL   string
	AccountAPIBase      string
	AllowPrivate        bool
	TLSInsecureUpstream bool
	AlwaysAllowEnv      []string
	FailClosed          bool
	Kill                bool
	sources             map[string]Source
}

// SourceOf reports where key's value came from.
func (s Settings) SourceOf(key string) Source { return s.sources[key] }

// Effective resolves st/env/flags into typed Settings.
func Effective(st appstate.State, getenv func(string) string, flags map[string]string) Settings {
	vals := Resolve(st, getenv, flags)
	m := make(map[string]Value, len(vals))
	src := make(map[string]Source, len(vals))
	for _, v := range vals {
		m[v.Key] = v
		src[v.Key] = v.Source
	}
	b := func(k string) bool { return m[k].Value == "true" }
	n := func(k string) int { i, _ := strconv.Atoi(m[k].Value); return i }
	return Settings{
		SchemaVersion:       SchemaVersion,
		NotifyLevel:         m["notify_level"].Value,
		DecisionTimeoutSec:  n("decision_timeout_sec"),
		ReaskIntervalSec:    n("reask_interval_sec"),
		PolicyProfile:       appstate.NormalizePolicyProfile(m["policy_profile"].Value),
		FailPolicy:          m["fail_policy"].Value,
		AskMode:             b("ask_mode"),
		AllowBrowserQUIC:    b("allow_browser_quic"),
		TunDataplane:        b("tun_dataplane"),
		QuicMITM:            b("quic_mitm"),
		BodyPureA:           b("body_pure_a"),
		AntiChunkEnabled:    b("anti_chunk_enabled"),
		SensitiveSinks:      b("sensitive_sinks_enabled"),
		SensitiveWrites:     b("sensitive_writes_enabled"),
		AlwaysAllowHosts:    EnvList(m["always_allow_hosts"].Value),
		UpdateManifestURL:   m["update_manifest_url"].Value,
		AccountAPIBase:      m["account_api_base"].Value,
		AllowPrivate:        b("allow_private"),
		TLSInsecureUpstream: b("tls_insecure_upstream"),
		AlwaysAllowEnv:      EnvList(m["always_allow_env"].Value),
		FailClosed:          b("fail_closed"),
		Kill:                b("kill"),
		sources:             src,
	}
}

// Validate checks a state file's values and returns every problem found. A
// non-empty result does not stop the app (it tolerates and clamps these), but
// `denyout-cli config show` surfaces them.
func Validate(st appstate.State) []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	switch st.NotifyLevel {
	case "", "quiet", "normal", "detailed":
	default:
		add("notify_level %q: want quiet|normal|detailed", st.NotifyLevel)
	}
	if st.DecisionTimeoutSec < 0 || st.DecisionTimeoutSec > 3600 {
		add("decision_timeout_sec %d: want 0 (default) or 1-3600", st.DecisionTimeoutSec)
	}
	if st.ReaskIntervalSec < 0 || st.ReaskIntervalSec > 86400 {
		add("reask_interval_sec %d: want 0 (default) or 1-86400", st.ReaskIntervalSec)
	}
	switch strings.ToLower(strings.TrimSpace(st.PolicyProfile)) {
	case "", appstate.PolicyProfileAgent, appstate.PolicyProfileBrowse:
	default:
		add("policy_profile %q: want browse|agent (unknown values behave as browse)", st.PolicyProfile)
	}
	if fp := strings.TrimSpace(st.FailPolicy); fp != "" && fp != "open" && fp != "closed" {
		add("fail_policy %q: want open|closed (anything else is treated as closed)", st.FailPolicy)
	}
	switch st.Scope {
	case appstate.ScopeOff, appstate.ScopeComputer, appstate.ScopeSession:
	default:
		add("scope %q: want \"\"|computer|session", st.Scope)
	}
	for name, u := range map[string]string{"update_manifest_url": st.UpdateManifestURL, "account_api_base": st.AccountAPIBase} {
		if u = strings.TrimSpace(u); u != "" && !strings.HasPrefix(strings.ToLower(u), "https://") {
			add("%s must be https", name)
		}
	}
	for name, ts := range map[string]string{
		"notify_snooze_until": st.NotifySnoozeUntil, "ask_paused_until": st.AskPausedUntil,
		"protect_paused_until": st.ProtectPausedUntil, "not_now_at": st.NotNowAt,
		"update_checked_at": st.UpdateCheckedAt, "config_updated_at": st.ConfigUpdatedAt,
	} {
		if ts = strings.TrimSpace(ts); ts != "" {
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				add("%s %q: not RFC3339", name, ts)
			}
		}
	}
	for _, h := range st.AlwaysAllowHosts {
		if !appstate.ValidAlwaysAllowHost(h) {
			add("always_allow_hosts: %q is not a plain DNS host name", h)
		}
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}
