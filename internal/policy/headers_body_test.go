package policy_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestHeaderSecretUnknownHostDenied(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "evil.example",
		DestPort: 443,
		RawURL:   "https://evil.example/",
		Headers: map[string][]string{
			"Authorization": {"Bearer sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "deny" {
		t.Fatalf("want deny, got %+v", d)
	}
	found := false
	for _, r := range d.Reasons {
		if r == "secret_in_header" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons=%v", d.Reasons)
	}
}

func TestHeaderAuthAllowlistedOK(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "api.anthropic.com",
		DestPort: 443,
		RawURL:   "https://api.anthropic.com/v1/messages",
		Headers: map[string][]string{
			"Authorization": {"Bearer sk-ant-denyouttest0000000000"},
			"x-api-key":     {"sk-ant-denyouttest0000000000"},
		},
	})
	if d.Verdict != "allow" {
		t.Fatalf("want allow for API auth headers, got %+v", d)
	}
}

func TestBrowseModeAuthHeadersToCursorOK(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "api2.cursor.sh",
		DestPort: 443,
		RawURL:   "https://api2.cursor.sh/aiserver.v1.AiService/Stream",
		Headers: map[string][]string{
			"Authorization": {"Bearer crsr_denyouttest000000000000000000000000"},
		},
	})
	if d.Verdict != "allow" {
		t.Fatalf("Safe desktop must allow Cursor API auth headers, got %+v", d)
	}
}

func TestBrowseModeAuthHeadersStillDeniedOnDenyHost(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "pastebin.com",
		DestPort: 443,
		RawURL:   "https://pastebin.com/",
		Headers: map[string][]string{
			"Authorization": {"Bearer sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "deny" {
		t.Fatalf("want deny toward deny-listed host, got %+v", d)
	}
}

func TestBodyPrefixSecretDenied(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost:   "api.anthropic.com",
		DestPort:   443,
		RawURL:     "https://api.anthropic.com/v1/messages",
		BodyPrefix: []byte(`{"prompt":"leak sk-denyouttest000000000000000"}`),
	})
	if d.Verdict != "deny" {
		t.Fatalf("want deny for secret in body even on allowlisted host, got %+v", d)
	}
	found := false
	for _, r := range d.Reasons {
		if r == "secret_in_body" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons=%v", d.Reasons)
	}
}

func TestUserAllowAllSkipsCookieSecret(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	// Without Book B allow: Cookie secret shape still denies on Safe desktop.
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "claude.ai",
		DestPort: 443,
		RawURL:   "https://claude.ai/api/x",
		Headers: map[string][]string{
			"Cookie": {"sessionKey=sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "deny" {
		t.Fatalf("browse without Always allow must still deny Cookie secret, got %+v", d)
	}

	cfg.Allow = append(cfg.Allow, policy.Rule{Host: "claude.ai", Reason: "user_always"})
	eng = policy.NewEngine(cfg)
	d = eng.Evaluate(policy.RequestView{
		DestHost: "claude.ai",
		DestPort: 443,
		RawURL:   "https://claude.ai/api/x",
		Headers: map[string][]string{
			"Cookie":        {"sessionKey=sk-denyouttest000000000000000"},
			"Authorization": {"Bearer sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "allow" {
		t.Fatalf("Allow this site must allow-all secrets (except canary), got %+v", d)
	}

	d = eng.Evaluate(policy.RequestView{
		DestHost: "claude.ai",
		DestPort: 443,
		RawURL:   "https://claude.ai/pixel.png?api_key=DENYOUT_CANARY_LAB",
		Headers: map[string][]string{
			"Cookie": {"sessionKey=sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "deny" {
		t.Fatalf("canary must still deny after Always allow, got %+v", d)
	}
}

func TestPresetAllowDoesNotSkipBodySecret(t *testing.T) {
	// Regression: pack/preset allowlist is not Book B allow-all.
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d := eng.Evaluate(policy.RequestView{
		DestHost: "api.anthropic.com",
		DestPort: 443,
		RawURL:   "https://api.anthropic.com/v1/messages",
		Headers: map[string][]string{
			"Cookie": {"session=sk-denyouttest000000000000000"},
		},
	})
	if d.Verdict != "deny" {
		t.Fatalf("preset allow must not skip Cookie secret, got %+v", d)
	}
}
