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
