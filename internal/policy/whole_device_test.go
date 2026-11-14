package policy_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestWholeDeviceAgentDeniesUnknownAllowsModels(t *testing.T) {
	cfg, err := policy.DefaultWholeDevice()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)

	denyHost, err := eng.EvaluateURL("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if denyHost.Verdict != "deny" {
		t.Fatalf("example.com: want deny (agent), got %+v", denyHost)
	}

	allowModel, err := eng.EvaluateURL("https://api.anthropic.com/")
	if err != nil {
		t.Fatal(err)
	}
	if allowModel.Verdict != "allow" {
		t.Fatalf("anthropic: want allow, got %+v", allowModel)
	}

	for _, u := range []string{
		"https://api2.cursor.sh/",
		"https://metrics.cursor.sh/",
		"https://api.origin.cursor.com/",
		"https://agentn.global.api5.cursor.sh/",
		"https://downloads.cursor.com/",
	} {
		d, err := eng.EvaluateURL(u)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != "allow" {
			t.Fatalf("cursor allowlist %s: want allow, got %+v", u, d)
		}
	}

	secret, err := eng.EvaluateURL("https://api.anthropic.com/?api_key=sk-ant-testvalue123456")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Verdict != "deny" {
		t.Fatalf("secret URL: want deny, got %+v", secret)
	}

	meta, err := eng.EvaluateURL("http://169.254.169.254/latest/meta-data/")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Verdict != "deny" {
		t.Fatalf("metadata: want deny, got %+v", meta)
	}
}

func TestWholeDeviceBrowseAllowsWeb(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	allow, err := eng.EvaluateURL("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if allow.Verdict != "allow" {
		t.Fatalf("browse example.com: want allow, got %+v", allow)
	}
}

func TestWholeDeviceAskDeniesUnknownUntilAllow(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceAsk(nil)
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	d, err := eng.EvaluateURL("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != "deny" {
		t.Fatalf("ask mode unknown host: want deny, got %+v", d)
	}

	cfg2, err := policy.DefaultWholeDeviceAsk([]policy.Rule{{Host: "example.com", Reason: "user_always"}})
	if err != nil {
		t.Fatal(err)
	}
	eng2 := policy.NewEngine(cfg2)
	d2, err := eng2.EvaluateURL("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d2.Verdict != "allow" {
		t.Fatalf("after allow: want allow, got %+v", d2)
	}
}
