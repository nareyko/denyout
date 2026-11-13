package check_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/policy"
)

func TestCheckCanaryDenies(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	url := "https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB"
	res, err := check.URL(cfg, url)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != check.VerdictDeny {
		t.Fatalf("verdict=%s reasons=%v", res.Verdict, res.Reasons)
	}
	joined := strings.Join(res.Reasons, ",")
	if !strings.Contains(joined, "canary_detected") && !strings.Contains(joined, "secret_in_url") && !strings.Contains(joined, "host_not_allowed") {
		t.Fatalf("unexpected reasons: %v", res.Reasons)
	}
	if strings.Contains(res.URL, "DENYOUT_CANARY_LAB") {
		t.Fatalf("raw canary leaked in output url=%s", res.URL)
	}
	if strings.Contains(res.Human(), "DENYOUT_CANARY_LAB") {
		t.Fatalf("raw canary leaked in human output")
	}
}

func TestCheckAllowModelHost(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	res, err := check.URL(cfg, "https://api.anthropic.com/")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != check.VerdictAllow {
		t.Fatalf("verdict=%s reasons=%v", res.Verdict, res.Reasons)
	}
}
