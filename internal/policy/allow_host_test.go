package policy_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestAllowHostLiveUpdate(t *testing.T) {
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
		t.Fatalf("before: %+v", d)
	}
	eng.AllowHost("example.com", "user_once")
	d2, err := eng.EvaluateURL("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if d2.Verdict != "allow" {
		t.Fatalf("after once: %+v", d2)
	}
}
