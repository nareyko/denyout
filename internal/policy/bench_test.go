package policy_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func BenchmarkEvaluateURLAllow(b *testing.B) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := policy.EvaluateURL(cfg, "https://api.anthropic.com/v1/messages"); err != nil {
			b.Fatal(err)
		}
	}
}
