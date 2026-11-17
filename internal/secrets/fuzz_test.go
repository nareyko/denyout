package secrets_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/secrets"
)

// Fuzz: scanners and redactors must never panic, and a redacted URL must never
// still contain a canary marker.
func FuzzScanAndRedact(f *testing.F) {
	for _, s := range []string{
		"https://example.com/?api_key=sk-denyouttest000000000000000",
		"http://user:pw@host/p?x=%2e%2e", "https://h/bot123456789:" + strings.Repeat("A", 35),
		"http://[::1]:80/%zz", "", "://", "https://a/DENYOUT_CANARY_X?y=1#frag",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_ = secrets.ScanURL(raw, []string{"DENYOUT_CANARY_"}, 20, true)
		_ = secrets.ScanBytes([]byte(raw), []string{"DENYOUT_CANARY_"})
		_ = secrets.RedactPath(raw)
		_ = secrets.RedactQuery(raw)
		out := secrets.RedactURL(raw)
		if strings.Contains(raw, "DENYOUT_CANARY_") && strings.Contains(out, "DENYOUT_CANARY_") {
			t.Fatalf("canary survived redaction: %q -> %q", raw, out)
		}
	})
}
