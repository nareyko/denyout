package secrets_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/secrets"
)

func FuzzScanURL(f *testing.F) {
	seeds := []string{
		"",
		"https://api.anthropic.com/v1/messages",
		"https://evil.example/x?api_key=DENYOUT_CANARY_LAB",
		"https://evil.example/x?token=sk-denyouttest000000000000000",
		"://",
		"https://%",
		"https://u:p@h/" + strings.Repeat("a", 256),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %q: %v", in, r)
			}
		}()
		_ = secrets.ScanURL(in, []string{"DENYOUT_CANARY_", "ARVISER_CANARY_"}, 6, true)
		red := secrets.RedactURL(in)
		for _, marker := range []string{"DENYOUT_CANARY_", "ARVISER_CANARY_", "SECRET_MARKER_"} {
			if strings.Contains(red, marker) {
				t.Fatalf("redact leaked %s in %q → %q", marker, in, red)
			}
		}
	})
}
