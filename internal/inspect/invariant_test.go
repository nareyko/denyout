package inspect

import (
	"strings"
	"testing"
)

var tokens = []string{
	"ghp_" + strings.Repeat("a1B2", 9),
	"sk-" + strings.Repeat("Ab1", 12),
	"sk_live_" + strings.Repeat("a", 30),
	"123456789:" + strings.Repeat("A", 35),
	"AKIAIOSFODNN7EXAMPLE",
	"xoxb-" + strings.Repeat("1", 12) + "-" + strings.Repeat("a", 24),
	"DENYOUT_CANARY_LAB",
}

// placements builds a request carrying tok in each place a URL can carry one.
func placements(tok string) map[string]Request {
	return map[string]Request{
		"query":    {URL: "https://example.com/p?x=" + tok, Path: "/p", RawQuery: "x=" + tok},
		"path":     {URL: "https://example.com/bot" + tok + "/send", Path: "/bot" + tok + "/send"},
		"userinfo": {URL: "https://" + tok + "@example.com/"},
		"password": {URL: "https://user:" + tok + "@example.com/"},
	}
}

// Invariant: whatever the scanners flag as a secret never appears in the log-safe form.
func TestScannedSecretsAreRedactedInLogs(t *testing.T) {
	opt := Options{Canaries: []string{"DENYOUT_CANARY_"}, MinValueLen: 6, NamedQueryEnabled: true}
	for _, tok := range tokens {
		for place, r := range placements(tok) {
			hits := r.Scan(opt)
			if len(hits) == 0 {
				continue // not detected => no promise (other tests cover detection)
			}
			red := r.Redacted()
			for name, v := range map[string]string{"url": red.URL, "path": red.Path, "query": red.Query} {
				if strings.Contains(v, tok) {
					t.Errorf("%s/%s: detected secret leaked in redacted %s: %q", place, tok[:6], name, v)
				}
			}
		}
	}
}

func FuzzScanRedactInvariant(f *testing.F) {
	for _, tk := range tokens {
		f.Add(tk, uint8(0))
	}
	f.Fuzz(func(t *testing.T, tok string, which uint8) {
		if len(tok) < 8 || strings.ContainsAny(tok, " \t\r\n#?/@:%\x00") {
			return
		}
		ps := placements(tok)
		keys := []string{"query", "path", "userinfo", "password"}
		r := ps[keys[int(which)%len(keys)]]
		opt := Options{MinValueLen: 6, NamedQueryEnabled: true}
		if len(r.Scan(opt)) == 0 {
			return
		}
		red := r.Redacted()
		if strings.Contains(red.URL, tok) || strings.Contains(red.Path, tok) || strings.Contains(red.Query, tok) {
			t.Fatalf("detected but not redacted: tok=%q url=%q path=%q query=%q", tok, red.URL, red.Path, red.Query)
		}
	})
}
