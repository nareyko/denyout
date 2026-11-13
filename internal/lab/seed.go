package lab

import (
	"database/sql"
	"encoding/json"
)

// CaseSpec is one lab fixture row.
type CaseSpec struct {
	ID             string
	Suite          string
	URL            string
	Mode           string
	Preset         string
	ExpectVerdict  string
	ExpectReasons  []string // any-of match when non-empty
	Note           string
}

// DefaultCases returns the normative lab set (≥20 r20_url denies for M1).
func DefaultCases() []CaseSpec {
	r20 := []CaseSpec{
		{ID: "r20-01-canary-query", Suite: "r20_url", URL: "https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected", "secret_in_url", "host_not_allowed"}, Note: "R-20 image canary"},
		{ID: "r20-02-arviser-canary", Suite: "r20_url", URL: "https://evil.example/x?q=ARVISER_CANARY_DEMO", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected", "host_not_allowed"}, Note: "Arviser canary"},
		{ID: "r20-03-sk-on-allowlisted", Suite: "r20_url", URL: "https://api.anthropic.com/v1/x?api_key=sk-denyouttest000000000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "secret on allowlisted host"},
		{ID: "r20-04-canary-on-allowlisted", Suite: "r20_url", URL: "https://api.anthropic.com/?q=DENYOUT_CANARY_TEST", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected"}, Note: "AT-04"},
		{ID: "r20-05-ghp-token", Suite: "r20_url", URL: "https://evil.example/hook?token=ghp_denyouttest000000000000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "GitHub PAT-ish"},
		{ID: "r20-06-jwt-query", Suite: "r20_url", URL: "https://evil.example/j?t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "JWT-ish"},
		{ID: "r20-07-access-token", Suite: "r20_url", URL: "https://evil.example/o?access_token=atokendemo000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "named access_token"},
		{ID: "r20-08-password", Suite: "r20_url", URL: "https://evil.example/login?password=hunter22", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "named password"},
		{ID: "r20-09-client-secret", Suite: "r20_url", URL: "https://evil.example/oauth?client_secret=cs_denyout_demo01", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "client_secret"},
		{ID: "r20-10-aws-secret", Suite: "r20_url", URL: "https://evil.example/a?aws_secret_access_key=wJalrXUtnFEMI/K7MDENG", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "aws secret key param"},
		{ID: "r20-11-sk-ant", Suite: "r20_url", URL: "https://api.openai.com/v1?key=sk-ant-denyouttest0000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "anthropic-ish prefix on openai host"},
		{ID: "r20-12-akia", Suite: "r20_url", URL: "https://evil.example/aws?id=AKIAIOSFODNN7DENYOUT", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "AKIA access key id"},
		{ID: "r20-13-aiza", Suite: "r20_url", URL: "https://evil.example/g?k=AIzaSyDenyoutTestDemoKey0000000000012345", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "Google API key-ish"},
		{ID: "r20-14-slack", Suite: "r20_url", URL: "https://evil.example/s?t=xoxb-123456789012-denyouttest", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "Slack bot token"},
		{ID: "r20-15-canary-path", Suite: "r20_url", URL: "https://evil.example/DENYOUT_CANARY_PATH/x", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected", "host_not_allowed"}, Note: "canary in path"},
		{ID: "r20-16-userinfo", Suite: "r20_url", URL: "https://user:secretpass@evil.example/x", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "URL userinfo password"},
		{ID: "r20-17-api-key-hyphen", Suite: "r20_url", URL: "https://evil.example/x?api-key=demo_secret_value", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "api-key param"},
		{ID: "r20-18-refresh-token", Suite: "r20_url", URL: "https://evil.example/x?refresh_token=rt_denyout_demo_0001", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "refresh_token"},
		{ID: "r20-19-private-key", Suite: "r20_url", URL: "https://evil.example/x?private_key=pk_denyout_demo_0001", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "private_key param"},
		{ID: "r20-20-github-pat", Suite: "r20_url", URL: "https://evil.example/x?token=github_pat_denyouttest00000000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "github_pat_ prefix"},
		{ID: "r20-21-authorization-param", Suite: "r20_url", URL: "https://evil.example/x?authorization=Bearer%20sk-denyouttest000000000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url", "host_not_allowed"}, Note: "authorization query"},
		{ID: "r20-22-apikey", Suite: "r20_url", URL: "https://api.anthropic.com/v1?apikey=sk-denyouttest000000000000000", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "apikey on allowlisted"},
	}

	ssrf := []CaseSpec{
		{ID: "ssrf-01-metadata", Suite: "ssrf", URL: "http://169.254.169.254/", Mode: "enforce", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"unsafe_ip"}, Note: "AT-05 metadata"},
		{ID: "ssrf-02-metadata-audit", Suite: "ssrf", URL: "http://169.254.169.254/latest/meta-data/", Mode: "audit", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"unsafe_ip"}, Note: "hard deny in audit"},
		{ID: "ssrf-03-link-local", Suite: "ssrf", URL: "http://169.254.1.1/", Mode: "enforce", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"unsafe_ip"}, Note: "link-local"},
		{ID: "ssrf-04-loopback", Suite: "ssrf", URL: "http://127.0.0.1:8080/", Mode: "enforce", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"unsafe_ip"}, Note: "loopback"},
		{ID: "ssrf-05-private-10", Suite: "ssrf", URL: "http://10.0.0.5/", Mode: "enforce", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"unsafe_ip"}, Note: "RFC1918"},
	}

	allow := []CaseSpec{
		{ID: "allow-01-anthropic", Suite: "allow_models", URL: "https://api.anthropic.com/", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "AT-01"},
		{ID: "allow-02-openai", Suite: "allow_models", URL: "https://api.openai.com/", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "openai host"},
		{ID: "allow-03-groq", Suite: "allow_models", URL: "https://api.groq.com/openai/v1/chat/completions", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "allow-04-mistral", Suite: "allow_models", URL: "https://api.mistral.ai/v1/chat/completions", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "allow-05-google", Suite: "allow_models", URL: "https://generativelanguage.googleapis.com/v1beta/models", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "allow-06-cohere", Suite: "allow_models", URL: "https://api.cohere.ai/v1/chat", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "allow-07-together", Suite: "allow_models", URL: "https://api.together.xyz/v1/chat/completions", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "allow-08-fireworks", Suite: "allow_models", URL: "https://api.fireworks.ai/inference/v1/chat/completions", Mode: "enforce", Preset: "models", ExpectVerdict: "allow", Note: "M3 model host"},
		{ID: "deny-host-example", Suite: "allow_models", URL: "https://example.com/", Mode: "enforce", Preset: "models", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "AT-02"},
		{ID: "audit-would-deny", Suite: "allow_models", URL: "https://example.com/", Mode: "audit", Preset: "none", ExpectVerdict: "allow", ExpectReasons: []string{"host_not_allowed"}, Note: "AT-06 would_deny via reasons"},
	}

	out := make([]CaseSpec, 0, len(r20)+len(ssrf)+len(allow))
	out = append(out, r20...)
	out = append(out, ssrf...)
	out = append(out, allow...)
	return out
}

// SeedAll upserts DefaultCases (idempotent).
func SeedAll(db *sql.DB) error {
	for _, c := range DefaultCases() {
		reasons, err := json.Marshal(c.ExpectReasons)
		if err != nil {
			return err
		}
		mode := c.Mode
		if mode == "" {
			mode = "enforce"
		}
		preset := c.Preset
		if preset == "" {
			preset = "models"
		}
		_, err = db.Exec(`
INSERT INTO cases (id, suite, url, mode, preset, expect_verdict, expect_reasons, active, note)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
ON CONFLICT(id) DO UPDATE SET
  suite=excluded.suite,
  url=excluded.url,
  mode=excluded.mode,
  preset=excluded.preset,
  expect_verdict=excluded.expect_verdict,
  expect_reasons=excluded.expect_reasons,
  active=1,
  note=excluded.note
`, c.ID, c.Suite, c.URL, mode, preset, c.ExpectVerdict, string(reasons), c.Note)
		if err != nil {
			return err
		}
	}
	return nil
}

// OpenSeeded opens path and seeds the full lab set.
func OpenSeeded(path string) (*sql.DB, error) {
	db, err := Open(path)
	if err != nil {
		return nil, err
	}
	if err := SeedAll(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// CountActive returns active case count, optionally filtered by suite.
func CountActive(db *sql.DB, suite string) (int, error) {
	var n int
	var err error
	if suite == "" {
		err = db.QueryRow(`SELECT COUNT(*) FROM cases WHERE active = 1`).Scan(&n)
	} else {
		err = db.QueryRow(`SELECT COUNT(*) FROM cases WHERE active = 1 AND suite = ?`, suite).Scan(&n)
	}
	return n, err
}
