package lab

import (
	"database/sql"
	"encoding/json"
)

// CaseSpec is one lab fixture row.
type CaseSpec struct {
	ID            string
	Suite         string
	URL           string
	Mode          string
	Preset        string
	ExpectVerdict string
	ExpectReasons []string // any-of match when non-empty
	Note          string
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

	fpSigned := []CaseSpec{
		{ID: "fp-signed-01-gh-release", Suite: "fp_signed", URL: "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r&sv=2018-11-09&sr=b&sig=XxRLfake&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "GitHub signed release asset"},
		{ID: "fp-signed-02-alive-session", Suite: "fp_signed", URL: "https://alive.github.com/socket?p=1&session=abc123sessionval&shared=true", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "alive.github session carve-out"},
		{ID: "fp-signed-03-sigv4", Suite: "fp_signed", URL: "https://mybucket.s3.amazonaws.com/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7DENYOUT%2F20260101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260101T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef01", Mode: "blocklist", Preset: "none", ExpectVerdict: "allow", Note: "SigV4 carve-out: no secret_in_url (blocklist so host policy does not mask)"},
		{ID: "fp-signed-04-gh-sk", Suite: "fp_signed", URL: "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r&sv=2018-11-09&sig=Xx&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000&api_key=sk-denyouttest000000000000000", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "real secret still denied on carve-out host"},
		{ID: "fp-signed-05-canary", Suite: "fp_signed", URL: "https://release-assets.githubusercontent.com/x?sig=Xx&q=DENYOUT_CANARY_LAB", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected"}, Note: "canary still denied on carve-out host"},
	}

	fpSession := []CaseSpec{
		{ID: "fp-session-01-plain", Suite: "fp_session", URL: "https://api.anthropic.com/x?session=abc_plain_session_id", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "plain session without token shape"},
		{ID: "fp-session-02-sk", Suite: "fp_session", URL: "https://api.anthropic.com/x?session=sk-denyouttest000000000000000", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "session value with sk- shape"},
		{ID: "fp-session-03-ghp", Suite: "fp_session", URL: "https://api.anthropic.com/x?session=ghp_denyouttest000000000000000000", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "session value with ghp_ shape"},
		{ID: "fp-session-04-ad", Suite: "fp_session", URL: "https://api.openai.com/go/jmap?session=plain_session_id_001&rnd=123456", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "ad-like session query"},
	}

	agentEgress := []CaseSpec{
		{ID: "agent-01-anthropic", Suite: "agent_egress", URL: "https://api.anthropic.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "model host"},
		{ID: "agent-02-openai", Suite: "agent_egress", URL: "https://api.openai.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "model host"},
		{ID: "agent-03-proxy-golang", Suite: "agent_egress", URL: "https://proxy.golang.org/", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "Go module proxy"},
		{ID: "agent-04-github", Suite: "agent_egress", URL: "https://github.com/nareyko/denyout", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "git host"},
		{ID: "agent-05-raw-gh", Suite: "agent_egress", URL: "https://raw.githubusercontent.com/nareyko/denyout/main/README.md", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "raw github"},
		{ID: "agent-06-evil", Suite: "agent_egress", URL: "https://evil.example/", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "unknown host"},
		{ID: "agent-07-example", Suite: "agent_egress", URL: "https://example.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "example.com not allowlisted"},
		{ID: "agent-08-pastebin", Suite: "agent_egress", URL: "https://pastebin.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "unknown host (no redundant deny-list under agent)"},
	}

	exfilTrue := []CaseSpec{
		{ID: "exfil-01-sk-anthropic", Suite: "exfil_true", URL: "https://api.anthropic.com/v1?api_key=sk-denyouttest000000000000000", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "secret on allowlisted"},
		{ID: "exfil-02-canary", Suite: "exfil_true", URL: "https://api.openai.com/?q=DENYOUT_CANARY_LAB", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected"}, Note: "canary on allowlisted"},
		{ID: "exfil-03-userinfo", Suite: "exfil_true", URL: "https://user:secretpass@github.com/x", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "userinfo on allowlisted"},
		{ID: "exfil-04-ghp", Suite: "exfil_true", URL: "https://api.github.com/?token=ghp_denyouttest000000000000000000", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "PAT on allowlisted"},
	}

	browseCompat := []CaseSpec{
		{ID: "browse-01-example", Suite: "browse_compat", URL: "https://example.com/", Mode: "blocklist", Preset: "none", ExpectVerdict: "allow", Note: "legacy Computer allows web"},
		{ID: "browse-02-secret", Suite: "browse_compat", URL: "https://example.com/x?api_key=sk-denyouttest000000000000000", Mode: "blocklist", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"secret_in_url"}, Note: "secrets still deny in browse"},
		{ID: "browse-03-pastebin", Suite: "browse_compat", URL: "https://pastebin.com/", Mode: "blocklist", Preset: "none", ExpectVerdict: "deny", ExpectReasons: []string{"host_denied"}, Note: "explicit deny host"},
		{ID: "browse-04-anthropic", Suite: "browse_compat", URL: "https://api.anthropic.com/", Mode: "blocklist", Preset: "none", ExpectVerdict: "allow", Note: "model host still allow"},
	}

	redirectPolicy := []CaseSpec{
		{ID: "redir-01-hop2-evil", Suite: "redirect_policy", URL: "https://evil.example/exfil", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "hop1 allowlisted → hop2 evil (re-eval dest)"},
		{ID: "redir-02-hop2-ok", Suite: "redirect_policy", URL: "https://api.openai.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "allow", Note: "hop1→hop2 both allowlisted"},
		{ID: "redir-03-hop2-example", Suite: "redirect_policy", URL: "https://example.com/", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "open-redirect class"},
	}

	trifecta := []CaseSpec{
		{ID: "trifecta-01-unknown-canary", Suite: "trifecta_smoke", URL: "https://evil.example/x?q=DENYOUT_CANARY_LAB", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"canary_detected", "host_not_allowed"}, Note: "destination cut + secret"},
		{ID: "trifecta-02-unknown-clean", Suite: "trifecta_smoke", URL: "https://evil.example/clean", Mode: "enforce", Preset: "agent", ExpectVerdict: "deny", ExpectReasons: []string{"host_not_allowed"}, Note: "clean unknown = host_not_allowed only"},
	}

	out := make([]CaseSpec, 0, len(r20)+len(ssrf)+len(allow)+len(fpSigned)+len(fpSession)+len(agentEgress)+len(exfilTrue)+len(browseCompat)+len(redirectPolicy)+len(trifecta))
	out = append(out, r20...)
	out = append(out, ssrf...)
	out = append(out, allow...)
	out = append(out, fpSigned...)
	out = append(out, fpSession...)
	out = append(out, agentEgress...)
	out = append(out, exfilTrue...)
	out = append(out, browseCompat...)
	out = append(out, redirectPolicy...)
	out = append(out, trifecta...)
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
