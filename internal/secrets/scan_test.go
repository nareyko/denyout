package secrets_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/secrets"
)

func TestScanCanaryAndRedact(t *testing.T) {
	hits := secrets.ScanURL(
		"https://evil.example/x?api_key=DENYOUT_CANARY_LAB",
		[]string{"DENYOUT_CANARY_"},
		6,
		true,
	)
	if len(hits) == 0 {
		t.Fatal("expected hits")
	}
	red := secrets.RedactURL("https://evil.example/x?api_key=DENYOUT_CANARY_LAB")
	if strings.Contains(red, "DENYOUT_CANARY_LAB") {
		t.Fatalf("leaked: %s", red)
	}
	q := secrets.RedactQuery("api_key=sk-denyouttest000000000000000&x=1")
	if strings.Contains(q, "sk-denyouttest") {
		t.Fatalf("leaked query: %s", q)
	}
}

func TestScanJWTAndPrefix(t *testing.T) {
	u := "https://evil.example/j?t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000"
	hits := secrets.ScanURL(u, nil, 6, true)
	found := false
	for _, h := range hits {
		if h.Detector == "jwt_ish" || h.Reason == "secret_in_url" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hits=%v", hits)
	}
}

func TestScanBytesCanary(t *testing.T) {
	hits := secrets.ScanBytes([]byte(`{"k":"ARVISER_CANARY_1"}`), []string{"ARVISER_CANARY_"})
	if len(hits) == 0 {
		t.Fatal("expected body canary")
	}
}

func TestRedactURLCanaryInHostLike(t *testing.T) {
	// Regression from FuzzScanURL: canary outside query must not survive.
	in := "0DENYOUT_CANARY_LAB"
	red := secrets.RedactURL(in)
	if strings.Contains(red, "DENYOUT_CANARY_") {
		t.Fatalf("leaked: %s", red)
	}
}

func TestFuzzScanURLSmoke(t *testing.T) {
	// Lightweight resilience smoke (not full go-fuzz); malformed inputs must not panic.
	inputs := []string{
		"",
		"://",
		"https://%",
		"https://h/" + strings.Repeat("a", 4096),
		"https://u:p@h/?token=" + strings.Repeat("x", 64),
	}
	for _, in := range inputs {
		_ = secrets.ScanURL(in, []string{"DENYOUT_CANARY_"}, 6, true)
		_ = secrets.RedactURL(in)
	}
}

func TestSignedURLCarveOutAndSessionTier(t *testing.T) {
	canaries := []string{"DENYOUT_CANARY_"}
	cases := []struct {
		name   string
		url    string
		want   bool // expect secret_in_url or canary hit
		reason string
	}{
		{
			name: "github_release_assets_signed",
			url:  "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r&sv=2018-11-09&sr=b&sig=XxRLfake&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000",
			want: false,
		},
		{
			name: "github_release_assets_with_api_key",
			url:  "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r&sv=2018-11-09&sig=Xx&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepartgoeshere000&api_key=sk-denyouttest000000000000000",
			want: true,
		},
		{
			name: "sigv4_s3",
			url:  "https://mybucket.s3.amazonaws.com/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7DENYOUT%2F20260101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260101T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef01",
			want: false,
		},
		{
			name: "plain_session_ok",
			url:  "https://alive.github.com/socket?p=1&session=abc123sessionval&shared=true",
			want: false,
		},
		{
			name: "session_with_sk",
			url:  "https://evil.example/x?session=sk-denyouttest000000000000000",
			want: true,
		},
		{
			name: "ad_session_ok",
			url:  "https://code.moviead55.ru/go/jmap?session=plain_session_id_001&rnd=123456",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := secrets.ScanURL(tc.url, canaries, 6, true)
			got := len(hits) > 0
			if got != tc.want {
				t.Fatalf("want hit=%v got=%v hits=%v", tc.want, got, hits)
			}
		})
	}
}

// splitJoin builds detector fixtures at runtime so source files do not contain
// vendor-shaped literals that trip GitHub push protection.
func qURL(parts ...string) string {
	return "https://api.anthropic.com/x?q=" + strings.Join(parts, "")
}

func TestPrefixPackCheapWins(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"stripe", qURL("sk", "_live_", "denyouttest000000000000")},
		{"stripe_rk", qURL("rk", "_live_", "denyouttest000000000000")},
		{"asia", qURL("ASIA", "DENYOUTTEST00000")},
		{"sendgrid", qURL("SG", ".", "denyoutTestPartA1", ".", "denyoutTestPartB2xxxxxxxxxx")},
		{"gitlab", qURL("gl", "pat-", "denyouttest000000")},
		{"gitlab_glrt", qURL("gl", "rt-", "denyouttest000000000000")},
		{"hf", qURL("hf", "_", "denyouttest00000000000000")},
		{"npm", qURL("npm", "_", "denyouttest000000000000000000")},
		{"slack_hook", qURL("https://hooks.slack.com/services/", "TDENYOUT/BDENYOUT/denyouttest")},
		{"slack_xoxt", qURL("xox", "t-", "00000000000-denyouttest000")},
		{"telegram", qURL("1000000000:", "denyouttest_telegram_token_value_xx")},
		{"discord_o", qURL("Odenyouttestdiscordtoken01", ".", "denyout", ".", "denyouttestdiscordtokenpartthree")},
		{"db_uri", qURL("postgres://admin:denyoutpass@db.example:5432/app")},
		{"basic", qURL("Authorization:%20Basic%20ZGVueW91dDpkZW55b3V0")},
		{"pem_encoded", qURL("-----BEGIN%20RSA%20PRIVATE%20KEY-----%20cQAOrcEQ")},
		{"azure", qURL("DefaultEndpointsProtocol=https;AccountName=denyout;AccountKey=ZGVueW91dGZpeHR1cmVhY2NvdW50a2V5dmFsdWU=")},
		{"shopify", qURL("shp", "at_", "denyouttest0000000000")},
		{"dd_named", "https://api.anthropic.com/x?dd_api_key=dddddddddddddddddddddddddddddddd"},
		{"database_url", "https://api.anthropic.com/x?database_url=postgres://u:p@h/db"},
		{"aws_pair", qURL("AKIAIOSFODNN7DENYOUT", "%2F", "denyoutAWSsecret0000000000000000xxxx")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := secrets.ScanURL(tc.url, nil, 6, true)
			if len(hits) == 0 {
				t.Fatalf("expected hit for %s url=%s", tc.name, tc.url)
			}
		})
	}
}

func TestAWSSecretAloneNotPaired(t *testing.T) {
	// Bare 40-char secret without access key id must not trip pairing.
	u := qURL("denyoutAWSsecret0000000000000000xxxx")
	hits := secrets.ScanURL(u, nil, 6, true)
	for _, h := range hits {
		if h.Detector == "aws_key_secret_pair" {
			t.Fatalf("unexpected pair hit: %v", hits)
		}
	}
}
