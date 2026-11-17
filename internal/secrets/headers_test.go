package secrets_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/secrets"
)

func TestScanHeadersDenyUnknownHost(t *testing.T) {
	h := map[string][]string{
		"Authorization": {"Bearer sk-denyouttest000000000000000"},
	}
	hits := secrets.ScanHeaders(h, nil, false)
	if len(hits) == 0 {
		t.Fatal("expected secret_in_header toward unknown host")
	}
	if hits[0].Reason != "secret_in_header" {
		t.Fatalf("reason=%s", hits[0].Reason)
	}
}

func TestScanHeadersAllowAuthOnAllowlisted(t *testing.T) {
	h := map[string][]string{
		"Authorization": {"Bearer sk-denyouttest000000000000000"},
	}
	hits := secrets.ScanHeaders(h, nil, true)
	if len(hits) != 0 {
		t.Fatalf("auth token to allowlisted host should pass, got %v", hits)
	}
}

func TestScanHeadersCanaryAlways(t *testing.T) {
	h := map[string][]string{
		"Authorization": {"Bearer DENYOUT_CANARY_LAB"},
	}
	hits := secrets.ScanHeaders(h, []string{"DENYOUT_CANARY_"}, true)
	if len(hits) == 0 {
		t.Fatal("canary in auth header must deny even on allowlisted host")
	}
}

func TestScanHeadersCookieAlways(t *testing.T) {
	h := map[string][]string{
		"Cookie": {"session=sk-denyouttest000000000000000"},
	}
	hits := secrets.ScanHeaders(h, nil, true)
	if len(hits) == 0 {
		t.Fatal("secret in Cookie must deny on allowlisted host")
	}
	if len(hits[0].Detector) < 7 || hits[0].Detector[:7] != "header:" {
		t.Fatalf("want header:… detector, got %q", hits[0].Detector)
	}
}

func TestRedactPathAndUserinfo(t *testing.T) {
	got := secrets.RedactPath("/bot123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage")
	if got != "/***/sendMessage" {
		t.Errorf("telegram path not redacted: %q", got)
	}
	if got := secrets.RedactPath("/api/v1/users"); got != "/api/v1/users" {
		t.Errorf("benign path changed: %q", got)
	}
	if got := secrets.RedactURL("https://user:hunter2@example.com/x"); strings.Contains(got, "hunter2") {
		t.Errorf("userinfo password leaked: %q", got)
	}
	if got := secrets.RedactURL("https://example.com/?x=sk_live_" + strings.Repeat("a", 30)); strings.Contains(got, "sk_live_") {
		t.Errorf("stripe token leaked in query: %q", got)
	}
}
