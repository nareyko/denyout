package secrets_test

import (
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
}
