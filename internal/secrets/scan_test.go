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
