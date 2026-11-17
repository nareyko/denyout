package proxy

import (
	"bytes"
	"compress/gzip"
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

func TestPeekRequestBodySkipsMedia(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://evil.example/", strings.NewReader("sk-denyouttest000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "image/png")
	if prefix := peekRequestBody(req, 65536); prefix != nil {
		t.Fatalf("expected nil for binary, got %q", prefix)
	}
}

func TestPeekRequestBodyScansMultipartOctetAndGzip(t *testing.T) {
	const tok = "sk-denyouttest000000000000000"
	for _, ct := range []string{"multipart/form-data; boundary=x", "application/octet-stream", "", "application/x-ndjson"} {
		req, _ := http.NewRequest(http.MethodPost, "https://evil.example/", strings.NewReader(tok))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		if got := peekRequestBody(req, 65536); !strings.Contains(string(got), tok) {
			t.Errorf("content-type %q not scanned", ct)
		}
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"k":"` + tok + `"}`))
	_ = zw.Close()
	req, _ := http.NewRequest(http.MethodPost, "https://evil.example/", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if got := peekRequestBody(req, 65536); !strings.Contains(string(got), tok) {
		t.Error("gzip body not decoded for scan")
	}
	rest, _ := io.ReadAll(req.Body)
	if !bytes.Equal(rest, buf.Bytes()) {
		t.Error("wire body must stay unmodified")
	}
}

func TestHostHeaderMatches(t *testing.T) {
	for _, c := range []struct {
		hdr, host string
		want      bool
	}{
		{"example.com", "example.com", true}, {"EXAMPLE.com:443", "example.com", true}, {"", "example.com", true},
		{"evil.com", "example.com", false}, {"example.com.evil.com", "example.com", false}, {"[::1]:443", "::1", true},
	} {
		if got := hostHeaderMatches(c.hdr, c.host); got != c.want {
			t.Errorf("hostHeaderMatches(%q,%q)=%v", c.hdr, c.host, got)
		}
	}
}
