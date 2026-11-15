package proxy

import "testing"

func TestTLSPassthroughHostCursor(t *testing.T) {
	yes := []string{
		"api2.cursor.sh",
		"api2direct.cursor.sh",
		"api3.cursor.sh",
		"metrics.cursor.sh",
		"agentn.global.api5.cursor.sh",
		"CURSOR.SH",
		"www.cursor.com",
		"api.cursor.com",
		"api2.cursor.sh:443",
	}
	for _, h := range yes {
		if !TLSPassthroughHost(h) {
			t.Fatalf("expected passthrough for %q", h)
		}
	}
	no := []string{
		"evil.example",
		"cursor.sh.evil.example",
		"notcursor.sh",
		"google.com",
		"",
	}
	for _, h := range no {
		if TLSPassthroughHost(h) {
			t.Fatalf("expected MITM for %q", h)
		}
	}
}

func TestHTTP2ClientPrefaceDetect(t *testing.T) {
	full := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nGET / HTTP/1.1\r\n")
	if !isHTTP2ClientPreface(full) {
		t.Fatal("full preface")
	}
	if !isHTTP2ClientPreface([]byte("PRI")) {
		t.Fatal("partial PRI")
	}
	if isHTTP2ClientPreface([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("HTTP/1 must not match")
	}
}
