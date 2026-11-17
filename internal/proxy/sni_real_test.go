package proxy

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// realClientHello captures the first flight of a genuine crypto/tls ClientHello.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = cl.Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	return buf[:n]
}

func TestParseSNIRealClientHello(t *testing.T) {
	for _, name := range []string{"example.com", "a.b.c.example.org", "xn--bcher-kva.de"} {
		if got := parseSNI(realClientHello(t, name)); got != name {
			t.Fatalf("sni %q -> %q", name, got)
		}
	}
}

// Every truncation of a valid hello must be rejected or parsed without panicking.
func TestParseSNITruncationsNeverPanic(t *testing.T) {
	h := realClientHello(t, "example.com")
	for i := 0; i <= len(h); i++ {
		_ = parseSNI(h[:i])
	}
	// Corrupt each byte: still no panic.
	for i := range h {
		c := append([]byte(nil), h...)
		c[i] ^= 0xff
		_ = parseSNI(c)
	}
	if got := parseSNI([]byte(strings.Repeat("\x16", 100))); got != "" {
		t.Fatalf("garbage must yield empty SNI, got %q", got)
	}
}

func FuzzParseSNI(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _ = parseSNI(b) })
}
