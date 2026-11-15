package proxy

import "strings"

// TLSPassthroughHost reports hosts that must not be MITM'd under Protect.
// Cursor/Electron agent APIs often require HTTP/2 or pin TLS; DenyOut's
// intercept path is HTTP/1.1-only today, which fails silently after handshake.
// L1 host/threat policy still runs; body/URL secret scanners do not see these hosts.
func TLSPassthroughHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(h, "]") && strings.Count(host, ":") == 1 {
		host = h
	}
	switch {
	case host == "cursor.sh", strings.HasSuffix(host, ".cursor.sh"):
		return true
	case host == "cursor.com", strings.HasSuffix(host, ".cursor.com"):
		return true
	default:
		return false
	}
}

// http2ClientPreface is the RFC 7540 connection preface.
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func isHTTP2ClientPreface(peek []byte) bool {
	if len(peek) < len(http2ClientPreface) {
		// Partial match on leading PRI is enough to avoid treating as HTTP/1.
		return len(peek) >= 3 && string(peek[:3]) == "PRI"
	}
	return string(peek[:len(http2ClientPreface)]) == http2ClientPreface
}
