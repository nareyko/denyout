package secrets

import "strings"

// Sensitive outbound headers that commonly carry credentials (R-20 / agent egress).
var sensitiveHeaderNames = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"x-api-key":            {},
	"x-auth-token":         {},
	"x-access-token":       {},
	"x-amz-security-token": {},
	"cookie":               {},
}

// AuthLikeHeader is true for headers that legitimate API clients send to allowlisted hosts.
func AuthLikeHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-access-token", "x-amz-security-token":
		return true
	default:
		return false
	}
}

// ScanHeaders scans sensitive header values for canaries and token shapes.
// When hostAllowed is true, auth-like headers may carry API tokens (not denied) but canaries still deny.
// Cookie and other sensitive headers always hard-deny on secret shapes.
// Hits use reason secret_in_header (canaries keep canary_detected).
func ScanHeaders(headers map[string][]string, canaries []string, hostAllowed bool) []Hit {
	if len(headers) == 0 {
		return nil
	}
	var out []Hit
	for name, values := range headers {
		key := strings.ToLower(strings.TrimSpace(name))
		_, sensitive := sensitiveHeaderNames[key]
		// Custom headers (X-GitHub-Token, X-Secret, Referer, ...) are scanned too: a fixed
		// name list let tokens leave in any header that was not on it. Credential-named
		// headers are treated as auth-like so allowlisted APIs keep working.
		authLike := AuthLikeHeader(key) || (!sensitive && credentialNamedHeader(key))
		if !sensitive && !authLike && skipScanHeader(key) {
			continue
		}
		for _, v := range values {
			if v == "" {
				continue
			}
			hits := ScanBytes([]byte(v), canaries)
			// Authorization header values are "Basic …" without the field name.
			if key == "authorization" || key == "proxy-authorization" {
				if reBasicAuthValue.MatchString(strings.TrimSpace(v)) {
					hits = append(hits, Hit{Detector: "basic_auth", Reason: "secret_in_header", Evidence: "***"})
				}
			}
			for _, h := range hits {
				if hostAllowed && authLike && h.Reason != "canary_detected" {
					continue
				}
				if h.Reason == "secret_in_body" {
					h.Reason = "secret_in_header"
				}
				// Surface which header fired (Cookie vs Authorization) without values.
				if h.Detector == "" {
					h.Detector = "header:" + key
				} else if !strings.HasPrefix(h.Detector, "header:") {
					h.Detector = "header:" + key + ":" + h.Detector
				}
				out = append(out, h)
			}
		}
	}
	return dedupeHits(out)
}

func credentialNamedHeader(key string) bool {
	for _, w := range []string{"token", "api-key", "apikey", "auth", "secret", "key"} {
		if strings.Contains(key, w) {
			return true
		}
	}
	return false
}

// skipScanHeader lists high-volume protocol headers that never carry user secrets
// and are not worth scanning.
func skipScanHeader(key string) bool {
	switch key {
	case "host", "content-length", "content-type", "accept", "accept-encoding", "accept-language",
		"connection", "user-agent", "te", "transfer-encoding", "upgrade", "date", "cache-control",
		"pragma", "if-none-match", "if-modified-since", "etag", "range", "content-encoding":
		return true
	}
	return false
}
