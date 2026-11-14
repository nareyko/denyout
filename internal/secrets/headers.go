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
		if _, ok := sensitiveHeaderNames[key]; !ok {
			continue
		}
		authLike := AuthLikeHeader(key)
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
				out = append(out, h)
			}
		}
	}
	return dedupeHits(out)
}
