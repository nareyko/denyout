package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// peekRequestBody reads up to max bytes for secret scanning and restores req.Body.
// Returns nil when body should not be scanned (empty, oversized disabled, or non-text type).
func peekRequestBody(req *http.Request, max int) []byte {
	if req == nil || req.Body == nil || max <= 0 {
		return nil
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions {
		return nil
	}
	if !scannableContentType(req.Header.Get("Content-Type")) {
		return nil
	}
	prefix, err := io.ReadAll(io.LimitReader(req.Body, int64(max)))
	if err != nil && err != io.EOF {
		// Best-effort: restore whatever we got plus remainder.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), req.Body))
		return prefix
	}
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), req.Body))
	if len(prefix) == 0 {
		return nil
	}
	return prefix
}

func scannableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case ct == "application/json", ct == "application/ld+json", ct == "application/graphql":
		return true
	case ct == "application/x-www-form-urlencoded", ct == "application/javascript", ct == "application/xml":
		return true
	case strings.HasPrefix(ct, "text/"):
		return true
	default:
		return false
	}
}
