package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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
	return decodeForScan(req.Header.Get("Content-Encoding"), prefix, max)
}

// decodeForScan returns a plaintext view of a (possibly gzip/deflate) body prefix
// so compressed exfiltration is still scanned. The wire body is not modified.
// Unknown encodings and decode failures fall back to the raw prefix.
func decodeForScan(enc string, prefix []byte, max int) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(prefix))
		if err != nil {
			return prefix
		}
		r = zr
	case "deflate":
		r = flate.NewReader(bytes.NewReader(prefix))
	default:
		return prefix
	}
	out, _ := io.ReadAll(io.LimitReader(r, int64(max))) // partial output is fine (truncated prefix)
	if len(out) == 0 {
		return prefix
	}
	return append(out, prefix...) // scan both views
}

// scannableContentType is deny-list based: any body that could carry a secret
// (JSON, forms, multipart, octet-stream, ndjson, unknown/missing type) is scanned.
// Only media/font/archive types, where text scanning is pointless, are skipped.
func scannableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case strings.HasPrefix(ct, "image/"), strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "audio/"), strings.HasPrefix(ct, "font/"):
		return false
	case ct == "application/zip", ct == "application/gzip", ct == "application/x-tar",
		ct == "application/pdf", ct == "application/wasm":
		return false
	}
	return true
}
