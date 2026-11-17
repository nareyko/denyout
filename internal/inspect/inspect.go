// Package inspect is the single place that turns an outbound request into
//
//  1. the hits the policy engine acts on (Scan), and
//  2. the log-safe forms that may be persisted (Redacted).
//
// Keeping both here enforces one invariant: anything the scanners treat as a secret
// is also masked in audit logs, desktop logs and CLI output. Before this package the
// two lived in different packages and drifted (tokens that blocked a request were
// still written to audit.jsonl in clear).
package inspect

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/nareyko/denyout/internal/secrets"
)

// Request is the scannable view of one outbound request.
type Request struct {
	URL      string // full URL (RawURL)
	Path     string
	RawQuery string
	Headers  map[string][]string
	Body     []byte // already decoded prefix (see BodyView)
}

// Custom is a user-defined pattern (scanners.custom_regex), pre-compiled by the caller.
type Custom struct {
	ID string
	RE *regexp.Regexp
}

// Options mirrors the policy scanner settings that influence detection.
type Options struct {
	Canaries          []string
	MinValueLen       int
	NamedQueryEnabled bool
	HostAllowed       bool // auth-like headers toward this host are legitimate
	Custom            []Custom
}

// Scan returns every secret hit in the request (URL, body, headers, custom patterns).
func (r Request) Scan(o Options) []secrets.Hit {
	hits := secrets.ScanURL(r.URL, o.Canaries, o.MinValueLen, o.NamedQueryEnabled)
	if len(r.Body) > 0 {
		hits = append(hits, secrets.ScanBytes(r.Body, o.Canaries)...)
	}
	hits = append(hits, r.scanCustom(o.Custom)...)
	hits = append(hits, secrets.ScanHeaders(r.Headers, o.Canaries, o.HostAllowed)...)
	return hits
}

func (r Request) scanCustom(custom []Custom) []secrets.Hit {
	var hits []secrets.Hit
	for _, c := range custom {
		if c.RE == nil {
			continue
		}
		det := "custom_regex:" + c.ID
		if c.RE.MatchString(r.URL) {
			hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_url", Evidence: "***"})
		}
		if len(r.Body) > 0 && c.RE.Match(r.Body) {
			hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_body", Evidence: "***"})
		}
		for _, vals := range r.Headers {
			for _, v := range vals {
				if c.RE.MatchString(v) {
					hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_header", Evidence: "***"})
				}
			}
		}
	}
	return hits
}

// Redacted is the only form of a request that may be written to logs.
type Redacted struct {
	URL   string
	Path  string
	Query string
}

// Redacted returns the log-safe URL, path and query.
func (r Request) Redacted() Redacted {
	return Redacted{
		URL:   secrets.RedactURL(r.URL),
		Path:  secrets.RedactPath(r.Path),
		Query: secrets.RedactQuery(r.RawQuery),
	}
}

// RedactURL is the log-safe form of a bare URL (desktop logs, CLI output, lab reports).
func RedactURL(raw string) string { return secrets.RedactURL(raw) }

// BodyView reads up to max bytes of req.Body for scanning and restores the body so it
// can still be forwarded unchanged. It returns nil when there is nothing to scan
// (no body, GET/HEAD/OPTIONS, or a media type where text scanning is pointless).
// gzip/deflate payloads are decoded for the returned view only.
func BodyView(req *http.Request, max int) []byte {
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
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), req.Body))
	if err != nil && err != io.EOF {
		return prefix // best effort: what we got, remainder restored above
	}
	if len(prefix) == 0 {
		return nil
	}
	return decodeForScan(req.Header.Get("Content-Encoding"), prefix, max)
}

// decodeForScan returns a plaintext view of a (possibly gzip/deflate) prefix, plus the
// raw bytes, so compressed exfiltration is still scanned. The wire body is untouched.
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
	out, _ := io.ReadAll(io.LimitReader(r, int64(max))) // partial output is fine
	if len(out) == 0 {
		return prefix
	}
	return append(out, prefix...)
}

// scannableContentType is deny-list based: anything that could carry a secret is
// scanned; only media/font/archive types are skipped.
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
