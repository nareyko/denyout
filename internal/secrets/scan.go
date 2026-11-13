package secrets

import (
	"net/url"
	"regexp"
	"strings"
)

// Hit is a scanner finding (evidence always redacted).
type Hit struct {
	Detector string
	Reason   string
	Evidence string
}

var namedQueryParams = map[string]struct{}{
	"password": {}, "passwd": {}, "secret": {}, "token": {},
	"access_token": {}, "refresh_token": {}, "id_token": {},
	"api_key": {}, "apikey": {}, "api-key": {}, "auth": {},
	"authorization": {}, "session": {}, "session_id": {},
	"private_key": {}, "client_secret": {}, "aws_secret_access_key": {},
	"sig": {}, "signature": {}, "hmac": {},
}

var (
	reOpenAI    = regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`)
	reAnthropic = regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{10,}`)
	reGitHub    = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}`)
	reAWS       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGoogle    = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	reSlack     = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`)
	reJWT       = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
	rePEM       = regexp.MustCompile(`-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----`)
)

// Options controls optional detectors.
type Options struct {
	Canaries          []string
	MinValueLen       int
	NamedQueryEnabled bool
	HighEntropy       bool // default off
}

// ScanURL runs MVP URL scanners.
func ScanURL(rawURL string, canaries []string, minValueLen int, namedQueryEnabled bool) []Hit {
	return Scan(rawURL, nil, Options{
		Canaries:          canaries,
		MinValueLen:       minValueLen,
		NamedQueryEnabled: namedQueryEnabled,
		HighEntropy:       false,
	})
}

// ScanBytes scans a body/header blob for canaries and token shapes.
func ScanBytes(b []byte, canaries []string) []Hit {
	return Scan("", b, Options{Canaries: canaries, MinValueLen: 6, NamedQueryEnabled: false})
}

// Scan is the unified detector pipeline.
func Scan(rawURL string, body []byte, opt Options) []Hit {
	var hits []Hit
	if opt.MinValueLen <= 0 {
		opt.MinValueLen = 6
	}

	haystacks := []string{}
	if rawURL != "" {
		haystacks = append(haystacks, rawURL)
	}
	if len(body) > 0 {
		haystacks = append(haystacks, string(body))
	}

	for _, hay := range haystacks {
		for _, c := range opt.Canaries {
			if c != "" && strings.Contains(hay, c) {
				hits = append(hits, Hit{Detector: "canary", Reason: "canary_detected", Evidence: "***"})
				break
			}
		}
	}

	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err == nil {
			if u.User != nil {
				if _, hasPass := u.User.Password(); hasPass {
					hits = append(hits, Hit{Detector: "userinfo", Reason: "secret_in_url", Evidence: "***"})
				}
			}
			if opt.NamedQueryEnabled {
				q := u.Query()
				for name, values := range q {
					key := strings.ToLower(name)
					if _, ok := namedQueryParams[key]; !ok {
						continue
					}
					for _, v := range values {
						if len(v) >= opt.MinValueLen {
							hits = append(hits, Hit{Detector: "named_query_params", Reason: "secret_in_url", Evidence: "***"})
							break
						}
					}
				}
			}
			blob := u.RawQuery + " " + u.Path + " " + u.Fragment
			hits = append(hits, scanTokenShapes(blob, "secret_in_url")...)
		}
	}
	if len(body) > 0 {
		hits = append(hits, scanTokenShapes(string(body), "secret_in_body")...)
	}

	// High entropy intentionally off unless opted in (S6).
	_ = opt.HighEntropy

	return dedupeHits(hits)
}

func scanTokenShapes(blob, reason string) []Hit {
	var hits []Hit
	checks := []struct {
		det string
		re  *regexp.Regexp
	}{
		{"known_token_prefixes", reAnthropic},
		{"known_token_prefixes", reOpenAI},
		{"known_token_prefixes", reGitHub},
		{"known_token_prefixes", reAWS},
		{"known_token_prefixes", reGoogle},
		{"known_token_prefixes", reSlack},
		{"jwt_ish", reJWT},
		{"known_token_prefixes", rePEM},
	}
	seen := map[string]struct{}{}
	for _, c := range checks {
		if c.re.MatchString(blob) {
			key := c.det + ":" + reason
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			hits = append(hits, Hit{Detector: c.det, Reason: reason, Evidence: "***"})
		}
	}
	return hits
}

func dedupeHits(in []Hit) []Hit {
	seen := map[string]struct{}{}
	var out []Hit
	for _, h := range in {
		k := h.Detector + "|" + h.Reason
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, h)
	}
	return out
}

// RedactURL replaces secret-looking query values with ***.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	q := u.Query()
	changed := false
	for name, values := range q {
		key := strings.ToLower(name)
		if _, ok := namedQueryParams[key]; !ok {
			continue
		}
		for i := range values {
			if values[i] != "" {
				values[i] = "***"
				changed = true
			}
		}
		q[name] = values
	}
	if changed {
		u.RawQuery = q.Encode()
		return u.String()
	}
	rq := u.RawQuery
	for _, marker := range []string{"DENYOUT_CANARY_", "ARVISER_CANARY_", "SECRET_MARKER_"} {
		if strings.Contains(rq, marker) || strings.Contains(u.Path, marker) {
			u.RawQuery = "redacted=***"
			return u.String()
		}
	}
	if reJWT.MatchString(raw) || reOpenAI.MatchString(raw) {
		u.RawQuery = "redacted=***"
		return u.String()
	}
	return raw
}

// RedactQuery returns query with sensitive values starred.
func RedactQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	red := RedactURL("https://host.example/?" + rawQuery)
	u, err := url.Parse(red)
	if err != nil {
		return "redacted=***"
	}
	return u.RawQuery
}
