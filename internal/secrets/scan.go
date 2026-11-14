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

// High-confidence query param names — always deny when value length >= min.
var highConfidenceQueryParams = map[string]struct{}{
	"password": {}, "passwd": {}, "secret": {},
	"access_token": {}, "refresh_token": {}, "id_token": {},
	"api_key": {}, "apikey": {}, "api-key": {},
	"authorization": {},
	"private_key":   {}, "client_secret": {}, "aws_secret_access_key": {},
	// Vendor / connection params (egress exfil often uses these names).
	"dd_api_key": {}, "dd_app_key": {}, "datadog_api_key": {}, "datadog_app_key": {},
	"database_url": {}, "db_url": {}, "connection_string": {},
	"mongodb_uri": {}, "mongo_url": {}, "redis_url": {}, "amqp_url": {},
}

// Context-sensitive names — deny only with token-shaped values (or outside carve-outs).
var contextSensitiveQueryParams = map[string]struct{}{
	"token": {}, "session": {}, "session_id": {},
	"sig": {}, "signature": {}, "hmac": {},
	"app_key": {}, // not bare "key" / "auth" — too noisy on MD5/ETag-like values
}

// Back-compat alias for RedactURL named-param redaction (union of both tiers).
var namedQueryParams = func() map[string]struct{} {
	m := map[string]struct{}{}
	for k := range highConfidenceQueryParams {
		m[k] = struct{}{}
	}
	for k := range contextSensitiveQueryParams {
		m[k] = struct{}{}
	}
	return m
}()

var (
	reOpenAI      = regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`) // covers sk-ant- too
	reStripe      = regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`)
	reGitHub      = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}`)
	reGitLab      = regexp.MustCompile(`gl(?:pat|ptt|rt|dt)-[A-Za-z0-9_\-]{10,}`)
	reAWS         = regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)        // not AROA (role id, not a secret)
	reAWSSecret40 = regexp.MustCompile(`[A-Za-z0-9]{20}[A-Za-z0-9+/]{20}`) // 40-char secret-ish; gated by access-key pair
	reGoogle      = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	reSlack       = regexp.MustCompile(`xox[baprst]-[A-Za-z0-9\-]{10,}`)
	reSlackHook   = regexp.MustCompile(`hooks\.slack\.com/services/[A-Za-z0-9/_-]+`)
	reSendGrid    = regexp.MustCompile(`SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	reHuggingFace = regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`)
	reNPM         = regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`)
	rePyPI        = regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+`)
	reTelegram    = regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35,}`)
	// Discord: require bot-like first segment prefix (M/N/O) to cut semver/package FPs.
	reDiscord      = regexp.MustCompile(`[MNO][A-Za-z0-9_-]{23,29}\.[A-Za-z0-9_-]{5,7}\.[A-Za-z0-9_-]{25,}`)
	reDigitalOcean = regexp.MustCompile(`dop_v1_[a-f0-9]{32,}`)
	reShopify      = regexp.MustCompile(`shp(?:at|ca|pa|ss)_[A-Za-z0-9]{20,}`)
	reHex32        = regexp.MustCompile(`(?i)^[a-f0-9]{32}$`)
	// In URL/body require the header name; bare "Basic …" is too noisy.
	reBasicAuth      = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/]{12,}={0,2}`)
	reBasicAuthValue = regexp.MustCompile(`(?i)^Basic\s+[A-Za-z0-9+/]{12,}={0,2}$`)
	reDBURI          = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://[^\s/:]+:[^\s/@]+@`)
	reAzureConn      = regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{20,}`)
	reJWT            = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
	rePEM            = regexp.MustCompile(`-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----`)
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

			carved := isSignedURLCarveOut(u)

			if opt.NamedQueryEnabled {
				q := u.Query()
				for name, values := range q {
					key := strings.ToLower(name)
					for _, v := range values {
						if len(v) < opt.MinValueLen {
							continue
						}
						if _, hi := highConfidenceQueryParams[key]; hi {
							hits = append(hits, Hit{Detector: "named_query_params", Reason: "secret_in_url", Evidence: "***"})
							break
						}
						if _, ctx := contextSensitiveQueryParams[key]; ctx {
							if valueLooksLikeSecret(v) || vendorShapedNamedValue(key, v) {
								hits = append(hits, Hit{Detector: "named_query_params", Reason: "secret_in_url", Evidence: "***"})
								break
							}
						}
					}
				}
			}

			// Token shapes in query/path/fragment — skip when structural signed-URL carve-out matches
			// (GitHub CDN JWT/sig, AWS SigV4), unless a high-confidence secret param is also present.
			if !carved || hasHighConfidenceSecretParam(u, opt.MinValueLen) {
				blob := u.RawQuery + " " + u.Path + " " + u.Fragment
				// Also scan query-decoded text so PEM / Basic / DB URIs survive %20 encoding.
				if dec, err := url.QueryUnescape(blob); err == nil && dec != blob {
					blob = blob + " " + dec
				}
				hits = append(hits, scanTokenShapes(blob, "secret_in_url")...)
				if awsAccessKeySecretPair(blob) {
					hits = append(hits, Hit{Detector: "aws_key_secret_pair", Reason: "secret_in_url", Evidence: "***"})
				}
			}
		}
	}
	if len(body) > 0 {
		hits = append(hits, scanTokenShapes(string(body), "secret_in_body")...)
	}

	_ = opt.HighEntropy

	return dedupeHits(hits)
}

func valueLooksLikeSecret(v string) bool {
	if dec, err := url.QueryUnescape(v); err == nil {
		v = dec
	}
	return len(scanTokenShapes(v, "secret_in_url")) > 0
}

// vendorShapedNamedValue catches datadog-like 32-hex under app_key / token only (not bare "key").
func vendorShapedNamedValue(param, v string) bool {
	if dec, err := url.QueryUnescape(v); err == nil {
		v = dec
	}
	switch param {
	case "app_key", "token":
		return reHex32.MatchString(strings.TrimSpace(v))
	default:
		return false
	}
}

// awsAccessKeySecretPair requires an access/role key id and a 40-char secret-shaped token in the same blob.
func awsAccessKeySecretPair(blob string) bool {
	if !reAWS.MatchString(blob) {
		return false
	}
	// Prefer secrets that look like AWS secret keys (often contain / or +).
	for _, m := range reAWSSecret40.FindAllString(blob, -1) {
		if len(m) == 40 && (strings.ContainsAny(m, "/+") || strings.Count(m, "A") < 8) {
			// Avoid matching the access key id itself (AKIA… is only 20 chars).
			if strings.HasPrefix(m, "AKIA") || strings.HasPrefix(m, "ASIA") {
				continue
			}
			return true
		}
	}
	return false
}

func hasHighConfidenceSecretParam(u *url.URL, minLen int) bool {
	q := u.Query()
	for name, values := range q {
		key := strings.ToLower(name)
		if _, ok := highConfidenceQueryParams[key]; !ok {
			continue
		}
		for _, v := range values {
			if len(v) >= minLen {
				return true
			}
		}
	}
	return false
}

// isSignedURLCarveOut recognizes structural CDN/presigned URLs that are not agent exfil.
func isSignedURLCarveOut(u *url.URL) bool {
	if u == nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	q := u.Query()

	// GitHub release-assets CDN (Azure blob SAS-like + jwt).
	if host == "release-assets.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com") {
		if q.Get("sig") != "" || q.Get("Signature") != "" || q.Get("jwt") != "" {
			if q.Get("se") != "" || q.Get("sv") != "" || q.Get("sp") != "" || q.Get("skoid") != "" {
				return true
			}
			// jwt alone on githubusercontent release path
			if strings.Contains(u.Path, "github-production-release-asset") && q.Get("jwt") != "" {
				return true
			}
		}
	}

	// AWS SigV4 presigned URL — all mandatory params once.
	if isAWSHost(host) && isValidSigV4Query(q) {
		return true
	}
	return false
}

func isAWSHost(host string) bool {
	return strings.HasSuffix(host, ".amazonaws.com") ||
		strings.HasSuffix(host, ".amazonaws.com.cn") ||
		host == "s3.amazonaws.com"
}

func isValidSigV4Query(q url.Values) bool {
	need := []string{
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date",
		"X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Expires",
	}
	for _, k := range need {
		if len(q[k]) != 1 || q.Get(k) == "" {
			return false
		}
	}
	return q.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
}

func scanTokenShapes(blob, reason string) []Hit {
	var hits []Hit
	checks := []struct {
		det string
		re  *regexp.Regexp
	}{
		{"known_token_prefixes", reOpenAI},
		{"known_token_prefixes", reStripe},
		{"known_token_prefixes", reGitHub},
		{"known_token_prefixes", reGitLab},
		{"known_token_prefixes", reAWS},
		{"known_token_prefixes", reGoogle},
		{"known_token_prefixes", reSlack},
		{"known_token_prefixes", reSlackHook},
		{"known_token_prefixes", reSendGrid},
		{"known_token_prefixes", reHuggingFace},
		{"known_token_prefixes", reNPM},
		{"known_token_prefixes", rePyPI},
		{"known_token_prefixes", reTelegram},
		{"known_token_prefixes", reDiscord},
		{"known_token_prefixes", reDigitalOcean},
		{"known_token_prefixes", reShopify},
		{"basic_auth", reBasicAuth},
		{"db_connection_string", reDBURI},
		{"azure_storage", reAzureConn},
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

// RedactURL replaces secret-looking query values and canary/token shapes with ***.
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
	}

	markers := []string{"DENYOUT_CANARY_", "ARVISER_CANARY_", "SECRET_MARKER_"}
	blob := u.String()
	if blob == "" {
		blob = raw
	}
	needsHeavy := false
	for _, marker := range markers {
		if strings.Contains(blob, marker) || strings.Contains(raw, marker) {
			needsHeavy = true
			break
		}
	}
	if !needsHeavy {
		needsHeavy = reJWT.MatchString(raw) || reOpenAI.MatchString(raw) ||
			reGitHub.MatchString(raw) || reAWS.MatchString(raw) || reSlack.MatchString(raw)
	}
	if needsHeavy {
		if u.User != nil {
			u.User = url.UserPassword("***", "***")
		}
		if u.Host != "" {
			u.Host = redactMarkers(u.Host, markers)
		}
		if u.Opaque != "" {
			u.Opaque = redactMarkers(u.Opaque, markers)
		}
		u.Path = redactMarkers(u.Path, markers)
		if u.RawQuery != "" {
			u.RawQuery = "redacted=***"
		} else if strings.Contains(raw, "?") {
			u.RawQuery = "redacted=***"
		}
		u.Fragment = ""
		out := u.String()
		for _, marker := range markers {
			if strings.Contains(out, marker) {
				return "***"
			}
		}
		return out
	}
	if changed {
		return u.String()
	}
	return raw
}

func redactMarkers(s string, markers []string) string {
	out := s
	for _, marker := range markers {
		for strings.Contains(out, marker) {
			i := strings.Index(out, marker)
			j := i + len(marker)
			for j < len(out) {
				c := out[j]
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
					j++
					continue
				}
				break
			}
			out = out[:i] + "***" + out[j:]
		}
	}
	return out
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
