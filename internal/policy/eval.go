package policy

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/secrets"
	"github.com/nareyko/denyout/internal/threatlists"
)

// Decision is the policy verdict.
type Decision struct {
	Verdict   string // allow | deny
	Reasons   []string
	Detectors []string
	WouldDeny bool // audit mode: would have denied in enforce
}

// Resolver looks up host addresses. nil → no DNS (check path / tests).
type Resolver func(host string) ([]net.IP, error)

// ThreatChecker is optional Book C (threat intel). nil = no subscriptions loaded.
type ThreatChecker interface {
	CheckThreat(host string) (feedID string, hit bool)
}

// Engine evaluates requests with optional DNS and simple rate limits.
type Engine struct {
	Cfg      *Config
	Resolve  Resolver
	Threats  ThreatChecker // Book C; optional
	mu       sync.Mutex
	hostHits map[string][]time.Time
	global   []time.Time
}

// NewEngine wraps cfg.
func NewEngine(cfg *Config) *Engine {
	return &Engine{Cfg: cfg, hostHits: map[string][]time.Time{}}
}

// EvaluateURL is the socket-free check path.
func EvaluateURL(cfg *Config, rawURL string) (Decision, error) {
	return NewEngine(cfg).EvaluateURL(rawURL)
}

// EvaluateURL parses URL into RequestView and evaluates without DNS.
func (e *Engine) EvaluateURL(rawURL string) (Decision, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Decision{Verdict: "deny", Reasons: []string{ReasonInvalidURL}}, nil
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return Decision{Verdict: "deny", Reasons: []string{ReasonInvalidURL}}, nil
	}
	port := uint16(0)
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return Decision{Verdict: "deny", Reasons: []string{ReasonInvalidURL}}, nil
		}
		port = uint16(n)
	}
	if port == 0 {
		if u.Scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	proto := u.Scheme
	if proto == "" {
		proto = "https"
	}
	rv := RequestView{
		DestHost:   host,
		DestPort:   port,
		Protocol:   proto,
		ServerName: host,
		Method:     "GET",
		Path:       u.EscapedPath(),
		RawQuery:   u.RawQuery,
		RawURL:     rawURL,
		Inspection: "intercept",
	}
	if ip := net.ParseIP(host); ip != nil {
		rv.DestIPs = []net.IP{ip}
	}
	return e.Evaluate(rv), nil
}

// Evaluate applies D04 order.
func (e *Engine) Evaluate(rv RequestView) Decision {
	// Snapshot under the lock: AllowHost/RevokeHost mutate Cfg.Allow concurrently
	// and the scanners below iterate it without holding e.mu.
	e.mu.Lock()
	snap := *e.Cfg
	e.mu.Unlock()
	cfg := &snap
	host := normalizeHost(rv.DestHost)
	if host == "" {
		return Decision{Verdict: "deny", Reasons: []string{ReasonInvalidURL}}
	}
	if d := denyForbiddenWildcards(cfg); d != nil {
		return *d
	}

	var reasons []string
	ips, early := e.resolveIPs(cfg, host, rv.DestIPs, &reasons)
	if early != nil {
		return *early
	}
	if d := denyUnsafeIPs(ips, cfg.AllowPrivate, reasons); d != nil {
		return *d
	}
	if d := denyDisallowedPort(cfg, rv.DestPort, reasons); d != nil {
		return *d
	}

	reasons, detectors, early := applySecretScanners(cfg, rv, reasons)
	if early != nil {
		return *early
	}
	if d := denyListedHost(cfg, host, reasons, detectors); d != nil {
		return *d
	}
	if d := e.denyThreatList(cfg, host, reasons, detectors); d != nil {
		return *d
	}
	if e.rateLimited(host) {
		return Decision{
			Verdict:   "deny",
			Reasons:   uniq(append(reasons, ReasonRateLimited)),
			Detectors: uniq(detectors),
		}
	}
	return e.verdictByMode(host, reasons, detectors)
}

// AllowHost adds a host to the in-memory allowlist (Ask once / Always without full restart).
// IP literals are ignored while allow_ip_literals is false (cannot bypass hard-deny).
func (e *Engine) AllowHost(host, reason string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if net.ParseIP(host) != nil && !e.Cfg.AllowIPLiterals {
		return
	}
	for _, r := range e.Cfg.Allow {
		if strings.EqualFold(r.Host, host) {
			return
		}
	}
	e.Cfg.Allow = append(e.Cfg.Allow, Rule{Host: host, Reason: reason})
}

// RevokeHost removes a host from the in-memory allowlist (Undo Allow / timed expiry).
func (e *Engine) RevokeHost(host string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, 0, len(e.Cfg.Allow)) // new slice: readers hold the old one
	for _, r := range e.Cfg.Allow {
		if strings.EqualFold(r.Host, host) {
			continue
		}
		out = append(out, r)
	}
	e.Cfg.Allow = out
}

func denyForbiddenWildcards(cfg *Config) *Decision {
	if cfg.InsecureAllowAll {
		return nil
	}
	for _, r := range cfg.Allow {
		if r.Host == "*" || r.Host == "*.*" {
			return &Decision{Verdict: "deny", Reasons: []string{ReasonHostNotAllowed}}
		}
	}
	return nil
}

func (e *Engine) resolveIPs(cfg *Config, host string, ips []net.IP, reasons *[]string) ([]net.IP, *Decision) {
	if len(ips) == 0 && e.Resolve != nil && net.ParseIP(host) == nil {
		resolved, err := e.Resolve(host)
		if err != nil || len(resolved) == 0 {
			denyDNS := true
			if cfg.DenyOnDNSFailure != nil {
				denyDNS = *cfg.DenyOnDNSFailure
			}
			if denyDNS {
				return nil, &Decision{Verdict: "deny", Reasons: []string{ReasonDNSFailure}}
			}
		} else {
			ips = resolved
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
		if !cfg.AllowIPLiterals {
			// Hard-deny: literals never proceed (Ask/AllowHost cannot bypass).
			// Prefer unsafe_ip when the literal is SSRF-sensitive (metadata/private/…).
			if d := denyUnsafeIPs(ips, cfg.AllowPrivate, nil); d != nil {
				return nil, d
			}
			return nil, &Decision{Verdict: "deny", Reasons: []string{ReasonIPLiteral}}
		}
	}
	return ips, nil
}

func denyUnsafeIPs(ips []net.IP, allowPrivate bool, reasons []string) *Decision {
	for _, ip := range ips {
		if UnsafeIP(ip, allowPrivate) {
			return &Decision{Verdict: "deny", Reasons: uniq(append(reasons, ReasonUnsafeIP))}
		}
	}
	return nil
}

func denyDisallowedPort(cfg *Config, port uint16, reasons []string) *Decision {
	if len(cfg.AllowedPorts) == 0 || port == 0 {
		return nil
	}
	for _, p := range cfg.AllowedPorts {
		if uint16(p) == port {
			return nil
		}
	}
	return &Decision{Verdict: "deny", Reasons: uniq(append(reasons, ReasonPortNotAllowed))}
}

func applySecretScanners(cfg *Config, rv RequestView, reasons []string) ([]string, []string, *Decision) {
	scanURL := rv.RawURL
	if scanURL == "" {
		scanURL = rebuildURL(rv)
	}
	hits := secrets.ScanURL(scanURL, cfg.Scanners.Canaries, cfg.MinValueLenOrDefault(), cfg.NamedQueryEnabled())
	if len(rv.BodyPrefix) > 0 {
		hits = append(hits, secrets.ScanBytes(rv.BodyPrefix, cfg.Scanners.Canaries)...)
	}
	hits = append(hits, scanCustomRegex(cfg, scanURL, rv)...)
	// Auth headers are OK toward destinations the mode would allow.
	// In blocklist (Safe desktop), HostAllowed is often false (empty allow[]) —
	// treating that as "unknown host" falsely denied Cursor/API Bearer tokens.
	hostAllowed := HostAllowed(cfg, rv.DestHost) || cfg.InsecureAllowAll || blocklistHostOK(cfg, rv.DestHost)
	hits = append(hits, secrets.ScanHeaders(rv.Headers, cfg.Scanners.Canaries, hostAllowed)...)
	// Book B "Allow this site" / Always allow = allow-all for that host: keep canaries only.
	// Pack/preset allows still scan Cookie/body/URL secrets (agent egress seatbelt).
	if UserAllowAll(cfg, rv.DestHost) || cfg.InsecureAllowAll {
		kept := hits[:0]
		for _, h := range hits {
			if h.Reason == ReasonCanaryDetected {
				kept = append(kept, h)
			}
		}
		hits = kept
	}
	var detectors []string
	for _, h := range hits {
		reasons = append(reasons, h.Reason)
		detectors = append(detectors, h.Detector)
	}
	if len(hits) == 0 {
		return reasons, detectors, nil
	}
	hard := true
	if cfg.Scanners.HardSecretsInAuditMode != nil {
		hard = *cfg.Scanners.HardSecretsInAuditMode
	}
	if cfg.Mode == "audit" && !hard {
		return reasons, detectors, nil
	}
	return reasons, detectors, &Decision{
		Verdict:   "deny",
		Reasons:   uniq(reasons),
		Detectors: uniq(detectors),
	}
}

func denyListedHost(cfg *Config, host string, reasons, detectors []string) *Decision {
	for _, r := range cfg.Deny {
		if HostMatch(r.Host, host) {
			return &Decision{
				Verdict:   "deny",
				Reasons:   uniq(append(reasons, ReasonHostDenied)),
				Detectors: uniq(detectors),
			}
		}
	}
	return nil
}

// UserAllowAll is true for Book B Always / Once (user_always / user_once) on this host.
// That is the desktop "Allow this site" / Always-allow trust: skip Book C threat lists and
// non-canary secret scanners (Cookie/Bearer/session FP on sites like claude.ai).
// Pack / preset / profile allows do NOT qualify.
func UserAllowAll(cfg *Config, host string) bool {
	if cfg == nil {
		return false
	}
	host = normalizeHost(host)
	for _, r := range cfg.Allow {
		if !HostMatch(r.Host, host) {
			continue
		}
		switch r.Reason {
		case "user_always", "user_once":
			return true
		}
	}
	return false
}

// UserAllowSkipsThreat is true for Book B Always / Once on this host.
// Pack / preset / profile allows do NOT skip Book C.
func UserAllowSkipsThreat(cfg *Config, host string) bool {
	return UserAllowAll(cfg, host)
}

func (e *Engine) denyThreatList(cfg *Config, host string, reasons, detectors []string) *Decision {
	if e == nil || e.Threats == nil {
		return nil
	}
	if UserAllowAll(cfg, host) {
		return nil
	}
	// Book D — product unbreak: skip threat lists only (scanners already ran).
	if UnbreakSkipsThreat(host) {
		return nil
	}
	feedID, hit := e.Threats.CheckThreat(host)
	if !hit {
		return nil
	}
	dets := detectors
	if feedID != "" {
		dets = append(dets, "threat:"+feedID)
	}
	return &Decision{
		Verdict:   "deny",
		Reasons:   uniq(append(reasons, ThreatReasonForFeed(feedID))),
		Detectors: uniq(dets),
	}
}

// ThreatReasonForFeed maps a Book C feed id to a category-specific deny reason.
func ThreatReasonForFeed(feedID string) string {
	if sub, ok := threatlists.CatalogByID(feedID); ok {
		switch threatlists.NormalizeCategory(sub.Category) {
		case threatlists.CategoryPhishing:
			return ReasonThreatPhishing
		case threatlists.CategoryMalware:
			return ReasonThreatMalware
		case threatlists.CategoryAdsTrackers:
			return ReasonThreatAds
		}
	}
	return ReasonThreatList
}

// blocklistHostOK is true in Safe desktop (blocklist) when the host is not on deny[].
func blocklistHostOK(cfg *Config, host string) bool {
	if cfg == nil || cfg.Mode != "blocklist" {
		return false
	}
	for _, r := range cfg.Deny {
		if HostMatch(r.Host, host) {
			return false
		}
	}
	return true
}

func (e *Engine) verdictByMode(host string, reasons, detectors []string) Decision {
	e.mu.Lock()
	cfg := e.Cfg
	allowed := HostAllowed(cfg, host) || cfg.InsecureAllowAll
	mode := cfg.Mode
	e.mu.Unlock()
	switch mode {
	case "audit":
		would := !allowed
		if would {
			reasons = append(reasons, ReasonHostNotAllowed)
		}
		return Decision{Verdict: "allow", Reasons: uniq(reasons), Detectors: uniq(detectors), WouldDeny: would}
	case "blocklist":
		return Decision{Verdict: "allow", Reasons: uniq(reasons), Detectors: uniq(detectors)}
	default: // enforce, ask (ask without UI → deny if not allowed)
		if !allowed {
			return Decision{
				Verdict:   "deny",
				Reasons:   uniq(append(reasons, ReasonHostNotAllowed)),
				Detectors: uniq(detectors),
			}
		}
		return Decision{Verdict: "allow", Reasons: uniq(reasons), Detectors: uniq(detectors)}
	}
}

func (e *Engine) rateLimited(host string) bool {
	cfg := e.Cfg
	if cfg.Limits.PerHostRPM <= 0 && cfg.Limits.GlobalRPM <= 0 {
		return false
	}
	now := time.Now()
	window := time.Minute
	e.mu.Lock()
	defer e.mu.Unlock()
	trim := func(ts []time.Time) []time.Time {
		cut := now.Add(-window)
		i := 0
		for i < len(ts) && ts[i].Before(cut) {
			i++
		}
		return ts[i:]
	}
	if cfg.Limits.PerHostRPM > 0 {
		e.hostHits[host] = append(trim(e.hostHits[host]), now)
		if len(e.hostHits[host]) > cfg.Limits.PerHostRPM {
			return true
		}
	}
	if cfg.Limits.GlobalRPM > 0 {
		e.global = append(trim(e.global), now)
		if len(e.global) > cfg.Limits.GlobalRPM {
			return true
		}
	}
	return false
}

func rebuildURL(rv RequestView) string {
	u := &url.URL{
		Scheme:   rv.Protocol,
		Host:     rv.DestHost,
		Path:     rv.Path,
		RawQuery: rv.RawQuery,
	}
	if rv.DestPort != 0 && rv.DestPort != 80 && rv.DestPort != 443 {
		u.Host = fmt.Sprintf("%s:%d", rv.DestHost, rv.DestPort)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return u.String()
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// HostAllowed reports allow-list match.
func HostAllowed(cfg *Config, host string) bool {
	host = normalizeHost(host)
	for _, r := range cfg.Allow {
		if HostMatch(r.Host, host) {
			return true
		}
	}
	return false
}

// HostMatch implements exact and *.domain rules (apex not matched by *.domain).
func HostMatch(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "*.*" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".domain"
		apex := pattern[2:]
		if host == apex {
			return false
		}
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

// UnsafeIP is true for metadata/link-local/loopback and (unless allowPrivate) RFC1918.
func UnsafeIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Cloud metadata endpoints are never reachable, even with allow_private.
	if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.Equal(net.ParseIP("100.100.100.200")) {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 { // broadcast
			return true
		}
		if ip4[0] == 0 { // 0.0.0.0/8 "this network"
			return true
		}
		if !allowPrivate && ip4[0] == 100 && ip4[1]&0xc0 == 64 { // 100.64.0.0/10 CGNAT
			return true
		}
	} else if len(ip) == net.IPv6len && ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		allZero(ip[4:12]) { // NAT64 64:ff9b::/96 — judge the embedded IPv4
		return UnsafeIP(net.IP(ip[12:16]), allowPrivate)
	}
	if !allowPrivate && (ip.IsPrivate() || ip.IsUnspecified()) {
		return true
	}
	return false
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

var customRegexCache sync.Map // pattern -> *regexp.Regexp

// scanCustomRegex applies the user's scanners.custom_regex patterns (validated at
// load) to the URL, body prefix and header values. Previously they were only
// validated and never used, so users believed they were protected.
func scanCustomRegex(cfg *Config, scanURL string, rv RequestView) []secrets.Hit {
	var hits []secrets.Hit
	for _, cr := range cfg.Scanners.CustomRegex {
		var re *regexp.Regexp
		if v, ok := customRegexCache.Load(cr.Pattern); ok {
			re = v.(*regexp.Regexp)
		} else {
			c, err := regexp.Compile(cr.Pattern)
			if err != nil {
				continue
			}
			customRegexCache.Store(cr.Pattern, c)
			re = c
		}
		det := "custom_regex:" + cr.ID
		if re.MatchString(scanURL) {
			hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_url", Evidence: "***"})
		}
		if len(rv.BodyPrefix) > 0 && re.Match(rv.BodyPrefix) {
			hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_body", Evidence: "***"})
		}
		for _, vals := range rv.Headers {
			for _, v := range vals {
				if re.MatchString(v) {
					hits = append(hits, secrets.Hit{Detector: det, Reason: "secret_in_header", Evidence: "***"})
				}
			}
		}
	}
	return hits
}
