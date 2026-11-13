package policy

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/secrets"
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

// Engine evaluates requests with optional DNS and simple rate limits.
type Engine struct {
	Cfg      *Config
	Resolve  Resolver
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
		var n int
		fmt.Sscanf(p, "%d", &n)
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
	cfg := e.Cfg
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
	if e.rateLimited(host) {
		return Decision{
			Verdict:   "deny",
			Reasons:   uniq(append(reasons, ReasonRateLimited)),
			Detectors: uniq(detectors),
		}
	}
	return verdictByMode(cfg, host, reasons, detectors)
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
			*reasons = append(*reasons, ReasonHostNotAllowed)
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

func verdictByMode(cfg *Config, host string, reasons, detectors []string) Decision {
	allowed := HostAllowed(cfg, host) || cfg.InsecureAllowAll
	switch cfg.Mode {
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
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	if !allowPrivate && (ip.IsPrivate() || ip.IsUnspecified()) {
		return true
	}
	return false
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
