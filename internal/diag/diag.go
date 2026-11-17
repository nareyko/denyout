// Package diag builds the redacted status report behind `denyout-cli doctor`
// and the desktop Diagnostics view, and runs the in-process interception
// self-check used by first-run verification.
//
// Nothing here changes host networking: probes read files, dial loopback and
// run a TLS handshake between two goroutines of this process.
//
// Redaction rule: every request URL shown comes from audit events (already
// log-safe) and is passed again through inspect.Request.Redacted, the only
// sanctioned source of display text for requests. Free text (last error,
// process labels) is token-scanned with the same detectors.
package diag

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/explain"
	"github.com/nareyko/denyout/internal/inspect"
	"github.com/nareyko/denyout/internal/secrets"
	"github.com/nareyko/denyout/internal/threatlists"
)

// Status is the outcome of one check.
type Status string

// Check outcomes.
const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Fix action ids the desktop maps to existing safe actions.
const (
	FixRetryProtect  = "retry_protect"
	FixRegenerateCA  = "regenerate_ca"
	FixRefreshThreat = "refresh_threats"
	FixOpenProblems  = "open_problems"
)

// Check is one line of the report.
type Check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Fix is an action id (Fix* constants) the UI can run, empty when none.
	Fix string `json:"fix,omitempty"`
	// FixLabel is the button text for Fix.
	FixLabel string `json:"fix_label,omitempty"`
}

// Denial is one redacted recent block.
type Denial struct {
	TS      string   `json:"ts"`
	Host    string   `json:"host"`
	URL     string   `json:"url"`
	Reasons []string `json:"reasons"`
	Why     string   `json:"why"`
	Rule    string   `json:"rule"`
	Process string   `json:"process,omitempty"`
}

// Report is the full diagnostics payload.
type Report struct {
	GeneratedAt string   `json:"generated_at"`
	Version     string   `json:"version"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	GoVersion   string   `json:"go_version"`
	Checks      []Check  `json:"checks"`
	Denials     []Denial `json:"denials"`
	LastError   string   `json:"last_error,omitempty"`
	// Status and StatusReason are the app status line and, when the state
	// model supplies one, why it is in that state.
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}

// HelperInfo is the privileged-helper state (filled by the caller).
type HelperInfo struct {
	Present  bool
	Degraded bool
}

// Inputs are the facts a report is built from. Zero values mean "unknown".
type Inputs struct {
	Version   string
	Now       time.Time
	Home      string // replaced by ~ in paths shown
	CADir     string
	AuditPath string
	ThreatDir string
	Helper    HelperInfo
	// ProtectionOn says the user expects Protect to be live (a missing CA is
	// then a failure instead of "not created yet").
	ProtectionOn bool
	// ProxyPort > 0 makes the report dial 127.0.0.1:port. Otherwise
	// ProxyRunning (when set) is used as is.
	ProxyPort    int
	ProxyRunning *bool
	LastError    string
	MaxDenials   int
	Status       string
	StatusReason string
}

const defaultDenials = 10

// Build assembles the report. It never writes anything.
func Build(in Inputs) Report {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	n := in.MaxDenials
	if n <= 0 {
		n = defaultDenials
	}
	if n > 50 {
		n = 50
	}
	r := Report{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Version:     RedactText(in.Version),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
	}
	r.Status = RedactText(in.Status)
	r.StatusReason = shortenHome(RedactText(truncate(in.StatusReason, 300)), in.Home)
	r.Checks = append(r.Checks, helperCheck(in.Helper))
	r.Checks = append(r.Checks, proxyCheck(in))
	r.Checks = append(r.Checks, SelfCheck(in.CADir, in.ProtectionOn)...)
	r.Checks = append(r.Checks, threatCheck(in.ThreatDir, now))
	r.Denials = recentDenials(in.AuditPath, n)
	if s := strings.TrimSpace(in.LastError); s != "" {
		r.LastError = shortenHome(RedactText(truncate(s, 400)), in.Home)
	}
	for i := range r.Checks {
		r.Checks[i].Detail = shortenHome(RedactText(r.Checks[i].Detail), in.Home)
	}
	return r
}

func helperCheck(h HelperInfo) Check {
	c := Check{ID: "helper", Name: "Privileged helper"}
	switch {
	case !h.Present:
		c.Status, c.Detail = Skip, "not installed (it is set up when Protect computer first turns on)"
	case h.Degraded:
		c.Status = Fail
		c.Detail = "installed but degraded: the watchdog removed the redirect because the proxy stopped answering, so Protect is not filtering"
		c.Fix, c.FixLabel = FixRetryProtect, "Turn Protect on again"
	default:
		c.Status, c.Detail = OK, "installed and healthy"
	}
	return c
}

func proxyCheck(in Inputs) Check {
	c := Check{ID: "proxy", Name: "Proxy listening"}
	switch {
	case in.ProxyPort > 0:
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(in.ProxyPort)), 700*time.Millisecond)
		if err != nil {
			c.Status = Fail
			c.Detail = fmt.Sprintf("nothing is listening on 127.0.0.1:%d", in.ProxyPort)
			if in.ProtectionOn {
				c.Fix, c.FixLabel = FixRetryProtect, "Turn Protect on again"
			}
			return c
		}
		_ = conn.Close()
		c.Status, c.Detail = OK, fmt.Sprintf("accepting connections on 127.0.0.1:%d", in.ProxyPort)
	case in.ProxyRunning != nil && *in.ProxyRunning:
		c.Status, c.Detail = OK, "proxy process is running"
	case in.ProxyRunning != nil && in.ProtectionOn:
		c.Status = Fail
		c.Detail = "Protect is meant to be on but the proxy is not running"
		c.Fix, c.FixLabel = FixRetryProtect, "Turn Protect on again"
	case in.ProxyRunning != nil:
		c.Status, c.Detail = Skip, "not running (Protect is off)"
	default:
		c.Status, c.Detail = Skip, "port not known here (pass --proxy-port, or use the desktop Diagnostics view)"
	}
	return c
}

// StaleAfter is how old a threat feed may be before the report warns.
const StaleAfter = threatlists.StaleAttentionAge

func threatCheck(dir string, now time.Time) Check {
	c := Check{ID: "threat_lists", Name: "Threat list freshness"}
	if dir == "" {
		c.Status, c.Detail = Skip, "no threat list directory"
		return c
	}
	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		c.Status, c.Detail = Skip, "no threat lists downloaded yet"
		return c
	}
	var st threatlists.StatusFile
	if err := json.Unmarshal(b, &st); err != nil {
		c.Status, c.Detail = Warn, "status file unreadable"
		return c
	}
	var ids []string
	for id, f := range st.Feeds {
		if f.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		c.Status, c.Detail = Skip, "no threat lists enabled"
		return c
	}
	var parts []string
	fresh := false
	for _, id := range ids {
		f := st.Feeds[id]
		if f.LastSuccess.IsZero() {
			parts = append(parts, id+": never updated")
			continue
		}
		age := now.Sub(f.LastSuccess)
		if age <= StaleAfter {
			fresh = true
		}
		parts = append(parts, fmt.Sprintf("%s: %s ago, %d entries", id, humanAge(age), f.EntryCount))
	}
	c.Detail = strings.Join(parts, "; ")
	if fresh {
		c.Status = OK
	} else {
		c.Status = Warn
		c.Fix, c.FixLabel = FixRefreshThreat, "Refresh lists"
	}
	return c
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func recentDenials(path string, n int) []Denial {
	events, err := audit.RecentDenials(path, n)
	if err != nil {
		return nil
	}
	out := make([]Denial, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- { // newest first
		e := events[i]
		if len(e.Reasons) == 0 {
			continue
		}
		primary := e.Reasons[0]
		out = append(out, Denial{
			TS:      e.TS,
			Host:    RedactText(e.Network.DestHost),
			URL:     RedactDisplayURL(audit.DisplayURL(e.Network, e.HTTP)),
			Reasons: append([]string(nil), e.Reasons...),
			Why:     explain.Describe(primary).Title,
			Rule:    explain.RuleLabel(primary, e.Detectors),
			Process: RedactText(truncate(e.Process, 80)),
		})
		if len(out) >= n {
			break
		}
	}
	return out
}

// RedactDisplayURL is the only way a request URL enters a report: it goes
// through inspect.Request.Redacted so scanner-flagged secrets are masked.
func RedactDisplayURL(raw string) string {
	if raw == "" {
		return ""
	}
	req := inspect.Request{URL: raw}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		req.RawQuery = strings.SplitN(raw[i+1:], "#", 2)[0]
		req.Path = raw[:i]
	} else {
		req.Path = raw
	}
	return req.Redacted().URL
}

// RedactText masks secrets in free text token by token. URL-shaped tokens go
// through the URL redactor; any other token the scanners flag becomes [redacted].
func RedactText(s string) string {
	if s == "" {
		return s
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	for i, f := range fields {
		switch {
		case strings.Contains(f, "://"):
			fields[i] = RedactDisplayURL(f)
			if len(secrets.ScanBytes([]byte(fields[i]), nil)) > 0 {
				fields[i] = "[redacted]"
			}
		case len(secrets.ScanBytes([]byte(f), nil)) > 0:
			fields[i] = "[redacted]"
		case strings.Contains(f, "=") && len(secrets.ScanURL("https://x.invalid/?"+f, nil, 6, true)) > 0:
			fields[i] = "[redacted]"
		}
	}
	return strings.Join(fields, " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func shortenHome(s, home string) string {
	if home == "" || len(home) < 2 {
		return s
	}
	return strings.ReplaceAll(s, home, "~")
}

// Text renders the report for pasting into a bug report.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("DenyOut diagnostics (secrets are redacted; safe to paste in a bug report)\n")
	fmt.Fprintf(&b, "Generated: %s\n", r.GeneratedAt)
	fmt.Fprintf(&b, "Version:   %s\n", r.Version)
	fmt.Fprintf(&b, "OS:        %s/%s (%s)\n", r.OS, r.Arch, r.GoVersion)
	if r.Status != "" {
		fmt.Fprintf(&b, "Status:    %s", r.Status)
		if r.StatusReason != "" {
			fmt.Fprintf(&b, " (%s)", r.StatusReason)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nChecks\n")
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  [%-4s] %s: %s\n", c.Status, c.Name, c.Detail)
		if c.Fix != "" && c.Status != OK {
			fmt.Fprintf(&b, "         fix: %s\n", c.FixLabel)
		}
	}
	if r.LastError != "" {
		fmt.Fprintf(&b, "\nLast error\n  %s\n", r.LastError)
	}
	fmt.Fprintf(&b, "\nLast %d denials (newest first)\n", len(r.Denials))
	if len(r.Denials) == 0 {
		b.WriteString("  none recorded\n")
	}
	for _, d := range r.Denials {
		fmt.Fprintf(&b, "  %s  %s  %s\n", d.TS, d.Host, strings.Join(d.Reasons, ","))
		fmt.Fprintf(&b, "      rule: %s | %s\n", d.Rule, d.Why)
		if d.URL != "" {
			fmt.Fprintf(&b, "      url:  %s\n", d.URL)
		}
		if d.Process != "" {
			fmt.Fprintf(&b, "      by:   %s\n", d.Process)
		}
	}
	return b.String()
}

// JSON renders the report as indented JSON.
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
