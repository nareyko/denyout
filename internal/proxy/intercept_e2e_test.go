package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
)

// Loopback is a hard deny in every mode (SSRF guard), so the upstream has to
// listen on a real RFC1918 address of this machine and be addressed by IP.
// The policy templates take that IP.
const interceptPolicy = `
apiVersion: denyout/v1
kind: Config
mode: enforce
allow_private: true
allow_ip_literals: true
allow:
  - host: %s
scanners:
  min_value_len: 6
  named_query:
    enabled: true
  canaries:
    - "DENYOUT_CANARY_"
`

// It returns an HTTPS client that trusts only the session CA and reaches the
// proxy via CONNECT, the upstream URL, a counter of upstream hits and the audit
// file path.
// privateIPv4 returns a non-loopback RFC1918 address of this machine, or skips.
func privateIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list interface addresses: %v", err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip := ipn.IP.To4(); ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	t.Skip("no RFC1918 interface address on this machine")
	return ""
}

// startIntercept runs the real proxy in TLS-intercept mode in front of a local
// TLS upstream. policyFmt is a policy with one %s for the upstream IP.
func startIntercept(t *testing.T, policyFmt string) (client *http.Client, upstreamURL string, hits *atomic.Int64, auditPath string) {
	t.Helper()
	return startInterceptH(t, policyFmt, nil)
}

// startInterceptH is startIntercept with a custom upstream handler (nil = "upstream-ok").
func startInterceptH(t *testing.T, policyFmt string, handler http.HandlerFunc) (client *http.Client, upstreamURL string, hits *atomic.Int64, auditPath string) {
	t.Helper()
	ip := privateIPv4(t)
	cfg, err := policy.LoadBytes([]byte(fmt.Sprintf(policyFmt, ip)))
	if err != nil {
		t.Fatal(err)
	}

	hits = &atomic.Int64{}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "upstream-ok") }
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	upstream.Listener = ln
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	ca, err := proxy.NewSessionCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(ca.CertFile())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("session CA PEM not parseable")
	}

	auditPath = t.TempDir() + "/audit.jsonl"
	sink, err := audit.Open(auditPath, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv, err := proxy.Start(ctx, proxy.Config{
		Engine:             policy.NewEngine(cfg),
		Audit:              sink,
		SessionID:          "intercept-e2e",
		TLSMode:            proxy.TLSIntercept,
		CA:                 ca,
		Version:            "test",
		InsecureSkipVerify: true, // upstream is httptest's self-signed cert
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	proxyURL, err := url.Parse("http://" + srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	client = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}

	return client, upstream.URL, hits, auditPath
}

func TestInterceptAllowsCleanRequest(t *testing.T) {
	client, base, hits, _ := startIntercept(t, interceptPolicy)

	resp, err := client.Get(base + "/v1/ping?q=hello")
	if err != nil {
		t.Fatalf("clean request through intercept failed (CA trust or relay broken): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "upstream-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits=%d, want 1", hits.Load())
	}
}

func TestInterceptDeniesCanaryAndNeverReachesUpstream(t *testing.T) {
	client, base, hits, auditPath := startIntercept(t, interceptPolicy)

	const canary = "DENYOUT_CANARY_E2E_SECRET"
	began := time.Now()
	resp, err := client.Get(base + "/pixel.png?api_key=" + canary)
	if err != nil {
		t.Fatalf("denied request should still produce an HTTP response: %v", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%q, want 403", resp.StatusCode, body)
	}
	if rerr != nil {
		t.Fatalf("reading the deny body failed after %s (proxy did not close or frame the response): %v", time.Since(began), rerr)
	}
	if hits.Load() != 0 {
		t.Fatalf("canary request reached upstream (%d hits): exfil not blocked", hits.Load())
	}
	if strings.Contains(string(body), canary) {
		t.Fatalf("deny response leaks the secret: %q", body)
	}

	// The audit trail must record the deny without the raw secret.
	raw := readAudit(t, auditPath)
	if strings.Contains(raw, canary) {
		t.Fatalf("audit log contains the raw secret: %s", raw)
	}
	if !strings.Contains(raw, "deny") {
		t.Fatalf("audit log has no deny verdict: %s", raw)
	}
}

func TestInterceptDeniesUnlistedHostBeforeDial(t *testing.T) {
	// Same upstream, but the policy does not allow its IP: CONNECT must be
	// refused before any dial, so the upstream sees nothing.
	const denyAll = `
apiVersion: denyout/v1
kind: Config
mode: enforce
allow_private: true
allow_ip_literals: true
allow:
  - host: api.example.invalid
# upstream IP %s is deliberately not allowed
`
	client, base, hits, auditPath := startIntercept(t, denyAll)

	resp, err := client.Get(base + "/")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("unlisted host got status %d, want CONNECT refused", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("unlisted host reached upstream (%d hits)", hits.Load())
	}
	raw := readAudit(t, auditPath)
	if !strings.Contains(raw, "host_not_allowed") {
		t.Fatalf("expected host_not_allowed in audit, got: %s", raw)
	}
}

// readAudit waits briefly for the sink to flush and returns the JSONL text.
func readAudit(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		if len(raw) > 0 || time.Now().After(deadline) {
			if len(raw) == 0 {
				t.Fatal("no audit event written")
			}
			return string(raw)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A client that sends "Expect: 100-continue" (curl does this for POST bodies over
// 1 MiB) waits for an interim "100 Continue" before it sends the body. The proxy must
// answer it, and must not hand the upstream's interim 100 back as the final response.
func TestInterceptExpectContinueLargeUpload(t *testing.T) {
	client, base, hits, _ := startIntercept(t, interceptPolicy)
	client.Transport.(*http.Transport).ExpectContinueTimeout = 5 * time.Second
	client.Timeout = 8 * time.Second

	body := strings.NewReader(strings.Repeat("x", 3<<20))
	req, err := http.NewRequest(http.MethodPost, base+"/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Expect", "100-continue")
	req.Header.Set("Content-Type", "application/octet-stream")

	began := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expect: 100-continue upload failed after %s: %v", time.Since(began), err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != "upstream-ok" {
		t.Fatalf("status=%d body=%q, want 200 upstream-ok", resp.StatusCode, got)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits=%d, want 1", hits.Load())
	}
	// The client waits ExpectContinueTimeout (5s) for a 100 before sending anyway: a fast
	// answer proves the proxy sent the interim 100 itself.
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("upload took %s: the proxy did not answer Expect: 100-continue", took)
	}
}

// A denied upload must end with a readable 403, not a connection reset: the proxy
// has to consume (a bounded amount of) the body the client is still sending.
func TestInterceptDenyLargeUploadIsNotReset(t *testing.T) {
	client, base, hits, _ := startIntercept(t, interceptPolicy)
	client.Timeout = 8 * time.Second

	body := strings.NewReader(strings.Repeat("x", 3<<20))
	req, err := http.NewRequest(http.MethodPost, base+"/upload?api_key=DENYOUT_CANARY_BIGPOST", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("denied large upload surfaced as a transport error (reset?), want a 403: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("canary upload reached upstream (%d hits)", hits.Load())
	}
}

// An upstream response with neither Content-Length nor chunking ends only when the
// connection closes (HTTP/1.0 style). The proxy must close the client connection after
// relaying it, or the client waits for an EOF that never comes.
func TestInterceptEOFDelimitedResponseEndsTheBody(t *testing.T) {
	client, base, _, _ := startInterceptH(t, interceptPolicy, func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nraw-body")
		_ = c.Close()
	})
	client.Timeout = 4 * time.Second

	began := time.Now()
	resp, err := client.Get(base + "/eof")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil || string(body) != "raw-body" {
		t.Fatalf("body=%q err=%v after %s: the proxy kept the connection open after an EOF-delimited response", body, rerr, time.Since(began))
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("took %s to see the end of an EOF-delimited body", took)
	}
}

// A client that sends headers and then stops (or a silent upstream) must not hold the
// connection and its goroutines forever.
func TestInterceptStalledRequestBodyIsDropped(t *testing.T) {
	defer proxy.SetIdleForTest(5*time.Second, 400*time.Millisecond, 5*time.Second)()
	client, base, _, _ := startInterceptH(t, interceptPolicy, nil)
	tr := client.Transport.(*http.Transport)

	// Raw request: Content-Length promises 1000 bytes, none follow.
	u, _ := url.Parse(base)
	proxyURL, _ := tr.Proxy(nil)
	pc, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, _ = fmt.Fprintf(pc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host, u.Host)
	br := bufio.NewReader(pc)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	for {
		l, _ := br.ReadString('\n')
		if l == "\r\n" || l == "" {
			break
		}
	}
	tcfg := tr.TLSClientConfig.Clone()
	tcfg.ServerName = ""
	tcfg.InsecureSkipVerify = true // the leaf is for the IP; trust is checked by the other tests
	tc := tls.Client(pc, tcfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = fmt.Fprintf(tc, "POST /stall HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n", u.Host)

	began := time.Now()
	buf := make([]byte, 1)
	_, rerr := tc.Read(buf)
	if rerr == nil {
		t.Fatalf("expected the proxy to drop the stalled connection, got data")
	}
	if took := time.Since(began); took > 4*time.Second {
		t.Fatalf("stalled body held the connection for %s (idle limit was 400ms + 2s early-answer window)", took)
	}
}

type countingReader struct {
	n    int64
	max  int64
	sent *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		return 0, io.EOF
	}
	k := int64(len(p))
	if c.max-c.n < k {
		k = c.max - c.n
	}
	for i := int64(0); i < k; i++ {
		p[i] = 'x'
	}
	c.n += k
	c.sent.Store(c.n)
	return int(k), nil
}

// When the upstream answers before the upload ends (401/413), the proxy may only consume a
// bounded amount of the rest. With a non-scannable content type it used to pull the whole body
// through (Request.Write closes a server-side body by draining it).
func TestInterceptEarlyAnswerDoesNotPullWholeUpload(t *testing.T) {
	client, base, _, _ := startInterceptH(t, interceptPolicy, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // answers without reading the body
	})
	client.Timeout = 20 * time.Second
	const total = 64 << 20
	var sent atomic.Int64
	body := &countingReader{max: total, sent: &sent}
	req, _ := http.NewRequest(http.MethodPost, base+"/video", body)
	req.ContentLength = total
	req.Header.Set("Content-Type", "video/mp4")

	resp, err := client.Do(req)
	if err != nil {
		// A transport error is acceptable only if the client was cut off well before the end.
		if sent.Load() >= total {
			t.Fatalf("whole upload (%d MiB) was consumed before the early answer was relayed: %v", total>>20, err)
		}
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	time.Sleep(300 * time.Millisecond)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d, want the upstream's 401", resp.StatusCode)
	}
	if got := sent.Load(); got >= total {
		t.Fatalf("proxy consumed the whole %d MiB upload after an early answer (drain bound is %d MiB)", total>>20, 8)
	}
}

// WebSocket upgrades are not relayed after interception; the client must get a clear 501
// instead of a 101 followed by a dead connection.
func TestInterceptWebSocketUpgradeIsRefused(t *testing.T) {
	client, base, hits, _ := startInterceptH(t, interceptPolicy, nil)
	req, _ := http.NewRequest(http.MethodGet, base+"/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upgrade request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("upgrade request reached the upstream (%d)", hits.Load())
	}
}

func TestHostHeaderMatches(t *testing.T) {
	cases := []struct {
		hdr, host string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.com:443", "example.com", true},
		{"example.com.", "example.com", true},
		{"example.com", "example.com.", true},
		{"", "example.com", true},
		{"[::1]", "::1", true},
		{"[::1]:8443", "::1", true},
		{"::1", "::1", true},
		{"evil.example", "example.com", false},
		{"example.com.evil.example", "example.com", false},
		{"example.com@evil.example", "example.com", false},
	}
	for _, c := range cases {
		if got := proxy.HostHeaderMatchesForTest(c.hdr, c.host); got != c.want {
			t.Errorf("hostHeaderMatches(%q,%q)=%v want %v", c.hdr, c.host, got, c.want)
		}
	}
}
