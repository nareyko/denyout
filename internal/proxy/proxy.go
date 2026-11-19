package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nareyko/denyout/internal/inspect"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
)

// TLSMode is intercept or passthrough.
type TLSMode string

const (
	TLSIntercept   TLSMode = "intercept"
	TLSPassthrough TLSMode = "passthrough"
)

// DenyHook is called after a deny decision.
// redactedURL is secrets.RedactURL of the request when known (may be empty).
type DenyHook func(host string, reasons []string, redactedURL string)

// Config for the local proxy.
type Config struct {
	Engine             *policy.Engine
	Audit              *audit.Sink
	SessionID          string
	PolicyHash         string
	Version            string
	TLSMode            TLSMode
	CA                 *SessionCA
	ListenHost         string // default 127.0.0.1
	ListenPort         int    // 0 = ephemeral
	OnDeny             DenyHook
	Transparent        bool   // accept redirected raw TCP (SNI/Host), not only HTTP-proxy protocol
	PolicyProfile      string // agent | browse (audit attribution)
	Process            string // best-effort client label
	InsecureSkipVerify bool   // lab dogfood: trust self-signed origins
}

// Server is the HTTP proxy.
type Server struct {
	cfg     Config
	ln      net.Listener
	ln6     net.Listener // transparent mode: ::1 twin so nft IPv6 redirects land somewhere
	httpSrv *http.Server
	mu      sync.Mutex
	closed  bool
}

// Start listens and serves in the background.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.ListenHost == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = TLSIntercept
	}
	addr := fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, ln: ln}
	s.httpSrv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if cfg.Transparent {
		go s.serveTransparentOn(ln)
		// nft redirects IPv6 80/443 to ::1:<port>; without this listener IPv6 web traffic
		// is refused (or, worse, users disable the v6 rules). Best-effort: v6 may be off.
		if cfg.ListenHost == "127.0.0.1" {
			if ln6, err6 := net.Listen("tcp", fmt.Sprintf("[::1]:%d", ln.Addr().(*net.TCPAddr).Port)); err6 == nil {
				s.ln6 = ln6
				go s.serveTransparentOn(ln6)
			}
		}
	} else {
		go func() {
			_ = s.httpSrv.Serve(ln)
		}()
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s, nil
}

// Addr returns the bound address (host:port).
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Port returns the TCP port.
func (s *Server) Port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

// Close shuts down the proxy.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if s.httpSrv != nil && !s.cfg.Transparent {
		_ = s.httpSrv.Shutdown(ctx)
	}
	if s.ln6 != nil {
		_ = s.ln6.Close()
	}
	return s.ln.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// parseConnectTarget splits a CONNECT authority into host and port. A missing
// port defaults to 443; ok is false for a non-numeric or out-of-range port
// (no uint16 wraparound: 65616 must not become 80).
func parseConnectTarget(authority string) (host, port string, portN int, ok bool) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host = authority
		port = "443"
	}
	portN, perr := strconv.Atoi(port)
	if perr != nil || portN < 1 || portN > 65535 {
		return "", "", 0, false
	}
	return host, port, portN, true
}

// decideConnect is the L1 policy decision for a CONNECT (host / IP / deny list).
// A DNS failure denies unless the engine config explicitly disables that.
func (s *Server) decideConnect(host string, portN int, ips []net.IP, resolveErr error) (policy.RequestView, policy.Decision) {
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   host,
		DestPort:   uint16(portN),
		DestIPs:    ips,
		Protocol:   "https",
		ServerName: host,
		Method:     http.MethodConnect,
		Inspection: string(s.cfg.TLSMode),
		RawURL:     "https://" + host + "/",
	}
	d := s.cfg.Engine.Evaluate(rv)
	if resolveErr != nil && d.Verdict != "deny" {
		// Engine may not have Resolve set; enforce DNS failure here if configured.
		denyDNS := true
		if s.cfg.Engine.Cfg.DenyOnDNSFailure != nil {
			denyDNS = *s.cfg.Engine.Cfg.DenyOnDNSFailure
		}
		if denyDNS {
			d = policy.Decision{Verdict: "deny", Reasons: []string{policy.ReasonDNSFailure}}
		}
	}
	return rv, d
}

func (s *Server) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, portN, ok := parseConnectTarget(r.Host)
	if !ok {
		http.Error(w, "bad port", http.StatusBadRequest)
		return
	}

	start := time.Now()
	ips, resolveErr := lookupIPs(host)
	rv, d := s.decideConnect(host, portN, ips, resolveErr)
	if d.Verdict == "deny" {
		s.logDecision(rv, d, start)
		http.Error(w, redactDenyMsg(d), http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	if s.useTLSPassthrough(host) {
		rv.Inspection = "passthrough"
		if err := s.tunnel(clientConn, host, port, ips, s.cfg.Engine.Cfg.AllowPrivate); err != nil {
			s.logPassthroughError(rv, err, start)
			return
		}
		s.logDecision(rv, d, start)
		return
	}
	s.serveIntercept(clientConn, rv, host, portN, ips, start)
}

// serveIntercept terminates the client's TLS with a per-host leaf and serves
// its requests through roundTripIntercept until the client or server closes.
func (s *Server) serveIntercept(clientConn net.Conn, rv policy.RequestView, host string, portN int, ips []net.IP, start time.Time) {
	if s.cfg.CA == nil {
		_ = clientConn.Close()
		return
	}
	leaf, err := s.cfg.CA.Leaf(host)
	if err != nil {
		s.logMitmError(rv, "mitm_leaf_error", start)
		_ = clientConn.Close()
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second)) // slowloris: bound the handshake
	if err := tlsClient.Handshake(); err != nil {
		s.logMitmError(rv, "mitm_handshake_failed", start)
		_ = tlsClient.Close()
		return
	}
	_ = clientConn.SetDeadline(time.Time{})
	defer tlsClient.Close()

	br := bufio.NewReader(tlsClient)
	if peek, perr := br.Peek(24); perr == nil && isHTTP2ClientPreface(peek) {
		s.logMitmError(rv, "mitm_http2_unsupported", start)
		return
	}
	for {
		// Idle/slow-header protection per request; cleared once the request line+headers arrived.
		_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = clientConn.SetReadDeadline(time.Time{})
		if !hostHeaderMatches(req.Host, host) {
			// Domain fronting: policy was evaluated for the CONNECT/SNI host, so a
			// different Host header would reach a host that was never checked.
			_ = misdirectedResponse().Write(tlsClient)
			return
		}
		if !s.roundTripIntercept(tlsClient, req, host, portN, ips, start) || req.Close {
			drainRequestBody(clientConn, req)
			return
		}
	}
}

// misdirectedResponse is the 421 sent when a Host header differs from the tunnel host.
func misdirectedResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusMisdirectedRequest, ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader("host header does not match tunnel host\n"))}
}

// roundTripIntercept handles one request on an intercepted connection. It returns
// true only when a complete upstream response was relayed and the client
// connection can serve another request. Every deny or error path returns false:
// the caller then closes the connection, so a client that waits for the end of a
// "Connection: close" body is released instead of hanging until its own timeout.
func (s *Server) roundTripIntercept(client io.ReadWriteCloser, req *http.Request, host string, port int, ips []net.IP, start time.Time) bool {
	rawURL := "https://" + host
	if port != 443 {
		rawURL = fmt.Sprintf("https://%s:%d", host, port)
	}
	rawURL += req.URL.RequestURI()

	// Clients (curl for bodies over 1 MiB) send "Expect: 100-continue" and wait for an
	// interim 100 before sending the body. The body is needed for scanning, so answer it
	// here and do not forward the expectation: the upstream's own interim 100 would
	// otherwise be relayed to the client as if it were the final response.
	if strings.EqualFold(strings.TrimSpace(req.Header.Get("Expect")), "100-continue") {
		req.Header.Del("Expect")
		if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return false
		}
	}

	bodyMax := 65536
	if s.cfg.Engine != nil && s.cfg.Engine.Cfg != nil {
		bodyMax = s.cfg.Engine.Cfg.BodyScanMaxBytesOrDefault()
	}
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   host,
		DestPort:   uint16(port),
		DestIPs:    ips,
		Protocol:   "https",
		ServerName: host,
		Method:     req.Method,
		Path:       req.URL.Path,
		RawQuery:   req.URL.RawQuery,
		RawURL:     rawURL,
		Inspection: "intercept",
		Headers:    req.Header,
		BodyPrefix: inspect.BodyView(req, bodyMax),
	}
	d := s.cfg.Engine.Evaluate(rv)
	s.logDecision(rv, d, start)
	if d.Verdict == "deny" {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(redactDenyMsg(d) + "\n")),
		}
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp.Header.Set("Connection", "close")
		_ = resp.Write(client)
		return false
	}

	ip, err := safeDialIP(host, ips, s.cfg.Engine.Cfg.AllowPrivate)
	if err != nil {
		reason := policy.ReasonUnsafeIP
		if err == errDNSFailure {
			reason = policy.ReasonDNSFailure
		}
		deny := policy.Decision{Verdict: "deny", Reasons: []string{reason}}
		rv.DestIPs = ips
		s.logDecision(rv, deny, start)
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(redactDenyMsg(deny) + "\n")),
		}
		_ = resp.Write(client)
		return false
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	raw, err := s.dialTCP(addr, 15*time.Second)
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream dial failed\n")),
		}
		_ = resp.Write(client)
		return false
	}
	up := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.cfg.InsecureSkipVerify,
	})
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if err := up.Handshake(); err != nil {
		_ = raw.Close()
		return false
	}
	_ = raw.SetDeadline(time.Time{})
	defer up.Close()

	outReq := req.Clone(context.Background())
	outReq.URL = &url.URL{Scheme: "https", Host: host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	outReq.RequestURI = ""
	// Read the response while the request is still being written: an upstream may answer
	// (401, 413) before it has consumed a large body and then close. Writing first and
	// reading after would fail on the write and lose that answer (seen on macOS/Windows,
	// where the resulting RST also discards unread data).
	type upResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan upResult, 1)
	go func() {
		upBuf := bufio.NewReader(up)
		r, rerr := http.ReadResponse(upBuf, outReq)
		for rerr == nil && r.StatusCode >= 100 && r.StatusCode < 200 && r.StatusCode != http.StatusSwitchingProtocols {
			r, rerr = http.ReadResponse(upBuf, outReq) // interim (100/103): the final response follows
		}
		respCh <- upResult{r, rerr}
	}()
	werr := outReq.Write(up)
	if werr != nil {
		// The upstream may have answered and closed; do not wait forever for more.
		_ = up.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	res := <-respCh
	if res.err != nil {
		return false
	}
	upResp := res.resp
	defer upResp.Body.Close()
	s.stripDeniedRedirect(upResp, start)
	_ = upResp.Write(client)
	// Early answer: the upstream replied before the whole request body was sent. The
	// client connection still has unread body bytes, so it cannot serve another request.
	return werr == nil
}

// maxDrainBytes bounds how much of an unread request body is consumed before an
// intercepted connection is closed.
const maxDrainBytes = 8 << 20

// drainRequestBody reads (a bounded amount of) the body the client is still sending
// before the connection is closed. Closing a socket with unread data makes the kernel
// send RST, and the client can then lose the 403 it was just sent. The deadline keeps a
// slow sender from holding the connection.
func drainRequestBody(conn net.Conn, req *http.Request) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.CopyN(io.Discard, req.Body, maxDrainBytes)
}

// stripDeniedRedirect re-evaluates absolute Location hosts (open-redirect / EchoLeak class).
// Relative Locations are left alone. Denied destinations lose Location so clients cannot follow.
func (s *Server) stripDeniedRedirect(resp *http.Response, start time.Time) {
	if resp == nil || s.cfg.Engine == nil {
		return
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	scheme := "https"
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme != "" {
		scheme = resp.Request.URL.Scheme
	}
	u, ok := redirectTarget(loc, scheme)
	if !ok {
		return
	}
	d, err := s.cfg.Engine.EvaluateURL(u.String())
	if err != nil {
		d = policy.Decision{Verdict: "deny", Reasons: []string{"dns_failure"}}
	}
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   u.Hostname(),
		DestPort:   443,
		Protocol:   u.Scheme,
		Method:     "GET",
		Path:       u.Path,
		RawQuery:   u.RawQuery,
		RawURL:     u.String(),
		Inspection: "redirect",
	}
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &rv.DestPort)
	} else if u.Scheme == "http" {
		rv.DestPort = 80
	}
	s.logDecision(rv, d, start)
	if d.Verdict == "deny" {
		resp.Header.Del("Location")
		resp.Header.Set("X-DenyOut-Redirect", "stripped")
	}
}

// redirectTarget returns the absolute URL a client would follow for a Location value, or
// ok=false when it stays on the same origin (relative path). Protocol-relative ("//host/x")
// and browser-normalised forms ("/\\host", tabs/newlines inside the value) are cross-host.
func redirectTarget(loc, baseScheme string) (*url.URL, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, strings.TrimSpace(loc))
	// Browsers treat backslashes like slashes in the authority position.
	if strings.HasPrefix(clean, "/\\") || strings.HasPrefix(clean, "\\") {
		clean = "//" + strings.TrimLeft(clean, "/\\")
	}
	u, err := url.Parse(clean)
	if err != nil || u.Hostname() == "" {
		return nil, false
	}
	if !u.IsAbs() {
		if !strings.HasPrefix(clean, "//") {
			return nil, false
		}
		u.Scheme = baseScheme
	}
	return u, true
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	u := r.URL
	host := u.Hostname()
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	port := 80
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	ips, _ := lookupIPs(host)
	raw := u.String()
	if !u.IsAbs() {
		raw = "http://" + r.Host + r.URL.RequestURI()
	}
	bodyMax := 65536
	if s.cfg.Engine != nil && s.cfg.Engine.Cfg != nil {
		bodyMax = s.cfg.Engine.Cfg.BodyScanMaxBytesOrDefault()
	}
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   host,
		DestPort:   uint16(port),
		DestIPs:    ips,
		Protocol:   "http",
		Method:     r.Method,
		Path:       u.Path,
		RawQuery:   u.RawQuery,
		RawURL:     raw,
		Inspection: "cleartext",
		Headers:    r.Header,
		BodyPrefix: inspect.BodyView(r, bodyMax),
	}
	d := s.cfg.Engine.Evaluate(rv)
	s.logDecision(rv, d, start)
	if d.Verdict == "deny" {
		http.Error(w, redactDenyMsg(d), http.StatusForbidden)
		return
	}
	// Pin the dial to the IPs that were just validated (no second DNS lookup, no
	// HTTP(S)_PROXY from the environment): closes DNS-rebinding SSRF.
	allowPrivate := s.cfg.Engine.Cfg.AllowPrivate
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ip, err := safeDialIP(host, ips, allowPrivate)
			if err != nil {
				return nil, err
			}
			_, p, _ := net.SplitHostPort(addr)
			return s.dialTCP(net.JoinHostPort(ip.String(), p), 15*time.Second)
		},
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer transport.CloseIdleConnections()
	r.RequestURI = ""
	// Hop-by-hop proxy headers must not leak upstream.
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	s.stripDeniedRedirect(resp, start)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) tunnel(client net.Conn, host, port string, ips []net.IP, allowPrivate bool) error {
	defer client.Close()
	ip, err := safeDialIP(host, ips, allowPrivate)
	if err != nil {
		return fmt.Errorf("passthrough_dial_ip: %w", err)
	}
	addr := net.JoinHostPort(ip.String(), port)
	up, err := s.dialTCP(addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("passthrough_dial_tcp: %w", err)
	}
	defer up.Close()
	return relayBidirectional(client, up)
}

// relayBidirectional copies both directions and waits for both to finish.
// Closing one side only half-closes the peer writer so HTTP/2 streams can drain
// (a single <-errCh + full Close used to RST Cursor/api2 early → silent agent).
func relayBidirectional(a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		closeWrite(b)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(a, b)
		closeWrite(a)
		errCh <- err
	}()
	err1 := <-errCh
	err2 := <-errCh
	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}

func closeWrite(c net.Conn) {
	type closer interface{ CloseWrite() error }
	if cw, ok := c.(closer); ok {
		_ = cw.CloseWrite()
	}
}

func (s *Server) useTLSPassthrough(host string) bool {
	if s.cfg.TLSMode == TLSPassthrough || s.cfg.CA == nil {
		return true
	}
	return TLSPassthroughHost(host)
}

func (s *Server) logMitmError(rv policy.RequestView, reason string, start time.Time) {
	rv.Inspection = "intercept"
	s.logDecision(rv, policy.Decision{Verdict: "error", Reasons: []string{reason}}, start)
}

func (s *Server) logPassthroughError(rv policy.RequestView, err error, start time.Time) {
	rv.Inspection = "passthrough"
	reason := "passthrough_tunnel_error"
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "passthrough_dial_ip"):
			reason = "passthrough_dial_ip"
		case strings.Contains(msg, "passthrough_dial_tcp"):
			reason = "passthrough_dial_tcp"
		}
	}
	s.logDecision(rv, policy.Decision{Verdict: "error", Reasons: []string{reason}}, start)
}

func (s *Server) logDecision(rv policy.RequestView, d policy.Decision, start time.Time) {
	red := inspect.Request{URL: rv.RawURL, Path: rv.Path, RawQuery: rv.RawQuery}.Redacted()
	redURL := red.URL
	if s.cfg.Audit == nil {
		if d.Verdict == "deny" {
			fmt.Fprintf(os.Stderr, "denyout: DENY %s reasons=%s\n", redURL, strings.Join(d.Reasons, ","))
			if s.cfg.OnDeny != nil {
				s.cfg.OnDeny(rv.DestHost, append([]string(nil), d.Reasons...), redURL)
			}
		} else if d.Verdict == "error" {
			fmt.Fprintf(os.Stderr, "denyout: MITM %s reasons=%s host=%s\n", redURL, strings.Join(d.Reasons, ","), rv.DestHost)
		}
		return
	}
	ips := make([]string, 0, len(rv.DestIPs))
	for _, ip := range rv.DestIPs {
		ips = append(ips, ip.String())
	}
	ev := audit.Event{
		SessionID:  s.cfg.SessionID,
		Verdict:    d.Verdict,
		Reasons:    d.Reasons,
		Mode:       s.cfg.Engine.Cfg.Mode,
		Inspection: rv.Inspection,
		Network: audit.Network{
			DestHost:   rv.DestHost,
			DestPort:   int(rv.DestPort),
			DestIPs:    ips,
			Protocol:   rv.Protocol,
			ServerName: rv.ServerName,
		},
		HTTP: &audit.HTTPInfo{
			Method:        rv.Method,
			Path:          red.Path,
			QueryRedacted: red.Query,
		},
		Detectors:      d.Detectors,
		LatencyMS:      time.Since(start).Milliseconds(),
		PolicyHash:     s.cfg.PolicyHash,
		DenyOutVersion: s.cfg.Version,
		WouldDeny:      d.WouldDeny,
		PolicyProfile:  s.cfg.PolicyProfile,
		Process:        s.cfg.Process,
	}
	_ = s.cfg.Audit.Log(ev)
	if d.Verdict == "deny" {
		fmt.Fprintf(os.Stderr, "denyout: DENY host=%s reasons=%s\n", rv.DestHost, strings.Join(d.Reasons, ","))
		if s.cfg.OnDeny != nil {
			s.cfg.OnDeny(rv.DestHost, append([]string(nil), d.Reasons...), redURL)
		}
	}
}

func redactDenyMsg(d policy.Decision) string {
	b, _ := json.Marshal(map[string]any{
		"verdict": "deny",
		"reasons": d.Reasons,
	})
	return string(b)
}

func lookupIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.LookupIP(host)
	return addrs, err
}

var (
	errDNSFailure = fmt.Errorf("dns failure")
	errUnsafeIP   = fmt.Errorf("unsafe ip")
)

// safeDialIP picks a dial address only after every candidate IP passes UnsafeIP.
// Never falls back to dialing by hostname (avoids a second DNS lookup without SSRF check).
func safeDialIP(host string, ips []net.IP, allowPrivate bool) (net.IP, error) {
	if len(ips) == 0 {
		var err error
		ips, err = lookupIPs(host)
		if err != nil || len(ips) == 0 {
			return nil, errDNSFailure
		}
	}
	for _, ip := range ips {
		if policy.UnsafeIP(ip, allowPrivate) {
			return nil, errUnsafeIP
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	return ips[0], nil
}

// hostHeaderMatches reports whether an HTTP Host header (optionally with a port)
// names the tunnel host. An empty header (HTTP/1.0) is accepted.
func hostHeaderMatches(hdr, tunnelHost string) bool {
	if hdr == "" {
		return true
	}
	h := hdr
	if hh, _, err := net.SplitHostPort(hdr); err == nil {
		h = hh
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	return strings.TrimSuffix(h, ".") == strings.TrimSuffix(strings.Trim(strings.ToLower(tunnelHost), "[]"), ".")
}
