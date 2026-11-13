package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/secrets"
)

// TLSMode is intercept or passthrough.
type TLSMode string

const (
	TLSIntercept   TLSMode = "intercept"
	TLSPassthrough TLSMode = "passthrough"
)

// DenyHook is called after a deny decision (host and reasons are safe to show).
type DenyHook func(host string, reasons []string)

// Config for the local proxy.
type Config struct {
	Engine     *policy.Engine
	Audit      *audit.Sink
	SessionID  string
	PolicyHash string
	Version    string
	TLSMode    TLSMode
	CA         *SessionCA
	ListenHost string // default 127.0.0.1
	ListenPort int    // 0 = ephemeral
	OnDeny     DenyHook
}

// Server is the HTTP proxy.
type Server struct {
	cfg     Config
	ln      net.Listener
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
	}
	go func() {
		_ = s.httpSrv.Serve(ln)
	}()
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
	_ = s.httpSrv.Shutdown(ctx)
	return s.ln.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}
	portN := 443
	fmt.Sscanf(port, "%d", &portN)

	start := time.Now()
	ips, resolveErr := lookupIPs(host)
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
	// L1 decision (host / IP / deny list) — no query yet in passthrough.
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

	if s.cfg.TLSMode == TLSPassthrough {
		s.tunnel(clientConn, host, port, ips, s.cfg.Engine.Cfg.AllowPrivate)
		s.logDecision(rv, d, start)
		return
	}

	if s.cfg.CA == nil {
		_ = clientConn.Close()
		return
	}
	leaf, err := s.cfg.CA.Leaf(host)
	if err != nil {
		_ = clientConn.Close()
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		_ = tlsClient.Close()
		return
	}
	defer tlsClient.Close()

	br := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		s.roundTripIntercept(tlsClient, req, host, portN, ips, start)
		if req.Close {
			return
		}
	}
}

func (s *Server) roundTripIntercept(client io.ReadWriteCloser, req *http.Request, host string, port int, ips []net.IP, start time.Time) {
	rawURL := "https://" + host
	if port != 443 {
		rawURL = fmt.Sprintf("https://%s:%d", host, port)
	}
	rawURL += req.URL.RequestURI()

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
		return
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
		return
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	up, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream dial failed\n")),
		}
		_ = resp.Write(client)
		return
	}
	defer up.Close()

	outReq := req.Clone(context.Background())
	outReq.URL = &url.URL{Scheme: "https", Host: host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	outReq.RequestURI = ""
	if err := outReq.Write(up); err != nil {
		return
	}
	upResp, err := http.ReadResponse(bufio.NewReader(up), outReq)
	if err != nil {
		return
	}
	defer upResp.Body.Close()
	_ = upResp.Write(client)
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
	}
	d := s.cfg.Engine.Evaluate(rv)
	s.logDecision(rv, d, start)
	if d.Verdict == "deny" {
		http.Error(w, redactDenyMsg(d), http.StatusForbidden)
		return
	}
	transport := http.DefaultTransport
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) tunnel(client net.Conn, host, port string, ips []net.IP, allowPrivate bool) {
	defer client.Close()
	ip, err := safeDialIP(host, ips, allowPrivate)
	if err != nil {
		return
	}
	addr := net.JoinHostPort(ip.String(), port)
	up, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	errCh := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); errCh <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); errCh <- struct{}{} }()
	<-errCh
}

func (s *Server) logDecision(rv policy.RequestView, d policy.Decision, start time.Time) {
	if s.cfg.Audit == nil {
		if d.Verdict == "deny" {
			fmt.Fprintf(os.Stderr, "denyout: DENY %s reasons=%s\n", secrets.RedactURL(rv.RawURL), strings.Join(d.Reasons, ","))
			if s.cfg.OnDeny != nil {
				s.cfg.OnDeny(rv.DestHost, append([]string(nil), d.Reasons...))
			}
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
			Path:          rv.Path,
			QueryRedacted: secrets.RedactQuery(rv.RawQuery),
		},
		Detectors:      d.Detectors,
		LatencyMS:      time.Since(start).Milliseconds(),
		PolicyHash:     s.cfg.PolicyHash,
		DenyOutVersion: s.cfg.Version,
		WouldDeny:      d.WouldDeny,
	}
	_ = s.cfg.Audit.Log(ev)
	if d.Verdict == "deny" {
		fmt.Fprintf(os.Stderr, "denyout: DENY host=%s reasons=%s\n", rv.DestHost, strings.Join(d.Reasons, ","))
		if s.cfg.OnDeny != nil {
			s.cfg.OnDeny(rv.DestHost, append([]string(nil), d.Reasons...))
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
