package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/nareyko/denyout/internal/inspect"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/policy"
)

func (s *Server) serveTransparentOn(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			// e.g. EMFILE: do not spin a CPU core on a failing Accept.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handleTransparent(conn)
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) handleTransparent(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReaderSize(conn, 65536)
	peek, err := br.Peek(1)
	if err != nil {
		return
	}

	if peek[0] == 0x16 {
		hello, err := br.Peek(5)
		if err != nil {
			return
		}
		recLen := int(hello[3])<<8 | int(hello[4])
		need := 5 + recLen
		if need > 65536 {
			need = 65536
		}
		hello, err = br.Peek(need)
		if err != nil && len(hello) < 43 {
			return
		}
		host := parseSNI(hello)
		port := 443
		if host == "" {
			h, p := originalDst(conn)
			host, port = h, p
		}
		if host == "" {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		s.serveTransparentTLS(&prefixConn{r: br, Conn: conn}, host, port)
		return
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host := req.Host
	port := 80
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if _, serr := fmt.Sscanf(p, "%d", &port); serr != nil || port < 1 || port > 65535 {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})
	s.handleTransparentHTTP(&prefixConn{r: br, Conn: conn}, req, host, port)
}

func (s *Server) serveTransparentTLS(conn net.Conn, host string, port int) {
	start := time.Now()
	// Host-only pre-check without DNS so we can complete the TLS handshake promptly
	// (clients time out if ServerHello is delayed by a slow resolver).
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   host,
		DestPort:   uint16(port),
		Protocol:   "https",
		ServerName: host,
		Method:     http.MethodConnect,
		Inspection: string(s.cfg.TLSMode),
		RawURL:     "https://" + host + "/",
	}
	d := s.cfg.Engine.Evaluate(rv)
	if d.Verdict == "deny" {
		s.logDecision(rv, d, start)
		return
	}
	if s.useTLSPassthrough(host) {
		rv.Inspection = "passthrough"
		ips, _ := lookupIPs(host)
		rv.DestIPs = ips
		if err := s.tunnel(conn, host, fmt.Sprintf("%d", port), ips, s.cfg.Engine.Cfg.AllowPrivate); err != nil {
			s.logPassthroughError(rv, err, start)
			return
		}
		s.logDecision(rv, d, start)
		return
	}
	// Same terminate-and-relay loop as the CONNECT path (handshake bound, Host check,
	// idle limits, close-and-drain on deny/error). DNS runs after the handshake.
	s.serveIntercept(conn, rv, host, port, func() []net.IP { ips, _ := lookupIPs(host); return ips }, start)
}

func (s *Server) handleTransparentHTTP(conn net.Conn, req *http.Request, host string, port int) {
	start := time.Now()
	ips, _ := lookupIPs(host)
	raw := req.URL.String()
	if !strings.HasPrefix(raw, "http") {
		raw = fmt.Sprintf("http://%s%s", req.Host, req.URL.RequestURI())
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
		Method:     req.Method,
		Path:       req.URL.Path,
		RawQuery:   req.URL.RawQuery,
		Inspection: "transparent",
		RawURL:     raw,
		Headers:    req.Header, // header + body scanners must see cleartext traffic too
		BodyPrefix: inspect.BodyView(req, bodyMax),
	}
	d := s.cfg.Engine.Evaluate(rv)
	if d.Verdict == "deny" {
		s.logDecision(rv, d, start)
		writeSimple(conn, http.StatusForbidden, redactDenyMsg(d)+"\n")
		drainRequestBody(conn, req) // a large upload must still end in a readable 403, not an RST
		return
	}
	// Dial the validated IP (never re-resolve the name: DNS-rebinding TOCTOU).
	dialIP, derr := safeDialIP(host, ips, s.cfg.Engine.Cfg.AllowPrivate)
	if derr != nil {
		s.logDecision(rv, policy.Decision{Verdict: "error", Reasons: []string{"upstream_unsafe_ip"}}, start)
		writeSimple(conn, http.StatusBadGateway, "upstream address refused\n")
		return
	}
	out, err := s.dialTCP(net.JoinHostPort(dialIP.String(), fmt.Sprintf("%d", port)), 10*time.Second)
	if err != nil {
		s.logDecision(rv, policy.Decision{Verdict: "error", Reasons: []string{"upstream_dial_failed"}}, start)
		writeSimple(conn, http.StatusBadGateway, "upstream dial failed\n")
		return
	}
	defer out.Close()
	// One request per connection: the upstream closes after its response, so io.Copy ends
	// instead of pinning this goroutine on a keep-alive upstream.
	req.Close = true
	upstream := newIdleConn(out, upstreamIdle)
	if err := req.Write(upstream); err != nil {
		s.logDecision(rv, policy.Decision{Verdict: "error", Reasons: []string{"upstream_write_failed"}}, start)
		writeSimple(conn, http.StatusBadGateway, "upstream write failed\n")
		return
	}
	_, _ = io.Copy(conn, upstream)
	s.logDecision(rv, d, start)
}

// prefixConn reads from bufio first, then the underlying conn.
type prefixConn struct {
	r *bufio.Reader
	net.Conn
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// CloseWrite forwards half-close to the underlying TCP conn (passthrough relay).
func (c *prefixConn) CloseWrite() error {
	type closer interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closer); ok {
		return cw.CloseWrite()
	}
	return nil
}

// parseSNI extracts server_name from a TLS ClientHello (best-effort).
func parseSNI(data []byte) string {
	if len(data) < 43 || data[0] != 0x16 {
		return ""
	}
	// TLS record: type(1) ver(2) len(2) handshake...
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		// incomplete; still try
	}
	p := 5
	if p >= len(data) || data[p] != 0x01 { // ClientHello
		return ""
	}
	p++
	if p+3 > len(data) {
		return ""
	}
	p += 3 // handshake length
	if p+2 > len(data) {
		return ""
	}
	p += 2 // client version
	p += 32
	if p >= len(data) {
		return ""
	}
	sidLen := int(data[p])
	p++
	p += sidLen
	if p+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2 + csLen
	if p >= len(data) {
		return ""
	}
	compLen := int(data[p])
	p++
	p += compLen
	if p+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(data) {
		end = len(data)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(data[p : p+2])
		l := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		p += 4
		if p+l > end {
			break
		}
		if typ == 0 { // server_name
			return parseServerNameList(data[p : p+l])
		}
		p += l
	}
	return ""
}

func parseServerNameList(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	p := 2
	for p+3 <= len(b) {
		nameType := b[p]
		l := int(binary.BigEndian.Uint16(b[p+1 : p+3]))
		p += 3
		if p+l > len(b) {
			return ""
		}
		if nameType == 0 {
			return string(b[p : p+l])
		}
		p += l
	}
	return ""
}
