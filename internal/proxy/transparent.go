package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/policy"
)

func (s *Server) serveTransparent() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
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
		fmt.Sscanf(p, "%d", &port)
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
	if s.cfg.TLSMode == TLSPassthrough || s.cfg.CA == nil {
		ips, _ := lookupIPs(host)
		s.tunnel(conn, host, fmt.Sprintf("%d", port), ips, s.cfg.Engine.Cfg.AllowPrivate)
		s.logDecision(rv, d, start)
		return
	}
	leaf, err := s.cfg.CA.Leaf(host)
	if err != nil {
		return
	}
	tlsClient := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		_ = tlsClient.Close()
		return
	}
	defer tlsClient.Close()
	ips, _ := lookupIPs(host)
	br := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		s.roundTripIntercept(tlsClient, req, host, port, ips, start)
	}
}

func (s *Server) handleTransparentHTTP(conn net.Conn, req *http.Request, host string, port int) {
	start := time.Now()
	ips, _ := lookupIPs(host)
	raw := req.URL.String()
	if !strings.HasPrefix(raw, "http") {
		raw = fmt.Sprintf("http://%s%s", req.Host, req.URL.RequestURI())
	}
	rv := policy.RequestView{
		SessionID:  s.cfg.SessionID,
		DestHost:   host,
		DestPort:   uint16(port),
		DestIPs:    ips,
		Protocol:   "http",
		Method:     req.Method,
		Inspection: "transparent",
		RawURL:     raw,
	}
	d := s.cfg.Engine.Evaluate(rv)
	if d.Verdict == "deny" {
		s.logDecision(rv, d, start)
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", redactDenyMsg(d))
		return
	}
	out, err := s.dialTCP(net.JoinHostPort(host, fmt.Sprintf("%d", port)), 10*time.Second)
	if err != nil {
		return
	}
	defer out.Close()
	if err := req.Write(out); err != nil {
		return
	}
	_, _ = io.Copy(conn, out)
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
