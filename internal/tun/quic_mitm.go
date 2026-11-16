package tun

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUICMITMSession terminates a client QUIC/TLS connection with DenyOut CA and
// re-encrypts to the origin. HTTP/3 requests are optional (HandleHTTP3).
type QUICMITMSession struct {
	SNI    string
	Config MITMConfig
}

// DialOrigin opens a QUIC connection to the origin for SNI:443.
func (s *QUICMITMSession) DialOrigin(ctx context.Context) (*quic.Conn, error) {
	if s.SNI == "" {
		return nil, fmt.Errorf("%w: empty SNI", ErrQUICMITMNotReady)
	}
	addr := net.JoinHostPort(s.SNI, "443")
	tlsConf := &tls.Config{
		ServerName: s.SNI,
		NextProtos: []string{http3.NextProtoH3},
		RootCAs:    s.Config.RootCAs,
		MinVersion: tls.VersionTLS13,
	}
	return quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
	})
}

// ListenMITM starts a QUIC listener that presents DenyOut certs (for tests / early Q2a).
func ListenMITM(ctx context.Context, udp net.PacketConn, cfg MITMConfig) (*quic.Listener, error) {
	_ = ctx
	if cfg.GetCertificate == nil {
		return nil, fmt.Errorf("%w: GetCertificate required", ErrQUICMITMNotReady)
	}
	tlsConf := &tls.Config{
		GetCertificate: cfg.GetCertificate,
		NextProtos:     []string{http3.NextProtoH3},
		MinVersion:     tls.VersionTLS13,
	}
	return quic.Listen(udp, tlsConf, &quic.Config{})
}

// HTTP3PolicyFunc inspects a decrypted HTTP/3 request (host/path/URL).
// Returns deny reasons; empty means allow.
type HTTP3PolicyFunc func(r *http.Request) (denyReasons []string)

// ServeHTTP3MITM serves HTTP/3 on ln, applies policy, and proxies allowed requests to origin.
func ServeHTTP3MITM(ctx context.Context, ln *quic.Listener, cfg MITMConfig, policyFn HTTP3PolicyFunc) error {
	if policyFn == nil {
		policyFn = func(*http.Request) []string { return nil }
	}
	h3 := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reasons := policyFn(r); len(reasons) > 0 {
				http.Error(w, "denied: "+reasons[0], http.StatusForbidden)
				return
			}
			origin, err := dialHTTP3Origin(r.Context(), cfg, r.Host)
			if err != nil {
				http.Error(w, "origin dial failed", http.StatusBadGateway)
				return
			}
			defer origin.Body.Close()
			for k, vv := range origin.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(origin.StatusCode)
			_, _ = io.Copy(w, origin.Body)
		}),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- h3.ServeListener(ln) }()
	select {
	case <-ctx.Done():
		_ = h3.Close()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func dialHTTP3Origin(ctx context.Context, cfg MITMConfig, host string) (*http.Response, error) {
	h := host
	if h == "" {
		return nil, fmt.Errorf("empty host")
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		// already host:port
	} else {
		h = net.JoinHostPort(h, "443")
	}
	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         stripPort(host),
			RootCAs:            cfg.RootCAs,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS13,
		},
	}
	defer rt.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+stripPort(host)+"/", nil)
	if err != nil {
		return nil, err
	}
	return rt.RoundTrip(req)
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}
