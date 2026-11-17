package diag

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/nareyko/denyout/internal/proxy"
)

const selfCheckHost = "selfcheck.denyout.invalid"

// SelfCheck verifies, without touching host networking or the trust store,
// that the desktop CA exists, is valid, can mint leaf certificates, that a TLS
// client trusting only this CA accepts them in a loopback handshake (what
// interception does to every HTTPS connection), and whether the operating
// system already trusts the CA. expectCA says a missing CA is a failure (the
// user turned Protect on) instead of "not created yet".
func SelfCheck(caDir string, expectCA bool) []Check {
	crtPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	if caDir == "" {
		return []Check{{ID: "ca", Name: "CA files", Status: Skip, Detail: "no CA directory"}}
	}
	_, crtErr := os.Stat(crtPath)
	_, keyErr := os.Stat(keyPath)
	if crtErr != nil || keyErr != nil {
		c := Check{ID: "ca", Name: "CA files"}
		if expectCA {
			c.Status = Fail
			c.Detail = "the DenyOut CA is missing, so HTTPS sites would show certificate errors"
			c.Fix, c.FixLabel = FixRetryProtect, "Create it and turn Protect on"
		} else {
			c.Status = Skip
			c.Detail = "not created yet (it is created when Protect computer first turns on)"
		}
		return []Check{c}
	}
	checks := []Check{{ID: "ca", Name: "CA files", Status: OK, Detail: "certificate and key present"}}

	pemBytes, err := os.ReadFile(crtPath)
	if err != nil {
		return append(checks, caBroken("CA certificate", "cannot read ca.crt: "+err.Error()))
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return append(checks, caBroken("CA certificate", "cannot read ca.key: "+err.Error()))
	}
	pair, err := tls.X509KeyPair(pemBytes, keyBytes)
	if err != nil {
		return append(checks, caBroken("CA certificate", "certificate and key do not match or are unreadable"))
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return append(checks, caBroken("CA certificate", "certificate is unreadable"))
	}
	now := time.Now()
	switch {
	case !ca.IsCA:
		return append(checks, caBroken("CA certificate", "certificate is not marked as a CA"))
	case now.After(ca.NotAfter):
		return append(checks, caBroken("CA certificate", "expired on "+ca.NotAfter.UTC().Format("2006-01-02")))
	case now.Before(ca.NotBefore):
		return append(checks, caBroken("CA certificate", "not valid yet (check the computer clock)"))
	}
	checks = append(checks, Check{ID: "ca_valid", Name: "CA certificate", Status: OK,
		Detail: "valid until " + ca.NotAfter.UTC().Format("2006-01-02")})

	// Load (never create: both files exist at this point).
	sess, err := proxy.LoadOrCreatePersistentCA(caDir)
	if err != nil {
		return append(checks, caBroken("Certificate signing", err.Error()))
	}
	leaf, err := sess.Leaf(selfCheckHost)
	if err != nil {
		return append(checks, caBroken("Certificate signing", err.Error()))
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if err := loopbackHandshake(leaf, pool); err != nil {
		return append(checks, caBroken("Interception handshake", err.Error()))
	}
	checks = append(checks, Check{ID: "intercept", Name: "Interception handshake", Status: OK,
		Detail: "a TLS client that trusts only the DenyOut CA accepted a minted certificate (loopback, in-process)"})

	checks = append(checks, osTrustCheck(leaf))
	return checks
}

func caBroken(name, detail string) Check {
	return Check{ID: "ca_valid", Name: name, Status: Fail, Detail: detail,
		Fix: FixRegenerateCA, FixLabel: "Recreate the CA and turn Protect on"}
}

// loopbackHandshake runs one TLS handshake between a server presenting leaf
// and a client that trusts only pool. It uses an ephemeral loopback listener
// inside this process.
func loopbackHandshake(leaf tls.Certificate, pool *x509.CertPool) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("cannot open a loopback socket: %w", err)
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})
		errc <- s.Handshake()
	}()
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	cl := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: selfCheckHost, MinVersion: tls.VersionTLS12})
	if err := cl.Handshake(); err != nil {
		return fmt.Errorf("client rejected the minted certificate: %w", err)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("server side handshake failed: %w", err)
	}
	return nil
}

// osTrustCheck asks the system verifier whether it trusts a certificate minted
// by the DenyOut CA. A miss is a warning: browsers with their own store may
// still trust it, but command-line tools will not.
func osTrustCheck(leaf tls.Certificate) Check {
	c := Check{ID: "os_trust", Name: "System trust"}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		c.Status, c.Detail = Warn, "could not parse the test certificate"
		return c
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: selfCheckHost}); err != nil {
		c.Status = Warn
		c.Detail = "this computer does not trust the DenyOut CA yet; command-line tools may show certificate errors (browsers with their own store may still work)"
		c.Fix, c.FixLabel = FixRetryProtect, "Turn Protect on again to install trust"
		return c
	}
	c.Status, c.Detail = OK, "the system trust store accepts certificates minted by DenyOut"
	return c
}
