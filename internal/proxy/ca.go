package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// SessionCA is an ephemeral MITM CA for one denyout run.
type SessionCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tlsCert tls.Certificate
	dir     string
	mu      sync.Mutex
	leaves  map[string]tls.Certificate
}

// NewSessionCA creates a CA and writes PEM files under dir (0600).
func NewSessionCA(dir string) (*SessionCA, error) {
	return createCA(dir, "DenyOut Session CA", 24*time.Hour)
}

// LoadOrCreatePersistentCA loads an existing desktop CA from dir or creates one
// with long validity (kept across Protect On/Off; removed only on uninstall).
func LoadOrCreatePersistentCA(dir string) (*SessionCA, error) {
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, err
			}
			tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, err
			}
			cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err != nil {
				return nil, err
			}
			key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("persistent CA key must be ECDSA")
			}
			return &SessionCA{
				cert:    cert,
				key:     key,
				tlsCert: tlsCert,
				dir:     dir,
				leaves:  map[string]tls.Certificate{},
			}, nil
		}
	}
	return createCA(dir, "DenyOut Desktop CA", 825*24*time.Hour)
}

func createCA(dir, cn string, validFor time.Duration) (*SessionCA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"DenyOut"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &SessionCA{
		cert:    cert,
		key:     key,
		tlsCert: tlsCert,
		dir:     dir,
		leaves:  map[string]tls.Certificate{},
	}, nil
}

// CertFile returns the CA certificate PEM path for child trust env.
func (c *SessionCA) CertFile() string {
	return c.dir + "/ca.crt"
}

// Fingerprint returns SHA-ish short id from serial.
func (c *SessionCA) Fingerprint() string {
	return fmt.Sprintf("%x", c.cert.SerialNumber)
}

// Leaf returns a host certificate signed by the session CA.
func (c *SessionCA) Leaf(host string) (tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// Shred removes CA material from disk (best-effort).
func (c *SessionCA) Shred() {
	_ = os.Remove(c.dir + "/ca.crt")
	_ = os.Remove(c.dir + "/ca.key")
	_ = os.Remove(c.dir)
}
