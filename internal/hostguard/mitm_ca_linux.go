//go:build linux

package hostguard

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/tun"
)

// mitmConfigFromCA builds tun.MITMConfig from a DenyOut CA PEM path or CA directory.
func mitmConfigFromCA(caPath string) (tun.MITMConfig, error) {
	var zero tun.MITMConfig
	if caPath == "" {
		return zero, fmt.Errorf("empty ca path")
	}
	dir := caPath
	if st, err := os.Stat(caPath); err == nil && !st.IsDir() {
		dir = filepath.Dir(caPath)
	}
	ca, err := proxy.LoadOrCreatePersistentCA(dir)
	if err != nil {
		return zero, err
	}
	// Verify real origins against the system trust store (plus the DenyOut CA).
	pool, perr := x509.SystemCertPool()
	if perr != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(ca.CertFile()); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return tun.MITMConfig{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := chi.ServerName
			if host == "" {
				host = "invalid.denyout"
			}
			leaf, err := ca.Leaf(host)
			if err != nil {
				return nil, err
			}
			return &leaf, nil
		},
		RootCAs: pool,
		// Only for lab dogfood with self-signed origins; never on by default.
		InsecureSkipVerify: os.Getenv("DENYOUT_TLS_INSECURE_UPSTREAM") == "1",
	}, nil
}
