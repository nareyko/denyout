package hostguard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHelperPeerAuthorized(t *testing.T) {
	cases := []struct {
		owner, peer int
		want        bool
	}{
		{1000, 1000, true}, {1000, 0, true}, {1000, 1001, false},
		{0, 1001, false}, {0, 0, false}, {1000, -1, false}, {-5, 1000, false},
	}
	for _, c := range cases {
		if got := helperPeerAuthorized(c.owner, c.peer); got != c.want {
			t.Errorf("owner=%d peer=%d got %v want %v", c.owner, c.peer, got, c.want)
		}
	}
}

func writeCert(t *testing.T, dir string, isCA bool) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateHelperCAPath(t *testing.T) {
	dir := t.TempDir()
	owner := os.Getuid()
	if err := validateHelperCAPath(writeCert(t, dir, true), owner); err != nil {
		t.Fatalf("valid CA rejected: %v", err)
	}
	notCA := t.TempDir()
	if err := validateHelperCAPath(writeCert(t, notCA, false), owner); err == nil {
		t.Error("non-CA cert accepted")
	}
	junk := filepath.Join(dir, "shadow")
	_ = os.WriteFile(junk, []byte("root:x:0:0\n"), 0o600)
	if err := validateHelperCAPath(junk, owner); err == nil {
		t.Error("non-PEM file accepted")
	}
	link := filepath.Join(dir, "link.pem")
	_ = os.Symlink(filepath.Join(dir, "ca.pem"), link)
	if err := validateHelperCAPath(link, owner); err == nil {
		t.Error("symlink accepted")
	}
	if err := validateHelperCAPath("relative/ca.pem", owner); err == nil {
		t.Error("relative path accepted")
	}
	if err := validateHelperCAPath(dir + "/../" + filepath.Base(dir) + "/ca.pem", owner); err == nil {
		t.Error("unclean path accepted")
	}
}
