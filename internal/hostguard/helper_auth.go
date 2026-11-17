package hostguard

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxHelperCABytes caps how much of a client-supplied CA file the root helper reads.
const maxHelperCABytes = 64 << 10

// helperPeerAuthorized is deny-by-default: the helper needs a configured owner
// (>0) and a peer credential that is that owner or root. Unknown peers (-1)
// and a missing owner are refused.
func helperPeerAuthorized(ownerUID, peerUID int) bool {
	if ownerUID <= 0 || peerUID < 0 {
		return false
	}
	return peerUID == ownerUID || peerUID == 0
}

// validateHelperCAPath makes sure the root helper only ever reads a plain,
// owner-controlled CA certificate and never an arbitrary file (shadow, keys…).
func validateHelperCAPath(path string, ownerUID int) error {
	if path == "" || path == "-" {
		return nil // no CA requested
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("ca path must be absolute and clean")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("ca path must be a regular file")
	}
	if !fileOwnedByOrRoot(fi, ownerUID) {
		return fmt.Errorf("ca file must be owned by the helper owner or root")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxHelperCABytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxHelperCABytes {
		return fmt.Errorf("ca file too large")
	}
	return validateCAPEM(data)
}

func validateCAPEM(data []byte) error {
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("ca file is not a PEM certificate")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("ca file: %w", err)
	}
	if !crt.IsCA {
		return fmt.Errorf("ca file is not a CA certificate")
	}
	return nil
}
