//go:build linux && e2e

package hostguard_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

// Run with: DENYOUT_E2E=1 go test -tags=e2e ./internal/hostguard -run TestLinuxProtectE2E -v -timeout 5m
// Approve the pkexec dialog when prompted.
func TestLinuxProtectE2E(t *testing.T) {
	if os.Getenv("DENYOUT_E2E") != "1" {
		t.Skip("set DENYOUT_E2E=1")
	}
	cfg, err := policy.DefaultWholeDevice()
	if err != nil {
		t.Fatal(err)
	}
	caDir := t.TempDir()
	sess, err := run.StartSession(run.SessionOptions{
		Config:      cfg,
		TLSMode:     proxy.TLSIntercept,
		PersistCA:   true,
		CADir:       caDir,
		Transparent: true,
		Version:     "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	uid, err := hostguard.CurrentUID()
	if err != nil {
		t.Fatal(err)
	}
	port := sess.Port()
	ca := sess.CACertFile()
	if _, err := os.Stat(ca); err != nil {
		t.Fatal(err)
	}
	t.Logf("elevating hostctl apply port=%d ca=%s uid=%d — approve pkexec", port, ca, uid)
	if err := hostguard.ElevateApply(port, ca, uid); err != nil {
		t.Fatalf("elevate apply: %v", err)
	}
	defer func() {
		_ = hostguard.ElevateRemove(port, uid)
	}()

	// Give nft a moment.
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	t.Log("hostguard apply OK")
}
