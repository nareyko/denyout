package hostguard

import "testing"

func TestDesktopCANickname(t *testing.T) {
	if DesktopCANickname != "DenyOut Desktop CA" {
		t.Fatalf("nickname=%q", DesktopCANickname)
	}
	if LinuxSystemCACert == "" || LinuxSystemCAHashLink == "" {
		t.Fatal("linux CA paths empty")
	}
}

func TestTeardownRemoveIdempotentNoRules(t *testing.T) {
	// Without root, Remove/uninstallCA should still be callable (best-effort).
	err := Teardown(Spec{ProxyPort: 0, UID: 1})
	_ = err // may fail without nft/root; must not panic
}

func TestUntrustCAForUserBrowsersMissingDB(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// No ~/.pki/nssdb -> no-op success (or certutil missing).
	if err := UntrustCAForUserBrowsers(); err != nil {
		t.Fatal(err)
	}
}
