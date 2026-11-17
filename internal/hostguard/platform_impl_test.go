package hostguard

import (
	"errors"
	"os"
	"testing"

	"github.com/nareyko/denyout/internal/platform"
	"github.com/nareyko/denyout/internal/platform/platformtest"
)

// The OS wrappers are exercised with injected fake OS commands: no nft/pf/
// certutil is ever run.
func TestOSRedirectorContract(t *testing.T) {
	platformtest.RedirectorContract(t, func() platform.Redirector[Spec] {
		return newOSRedirector(func(Spec) error { return nil }, func(Spec) error { return nil })
	}, Spec{ProxyPort: 18080, UID: 1000})
}

func TestOSTrustStoreContract(t *testing.T) {
	platformtest.TrustStoreContract(t, func() platform.TrustStore {
		f := &platformtest.FakeTrustStore{}
		installed := false
		return newOSTrustStore(
			func(p string) error {
				if err := f.Install(p); err != nil {
					return err
				}
				installed = true
				return nil
			},
			func() error { installed = false; return f.Remove() },
			func() bool { return installed },
		)
	})
}

func TestOSRedirectorApplyFailureKeepsInactive(t *testing.T) {
	r := newOSRedirector(func(Spec) error { return platformtest.ErrFake }, func(Spec) error { return nil })
	if err := r.Apply(Spec{}); !errors.Is(err, platformtest.ErrFake) {
		t.Fatalf("err=%v", err)
	}
	if r.Status().Active {
		t.Fatal("active after failed apply")
	}
}

func withFakes(t *testing.T) (*platformtest.FakeRedirector[Spec], *platformtest.FakeTrustStore) {
	t.Helper()
	oldR, oldT := redirector, trustStore
	fr, ft := &platformtest.FakeRedirector[Spec]{}, &platformtest.FakeTrustStore{}
	redirector, trustStore = fr, ft
	t.Cleanup(func() { redirector, trustStore = oldR, oldT })
	return fr, ft
}

func TestApplyGoesThroughInterfaces(t *testing.T) {
	fr, ft := withFakes(t)
	cert := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(Spec{ProxyPort: 18080, UID: 1, CACert: cert}); err != nil {
		t.Fatal(err)
	}
	if !ft.Installed() || !fr.Status().Active {
		t.Fatal("expected CA installed and redirect active")
	}
	if err := Remove(Spec{UID: 1}); err != nil {
		t.Fatal(err)
	}
	if fr.Status().Active || !ft.Installed() {
		t.Fatal("Remove must drop redirect only; CA stays")
	}
	if err := Teardown(Spec{UID: 1}); err != nil {
		t.Fatal(err)
	}
	if ft.Installed() {
		t.Fatal("Teardown must remove CA")
	}
}

func TestApplyCAFailureSkipsRedirect(t *testing.T) {
	fr, ft := withFakes(t)
	ft.Fail = platformtest.ErrFake
	if err := Apply(Spec{ProxyPort: 18080, UID: 1, CACert: "x"}); !errors.Is(err, platformtest.ErrFake) {
		t.Fatalf("err=%v", err)
	}
	if len(fr.Calls) != 0 {
		t.Fatalf("redirect must not run after CA failure: %v", fr.Calls)
	}
}

func TestApplyDryRunTouchesNothing(t *testing.T) {
	fr, ft := withFakes(t)
	_ = Apply(Spec{ProxyPort: 18080, UID: 1, DryRun: true})
	if len(fr.Calls)+len(ft.Calls) != 0 {
		t.Fatal("dry run must not call the OS")
	}
}

func TestTeardownStillRemovesCAWhenRedirectRemoveFails(t *testing.T) {
	oldR, oldT := redirector, trustStore
	t.Cleanup(func() { redirector, trustStore = oldR, oldT })
	ft := &platformtest.FakeTrustStore{}
	redirector = newOSRedirector(nil, func(Spec) error { return platformtest.ErrFake })
	trustStore = ft
	if err := Teardown(Spec{UID: 1}); !errors.Is(err, platformtest.ErrFake) {
		t.Fatalf("err=%v", err)
	}
	if len(ft.Calls) != 1 || ft.Calls[0] != "remove" {
		t.Fatalf("CA remove not attempted: %v", ft.Calls)
	}
}
