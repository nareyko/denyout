// Package platformtest holds the shared contract suites and in-memory fakes for
// the internal/platform interfaces. Every implementation (real implementations
// are exercised with injected fake OS commands) must pass these.
package platformtest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/platform"
)

// RedirectorContract checks the behaviour documented on platform.Redirector.
func RedirectorContract[S any](t *testing.T, newR func() platform.Redirector[S], spec S) {
	t.Helper()
	cases := []struct {
		name string
		run  func(t *testing.T, r platform.Redirector[S])
	}{
		{"remove without apply is ok and inactive", func(t *testing.T, r platform.Redirector[S]) {
			if err := r.Remove(spec); err != nil {
				t.Fatal(err)
			}
			if r.Status().Active {
				t.Fatal("active after Remove")
			}
		}},
		{"apply marks active, remove clears", func(t *testing.T, r platform.Redirector[S]) {
			if err := r.Apply(spec); err != nil {
				t.Fatal(err)
			}
			if !r.Status().Active {
				t.Fatal("not active after Apply")
			}
			if err := r.Remove(spec); err != nil {
				t.Fatal(err)
			}
			if r.Status().Active {
				t.Fatal("active after Remove")
			}
		}},
		{"apply twice replaces, remove twice is idempotent", func(t *testing.T, r platform.Redirector[S]) {
			for i := 0; i < 2; i++ {
				if err := r.Apply(spec); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := r.Remove(spec); err != nil {
					t.Fatal(err)
				}
			}
			if r.Status().Active {
				t.Fatal("active after Remove")
			}
		}},
		{"status names a platform", func(t *testing.T, r platform.Redirector[S]) {
			if r.Status().Platform == "" {
				t.Fatal("empty Platform")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, newR()) })
	}
}

// TrustStoreContract checks platform.TrustStore.
func TrustStoreContract(t *testing.T, newS func() platform.TrustStore) {
	t.Helper()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cert, []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("empty path rejected", func(t *testing.T) {
		s := newS()
		if err := s.Install(""); err == nil {
			t.Fatal("expected error")
		}
		if s.Installed() {
			t.Fatal("installed after failed Install")
		}
	})
	t.Run("missing file rejected", func(t *testing.T) {
		s := newS()
		if err := s.Install(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("install then remove", func(t *testing.T) {
		s := newS()
		if err := s.Install(cert); err != nil {
			t.Fatal(err)
		}
		if !s.Installed() {
			t.Fatal("not installed")
		}
		for i := 0; i < 2; i++ { // idempotent remove
			if err := s.Remove(); err != nil {
				t.Fatal(err)
			}
		}
		if s.Installed() {
			t.Fatal("still installed")
		}
	})
}

// AutostartContract checks platform.Autostart.
func AutostartContract(t *testing.T, newA func() platform.Autostart) {
	t.Helper()
	t.Run("unregister idempotent", func(t *testing.T) {
		a := newA()
		for i := 0; i < 2; i++ {
			if err := a.Unregister(); err != nil {
				t.Fatal(err)
			}
		}
		if a.Registered() {
			t.Fatal("registered")
		}
	})
	t.Run("register then unregister", func(t *testing.T) {
		a := newA()
		if err := a.Register(filepath.Join(t.TempDir(), "denyout")); err != nil {
			t.Fatal(err)
		}
		if !a.Registered() {
			t.Fatal("not registered")
		}
		if err := a.Unregister(); err != nil {
			t.Fatal(err)
		}
		if a.Registered() {
			t.Fatal("still registered")
		}
	})
}

// ErrFake is returned by fakes configured to fail.
var ErrFake = errors.New("platformtest: injected failure")
