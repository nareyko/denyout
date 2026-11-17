package hostguard

import (
	"runtime"
	"sync"

	"github.com/nareyko/denyout/internal/platform"
)

// The per-OS functions applyRedirect/removeRedirect (apply_*.go) and
// installCA/uninstallCA/caInstalled (ca_*.go) are wrapped here behind the
// internal/platform interfaces. Callers (Apply/Remove/Teardown) only use the
// package-level redirector and trustStore, which tests may swap for fakes.

var (
	redirector platform.Redirector[Spec] = newOSRedirector(applyRedirect, removeRedirect)
	trustStore platform.TrustStore       = newOSTrustStore(installCA, uninstallCA, caInstalled)
)

type osRedirector struct {
	apply, remove func(Spec) error
	mu            sync.Mutex
	active        bool
}

func newOSRedirector(apply, remove func(Spec) error) *osRedirector {
	return &osRedirector{apply: apply, remove: remove}
}

func (r *osRedirector) Apply(spec Spec) error {
	if err := r.apply(spec); err != nil {
		return err
	}
	r.mu.Lock()
	r.active = true
	r.mu.Unlock()
	return nil
}

func (r *osRedirector) Remove(spec Spec) error {
	err := r.remove(spec)
	if err == nil {
		r.mu.Lock()
		r.active = false
		r.mu.Unlock()
	}
	return err
}

func (r *osRedirector) Status() platform.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return platform.Status{Active: r.active, Platform: runtime.GOOS, Detail: "tracked in-process; the helper owns authoritative state"}
}

type osTrustStore struct {
	install   func(string) error
	uninstall func() error
	installed func() bool
}

func newOSTrustStore(install func(string) error, uninstall func() error, installed func() bool) *osTrustStore {
	return &osTrustStore{install: install, uninstall: uninstall, installed: installed}
}

func (s *osTrustStore) Install(certPath string) error { return s.install(certPath) }
func (s *osTrustStore) Remove() error                 { return s.uninstall() }
func (s *osTrustStore) Installed() bool               { return s.installed() }
