// Package platform defines the small per-OS seams of DenyOut: traffic redirect
// (nft / pf / WinDivert), CA trust store and login autostart. Concrete
// implementations live next to the code they wrap (internal/hostguard,
// internal/desktop); this package holds only the contracts so callers and tests
// do not depend on build tags.
package platform

// Status is a coarse, unprivileged view of a Redirector.
type Status struct {
	Active   bool   // redirect applied by this process and not removed since
	Platform string // runtime.GOOS of the implementation
	Detail   string
}

// Redirector installs and removes the transparent HTTP(S) redirect.
// S is the implementation's spec type (hostguard.Spec).
//
// Contract: Remove is idempotent and succeeds without a prior Apply; Apply may
// be repeated (replaces the previous rules); Status reflects the last
// successful Apply/Remove.
type Redirector[S any] interface {
	Apply(spec S) error
	Remove(spec S) error
	Status() Status
}

// TrustStore manages the DenyOut CA in the OS trust store.
//
// Contract: Install rejects an empty path and a missing file; Remove is
// idempotent; Installed reports the state after Install/Remove.
type TrustStore interface {
	Install(certPath string) error
	Remove() error
	Installed() bool
}

// Autostart manages login launch of the desktop app.
//
// Contract: Unregister is idempotent; Registered reflects Register/Unregister.
type Autostart interface {
	Register(exe string) error
	Unregister() error
	Registered() bool
}
