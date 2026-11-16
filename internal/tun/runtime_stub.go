//go:build !linux

package tun

import "fmt"

// StartOpts configures real denyout0 bring-up (unsupported off Linux).
type StartOpts struct {
	UID        int
	ProxyPort  int
	EnableTCP  bool
	QUICMITM   bool
	OnSighting func(QUICDecision)
}

// StartReal starts the TUN dataplane (unsupported off Linux).
func (r *Runtime) StartReal(uid int) error {
	return r.StartRealOpts(StartOpts{UID: uid})
}

// StartRealOpts is unsupported off Linux.
func (r *Runtime) StartRealOpts(opts StartOpts) error {
	_ = opts
	return fmt.Errorf("tun: real denyout0 only on Linux")
}

// StopReal tears down the TUN dataplane (no-op off Linux).
func (r *Runtime) StopReal() error { return nil }
