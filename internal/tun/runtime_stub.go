//go:build !linux

package tun

import "fmt"

// StartReal starts the TUN dataplane (unsupported off Linux).
func (r *Runtime) StartReal(uid int) error {
	_ = uid
	return fmt.Errorf("tun: real denyout0 only on Linux")
}

// StopReal tears down the TUN dataplane (no-op off Linux).
func (r *Runtime) StopReal() error { return nil }
