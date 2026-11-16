//go:build !linux

package tun

import "fmt"

// ApplyVPNEgress is unsupported off Linux.
func ApplyVPNEgress(iface string) error {
	_ = iface
	return fmt.Errorf("tun: vpn egress apply only on Linux")
}

// RemoveVPNEgress is a no-op off Linux.
func RemoveVPNEgress() error { return nil }
