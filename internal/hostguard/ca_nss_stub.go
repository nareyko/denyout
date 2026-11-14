//go:build !linux

package hostguard

// TrustCAForUserBrowsers is a no-op outside Linux (Keychain / Windows store elsewhere).
func TrustCAForUserBrowsers(certPath string) error {
	_ = certPath
	return nil
}
