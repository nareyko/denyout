//go:build !linux

package hostguard

func helperAvailable() bool { return false }

func helperCall(verb string, proxyPort int, caCert string, uid int, allowQUIC bool) error {
	_ = verb
	_ = proxyPort
	_ = caCert
	_ = uid
	_ = allowQUIC
	return ErrHelperUnavailable
}

func helperQUICStats(uid int) (QUICDropStats, error) {
	_ = uid
	return QUICDropStats{}, ErrHelperUnavailable
}

func helperTunCall(verb string, uid int) (string, error) {
	_ = uid
	// Non-Linux: still expose the closed-loop protocol string (no device).
	return tunHelperReply(verb)
}

// InstallHelper is a no-op outside Linux (macOS/Windows helpers are a later platform track).
func InstallHelper(ownerUID int) error {
	_ = ownerUID
	return nil
}

// UninstallHelper is a no-op outside Linux.
func UninstallHelper() error { return nil }

// ServeHelper is unsupported outside Linux.
func ServeHelper() error {
	return ErrUnsupported
}
