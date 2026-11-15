package hostguard

import "errors"

// ErrHelperUnavailable means the privileged restore helper is not installed or not reachable.
var ErrHelperUnavailable = errors.New("denyout hostguard: helper unavailable")

// HelperAvailable reports whether the local privileged helper can be used (no OS password).
func HelperAvailable() bool {
	return helperAvailable()
}

// HelperApply asks the helper to apply redirect + CA (passwordless when helper is up).
func HelperApply(proxyPort int, caCert string, uid int) error {
	return helperCall("apply", proxyPort, caCert, uid)
}

// HelperRemove asks the helper to remove redirect rules.
func HelperRemove(proxyPort int, uid int) error {
	return helperCall("remove", proxyPort, "", uid)
}

// HelperTeardown asks the helper to remove rules + system CA.
// On Linux the helper also uninstalls its own systemd unit after a successful teardown.
func HelperTeardown(proxyPort int, uid int) error {
	return helperCall("teardown", proxyPort, "", uid)
}

// HelperUninstallHelper asks the running helper to stop/remove its systemd unit.
func HelperUninstallHelper() error {
	return helperCall("uninstall-helper", 0, "", 0)
}
