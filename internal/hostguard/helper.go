package hostguard

import "errors"

// ErrHelperUnavailable means the privileged restore helper is not installed or not reachable.
var ErrHelperUnavailable = errors.New("denyout hostguard: helper unavailable")

// HelperAvailable reports whether the local privileged helper can be used (no OS password).
func HelperAvailable() bool {
	return helperAvailable()
}

// HelperApply asks the helper to apply redirect + CA (passwordless when helper is up).
// allowQUIC=false drops UDP/443 (default Protect path so browsers use TCP MITM).
func HelperApply(proxyPort int, caCert string, uid int, allowQUIC bool) error {
	return helperCall("apply", proxyPort, caCert, uid, allowQUIC)
}

// HelperRemove asks the helper to remove redirect rules.
func HelperRemove(proxyPort int, uid int) error {
	return helperCall("remove", proxyPort, "", uid, false)
}

// HelperTeardown asks the helper to remove rules + system CA.
// On Linux the helper also uninstalls its own systemd unit after a successful teardown.
func HelperTeardown(proxyPort int, uid int) error {
	return helperCall("teardown", proxyPort, "", uid, false)
}

// HelperUninstallHelper asks the running helper to stop/remove its systemd unit.
func HelperUninstallHelper() error {
	return helperCall("uninstall-helper", 0, "", 0, false)
}

// HelperQUICStats asks the helper to read nft QUIC-drop counters (Linux).
func HelperQUICStats(uid int) (QUICDropStats, error) {
	return helperQUICStats(uid)
}

// HelperCaps asks the helper for capability tags (caps1/quic1/tun1/…).
func HelperCaps() (CapsReply, error) {
	return helperCaps()
}
