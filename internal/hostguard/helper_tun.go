package hostguard

import "github.com/nareyko/denyout/internal/tun"

// HelperTunCall sends tun-start|tun-stop|tun-stats (or returns the local disabled stub).
// Without real=true the helper keeps the closed-loop stub (safe for preflight).
func HelperTunCall(verb string, uid int) (string, error) {
	return helperTunCall(verb, uid, false, false)
}

// HelperTunCallReal asks the helper to create/steer denyout0 (G3+).
func HelperTunCallReal(verb string, uid int) (string, error) {
	return helperTunCall(verb, uid, true, false)
}

// HelperTunCallRealMITM asks for denyout0 + QUIC MITM gate (G6).
func HelperTunCallRealMITM(verb string, uid int) (string, error) {
	return helperTunCall(verb, uid, true, true)
}

// HelperVPNEgressApply asks the helper to install mark→VPN routes.
func HelperVPNEgressApply(iface string) (string, error) {
	return helperVPNEgressCall("vpn-egress-apply", iface)
}

// HelperVPNEgressRemove asks the helper to remove VPN egress routes.
func HelperVPNEgressRemove() (string, error) {
	return helperVPNEgressCall("vpn-egress-remove", "")
}

// TunLocalReply is the closed-loop disabled contract without dialing the helper.
func TunLocalReply(verb string) (string, error) {
	return tun.HelperReply(verb)
}

func tunHelperReply(verb string) (string, error) {
	return tun.HelperReply(verb)
}
