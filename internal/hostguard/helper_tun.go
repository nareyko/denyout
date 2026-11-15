package hostguard

import "github.com/nareyko/denyout/internal/tun"

// HelperTunCall sends tun-start|tun-stop|tun-stats (or returns the local disabled stub).
// Never creates a TUN from the CLI path alone; real device work stays helper+VM gated.
func HelperTunCall(verb string, uid int) (string, error) {
	return helperTunCall(verb, uid)
}

// TunLocalReply is the closed-loop disabled contract without dialing the helper.
func TunLocalReply(verb string) (string, error) {
	return tun.HelperReply(verb)
}

func tunHelperReply(verb string) (string, error) {
	return tun.HelperReply(verb)
}
