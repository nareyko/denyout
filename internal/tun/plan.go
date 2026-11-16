// Package tun holds the T1 closed-loop path for a future TUN egress.
// It classifies packets, decides DropLog, formats helper/stats lines, and
// renders nft steer tables as strings. It must not open /dev/net/tun or
// change routing; see docs/design-tun-egress.md.
package tun

import (
	"fmt"
	"strings"
)

// Phase is the rollout stage from the design spike.
type Phase string

const (
	PhaseT0NFTOnly Phase = "T0" // nft counter drop only (current production)
	PhaseT1UDP443  Phase = "T1" // TUN for UDP/443 drop+log
	PhaseT2DNS     Phase = "T2"
	PhaseT3FullUID Phase = "T3"
	PhaseT4QUICMITM Phase = "T4"
)

// DenyOutMark is the existing hostguard skip mark ('dny' = 0x646e79).
const DenyOutMark = 0x646e79

// Packet is a minimal L4 view for policy decisions (no real capture).
type Packet struct {
	Proto   string // tcp | udp
	DstPort uint16
	Mark    uint32
	UID     int
}

// Action is what userspace would do after classification.
type Action string

const (
	ActionSkip       Action = "skip"        // our own marked traffic
	ActionDropLog    Action = "drop_log"    // default QUIC policy
	ActionDirect     Action = "direct"      // allow without inspect
	ActionToProxyTCP Action = "to_proxy"    // future TCP→proxyd
	ActionUnsupported Action = "unsupported"
)

// DecideT1 implements the T1 UDP/443 policy without touching the kernel.
func DecideT1(p Packet) Action {
	if p.Mark == DenyOutMark {
		return ActionSkip
	}
	switch strings.ToLower(p.Proto) {
	case "udp":
		if p.DstPort == 443 {
			return ActionDropLog
		}
		return ActionDirect // T1 does not steer other UDP
	case "tcp":
		// T1 leaves TCP to existing nft redirect.
		return ActionUnsupported
	default:
		return ActionUnsupported
	}
}

// EnabledForPhase reports whether a real TUN device would be created.
// Always false for T0; T1+ would be gated by config/feature flag later.
func EnabledForPhase(ph Phase) bool {
	switch ph {
	case PhaseT1UDP443, PhaseT2DNS, PhaseT3FullUID, PhaseT4QUICMITM:
		return true
	default:
		return false
	}
}

// HelperLine formats a helper protocol line (closed-loop / stub path).
func HelperLine(verb string, uid int) (string, error) {
	return HelperLineOpts(verb, uid, false)
}

// HelperLineReal requests real denyout0 work from the helper (G3+).
func HelperLineReal(verb string, uid int) (string, error) {
	return HelperLineOpts(verb, uid, true)
}

// HelperLineOpts formats tun-start|stop|stats [real].
func HelperLineOpts(verb string, uid int, real bool) (string, error) {
	switch verb {
	case "tun-start", "tun-stop", "tun-stats":
		if real {
			return fmt.Sprintf("%s 0 %d - real\n", verb, uid), nil
		}
		return fmt.Sprintf("%s 0 %d -\n", verb, uid), nil
	default:
		return "", fmt.Errorf("tun: unknown verb %q", verb)
	}
}
