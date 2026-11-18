//go:build linux

package hostguard

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nareyko/denyout/internal/protectstate"
	"github.com/nareyko/denyout/internal/tun"
)

// helperEffects are the privileged side effects of helper verbs. Production
// values are the real implementations; tests replace them so verb dispatch
// and reply shaping can be checked without touching the host.
type helperEffects struct {
	stopTun       func() error
	removeVPN     func() error
	applyVPN      func(iface string) error
	apply         func(Spec) error
	remove        func(Spec) error
	teardown      func(Spec) error
	uninstall     func() error
	clearApplied  func()
	persist       func(Spec)
	setFailPolicy func(protectstate.FailPolicy)
	quicStats     func() (QUICDropStats, error)
	startTun      func(tun.StartOpts) error
	tunSnapshot   func() (st tun.DropStats, active bool)
	suppressT0    func(bool)
	mitmConfig    func(caPath string) (tun.MITMConfig, error)
}

var fx = helperEffects{
	stopTun:       func() error { return tun.GlobalRuntime().StopReal() },
	removeVPN:     tun.RemoveVPNEgress,
	applyVPN:      tun.ApplyVPNEgress,
	apply:         Apply,
	remove:        Remove,
	teardown:      Teardown,
	uninstall:     UninstallHelper,
	clearApplied:  clearApplied,
	persist:       persistHelperState,
	setFailPolicy: SetFailPolicy,
	quicStats:     ReadQUICDropStats,
	startTun:      func(o tun.StartOpts) error { return tun.GlobalRuntime().StartRealOpts(o) },
	tunSnapshot: func() (tun.DropStats, bool) {
		rt := tun.GlobalRuntime()
		return rt.StatsSnapshot(), rt.IsActive()
	},
	suppressT0: suppressT0ForTUN,
	mitmConfig: mitmConfigFromCA,
}

// helperHandler executes one verb. The returned string is the full reply.
type helperHandler func(req Request, spec Spec) (string, error)

// replyQuic1 is the cap tag reply; it lets clients detect a pre-QUIC helper
// (plain "OK") and re-elevate once.
const replyQuic1 = "OK quic1"

// helperHandlers maps exactly the verbs of the closed table in helper_proto.go
// (see TestHelperHandlersMatchVerbTable). A verb without a handler is refused.
var helperHandlers = map[string]helperHandler{
	"caps":              handleCaps,
	"version":           handleCaps,
	"apply":             handleApply,
	"fail-policy":       handleFailPolicy,
	"fail-status":       func(Request, Spec) (string, error) { return failStatusReply(), nil },
	"audit-tail":        handleAuditTail,
	"remove":            handleRemove,
	"teardown":          handleTeardown,
	"uninstall-helper":  handleUninstall,
	"quic-stats":        handleQUICStats,
	"tun-start":         handleTun,
	"tun-stop":          handleTun,
	"tun-stats":         handleTun,
	"vpn-egress-apply":  handleVPNApply,
	"vpn-egress-remove": handleVPNRemove,
}

// executeHelperRequest runs one validated request. The caller holds helperOpMu.
func executeHelperRequest(req Request) (string, error) {
	h, ok := helperHandlers[req.Verb]
	if !ok {
		return "", fmt.Errorf("unknown verb")
	}
	spec := Spec{ProxyPort: req.Port, UID: req.UID, CACert: req.CA, AllowQUIC: req.AllowQUIC}
	return h(req, spec)
}

func handleCaps(Request, Spec) (string, error) {
	exe := ""
	if p, e := SelfExe(); e == nil {
		exe = filepath.Base(p)
	}
	return FormatCapsReply(exe, CapQUIC, CapTUN, CapVPN, CapFailPolicy, CapAudit), nil
}

func handleAuditTail(req Request, _ Spec) (string, error) {
	return FormatAuditTailReply(currentAuditLog().Tail(req.Count))
}

func handleApply(req Request, spec Spec) (string, error) {
	_ = fx.stopTun()
	if err := fx.apply(spec); err != nil {
		return "", err
	}
	lastApplyMu.Lock()
	lastApplySpec = spec
	lastApplyOK = true
	lastApplyMu.Unlock()
	if req.FailPolicy != "" {
		fx.setFailPolicy(req.FailPolicy)
	}
	fx.persist(spec)
	return replyQuic1, nil
}

func handleFailPolicy(req Request, _ Spec) (string, error) {
	fx.setFailPolicy(req.FailPolicy)
	lastApplyMu.Lock()
	spec, on := lastApplySpec, lastApplyOK
	lastApplyMu.Unlock()
	if on {
		fx.persist(spec) // survives a helper restart while Protect is on
	}
	return failStatusReply(), nil
}

// dropAppliedState is the common prefix of the verbs that end Protect: the
// watchdog must not re-apply rules later and the TUN/VPN data plane goes too.
func dropAppliedState() {
	fx.clearApplied()
	_ = fx.stopTun()
	_ = fx.removeVPN()
}

func handleRemove(_ Request, spec Spec) (string, error) {
	dropAppliedState() // Protect Off
	if err := fx.remove(spec); err != nil {
		return "", err
	}
	return replyQuic1, nil
}

func handleTeardown(_ Request, spec Spec) (string, error) {
	dropAppliedState()
	if err := fx.teardown(spec); err != nil {
		return "", err
	}
	return replyQuic1, nil
}

func handleUninstall(Request, Spec) (string, error) {
	dropAppliedState()
	if err := fx.uninstall(); err != nil {
		return "", err
	}
	return replyQuic1, nil
}

func handleQUICStats(Request, Spec) (string, error) {
	st, err := fx.quicStats()
	if err != nil {
		return "", err
	}
	st.Source = "nft"
	return "OK quic1 " + FormatQUICDropStatsLine(st), nil
}

func handleVPNApply(req Request, _ Spec) (string, error) {
	if err := fx.applyVPN(req.Iface); err != nil {
		return "", err
	}
	return "OK " + CapVPN + " applied iface=" + req.Iface, nil
}

func handleVPNRemove(Request, Spec) (string, error) {
	_ = fx.removeVPN()
	return "OK " + CapVPN + " removed", nil
}

func handleTun(req Request, _ Spec) (string, error) {
	return helperTunVerb(req.Verb, req.UID, req.Real, req.Mitm)
}

// tunStatsReason is the reason= field of a tun-stats reply.
func tunStatsReason(real, active, wantDevice, present bool) string {
	if !(real || active || wantDevice) {
		return "flag_off"
	}
	if present {
		return "ok"
	}
	if wantDevice || real {
		return "inactive"
	}
	return "flag_off"
}

// tunStartOpts builds the StartOpts for tun-start; ok=false when the caller
// must answer with the disabled stub instead.
func tunStartOpts(uid int, real, mitm bool) (tun.StartOpts, bool) {
	if !real && !tun.WantDevice() {
		return tun.StartOpts{}, false
	}
	wantMITM := mitm || tun.WantQUICMITM()
	return tun.StartOpts{
		UID:       uid,
		EnableTCP: true,
		QUICMITM:  wantMITM,
		OnSighting: func(dec tun.QUICDecision) {
			fmt.Fprintf(os.Stderr, "denyout tun quic sight action=%s sni=%q reason=%s\n", dec.Action, dec.SNI, dec.Reason)
		},
	}, true
}

func tunStartReply(verb string, mitm bool) string {
	return fmt.Sprintf("OK %s enabled=true verb=%s reason=ok tcp=1 mitm=%v", tun.CapTag, verb, mitm)
}

func tunStopReply(verb string) string {
	return fmt.Sprintf("OK %s enabled=false verb=%s reason=ok", tun.CapTag, verb)
}

func helperTunStats(real bool) string {
	st, active := fx.tunSnapshot()
	reason := tunStatsReason(real, active, tun.WantDevice(), st.Present)
	return "OK " + tun.CapTag + " " + tun.FormatDropStatsLine(st) + " reason=" + reason
}

func helperTunStart(verb string, uid int, real, mitm bool) (string, error) {
	opts, ok := tunStartOpts(uid, real, mitm)
	if !ok {
		return tun.HelperReply(verb)
	}
	lastApplyMu.Lock()
	opts.ProxyPort = lastApplySpec.ProxyPort
	caPath := lastApplySpec.CACert
	lastApplyMu.Unlock()
	if opts.QUICMITM {
		if cfg, err := fx.mitmConfig(caPath); err == nil {
			opts.MITM = cfg
		} else {
			fmt.Fprintf(os.Stderr, "denyout tun quic mitm ca: %v (sight/drop only)\n", err)
		}
	}
	if err := fx.startTun(opts); err != nil {
		return "", err
	}
	// Suppress T0 UDP drop + TCP redirect while TUN/gVisor owns those paths.
	fx.suppressT0(true)
	return tunStartReply(verb, opts.QUICMITM), nil
}

func helperTunStop(verb string, real bool) (string, error) {
	_ = fx.stopTun()
	fx.suppressT0(false)
	if !real && !tun.WantDevice() {
		return tun.HelperReply(verb)
	}
	return tunStopReply(verb), nil
}

// helperTunVerb runs inside helper-serve.
func helperTunVerb(verb string, uid int, real, mitm bool) (string, error) {
	switch verb {
	case "tun-stats":
		return helperTunStats(real), nil
	case "tun-start":
		return helperTunStart(verb, uid, real, mitm)
	case "tun-stop":
		return helperTunStop(verb, real)
	default:
		return "", fmt.Errorf("tun: unknown helper verb %q", verb)
	}
}
