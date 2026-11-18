package main

import (
	"fmt"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/protectstate"
	"github.com/nareyko/denyout/internal/tun"
)

const hostctlUsage = `Usage: denyout-cli hostctl apply|remove|teardown|render|proxyd|quic-stats|tun-stats|tun-start|tun-stop|tun-rollback-plan|tun-device-plan|tun-device-rollback-plan|vpn-egress-plan|vpn-egress-rollback-plan|vpn-egress-apply|vpn-egress-remove|fail-policy|helper-serve|helper-install|helper-uninstall|caps [flags]

  Privileged helper for Protect this computer (transparent redirect + CA trust).
  proxyd runs the transparent proxy (started after setcap so SO_MARK works).
  teardown removes redirect rules and the system CA (used by denyout-cli uninstall).
  quic-stats prints nft UDP/443 drop counters (Linux; helper or root).
  tun-stats|tun-start|tun-stop  T1 helper protocol (stub unless --real / DENYOUT_TUN_E2E / TunDataplane).
  tun-rollback-plan  print T1→T0 restore steps (docs only; not executed).
  tun-device-plan  print ip tuntap create commands for denyout0 (not executed; see docs/tun-implementation-plan.md).
  tun-device-rollback-plan  print delete denyout0 + T0 restore hint (not executed).
  vpn-egress-plan --iface IF  print DenyOut mark→VPN ip rule/route plan (not executed; see docs/design-vpn-egress.md).
  vpn-egress-rollback-plan  print remove commands for that plan (not executed).
  vpn-egress-apply --iface IF  apply mark→VPN routes (requires DENYOUT_VPN_EGRESS_E2E=1 + admin/helper).
  vpn-egress-remove  remove VPN egress routes (admin/helper).
  caps  print helper capability tags (quic1 tun1 vpn1 fail1).
  fail-policy open|closed|status  set or show what the helper does when the proxy stops
    (open = keep the internet working, closed = block web traffic until it recovers).
  helper-serve runs the root unix-socket helper (systemd; Linux).
  helper-install installs/restarts denyout-hostguard.service from this binary (Linux; root).
  helper-uninstall stops/removes denyout-hostguard.service (Linux; used by uninstall).

Flags:
  --port N     local DenyOut proxy port
  --ca PATH    CA certificate PEM to trust
  --ca-dir D   persistent CA directory (proxyd)
  --uid N      desktop user uid (Unix)
  --iface IF   VPN egress interface (vpn-egress-plan/apply; e.g. wg0)
  --real       with tun-start|stop: request real denyout0 (helper; Linux)
  --fail-policy P  with apply: open|closed proxy-loss policy sent to the helper
  --allow-quic allow UDP/443 (HTTP/3); default is drop QUIC so browsers use TCP MITM
  --tun        with render: append T1 steer table preview (not applied)
  --ask        Ask mode policy (proxyd)
  --allow-base URL  wizard base for Ask allow page (proxyd)
  --no-elevate already running elevated (internal)`

// hostctlOps are the privileged / host-touching operations behind
// `denyout-cli hostctl`. Handlers only reach the host through this table so
// tests can drive every action with fakes and never touch the real helper.
type hostctlOps struct {
	currentUID       func() (int, error)
	quicStatsLine    func(uid int) string
	tunCall          func(verb string, uid int) (string, error)
	tunCallReal      func(verb string, uid int) (string, error)
	tunCallRealMITM  func(verb string, uid int) (string, error)
	caps             func() (string, error)
	vpnApplyHelper   func(iface string) (string, error)
	vpnApplyLocal    func(iface string) error
	vpnRemoveHelper  func() (string, error)
	vpnRemoveLocal   func() error
	failPolicyStatus func() (hostguard.FailPolicyStatus, error)
	failPolicySet    func(p protectstate.FailPolicy) (hostguard.FailPolicyStatus, error)
	failPolicyLocal  func(p protectstate.FailPolicy)
	elevateInstall   func(uid int) error
	installHelper    func(uid int) error
	serveHelper      func() error
	elevateUninstall func() error
	uninstallHelper  func() error
	elevateApply     func(port int, ca string, uid int, allowQUIC bool) error
	apply            func(spec hostguard.Spec) error
	elevateRemove    func(port, uid int) error
	remove           func(spec hostguard.Spec) error
	elevateTeardown  func(port, uid int) error
	teardown         func(spec hostguard.Spec) error
	render           func(spec hostguard.Spec) (string, error)
	renderWithTUN    func(spec hostguard.Spec) (string, error)
}

func realHostctlOps() hostctlOps {
	return hostctlOps{
		currentUID: hostguard.CurrentUID,
		quicStatsLine: func(uid int) string {
			return hostguard.FormatQUICDropStatsLine(hostguard.QUICDropStatsBestEffort(uid))
		},
		tunCall:         hostguard.HelperTunCall,
		tunCallReal:     hostguard.HelperTunCallReal,
		tunCallRealMITM: hostguard.HelperTunCallRealMITM,
		caps: func() (string, error) {
			c, err := hostguard.HelperCaps()
			if err != nil {
				return "", err
			}
			return c.Raw, nil
		},
		vpnApplyHelper:   hostguard.HelperVPNEgressApply,
		vpnApplyLocal:    tun.ApplyVPNEgress,
		vpnRemoveHelper:  hostguard.HelperVPNEgressRemove,
		vpnRemoveLocal:   tun.RemoveVPNEgress,
		failPolicyStatus: hostguard.HelperFailPolicyStatus,
		failPolicySet:    hostguard.HelperSetFailPolicy,
		failPolicyLocal:  hostguard.SetFailPolicy,
		elevateInstall:   hostguard.ElevateInstallHelper,
		installHelper:    hostguard.InstallHelper,
		serveHelper:      hostguard.ServeHelper,
		elevateUninstall: hostguard.ElevateUninstallHelper,
		uninstallHelper:  hostguard.UninstallHelper,
		elevateApply:     hostguard.ElevateApply,
		apply:            hostguard.Apply,
		elevateRemove:    hostguard.ElevateRemove,
		remove:           hostguard.Remove,
		elevateTeardown:  hostguard.ElevateTeardown,
		teardown:         hostguard.Teardown,
		render:           hostguard.Render,
		renderWithTUN:    hostguard.RenderWithTUNPreview,
	}
}

// hostOps is the live implementation; tests replace it.
var hostOps = realHostctlOps()

// hostctlHandler runs one hostctl action; rest is the args after the action.
type hostctlHandler func(action string, rest []string) int

// hostctlActions is the dispatch table for actions with their own flag
// handling. Anything else falls through to the spec actions (render, apply,
// remove, teardown) which share one flag set.
var hostctlActions = map[string]hostctlHandler{
	"proxyd":                   func(_ string, rest []string) int { return cmdHostctlProxyd(rest) },
	"quic-stats":               hostctlQUICStats,
	"tun-stats":                hostctlTun,
	"tun-start":                hostctlTun,
	"tun-stop":                 hostctlTun,
	"caps":                     hostctlCaps,
	"tun-rollback-plan":        hostctlPrint(tunRollbackPlan),
	"tun-device-plan":          hostctlPrint(tun.FormatDevicePlan),
	"tun-device-rollback-plan": hostctlPrint(tun.FormatDeviceRollback),
	"vpn-egress-plan":          hostctlVPNPlan,
	"vpn-egress-rollback-plan": hostctlPrint(tun.FormatVPNEgressRollback),
	"vpn-egress-apply":         hostctlVPNApply,
	"vpn-egress-remove":        hostctlVPNRemove,
	"fail-policy":              hostctlFailPolicy,
	"helper-install":           hostctlHelperInstall,
	"helper-serve":             hostctlHelperServe,
	"helper-uninstall":         hostctlHelperUninstall,
}

// hostctlSpecActions are the actions that take the full spec flag set.
var hostctlSpecActions = map[string]func(o hostctlSpecOpts) int{
	"render":   hostctlRender,
	"apply":    hostctlApply,
	"remove":   hostctlRemove,
	"teardown": hostctlTeardown,
}

func cmdHostctl(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(hostctlUsage)
		return 0
	}
	if h, ok := hostctlActions[args[0]]; ok {
		return h(args[0], args[1:])
	}
	return hostctlSpecAction(args[0], args[1:])
}

// hostctlFail prints "denyout-cli hostctl <action>: err" and returns exit 2.
func hostctlFail(action string, err error) int {
	return failExit("denyout-cli hostctl %s: %v", action, err).emit()
}

// hostctlErr is hostctlFail without an action (spec actions).
func hostctlErr(err error) int {
	return failExit("denyout-cli hostctl: %v", err).emit()
}

func hostctlPrint(f func() string) hostctlHandler {
	return func(string, []string) int {
		fmt.Print(f())
		return 0
	}
}

// uidFlag is the shared lenient --uid flag.
func uidFlag(dst *int) flagSpec {
	return flagSpec{names: []string{"--uid"}, eq: true, set: setInt(dst)}
}

func ifaceFlag(dst *string) flagSpec {
	return flagSpec{names: []string{"--iface"}, eq: true, set: setStr(dst)}
}

// lenientParse runs a flag set that silently ignores anything it does not know.
func lenientParse(cmd string, rest []string, values []flagSpec, bools map[string]func()) {
	fs := flagSet{cmd: cmd, values: values, bools: bools}
	fs.parse(rest)
}

func hostctlQUICStats(_ string, rest []string) int {
	uid, _ := hostOps.currentUID()
	lenientParse("hostctl", rest, []flagSpec{uidFlag(&uid)}, nil)
	fmt.Printf("%s\n", hostOps.quicStatsLine(uid))
	return 0
}

// tunVerbCall picks the helper call variant for tun-stats/start/stop.
func tunVerbCall(real, mitm bool) func(verb string, uid int) (string, error) {
	switch {
	case real && mitm:
		return hostOps.tunCallRealMITM
	case real:
		return hostOps.tunCallReal
	default:
		return hostOps.tunCall
	}
}

func hostctlTun(action string, rest []string) int {
	uid, _ := hostOps.currentUID()
	real, mitm := false, false
	lenientParse("hostctl", rest, []flagSpec{uidFlag(&uid)}, map[string]func(){
		"--real": func() { real = true },
		"--mitm": func() { mitm = true },
	})
	line, err := tunVerbCall(real, mitm)(action, uid)
	if err != nil {
		return hostctlFail(action, err)
	}
	fmt.Println(line)
	return 0
}

func hostctlCaps(_ string, _ []string) int {
	c, err := hostOps.caps()
	if err != nil {
		return hostctlFail("caps", err)
	}
	fmt.Println(c)
	return 0
}

func hostctlVPNPlan(_ string, rest []string) int {
	iface := ""
	lenientParse("hostctl", rest, []flagSpec{ifaceFlag(&iface)}, nil)
	out, err := tun.FormatVPNEgressPlan(iface)
	if err != nil {
		return hostctlFail("vpn-egress-plan", err)
	}
	fmt.Print(out)
	return 0
}

func hostctlVPNApply(_ string, rest []string) int {
	if !tun.WantVPNEgressApply() {
		return failExit("denyout-cli hostctl vpn-egress-apply: set %s=1 (VM only)", tun.EnvVPNEgressE2E).emit()
	}
	iface := ""
	lenientParse("hostctl", rest, []flagSpec{ifaceFlag(&iface)}, nil)
	line, err := hostOps.vpnApplyHelper(iface)
	if err != nil {
		// Fallback: elevated/local apply when helper missing.
		if applyErr := hostOps.vpnApplyLocal(iface); applyErr != nil {
			return failExit("denyout-cli hostctl vpn-egress-apply: %v (helper: %v)", applyErr, err).emit()
		}
		fmt.Printf("OK vpn1 applied iface=%s source=local\n", iface)
		return 0
	}
	fmt.Println(line)
	return 0
}

func hostctlVPNRemove(string, []string) int {
	if line, err := hostOps.vpnRemoveHelper(); err == nil {
		fmt.Println(line)
		return 0
	}
	_ = hostOps.vpnRemoveLocal()
	fmt.Println("OK vpn1 removed source=local")
	return 0
}

// failPolicyCall chooses status vs set from the fail-policy operands; ok is
// false for anything that is not exactly "status" or "open"/"closed".
func failPolicyCall(rest []string) (st func() (hostguard.FailPolicyStatus, error), ok bool) {
	if len(rest) != 1 {
		return nil, false
	}
	switch rest[0] {
	case "status":
		return hostOps.failPolicyStatus, true
	case "open", "closed":
		p := protectstate.FailPolicy(rest[0])
		return func() (hostguard.FailPolicyStatus, error) { return hostOps.failPolicySet(p) }, true
	}
	return nil, false
}

func hostctlFailPolicy(_ string, rest []string) int {
	call, ok := failPolicyCall(rest)
	if !ok {
		return failExit("Usage: denyout-cli hostctl fail-policy open|closed|status").emit()
	}
	st, err := call()
	if err != nil {
		return hostctlFail("fail-policy", err)
	}
	fmt.Println(hostguard.FormatFailPolicyReply(st.Policy, st.Source, st.Configured))
	return 0
}

func hostctlHelperInstall(_ string, rest []string) int {
	uid, _ := hostOps.currentUID()
	noElevate := false
	lenientParse("hostctl", rest, []flagSpec{uidFlag(&uid)}, map[string]func(){"--no-elevate": func() { noElevate = true }})
	install := hostOps.elevateInstall
	if noElevate {
		install = hostOps.installHelper
	}
	if err := install(uid); err != nil {
		return hostctlFail("helper-install", err)
	}
	return 0
}

func hostctlHelperServe(string, []string) int {
	if err := hostOps.serveHelper(); err != nil {
		return hostctlFail("helper-serve", err)
	}
	return 0
}

func hostctlHelperUninstall(_ string, rest []string) int {
	noElevate := false
	lenientParse("hostctl", rest, nil, map[string]func(){"--no-elevate": func() { noElevate = true }})
	uninstall := hostOps.elevateUninstall
	if noElevate {
		uninstall = hostOps.uninstallHelper
	}
	if err := uninstall(); err != nil {
		return hostctlFail("helper-uninstall", err)
	}
	return 0
}

// hostctlSpecOpts are the flags shared by render/apply/remove/teardown.
type hostctlSpecOpts struct {
	port       int
	ca         string
	uid        int
	noElevate  bool
	allowQUIC  bool
	failPolicy string
	tunPreview bool
}

func (o hostctlSpecOpts) spec() hostguard.Spec {
	return hostguard.Spec{ProxyPort: o.port, UID: o.uid, CACert: o.ca, AllowQUIC: o.allowQUIC}
}

// parseHostctlSpecArgs parses the spec flag set; unknown flags are an error.
func parseHostctlSpecArgs(rest []string) (hostctlSpecOpts, *cliExit) {
	var o hostctlSpecOpts
	fs := flagSet{
		cmd: "hostctl",
		values: []flagSpec{
			{names: []string{"--fail-policy"}, eq: true, set: setStr(&o.failPolicy)},
			{names: []string{"--port"}, eq: true, set: setInt(&o.port)},
			{names: []string{"--ca"}, eq: true, set: setStr(&o.ca)},
			uidFlag(&o.uid),
		},
		bools: map[string]func(){
			"--no-elevate": func() { o.noElevate = true },
			"--allow-quic": func() { o.allowQUIC = true },
			"--tun":        func() { o.tunPreview = true },
		},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(rest); ex != nil {
		return o, ex
	}
	return o, nil
}

func hostctlSpecAction(action string, rest []string) int {
	o, ex := parseHostctlSpecArgs(rest)
	if ex != nil {
		return ex.emit()
	}
	h, ok := hostctlSpecActions[action]
	if !ok {
		return failExit("denyout-cli hostctl: unknown action %q", action).emit()
	}
	return h(o)
}

func hostctlRender(o hostctlSpecOpts) int {
	render := hostOps.render
	if o.tunPreview {
		render = hostOps.renderWithTUN
	}
	out, err := render(o.spec())
	if err != nil {
		return hostctlErr(err)
	}
	fmt.Print(out)
	return 0
}

func hostctlApply(o hostctlSpecOpts) int {
	if o.failPolicy != "" {
		if !protectstate.ValidFailPolicy(o.failPolicy) {
			return failExit("denyout-cli hostctl: --fail-policy must be open or closed").emit()
		}
		hostOps.failPolicyLocal(protectstate.FailPolicy(o.failPolicy))
	}
	if !o.noElevate {
		if err := hostOps.elevateApply(o.port, o.ca, o.uid, o.allowQUIC); err != nil {
			return hostctlErr(err)
		}
		return 0
	}
	if err := hostOps.apply(o.spec()); err != nil {
		return hostctlErr(err)
	}
	// Refresh helper unit/binary after every elevated apply (covers upgrades + first install).
	_ = hostOps.installHelper(o.uid)
	return 0
}

func hostctlRemove(o hostctlSpecOpts) int {
	var err error
	if o.noElevate {
		err = hostOps.remove(o.spec())
	} else {
		err = hostOps.elevateRemove(o.port, o.uid)
	}
	if err != nil {
		return hostctlErr(err)
	}
	return 0
}

func hostctlTeardown(o hostctlSpecOpts) int {
	if !o.noElevate {
		if err := hostOps.elevateTeardown(o.port, o.uid); err != nil {
			return hostctlErr(err)
		}
		return 0
	}
	if err := hostOps.teardown(o.spec()); err != nil {
		return hostctlErr(err)
	}
	_ = hostOps.uninstallHelper()
	return 0
}
