package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/protectstate"
)

// fakeHostOps installs recording fakes for every host-touching operation, so
// no test can reach the real helper, nft/pf or elevation. calls records the
// order; fail[name] makes that operation return an error.
func fakeHostOps(t *testing.T) (calls *[]string, fail map[string]bool) {
	t.Helper()
	old := hostOps
	t.Cleanup(func() { hostOps = old })
	var rec []string
	failures := map[string]bool{}
	do := func(name string, args ...any) error {
		rec = append(rec, name+"["+strings.TrimSpace(fmt.Sprintln(args...))+"]")
		if failures[name] {
			return errors.New(name + " failed")
		}
		return nil
	}
	line := func(name string, args ...any) (string, error) {
		if err := do(name, args...); err != nil {
			return "", err
		}
		return "LINE-" + name, nil
	}
	hostOps = hostctlOps{
		currentUID:    func() (int, error) { return 1234, nil },
		quicStatsLine: func(uid int) string { rec = append(rec, fmt.Sprint("quic", uid)); return "QUIC" },
		tunCall:       func(v string, uid int) (string, error) { return line("tun:"+v, uid) },
		tunCallReal:   func(v string, uid int) (string, error) { return line("tunreal:"+v, uid) },
		tunCallRealMITM: func(v string, uid int) (string, error) {
			return line("tunmitm:"+v, uid)
		},
		caps:            func() (string, error) { return line("caps") },
		vpnApplyHelper:  func(i string) (string, error) { return line("vpnhelper", i) },
		vpnApplyLocal:   func(i string) error { return do("vpnlocal", i) },
		vpnRemoveHelper: func() (string, error) { return line("vpnrmhelper") },
		vpnRemoveLocal:  func() error { return do("vpnrmlocal") },
		failPolicyStatus: func() (hostguard.FailPolicyStatus, error) {
			return hostguard.FailPolicyStatus{Policy: "open", Source: "state", Configured: "open"}, do("fpstatus")
		},
		failPolicySet: func(p protectstate.FailPolicy) (hostguard.FailPolicyStatus, error) {
			return hostguard.FailPolicyStatus{Policy: p, Source: "state", Configured: p}, do("fpset", p)
		},
		auditTail: func(n int) (hostguard.AuditTail, error) {
			rec = append(rec, fmt.Sprint("audit", n))
			return hostguard.AuditTail{Events: []hostguard.AuditEvent{{
				Time: "t1", Verb: "remove", Result: "ok", Lowers: true,
				Peer: hostguard.PeerInfo{PID: 9, UID: 1000, Exe: "/usr/bin/nc", ExeClass: hostguard.ExeOther},
			}, {
				Time: "t2", Verb: "remove", Result: "ok", Lowers: true,
				Peer: hostguard.PeerInfo{PID: 10, UID: 1000, Exe: "/usr/lib/denyout/denyout-cli", ExeClass: hostguard.ExeSystem, Trusted: true},
			}}}, do("audit")
		},
		failPolicyLocal:  func(p protectstate.FailPolicy) { rec = append(rec, "fplocal"+string(p)) },
		elevateInstall:   func(uid int) error { return do("elevinstall", uid) },
		installHelper:    func(uid int) error { return do("install", uid) },
		serveHelper:      func() error { return do("serve") },
		elevateUninstall: func() error { return do("elevuninstall") },
		uninstallHelper:  func() error { return do("uninstall") },
		elevateApply: func(port int, ca string, uid int, q bool) error {
			return do("elevapply", port, ca, uid, q)
		},
		apply:           func(s hostguard.Spec) error { return do("apply", s.ProxyPort, s.UID, s.CACert, s.AllowQUIC) },
		elevateRemove:   func(port, uid int) error { return do("elevremove", port, uid) },
		remove:          func(s hostguard.Spec) error { return do("remove", s.ProxyPort) },
		elevateTeardown: func(port, uid int) error { return do("elevteardown", port, uid) },
		teardown:        func(s hostguard.Spec) error { return do("teardown", s.ProxyPort) },
		render:          func(s hostguard.Spec) (string, error) { return line("render", s.ProxyPort) },
		renderWithTUN:   func(s hostguard.Spec) (string, error) { return line("rendertun", s.ProxyPort) },
	}
	return &rec, failures
}

func runHostctl(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return capture(t, func() int { return cmdHostctl(args) })
}

func TestHostctlReadOnlyActions(t *testing.T) {
	calls, _ := fakeHostOps(t)
	code, out, _ := runHostctl(t, "quic-stats", "--uid=5")
	if code != 0 || out != "QUIC\n" || strings.Join(*calls, ",") != "quic5" {
		t.Fatalf("quic: %d %q %v", code, out, *calls)
	}
	cases := []struct {
		args []string
		call string
		out  string
	}{
		{[]string{"tun-stats"}, "tun:tun-stats[1234]", "LINE-tun:tun-stats\n"},
		{[]string{"tun-start", "--real", "--uid", "9"}, "tunreal:tun-start[9]", "LINE-tunreal:tun-start\n"},
		{[]string{"tun-stop", "--real", "--mitm"}, "tunmitm:tun-stop[1234]", "LINE-tunmitm:tun-stop\n"},
		{[]string{"tun-stop", "--mitm"}, "tun:tun-stop[1234]", "LINE-tun:tun-stop\n"},
		{[]string{"caps"}, "caps[]", "LINE-caps\n"},
		{[]string{"fail-policy", "status"}, "fpstatus[]", ""},
		{[]string{"fail-policy", "closed"}, "fpset[closed]", ""},
	}
	for _, c := range cases {
		*calls = nil
		code, out, errS := runHostctl(t, c.args...)
		if code != 0 || errS != "" || (*calls)[0] != c.call {
			t.Fatalf("%v: %d %q %v", c.args, code, errS, *calls)
		}
		if c.out != "" && out != c.out {
			t.Fatalf("%v out %q", c.args, out)
		}
		if c.out == "" && !strings.Contains(out, "closed") && !strings.Contains(out, "open") {
			t.Fatalf("%v out %q", c.args, out)
		}
	}
}

func TestHostctlFailures(t *testing.T) {
	_, fail := fakeHostOps(t)
	for name, want := range map[string]struct {
		args []string
		msg  string
	}{
		"tun:tun-stats": {[]string{"tun-stats"}, "denyout-cli hostctl tun-stats: tun:tun-stats failed\n"},
		"caps":          {[]string{"caps"}, "denyout-cli hostctl caps: caps failed\n"},
		"fpstatus":      {[]string{"fail-policy", "status"}, "denyout-cli hostctl fail-policy: fpstatus failed\n"},
		"install":       {[]string{"helper-install", "--no-elevate"}, "denyout-cli hostctl helper-install: install failed\n"},
		"elevinstall":   {[]string{"helper-install"}, "denyout-cli hostctl helper-install: elevinstall failed\n"},
		"serve":         {[]string{"helper-serve"}, "denyout-cli hostctl helper-serve: serve failed\n"},
		"uninstall":     {[]string{"helper-uninstall", "--no-elevate"}, "denyout-cli hostctl helper-uninstall: uninstall failed\n"},
		"elevuninstall": {[]string{"helper-uninstall"}, "denyout-cli hostctl helper-uninstall: elevuninstall failed\n"},
		"render":        {[]string{"render"}, "denyout-cli hostctl: render failed\n"},
		"rendertun":     {[]string{"render", "--tun"}, "denyout-cli hostctl: rendertun failed\n"},
		"elevapply":     {[]string{"apply"}, "denyout-cli hostctl: elevapply failed\n"},
		"apply":         {[]string{"apply", "--no-elevate"}, "denyout-cli hostctl: apply failed\n"},
		"elevremove":    {[]string{"remove"}, "denyout-cli hostctl: elevremove failed\n"},
		"remove":        {[]string{"remove", "--no-elevate"}, "denyout-cli hostctl: remove failed\n"},
		"elevteardown":  {[]string{"teardown"}, "denyout-cli hostctl: elevteardown failed\n"},
		"teardown":      {[]string{"teardown", "--no-elevate"}, "denyout-cli hostctl: teardown failed\n"},
	} {
		fail[name] = true
		code, _, errS := runHostctl(t, want.args...)
		if code != 2 || errS != want.msg {
			t.Errorf("%s: %d %q want %q", name, code, errS, want.msg)
		}
		delete(fail, name)
	}
}

func TestHostctlSpecActions(t *testing.T) {
	calls, _ := fakeHostOps(t)
	run := func(args ...string) string {
		*calls = nil
		code, _, errS := runHostctl(t, args...)
		if code != 0 || errS != "" {
			t.Fatalf("%v: %d %q", args, code, errS)
		}
		return strings.Join(*calls, ",")
	}
	if got := run("render", "--port", "7"); got != "render[7]" {
		t.Fatal(got)
	}
	if got := run("render", "--port=7", "--tun"); got != "rendertun[7]" {
		t.Fatal(got)
	}
	if got := run("apply", "--port", "7", "--ca", "/c", "--uid", "3", "--allow-quic"); got != "elevapply[7 /c 3 true]" {
		t.Fatal(got)
	}
	// local apply refreshes the helper afterwards; fail-policy is persisted first
	if got := run("apply", "--no-elevate", "--port", "7", "--uid", "3", "--fail-policy", "closed"); got != "fplocalclosed,apply[7 3  false],install[3]" {
		t.Fatal(got)
	}
	if got := run("remove", "--port", "7", "--uid", "3"); got != "elevremove[7 3]" {
		t.Fatal(got)
	}
	if got := run("remove", "--no-elevate", "--port", "7"); got != "remove[7]" {
		t.Fatal(got)
	}
	if got := run("teardown", "--port", "7", "--uid", "3"); got != "elevteardown[7 3]" {
		t.Fatal(got)
	}
	if got := run("teardown", "--no-elevate", "--port", "7"); got != "teardown[7],uninstall[]" {
		t.Fatal(got)
	}
	if got := run("helper-install", "--uid=8"); got != "elevinstall[8]" {
		t.Fatal(got)
	}
	if got := run("helper-install", "--no-elevate"); got != "install[1234]" {
		t.Fatal(got)
	}
	if got := run("helper-serve"); got != "serve[]" {
		t.Fatal(got)
	}
	if got := run("helper-uninstall"); got != "elevuninstall[]" {
		t.Fatal(got)
	}
	if got := run("helper-uninstall", "--no-elevate"); got != "uninstall[]" {
		t.Fatal(got)
	}
}

func TestHostctlVPNEgress(t *testing.T) {
	calls, fail := fakeHostOps(t)
	t.Setenv("DENYOUT_VPN_EGRESS_E2E", "1")
	code, out, _ := runHostctl(t, "vpn-egress-apply", "--iface", "wg0")
	if code != 0 || out != "LINE-vpnhelper\n" || (*calls)[0] != "vpnhelper[wg0]" {
		t.Fatalf("%d %q %v", code, out, *calls)
	}
	fail["vpnhelper"] = true
	code, out, _ = runHostctl(t, "vpn-egress-apply", "--iface=wg0")
	if code != 0 || out != "OK vpn1 applied iface=wg0 source=local\n" {
		t.Fatalf("local fallback: %d %q", code, out)
	}
	fail["vpnlocal"] = true
	code, _, errS := runHostctl(t, "vpn-egress-apply", "--iface=wg0")
	if code != 2 || errS != "denyout-cli hostctl vpn-egress-apply: vpnlocal failed (helper: vpnhelper failed)\n" {
		t.Fatalf("%d %q", code, errS)
	}
	delete(fail, "vpnhelper")
	delete(fail, "vpnlocal")
	code, out, _ = runHostctl(t, "vpn-egress-remove")
	if code != 0 || out != "LINE-vpnrmhelper\n" {
		t.Fatalf("%d %q", code, out)
	}
	fail["vpnrmhelper"] = true
	code, out, _ = runHostctl(t, "vpn-egress-remove")
	if code != 0 || out != "OK vpn1 removed source=local\n" || !strings.Contains(strings.Join(*calls, ","), "vpnrmlocal") {
		t.Fatalf("%d %q %v", code, out, *calls)
	}
}

func TestHostctlProxydDelegates(t *testing.T) {
	fakeHostOps(t)
	code, _, errS := runHostctl(t, "proxyd")
	if code != 2 || errS != "denyout-cli hostctl proxyd: --port and --ca-dir required\n" {
		t.Fatalf("%d %q", code, errS)
	}
}

func TestHostctlAuditTail(t *testing.T) {
	calls, fail := fakeHostOps(t)
	code, out, _ := runHostctl(t, "audit-tail", "7")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || (*calls)[0] != "audit7" || len(lines) != 2 {
		t.Fatalf("%d %q %v", code, out, *calls)
	}
	if !strings.Contains(lines[0], "SUSPICIOUS:untrusted_exe") || strings.Contains(lines[1], "SUSPICIOUS") {
		t.Fatalf("flagging wrong:\n%s", out)
	}
	if code, out, _ = runHostctl(t, "audit-tail", "--json"); code != 0 || !strings.HasPrefix(out, `{"events":[`) || !strings.Contains(strings.Join(*calls, ","), "audit50") {
		t.Fatalf("json: %d %q %v", code, out, *calls)
	}
	for _, bad := range [][]string{{"0"}, {"201"}, {"x"}, {"5", "--nope"}} {
		if code, _, _ := runHostctl(t, append([]string{"audit-tail"}, bad...)...); code == 0 {
			t.Fatalf("%v accepted", bad)
		}
	}
	fail["audit"] = true
	if code, _, errS := runHostctl(t, "audit-tail"); code == 0 || !strings.Contains(errS, "audit-tail") {
		t.Fatalf("failure not reported: %d %q", code, errS)
	}
}
