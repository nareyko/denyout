//go:build linux

package hostguard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nareyko/denyout/internal/tun"
)

var (
	helperOpMu    sync.Mutex // serializes state-changing helper verbs
	lastApplyMu   sync.Mutex
	lastApplySpec Spec
	lastApplyOK   bool
)

const (
	helperSockPath  = "/run/denyout-hostguard.sock"
	helperStateDir  = "/var/lib/denyout"
	helperOwnerFile = "/var/lib/denyout/owner_uid"
	helperUnitPath  = "/etc/systemd/system/denyout-hostguard.service"
	helperUnitName  = "denyout-hostguard.service"
)

func helperAvailable() bool {
	if st, err := os.Stat(helperSockPath); err != nil || st.Mode()&os.ModeSocket == 0 {
		return false
	}
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func helperCall(verb string, proxyPort int, caCert string, uid int, allowQUIC bool) error {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	aq := "0"
	if allowQUIC {
		aq = "1"
	}
	// apply PORT UID CA allow_quic(0|1) — older helpers ignore the 5th field.
	line := fmt.Sprintf("%s %d %d %s %s\n", verb, proxyPort, uid, strings.ReplaceAll(caCert, " ", ""), aq)
	if _, err := c.Write([]byte(line)); err != nil {
		return err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "OK") {
		// apply must understand the 5th allow_quic field + UDP/443 drop.
		// Pre-QUIC helpers reply plain "OK" and ignore the flag — force elevate refresh.
		if verb == "apply" && !strings.Contains(resp, "quic1") {
			return fmt.Errorf("%w: helper lacks quic1 (plain OK)", ErrHelperUnavailable)
		}
		return nil
	}
	return fmt.Errorf("helper %s: %s", verb, resp)
}

func helperQUICStats(uid int) (QUICDropStats, error) {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return QUICDropStats{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	// quic-stats PORT UID — port unused; keep 3-field shape for the helper parser.
	line := fmt.Sprintf("quic-stats 0 %d -\n", uid)
	if _, err := c.Write([]byte(line)); err != nil {
		return QUICDropStats{}, err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return QUICDropStats{}, err
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		if strings.Contains(resp, "unknown verb") {
			return QUICDropStats{}, fmt.Errorf("%w: helper lacks quic-stats", ErrHelperUnavailable)
		}
		return QUICDropStats{}, fmt.Errorf("helper quic-stats: %s", resp)
	}
	return ParseQUICDropStatsLine(resp)
}

func helperTunCall(verb string, uid int, real, mitm bool) (string, error) {
	if !tun.IsHelperVerb(verb) {
		return "", fmt.Errorf("hostguard: not a tun verb %q", verb)
	}
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		// Root + --real: run dataplane locally (Docker/VM dogfood without helper-serve).
		if real && os.Geteuid() == 0 {
			return helperTunVerb(verb, uid, real, mitm)
		}
		// Closed-loop fallback: local stub reply (no elevate, no device).
		return tun.HelperReply(verb)
	}
	defer c.Close()
	line, err := tun.HelperLineOpts(verb, uid, real, mitm)
	if err != nil {
		return "", err
	}
	if _, err := c.Write([]byte(line)); err != nil {
		return "", err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		// Pre-tun helpers: fall back to local disabled contract (no device).
		if strings.Contains(resp, "unknown verb") {
			return tun.HelperReply(verb)
		}
		return "", fmt.Errorf("helper %s: %s", verb, resp)
	}
	return resp, nil
}

// helperTunVerb runs inside helper-serve.
func helperTunVerb(verb string, uid int, real, mitm bool) (string, error) {
	rt := tun.GlobalRuntime()
	switch verb {
	case "tun-stats":
		st := rt.StatsSnapshot()
		reason := "flag_off"
		if real || rt.IsActive() || tun.WantDevice() {
			if st.Present {
				reason = "ok"
			} else if tun.WantDevice() || real {
				reason = "inactive"
			}
		}
		return "OK " + tun.CapTag + " " + tun.FormatDropStatsLine(st) + " reason=" + reason, nil
	case "tun-start":
		if !real && !tun.WantDevice() {
			return tun.HelperReply(verb)
		}
		lastApplyMu.Lock()
		port := lastApplySpec.ProxyPort
		caPath := lastApplySpec.CACert
		lastApplyMu.Unlock()
		wantMITM := mitm || tun.WantQUICMITM()
		opts := tun.StartOpts{
			UID:       uid,
			ProxyPort: port,
			EnableTCP: true,
			QUICMITM:  wantMITM,
			OnSighting: func(dec tun.QUICDecision) {
				fmt.Fprintf(os.Stderr, "denyout tun quic sight action=%s sni=%q reason=%s\n", dec.Action, dec.SNI, dec.Reason)
			},
		}
		if wantMITM {
			if cfg, err := mitmConfigFromCA(caPath); err == nil {
				opts.MITM = cfg
			} else {
				fmt.Fprintf(os.Stderr, "denyout tun quic mitm ca: %v (sight/drop only)\n", err)
			}
		}
		if err := rt.StartRealOpts(opts); err != nil {
			return "", err
		}
		// Suppress T0 UDP drop + TCP redirect while TUN/gVisor owns those paths.
		suppressT0ForTUN(true)
		return fmt.Sprintf("OK %s enabled=true verb=%s reason=ok tcp=1 mitm=%v", tun.CapTag, verb, opts.QUICMITM), nil
	case "tun-stop":
		_ = rt.StopReal()
		suppressT0ForTUN(false)
		if !real && !tun.WantDevice() {
			return tun.HelperReply(verb)
		}
		return fmt.Sprintf("OK %s enabled=false verb=%s reason=ok", tun.CapTag, verb), nil
	default:
		return "", fmt.Errorf("tun: unknown helper verb %q", verb)
	}
}

func suppressT0ForTUN(suppress bool) {
	lastApplyMu.Lock()
	defer lastApplyMu.Unlock()
	if !lastApplyOK || lastApplySpec.ProxyPort <= 0 {
		return
	}
	s := lastApplySpec
	if suppress {
		s.AllowQUIC = true // omit denyout-block-quic; TUN steers/drops instead
		s.TunTCP = true    // omit TCP redirect; gVisor owns TCP
	}
	_ = Apply(s)
}

func helperCaps() (CapsReply, error) {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return CapsReply{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("caps 0 0 -\n")); err != nil {
		return CapsReply{}, err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return CapsReply{}, err
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		if strings.Contains(resp, "unknown verb") {
			return CapsReply{Raw: resp}, ErrStaleHelperCaps([]string{CapCaps, CapQUIC, CapTUN})
		}
		return CapsReply{}, fmt.Errorf("helper caps: %s", resp)
	}
	return ParseCapsReply(resp), nil
}

func helperVPNEgressCall(verb, iface string) (string, error) {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	// vpn-egress-apply|remove PORT UID IFACE
	if iface == "" {
		iface = "-"
	}
	line := fmt.Sprintf("%s 0 0 %s\n", verb, strings.ReplaceAll(iface, " ", ""))
	if _, err := c.Write([]byte(line)); err != nil {
		return "", err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return "", fmt.Errorf("helper %s: %s", verb, resp)
	}
	return resp, nil
}

// InstallHelper installs and starts the systemd helper (must run as root).
func InstallHelper(ownerUID int) error {
	if os.Geteuid() != 0 {
		return ErrNeedsAdmin
	}
	if ownerUID <= 0 {
		if u, err := CurrentUID(); err == nil {
			ownerUID = u
		}
	}
	if ownerUID <= 0 {
		return fmt.Errorf("hostguard helper needs a non-root owner uid (run via the desktop app or pass --uid)")
	}
	exe, err := SelfExe()
	if err != nil {
		return err
	}
	// Never point a root service at a binary an unprivileged user can replace.
	exe, err = trustedHelperExe(exe)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(helperStateDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(helperOwnerFile, []byte(strconv.Itoa(ownerUID)+"\n"), 0o644); err != nil {
		return err
	}
	// Also install polkit action if packaged beside repo / next to binary.
	_ = installPolkitAction(exe)

	unit := fmt.Sprintf(`[Unit]
Description=DenyOut hostguard helper (passwordless restore)
After=network.target

[Service]
Type=simple
ExecStart=%s hostctl helper-serve
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`, exe)
	if err := os.WriteFile(helperUnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", helperUnitName).Run()
	if err := exec.Command("systemctl", "restart", helperUnitName).Run(); err != nil {
		// Fallback: run serve in background if systemd unavailable (dev containers).
		cmd := exec.Command(exe, "hostctl", "helper-serve")
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		_ = cmd.Start()
		return nil
	}
	return nil
}

func installPolkitAction(exe string) error {
	_ = exe
	dst := "/usr/share/polkit-1/actions/com.denyout.hostctl.policy"
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	// Prefer contrib next to source; else embed minimal policy.
	candidates := []string{
		"contrib/polkit/com.denyout.hostctl.policy",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "com.denyout.hostctl.policy"))
	}
	var body []byte
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil {
			body = b
			break
		}
	}
	if len(body) == 0 {
		body = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="com.denyout.hostctl">
    <description>DenyOut hostguard</description>
    <message>Authentication is required to turn DenyOut computer protection on or off</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
`)
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0o755)
	return os.WriteFile(dst, body, 0o644)
}

// UninstallHelper stops and removes the helper unit (must be root).
func UninstallHelper() error {
	if os.Geteuid() != 0 {
		return ErrNeedsAdmin
	}
	_ = exec.Command("systemctl", "disable", "--now", helperUnitName).Run()
	_ = os.Remove(helperUnitPath)
	_ = os.Remove(helperSockPath)
	_ = os.Remove(helperOwnerFile)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// ServeHelper runs the root unix-socket server.
func ServeHelper() error {
	if os.Geteuid() != 0 {
		return ErrNeedsAdmin
	}
	owner := 0
	if b, err := os.ReadFile(helperOwnerFile); err == nil {
		owner, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	_ = os.Remove(helperSockPath)
	_ = os.MkdirAll(filepath.Dir(helperSockPath), 0o755)
	ln, err := net.Listen("unix", helperSockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	// Stale TUN/VPN state from a previous crashed helper must not linger.
	_ = tun.GlobalRuntime().StopReal()
	_ = tun.RemoveVPNEgress()
	// On SIGTERM/SIGINT (systemctl stop) remove our rules so a stopped helper
	// never leaves a REDIRECT to a dead proxy (orphan blackhole).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigc
		helperOpMu.Lock()
		_ = tun.GlobalRuntime().StopReal()
		_ = tun.RemoveVPNEgress()
		_ = removeRedirect(Spec{})
		_ = os.Remove(helperSockPath)
		helperOpMu.Unlock()
		_ = ln.Close()
	}()
	// Owner-only socket (plus root); SO_PEERCRED is checked again per connection.
	if owner > 0 {
		_ = os.Chown(helperSockPath, owner, 0)
		_ = os.Chmod(helperSockPath, 0o600)
	} else {
		_ = os.Chmod(helperSockPath, 0o600) // root only until an owner is configured
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // clean shutdown
			}
			return err
		}
		go handleHelperConn(c, owner)
	}
}

func handleHelperConn(c net.Conn, ownerUID int) {
	defer c.Close()
	if !helperPeerAuthorized(ownerUID, peerUID(c)) {
		_, _ = c.Write([]byte("ERR unauthorized\n"))
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, 4096)).ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 {
		_, _ = c.Write([]byte("ERR bad request\n"))
		return
	}
	verb := strings.ToLower(parts[0])
	port, _ := strconv.Atoi(parts[1])
	// Redirect rules always target the configured owner; never trust a client uid
	// (a zero or foreign uid would let the owner redirect root's or others' traffic).
	uid := ownerUID
	ca := ""
	if len(parts) >= 4 {
		ca = parts[3]
	}
	if verb == "apply" {
		if err := validateHelperCAPath(ca, ownerUID); err != nil {
			_, _ = c.Write([]byte("ERR " + err.Error() + "\n"))
			return
		}
	}
	allowQUIC := false
	if len(parts) >= 5 && (parts[4] == "1" || strings.EqualFold(parts[4], "true") || parts[4] == "allow_quic") {
		allowQUIC = true
	}
	spec := Spec{ProxyPort: port, UID: uid, CACert: ca, AllowQUIC: allowQUIC}
	helperOpMu.Lock()
	defer helperOpMu.Unlock()
	var opErr error
	switch verb {
	case "caps", "version":
		exe := ""
		if p, e := SelfExe(); e == nil {
			exe = filepath.Base(p)
		}
		_, _ = c.Write([]byte(FormatCapsReply(exe, CapQUIC, CapTUN, CapVPN) + "\n"))
		return
	case "apply":
		_ = tun.GlobalRuntime().StopReal()
		opErr = Apply(spec)
		if opErr == nil {
			lastApplyMu.Lock()
			lastApplySpec = spec
			lastApplyOK = true
			lastApplyMu.Unlock()
		}
	case "remove":
		_ = tun.GlobalRuntime().StopReal()
		_ = tun.RemoveVPNEgress()
		opErr = Remove(spec)
	case "teardown":
		_ = tun.GlobalRuntime().StopReal()
		_ = tun.RemoveVPNEgress()
		opErr = Teardown(spec)
	case "uninstall-helper":
		_ = tun.GlobalRuntime().StopReal()
		_ = tun.RemoveVPNEgress()
		opErr = UninstallHelper()
	case "quic-stats":
		st, rerr := ReadQUICDropStats()
		if rerr != nil {
			_, _ = c.Write([]byte("ERR " + rerr.Error() + "\n"))
			return
		}
		st.Source = "nft"
		_, _ = c.Write([]byte("OK quic1 " + FormatQUICDropStatsLine(st) + "\n"))
		return
	case "tun-start", "tun-stop", "tun-stats":
		real, mitm := false, false
		for _, p := range parts[3:] {
			switch strings.ToLower(p) {
			case "real", "real=1":
				real = true
			case "mitm", "mitm=1":
				mitm = true
			}
		}
		reply, rerr := helperTunVerb(verb, uid, real, mitm)
		if rerr != nil {
			_, _ = c.Write([]byte("ERR " + rerr.Error() + "\n"))
			return
		}
		_, _ = c.Write([]byte(reply + "\n"))
		return
	case "vpn-egress-apply":
		iface := ca // 4th field
		if iface == "" || iface == "-" {
			_, _ = c.Write([]byte("ERR vpn iface required\n"))
			return
		}
		if err := tun.ApplyVPNEgress(iface); err != nil {
			_, _ = c.Write([]byte("ERR " + err.Error() + "\n"))
			return
		}
		_, _ = c.Write([]byte("OK " + CapVPN + " applied iface=" + iface + "\n"))
		return
	case "vpn-egress-remove":
		_ = tun.RemoveVPNEgress()
		_, _ = c.Write([]byte("OK " + CapVPN + " removed\n"))
		return
	default:
		_, _ = c.Write([]byte("ERR unknown verb\n"))
		return
	}
	if opErr != nil {
		_, _ = c.Write([]byte("ERR " + opErr.Error() + "\n"))
		return
	}
	// Cap tag lets clients detect a pre-QUIC helper (plain "OK") and re-elevate once.
	_, _ = c.Write([]byte("OK quic1\n"))
	// After uninstall teardown, drop the systemd helper so uninstall does not
	// leave helper-serve running with a deleted binary path.
	if verb == "teardown" {
		_ = UninstallHelper()
	}
}

func peerUID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	var uid int = -1
	_ = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid
}
