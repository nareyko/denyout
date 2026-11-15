//go:build linux

package hostguard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

func helperCall(verb string, proxyPort int, caCert string, uid int) error {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	line := fmt.Sprintf("%s %d %d %s\n", verb, proxyPort, uid, strings.ReplaceAll(caCert, " ", ""))
	if _, err := c.Write([]byte(line)); err != nil {
		return err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "OK") {
		return nil
	}
	return fmt.Errorf("helper %s: %s", verb, resp)
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
	exe, err := SelfExe()
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

// UninstallHelper stops and removes the helper unit (root).
func UninstallHelper() error {
	if os.Geteuid() != 0 {
		return nil
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
	_ = os.Chmod(helperSockPath, 0o666) // peercred still gates; world-connectable then auth by uid
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleHelperConn(c, owner)
	}
}

func handleHelperConn(c net.Conn, ownerUID int) {
	defer c.Close()
	ucred := peerUID(c)
	if ownerUID > 0 && ucred > 0 && ucred != ownerUID && ucred != 0 {
		_, _ = c.Write([]byte("ERR unauthorized\n"))
		return
	}
	line, err := bufio.NewReader(c).ReadString('\n')
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
	uid, _ := strconv.Atoi(parts[2])
	ca := ""
	if len(parts) >= 4 {
		ca = parts[3]
	}
	spec := Spec{ProxyPort: port, UID: uid, CACert: ca}
	var opErr error
	switch verb {
	case "apply":
		opErr = Apply(spec)
	case "remove":
		opErr = Remove(spec)
	case "teardown":
		opErr = Teardown(spec)
	default:
		_, _ = c.Write([]byte("ERR unknown verb\n"))
		return
	}
	if opErr != nil {
		_, _ = c.Write([]byte("ERR " + opErr.Error() + "\n"))
		return
	}
	_, _ = c.Write([]byte("OK\n"))
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
