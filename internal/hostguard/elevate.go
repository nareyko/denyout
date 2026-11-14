package hostguard

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ElevateApply re-executes `denyout hostctl apply` with admin rights.
func ElevateApply(proxyPort int, caCert string, uid int) error {
	exe, err := SelfExe()
	if err != nil {
		return err
	}
	args := []string{"hostctl", "apply",
		"--port", strconv.Itoa(proxyPort),
		"--ca", caCert,
		"--uid", strconv.Itoa(uid),
		"--no-elevate",
	}
	return elevate(exe, args)
}

// ElevateRemove re-executes hostctl remove with admin rights.
func ElevateRemove(proxyPort int, uid int) error {
	exe, err := SelfExe()
	if err != nil {
		return err
	}
	args := []string{"hostctl", "remove",
		"--port", strconv.Itoa(proxyPort),
		"--uid", strconv.Itoa(uid),
		"--no-elevate",
	}
	return elevate(exe, args)
}

func elevate(exe string, args []string) error {
	switch runtime.GOOS {
	case "linux":
		return elevateLinux(exe, args)
	case "darwin":
		return elevateDarwin(exe, args)
	case "windows":
		return elevateWindows(exe, args)
	default:
		return ErrUnsupported
	}
}

func elevateLinux(exe string, args []string) error {
	var cmd *exec.Cmd
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd = exec.Command("pkexec", append([]string{exe}, args...)...)
		if _, err := os.Stat("/usr/share/polkit-1/actions/com.denyout.hostctl.policy"); err == nil {
			cmd = exec.Command("pkexec", append([]string{"--action-id=com.denyout.hostctl", exe}, args...)...)
		}
	} else {
		cmd = exec.Command("sudo", append([]string{"-n", exe}, args...)...)
	}
	return runElevate(cmd, "linux")
}

func elevateDarwin(exe string, args []string) error {
	quoted := shellQuote(exe)
	for _, a := range args {
		quoted += " " + shellQuote(a)
	}
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, strconv.Quote(quoted))
	cmd := exec.Command("osascript", "-e", script)
	return runElevate(cmd, "darwin")
}

func elevateWindows(exe string, args []string) error {
	ps := fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -Wait`,
		strconv.Quote(exe), strconv.Quote(strings.Join(args, " ")))
	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	return runElevate(cmd, "windows")
}

func runElevate(cmd *exec.Cmd, platform string) error {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())
	if err == nil {
		if out != "" {
			fmt.Fprintln(os.Stderr, out)
		}
		return nil
	}
	detail := strings.TrimSpace(strings.Join([]string{out, errOut, err.Error()}, "\n"))
	return fmt.Errorf("%w (%s): %s", ErrNeedsAdmin, platform, detail)
}

func shellQuote(s string) string {
	if s == "" {
		return `''`
	}
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}
