package hostguard

import (
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
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd := exec.Command("pkexec", append([]string{exe}, args...)...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%w: %v", ErrNeedsAdmin, err)
		}
		return nil
	}
	cmd := exec.Command("sudo", append([]string{"-n", exe}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v", ErrNeedsAdmin, err)
	}
	return nil
}

func elevateDarwin(exe string, args []string) error {
	// osascript admin privileges for one shot.
	quoted := shellQuote(exe)
	for _, a := range args {
		quoted += " " + shellQuote(a)
	}
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, strconv.Quote(quoted))
	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v", ErrNeedsAdmin, err)
	}
	return nil
}

func elevateWindows(exe string, args []string) error {
	// PowerShell Start-Process -Verb RunAs
	psArgs := make([]string, 0, len(args))
	for _, a := range args {
		psArgs = append(psArgs, shellQuote(a))
	}
	cmdLine := shellQuote(exe) + " " + strings.Join(psArgs, " ")
	ps := fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -Wait`,
		strconv.Quote(exe), strconv.Quote(strings.Join(args, " ")))
	_ = cmdLine
	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v", ErrNeedsAdmin, err)
	}
	return nil
}

func shellQuote(s string) string {
	if s == "" {
		return `''`
	}
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}
