package desktop

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// StopPreviousInstances stops an older tray / proxyd so reinstall can replace
// the binary and start a fresh desktop. Hostguard nft/pf rules are left in
// place; the new tray's ElevateApply replaces them in one admin prompt.
func StopPreviousInstances() {
	selfPID := os.Getpid()
	switch runtime.GOOS {
	case "windows":
		stopPreviousWindows(selfPID)
	default:
		stopPreviousUnix(selfPID)
	}
	time.Sleep(300 * time.Millisecond)
}

func stopPreviousUnix(selfPID int) {
	out, err := exec.Command("ps", "-eo", "pid=,args=").Output()
	if err != nil {
		// Best-effort fallbacks.
		_ = exec.Command("pkill", "-f", `denyout[[:space:]]+desktop`).Run()
		_ = exec.Command("pkill", "-f", `denyout[[:space:]]+hostctl[[:space:]]+proxyd`).Run()
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 1 || pid == selfPID {
			continue
		}
		args := strings.Join(fields[1:], " ")
		if !isDenyoutDesktopOrProxyd(args) {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		_ = proc.Signal(os.Interrupt)
		time.Sleep(150 * time.Millisecond)
		_ = proc.Kill()
	}
}

func isDenyoutDesktopOrProxyd(args string) bool {
	parts := strings.Fields(strings.ToLower(args))
	for i, p := range parts {
		if !strings.HasSuffix(p, "denyout") && !strings.HasSuffix(p, "denyout.exe") {
			continue
		}
		if i+1 < len(parts) && parts[i+1] == "desktop" {
			return true
		}
		if i+2 < len(parts) && parts[i+1] == "hostctl" && parts[i+2] == "proxyd" {
			return true
		}
	}
	return false
}

func stopPreviousWindows(selfPID int) {
	// Prefer PowerShell filter so we do not kill this install process.
	script := `
$me = ` + strconv.Itoa(selfPID) + `
Get-CimInstance Win32_Process -Filter "Name='denyout.exe'" | ForEach-Object {
  if ($_.ProcessId -eq $me) { return }
  $cmd = $_.CommandLine
  if ($null -eq $cmd) { return }
  if ($cmd -match 'denyout(\.exe)?\s+desktop' -or $cmd -match 'denyout(\.exe)?\s+hostctl\s+proxyd') {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  }
}
`
	_ = exec.Command("powershell", "-NoProfile", "-Command", script).Run()
}
