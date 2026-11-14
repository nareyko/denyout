package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	waitUntilPreviousGone(selfPID, 2*time.Second)
}

func stopPreviousUnix(selfPID int) {
	out, err := exec.Command("ps", "-eo", "pid=,args=").Output()
	if err != nil {
		// Best-effort fallbacks.
		_ = exec.Command("pkill", "-f", `denyout[[:space:]]+desktop`).Run()
		_ = exec.Command("pkill", "-f", `[d]enyout-desktop`).Run()
		_ = exec.Command("pkill", "-f", `denyout[[:space:]]+hostctl[[:space:]]+proxyd`).Run()
		return
	}
	for _, pid := range matchDenyoutPIDs(string(out), selfPID) {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		_ = proc.Signal(os.Interrupt)
		time.Sleep(150 * time.Millisecond)
		_ = proc.Kill()
	}
}

func matchDenyoutPIDs(psOut string, selfPID int) []int {
	var pids []int
	seen := map[int]bool{}
	for _, line := range strings.Split(psOut, "\n") {
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
		if seen[pid] {
			continue
		}
		seen[pid] = true
		pids = append(pids, pid)
	}
	return pids
}

func waitUntilPreviousGone(selfPID int, budget time.Duration) {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if runtime.GOOS == "windows" {
			return
		}
		out, err := exec.Command("ps", "-eo", "pid=,args=").Output()
		if err != nil {
			return
		}
		left := matchDenyoutPIDs(string(out), selfPID)
		if len(left) == 0 {
			return
		}
		for _, pid := range left {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func isDenyoutDesktopOrProxyd(args string) bool {
	parts := strings.Fields(strings.ToLower(args))
	for i, p := range parts {
		base := filepath.Base(p)
		// Strip occasional argv noise (e.g. "denyout-desktop:").
		base = strings.Trim(base, ":")
		if base == "denyout-desktop" || base == "denyout-desktop.exe" {
			return true
		}
		if base != "denyout" && base != "denyout.exe" {
			continue
		}
		if i+1 >= len(parts) {
			continue
		}
		next := parts[i+1]
		if next == "desktop" {
			return true
		}
		// `denyout hostctl proxyd ...`
		if next == "hostctl" && i+2 < len(parts) && parts[i+2] == "proxyd" {
			return true
		}
	}
	return false
}

func stopPreviousWindows(selfPID int) {
	// Prefer PowerShell filter so we do not kill this install process.
	script := `
$me = ` + strconv.Itoa(selfPID) + `
Get-CimInstance Win32_Process | Where-Object {
  $_.Name -eq 'denyout.exe' -or $_.Name -eq 'denyout-desktop.exe'
} | ForEach-Object {
  if ($_.ProcessId -eq $me) { return }
  $cmd = $_.CommandLine
  $name = $_.Name
  if ($name -eq 'denyout-desktop.exe') {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    return
  }
  if ($null -eq $cmd) { return }
  if ($cmd -match 'denyout(\.exe)?\s+desktop' -or $cmd -match 'denyout(\.exe)?\s+hostctl\s+proxyd') {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  }
}
`
	_ = exec.Command("powershell", "-NoProfile", "-Command", script).Run()
}

// WarnStaleBinariesOnPATH reports denyout / denyout-desktop executables on PATH
// that are outside installDir (common cause of "second version" after upgrade).
// Does not delete anything.
func WarnStaleBinariesOnPATH(installDir string) {
	installDir = filepath.Clean(installDir)
	if resolved, err := filepath.EvalSymlinks(installDir); err == nil {
		installDir = resolved
	}
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return
	}
	names := []string{"denyout", "denyout-desktop"}
	if runtime.GOOS == "windows" {
		names = []string{"denyout.exe", "denyout-desktop.exe"}
	}
	seen := map[string]bool{}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			clean = resolved
		}
		if sameFilePath(clean, installDir) {
			continue
		}
		for _, name := range names {
			cand := filepath.Join(clean, name)
			st, err := os.Stat(cand)
			if err != nil || st.IsDir() {
				continue
			}
			real := cand
			if resolved, err := filepath.EvalSymlinks(cand); err == nil {
				real = resolved
			}
			if seen[real] {
				continue
			}
			// Skip if the resolved file still lives under installDir (symlink).
			if strings.HasPrefix(real, installDir+string(os.PathSeparator)) {
				continue
			}
			seen[real] = true
			fmt.Fprintf(os.Stderr, "denyout install: warning - stale %s on PATH: %s (install dir is %s)\n", name, real, installDir)
			fmt.Fprintf(os.Stderr, "  remove or rename it so upgrades use %s\n", filepath.Join(installDir, name))
		}
	}
}

func sameFilePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if a == b {
		return true
	}
	if ra, err := filepath.EvalSymlinks(a); err == nil {
		a = ra
	}
	if rb, err := filepath.EvalSymlinks(b); err == nil {
		b = rb
	}
	return a == b
}

// DefaultInstallDir is ~/.local/bin (or %LOCALAPPDATA%\denyout on Windows).
func DefaultInstallDir() string {
	if d := os.Getenv("DENYOUT_INSTALL_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "denyout")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin")
}
