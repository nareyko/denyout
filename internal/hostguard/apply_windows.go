//go:build windows

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Windows transparent divert requires WinDivert (DLL+SYS) next to denyout.exe.
// Without it, Apply returns ErrDriverMissing (UI shows Needs setup — not a fake On).

func applyRedirect(spec Spec) error {
	exe, err := SelfExe()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	dll := filepath.Join(dir, "WinDivert.dll")
	sys := filepath.Join(dir, "WinDivert64.sys")
	if _, err := os.Stat(dll); err != nil {
		// also accept WinDivert64.dll naming
		dll = filepath.Join(dir, "WinDivert64.dll")
		if _, err2 := os.Stat(dll); err2 != nil {
			return ErrDriverMissing
		}
	}
	_ = sys
	filter := "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443)"
	// Persist divert worker via a helper script that loops with WinDivert CLI if present.
	helper := filepath.Join(dir, "denyout-divert.ps1")
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$port = %d
$filter = %q
# Prefer bundled windivert-proxy helper if present; else record intent for service.
$marker = Join-Path $env:ProgramData 'denyout\divert.port'
New-Item -ItemType Directory -Force -Path (Split-Path $marker) | Out-Null
Set-Content -Path $marker -Value $port
Write-Host "denyout: divert marker written for port $port filter=$filter"
`, spec.ProxyPort, filter)
	if err := os.WriteFile(helper, []byte(script), 0o644); err != nil {
		return err
	}
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("windows divert helper: %w", err)
	}
	// Launch userspace divert bridge if denyout-windivert.exe exists (optional companion).
	bridge := filepath.Join(dir, "denyout-windivert.exe")
	if _, err := os.Stat(bridge); err == nil {
		c := exec.Command(bridge, "--port", strconv.Itoa(spec.ProxyPort))
		if err := c.Start(); err != nil {
			return fmt.Errorf("start divert bridge: %w", err)
		}
		return nil
	}
	// DLL present but no bridge yet: still require bridge for true transparent mode.
	return fmt.Errorf("%w: place denyout-windivert.exe beside denyout.exe (see docs/07-desktop.md)", ErrDriverMissing)
}

func removeRedirect(spec Spec) error {
	_ = spec
	marker := filepath.Join(os.Getenv("ProgramData"), "denyout", "divert.port")
	_ = os.Remove(marker)
	// Best-effort kill companion.
	_ = exec.Command("taskkill", "/F", "/IM", "denyout-windivert.exe").Run()
	return nil
}
