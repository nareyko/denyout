package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/nareyko/denyout/internal/audit"
)

// AuditLogPath returns the desktop audit JSONL path.
func AuditLogPath() string {
	return audit.DefaultDesktopPath()
}

// OpenLogs reveals or opens the audit log file.
func OpenLogs() error {
	path := AuditLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = os.WriteFile(path, []byte(""), 0o600)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", "-R", path).Start()
	case "windows":
		return exec.Command("explorer", "/select,", path).Start()
	default:
		// Prefer folder; fall back to xdg-open on file.
		dir := filepath.Dir(path)
		if err := exec.Command("xdg-open", dir).Start(); err == nil {
			return nil
		}
		return exec.Command("xdg-open", path).Start()
	}
}

// EnsureLogsReadable is a tiny helper for status copy.
func EnsureLogsReadable() string {
	p := AuditLogPath()
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func openLogsOrPrint() {
	if err := OpenLogs(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: open logs: %v\n  path: %s\n", err, EnsureLogsReadable())
	}
}
