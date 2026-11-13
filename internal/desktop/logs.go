package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
)

// AuditLogPath returns the desktop audit JSONL path.
func AuditLogPath() string {
	return audit.DefaultDesktopPath()
}

// LogDir is where desktop diagnostics live (audit + desktop.log + last-error.txt).
func LogDir() string {
	return filepath.Dir(AuditLogPath())
}

// DesktopLogPath is the append-only desktop/hostguard diagnostic log.
func DesktopLogPath() string {
	return filepath.Join(LogDir(), "desktop.log")
}

// LastErrorPath is a short file with the most recent actionable error (easy to copy).
func LastErrorPath() string {
	return filepath.Join(LogDir(), "last-error.txt")
}

// AppendDesktopLog writes a timestamped line to desktop.log.
func AppendDesktopLog(format string, args ...any) {
	_ = os.MkdirAll(LogDir(), 0o755)
	line := time.Now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, args...) + "\n"
	f, err := os.OpenFile(DesktopLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprint(os.Stderr, line)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
	fmt.Fprint(os.Stderr, line)
}

// RecordError persists the last error for tray "Open logs" / "Copy last error".
func RecordError(kind, detail string) {
	AppendDesktopLog("ERROR [%s] %s", kind, detail)
	_ = os.MkdirAll(LogDir(), 0o755)
	body := fmt.Sprintf(`DenyOut error
Time (UTC): %s
Kind: %s

%s

---
Logs folder: %s
desktop.log: %s
audit.jsonl: %s
`, time.Now().UTC().Format(time.RFC3339), kind, strings.TrimSpace(detail), LogDir(), DesktopLogPath(), AuditLogPath())
	_ = os.WriteFile(LastErrorPath(), []byte(body), 0o600)
}

// ReadLastError returns last-error.txt contents (may be empty).
func ReadLastError() string {
	b, err := os.ReadFile(LastErrorPath())
	if err != nil {
		return ""
	}
	return string(b)
}

// OpenLogs reveals the log directory (audit + desktop.log + last-error.txt).
func OpenLogs() error {
	dir := LogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Ensure files exist so the folder looks useful.
	if _, err := os.Stat(AuditLogPath()); os.IsNotExist(err) {
		_ = os.WriteFile(AuditLogPath(), []byte(""), 0o600)
	}
	if _, err := os.Stat(DesktopLogPath()); os.IsNotExist(err) {
		_ = os.WriteFile(DesktopLogPath(), []byte(""), 0o600)
	}
	if _, err := os.Stat(LastErrorPath()); os.IsNotExist(err) {
		_ = os.WriteFile(LastErrorPath(), []byte("No errors recorded yet.\n"), 0o600)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", dir).Start()
	case "windows":
		return exec.Command("explorer", dir).Start()
	default:
		if err := exec.Command("xdg-open", dir).Start(); err == nil {
			return nil
		}
		return exec.Command("xdg-open", LastErrorPath()).Start()
	}
}

// CopyLastErrorToClipboard copies last-error.txt (or a hint) to the clipboard.
func CopyLastErrorToClipboard() (string, error) {
	text := strings.TrimSpace(ReadLastError())
	if text == "" || text == "No errors recorded yet." {
		text = fmt.Sprintf("No DenyOut error recorded yet.\nLogs: %s", LogDir())
	}
	if err := copyToClipboard(text); err != nil {
		return text, err
	}
	return text, nil
}

func copyToClipboard(text string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Set-Clipboard -Value $input")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd := exec.Command("wl-copy")
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd := exec.Command("xclip", "-selection", "clipboard")
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		}
		if _, err := exec.LookPath("xsel"); err == nil {
			cmd := exec.Command("xsel", "--clipboard", "--input")
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		}
		return fmt.Errorf("no clipboard tool (wl-copy/xclip/xsel)")
	}
}

func openLogsOrPrint() {
	AppendDesktopLog("INFO open logs dir=%s", LogDir())
	if err := OpenLogs(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: open logs: %v\n  dir: %s\n", err, LogDir())
		notifyLogHint()
	}
}

func copyLastErrorOrPrint() {
	text, err := CopyLastErrorToClipboard()
	if err != nil {
		AppendDesktopLog("WARN clipboard: %v — print last error instead", err)
		fmt.Fprintln(os.Stderr, "----- DenyOut last error (copy from here) -----")
		fmt.Fprintln(os.Stderr, text)
		fmt.Fprintln(os.Stderr, "----- end -----")
		notify.Info("DenyOut", "Could not copy — last error printed to terminal. Logs: "+LogDir())
		return
	}
	AppendDesktopLog("INFO copied last error to clipboard (%d bytes)", len(text))
	notify.Info("DenyOut", "Last error copied to clipboard. Also in "+LastErrorPath())
}

func notifyLogHint() {
	notify.Info("DenyOut", "Logs: "+LogDir())
}
