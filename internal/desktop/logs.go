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

// ReadmePath explains which files in the log dir matter for support.
func ReadmePath() string {
	return filepath.Join(LogDir(), "README.txt")
}

const logsReadme = `DenyOut diagnostics - which file to send

1) last-error.txt -> SEND THIS for admin / protect failures
2) desktop.log -> send if last-error is empty or unclear
3) audit.jsonl -> traffic decisions (allow/deny). NOT an admin error log.
 Rotates when large (~32 MiB). Use: denyout audit tail --denials

Left-click the tray icon (or Open DenyOut...) for Home / History.
Settings -> Advanced for Always-allow list and diagnostics.
Problems covers admin/CA errors and this folder.

If last-error.txt says "No errors recorded yet", Protect is OK or the
failure was not recorded.
`

// LastErrorSummary returns a short snippet for Problems UI.
func LastErrorSummary() string {
	s := strings.TrimSpace(ReadLastError())
	if s == "" {
		return ""
	}
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
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

// RecordError persists the last error for tray "Open diagnostics" / "Copy last error".
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

// OpenLogs reveals the log directory and opens last-error.txt (not audit.jsonl).
func OpenLogs() error {
	dir := LogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = os.WriteFile(ReadmePath(), []byte(logsReadme), 0o644)
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
	// Prefer opening the actionable file so users do not paste audit.jsonl.
	last := LastErrorPath()
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", "-R", last).Start()
		return exec.Command("open", last).Start()
	case "windows":
		_ = exec.Command("explorer", "/select,", last).Start()
		return exec.Command("notepad", last).Start()
	default:
		_ = exec.Command("xdg-open", last).Start()
		if err := exec.Command("xdg-open", dir).Start(); err == nil {
			return nil
		}
		return nil
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
	AppendDesktopLog("INFO open diagnostics dir=%s", LogDir())
	if err := OpenLogs(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: open diagnostics: %v\n dir: %s\n", err, LogDir())
		notifyLogHint()
	}
}

func copyLastErrorOrPrint() {
	raw := strings.TrimSpace(ReadLastError())
	noErr := raw == "" || raw == "No errors recorded yet."
	text, err := CopyLastErrorToClipboard()
	if noErr {
		if err != nil {
			AppendDesktopLog("INFO clipboard unavailable (%v); no DenyOut error recorded", err)
			notify.Info("DenyOut", "No error recorded. Install wl-clipboard to copy status. Logs: "+LogDir())
			return
		}
		AppendDesktopLog("INFO copied status (no error) to clipboard")
		notify.Info("DenyOut", "No DenyOut error recorded - status OK.")
		return
	}
	if err != nil {
		AppendDesktopLog("WARN clipboard: %v - print last error instead", err)
		fmt.Fprintln(os.Stderr, "----- DenyOut last error (copy from here) -----")
		fmt.Fprintln(os.Stderr, text)
		fmt.Fprintln(os.Stderr, "----- end -----")
		notify.Info("DenyOut", "Could not copy - see terminal or "+LastErrorPath())
		return
	}
	AppendDesktopLog("INFO copied last error to clipboard (%d bytes)", len(text))
	notify.Info("DenyOut", "Last error copied to clipboard.")
}

func notifyLogHint() {
	notify.Info("DenyOut", "Logs: "+LogDir())
}
