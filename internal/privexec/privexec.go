// Package privexec is the single place where DenyOut runs system tools with
// elevated privileges (nft, ip, setcap, systemctl, pfctl, ...).
//
// Rules it enforces, so callers cannot get them wrong:
//   - no shell: only an allow-listed tool, argv only (a past root command
//     injection came from interpolating an interface name into `sh -c`);
//   - tools are resolved from fixed system directories, never from $PATH or the
//     current directory;
//   - a minimal, fixed environment;
//   - a default timeout so a hung tool cannot wedge the root helper.
package privexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultTimeout bounds every tool invocation.
const DefaultTimeout = 30 * time.Second

// allowed lists the tools DenyOut may run privileged, per purpose.
var allowed = map[string]bool{
	"nft": true, "ip": true, "setcap": true, "systemctl": true,
	"update-ca-certificates": true, "pfctl": true, "security": true,
	"certutil": true, "taskkill": true,
}

var sysDirs = func() []string {
	if runtime.GOOS == "windows" {
		return []string{filepath.Join(os.Getenv("SystemRoot"), "System32")}
	}
	return []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}
}()

// Resolve returns the absolute path of an allow-listed tool.
func Resolve(tool string) (string, error) {
	if !allowed[tool] {
		return "", fmt.Errorf("privexec: tool %q is not allow-listed", tool)
	}
	exe := tool
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	for _, d := range sysDirs {
		p := filepath.Join(d, exe)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("privexec: %s not found in system directories %v", tool, sysDirs)
}

func checkArgs(args []string) error {
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("privexec: NUL byte in argument")
		}
	}
	return nil
}

func build(ctx context.Context, tool string, args []string) (*exec.Cmd, error) {
	p, err := Resolve(tool)
	if err != nil {
		return nil, err
	}
	if err := checkArgs(args); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=" + strings.Join(sysDirs, string(os.PathListSeparator)), "LC_ALL=C", "LANG=C"}
	return cmd, nil
}

// Output runs tool with args and returns combined stdout+stderr.
func Output(tool string, args ...string) ([]byte, error) {
	return OutputStdin("", tool, args...)
}

// OutputStdin is Output with data fed on stdin (e.g. an nft ruleset for `nft -f -`).
func OutputStdin(stdin, tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	cmd, err := build(ctx, tool, args)
	if err != nil {
		return nil, err
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	return buf.Bytes(), err
}

// Run runs tool and returns an error that includes the tool output.
func Run(tool string, args ...string) error {
	out, err := Output(tool, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", tool, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Best runs tool ignoring failures (cleanup paths).
func Best(tool string, args ...string) { _, _ = Output(tool, args...) }
