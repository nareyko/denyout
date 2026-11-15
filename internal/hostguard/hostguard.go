// Package hostguard installs transparent HTTP(S) redirect + CA trust for
// "Protect this computer" mode (Linux nftables, macOS pf, Windows WinDivert).
package hostguard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ErrNeedsAdmin means elevation was denied or required.
var ErrNeedsAdmin = errors.New("denyout hostguard: administrator privileges required")

// ErrElevateDisabled means pkexec/sudo was skipped (DENYOUT_TEST_NO_ELEVATE or GITHUB_ACTIONS).
// Not a user password cancel — desktop must not sticky "Off (unavailable)" or claim a password window appeared.
var ErrElevateDisabled = errors.New("elevate disabled in test/CI")

// ErrUnsupported is returned when Protect computer cannot be enabled on this OS build.
var ErrUnsupported = errors.New("denyout hostguard: Protect this computer is not available on this platform build")

// ElevateDisabledByEnv reports whether elevation is short-circuited for tests/CI.
func ElevateDisabledByEnv() bool {
	return os.Getenv("DENYOUT_TEST_NO_ELEVATE") == "1" || os.Getenv("GITHUB_ACTIONS") == "true"
}

// IsElevateDisabled reports whether err is the test/CI elevate skip (possibly wrapped).
func IsElevateDisabled(err error) bool {
	return err != nil && errors.Is(err, ErrElevateDisabled)
}

// ErrDriverMissing means Windows WinDivert driver/DLL is not beside the binary.
var ErrDriverMissing = errors.New("denyout hostguard: WinDivert driver not found (required on Windows)")

// Spec describes a transparent redirect target.
type Spec struct {
	ProxyPort int
	UID       int    // desktop user uid (Unix); ignored on Windows
	CACert    string // path to DenyOut CA PEM
	DryRun    bool   // render only; do not apply
}

// Status is a short machine-readable state for the tray/UI.
type Status struct {
	Active   bool   `json:"active"`
	Platform string `json:"platform"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

// CurrentUID returns the numeric uid for the current user (Unix), or 0 on Windows.
func CurrentUID() (int, error) {
	u, err := user.Current()
	if err != nil {
		return 0, err
	}
	if u.Uid == "" {
		return 0, nil
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Apply installs CA trust (best-effort) and transparent redirect rules.
func Apply(spec Spec) error {
	if spec.ProxyPort <= 0 || spec.ProxyPort > 65535 {
		return fmt.Errorf("invalid proxy port %d", spec.ProxyPort)
	}
	if spec.UID == 0 {
		uid, err := CurrentUID()
		if err != nil {
			return err
		}
		spec.UID = uid
	}
	if spec.DryRun {
		_, err := Render(spec)
		return err
	}
	if err := installCA(spec.CACert); err != nil {
		return err
	}
	return applyRedirect(spec)
}

// Remove tears down redirect rules. CA is left in the trust store.
// Use Teardown (uninstall) to also remove system CA trust.
func Remove(spec Spec) error {
	if spec.UID == 0 {
		uid, err := CurrentUID()
		if err == nil {
			spec.UID = uid
		}
	}
	return removeRedirect(spec)
}

// Teardown removes redirect rules and the system CA installed by Apply.
// User NSS trust is removed separately via UntrustCAForUserBrowsers (no root).
func Teardown(spec Spec) error {
	if err := Remove(spec); err != nil {
		// Still attempt CA uninstall even if rules were already gone.
		_ = uninstallCA()
		return err
	}
	return uninstallCA()
}

// Render returns the platform rule text for tests / dry-run (no privileges).
func Render(spec Spec) (string, error) {
	return renderRules(spec)
}

// SelfExe returns the path to the CLI `denyout` binary for pkexec/osascript/proxyd.
// When the running process is denyout-desktop (Wails), elevation must not re-exec
// the GUI binary (GTK init fails under pkexec) — resolve sibling/PATH `denyout`.
func SelfExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return ResolveCLIExe(exe)
}

// ResolveCLIExe maps a running executable path to the CLI denyout used for hostctl.
func ResolveCLIExe(exe string) (string, error) {
	base := filepath.Base(exe)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if !strings.Contains(strings.ToLower(name), "denyout-desktop") {
		return exe, nil
	}
	dir := filepath.Dir(exe)
	cand := filepath.Join(dir, "denyout")
	if runtime.GOOS == "windows" {
		cand += ".exe"
	}
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return cand, nil
	}
	if p, err := exec.LookPath("denyout"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("denyout CLI not found beside %s (install denyout next to denyout-desktop for Protect computer)", exe)
}
