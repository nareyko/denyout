package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
)

// UninstallOptions controls product uninstall.
type UninstallOptions struct {
	KeepConfig  bool // leave XDG config/state/share/cache
	Yes         bool // reserved for non-interactive (always non-interactive today)
	SkipElevate bool // tests / already-root callers: run Teardown without pkexec
}

// Uninstall fully tears down a machine install: processes, hostguard+system CA,
// NSS trust, autostart, optional XDG data, and binaries in DefaultInstallDir.
// Does not delete source trees or cloud account data.
func Uninstall(opts UninstallOptions) error {
	_ = opts.Yes
	fmt.Fprintln(os.Stderr, "denyout uninstall: stopping tray/proxyd...")
	StopPreviousInstances()
	notify.CloseAll()

	uid, _ := hostguard.CurrentUID()
	fmt.Fprintln(os.Stderr, "denyout uninstall: removing hostguard + system CA (admin once if prompted)...")
	var tearErr error
	if opts.SkipElevate || os.Getenv("DENYOUT_UNINSTALL_NO_ELEVATE") == "1" {
		tearErr = hostguard.Teardown(hostguard.Spec{ProxyPort: 0, UID: uid})
		_ = hostguard.UninstallHelper() // no-op unless already root
	} else {
		tearErr = hostguard.ElevateTeardown(0, uid)
	}
	if tearErr != nil {
		fmt.Fprintf(os.Stderr, "denyout uninstall: warning: elevated teardown: %v\n", tearErr)
		fmt.Fprintln(os.Stderr, "  (continue with user-space cleanup; re-run with sudo/pkexec if rules/CA remain)")
	}
	// Belt-and-suspenders: helper teardown should remove the unit, but if
	// ElevateTeardown used a live helper that only tore down rules/CA, or pkexec
	// was cancelled mid-way, stop/disable denyout-hostguard.service explicitly.
	fmt.Fprintln(os.Stderr, "denyout uninstall: removing hostguard helper unit (if any)...")
	if opts.SkipElevate || os.Getenv("DENYOUT_UNINSTALL_NO_ELEVATE") == "1" {
		_ = hostguard.UninstallHelper()
	} else if err := hostguard.ElevateUninstallHelper(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout uninstall: warning: helper unit: %v\n", err)
		fmt.Fprintln(os.Stderr, "  (if denyout-hostguard.service is still active: sudo systemctl disable --now denyout-hostguard.service)")
	}

	fmt.Fprintln(os.Stderr, "denyout uninstall: removing browser NSS CA (if any)...")
	if err := hostguard.UntrustCAForUserBrowsers(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout uninstall: warning: NSS untrust: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "denyout uninstall: unregistering autostart...")
	if err := UnregisterAutostart(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout uninstall: warning: autostart: %v\n", err)
	}
	cleanupExtraAutostartArtifacts()

	if !opts.KeepConfig {
		fmt.Fprintln(os.Stderr, "denyout uninstall: removing config/state/cache...")
		for _, p := range uninstallDataDirs() {
			if err := os.RemoveAll(p); err != nil {
				fmt.Fprintf(os.Stderr, "denyout uninstall: warning: remove %s: %v\n", p, err)
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "denyout uninstall: keeping config/state (--keep-config)")
	}

	dir := DefaultInstallDir()
	fmt.Fprintf(os.Stderr, "denyout uninstall: removing binaries in %s...\n", dir)
	for _, name := range []string{"denyout", "denyout-desktop"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "denyout uninstall: warning: remove %s: %v\n", p, err)
		}
	}
	if dir != "" {
		WarnStaleBinariesOnPATH(dir)
	}

	printUninstallVerification(opts.KeepConfig)
	fmt.Fprintln(os.Stderr, "denyout uninstall: done")
	return nil
}

func uninstallDataDirs() []string {
	home, _ := os.UserHomeDir()
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" && home != "" {
		cfg = filepath.Join(home, ".config")
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" && home != "" {
		state = filepath.Join(home, ".local", "state")
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" && home != "" {
		data = filepath.Join(home, ".local", "share")
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" && home != "" {
		cache = filepath.Join(home, ".cache")
	}
	var out []string
	if cfg != "" {
		out = append(out, filepath.Join(cfg, "denyout"))
	}
	if state != "" {
		out = append(out, filepath.Join(state, "denyout"))
	}
	if data != "" {
		out = append(out, filepath.Join(data, "denyout-desktop"))
	}
	if cache != "" {
		out = append(out, filepath.Join(cache, "denyout-desktop"))
	}
	return out
}

func cleanupExtraAutostartArtifacts() {
	if runtime.GOOS != "linux" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	unitDir := filepath.Join(cfg, "systemd", "user")
	_ = os.Remove(filepath.Join(unitDir, "denyout-desktop.service"))
	_ = os.Remove(filepath.Join(unitDir, "denyout-desktop.service.off"))
	// Masked unit may be a symlink to /dev/null.
	mask := filepath.Join(unitDir, "denyout-desktop.service")
	if fi, err := os.Lstat(mask); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(mask)
	}
}

func printUninstallVerification(keepConfig bool) {
	fmt.Fprintln(os.Stderr, "denyout uninstall: verification")
	check := func(ok bool, label string) {
		if ok {
			fmt.Fprintf(os.Stderr, "  OK  %s\n", label)
		} else {
			fmt.Fprintf(os.Stderr, "  FAIL %s\n", label)
		}
	}
	dir := DefaultInstallDir()
	bin := filepath.Join(dir, "denyout")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	_, err := os.Stat(bin)
	check(os.IsNotExist(err), "no install-dir denyout binary")

	if runtime.GOOS == "linux" {
		_, err = os.Stat(hostguard.LinuxSystemCACert)
		check(os.IsNotExist(err), "no system CA crt")
		_, err = os.Stat(hostguard.LinuxSystemCAHashLink)
		check(os.IsNotExist(err), "no /etc/ssl/certs/denyout-desktop.pem")
		_, err = os.Stat("/etc/systemd/system/denyout-hostguard.service")
		check(os.IsNotExist(err), "no denyout-hostguard.service unit")
	}
	if !keepConfig {
		cfg := filepath.Dir(StatePath())
		_, err = os.Stat(cfg)
		check(os.IsNotExist(err), "no ~/.config/denyout")
	}
	// Stale PATH hint already printed by WarnStaleBinariesOnPATH.
	_ = strings.Builder{}
}
