package main

import (
	"github.com/nareyko/denyout/internal/desktop"
)

const uninstallUsage = `Usage: denyout-cli uninstall [--keep-config] [--yes]

  Full local uninstall: stop tray/proxyd, tear down hostguard + system CA
  (one admin prompt), remove NSS CA, autostart, XDG data, and binaries in
  DENYOUT_INSTALL_DIR (default ~/.local/bin).

  --keep-config  leave ~/.config/denyout-cli and related state/cache
  --yes          non-interactive (default behavior; reserved)

  Does not delete source trees or cloud account data.
  Upgrade (install.sh) is different: it keeps CA/hostguard for one Apply.`

// uninstallRun performs the uninstall; swappable in tests.
var uninstallRun = desktop.Uninstall

func parseUninstallArgs(args []string) (desktop.UninstallOptions, *cliExit) {
	var o desktop.UninstallOptions
	fs := flagSet{
		cmd:  "uninstall",
		help: uninstallUsage,
		bools: map[string]func(){
			"--keep-config": func() { o.KeepConfig = true },
			"--yes":         func() { o.Yes = true },
			"-y":            func() { o.Yes = true },
		},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	return o, nil
}

func cmdUninstall(args []string) int {
	o, ex := parseUninstallArgs(args)
	if ex != nil {
		return ex.emit()
	}
	if err := uninstallRun(o); err != nil {
		return (&cliExit{code: 1, err: "denyout-cli uninstall: " + err.Error() + "\n"}).emit()
	}
	return 0
}
