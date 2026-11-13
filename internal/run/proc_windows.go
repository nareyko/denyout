//go:build windows

package run

import "os/exec"

func setProcGroup(cmd *exec.Cmd) {
	// Windows: no POSIX process groups; child lifetime still ends with Wait.
}

func killProcGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
