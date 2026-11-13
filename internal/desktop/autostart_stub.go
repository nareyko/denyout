//go:build !linux && !darwin && !windows

package desktop

import (
	"fmt"
	"os/exec"
)

func registerAutostartLinux(string) error  { return fmt.Errorf("not linux") }
func registerAutostartDarwin(string) error { return fmt.Errorf("not darwin") }
func registerAutostartWindows(string) error {
	return fmt.Errorf("not windows")
}

func updateMacAutostartEnv(string, string) error { return nil }
func writeWindowsUserProxy(string, string) error { return nil }
func clearWindowsUserProxy() error               { return nil }

func detachCmd(cmd *exec.Cmd) {}
