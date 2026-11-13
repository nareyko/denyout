//go:build linux

package desktop

import "fmt"

func registerAutostartDarwin(string) error  { return fmt.Errorf("not darwin") }
func registerAutostartWindows(string) error { return fmt.Errorf("not windows") }

func updateMacAutostartEnv(string, string) error { return nil }
func writeWindowsUserProxy(string, string) error { return nil }
func clearWindowsUserProxy() error               { return nil }
