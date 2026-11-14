//go:build windows

package desktop

import "fmt"

func registerAutostartLinux(string) error  { return fmt.Errorf("not linux") }
func registerAutostartDarwin(string) error { return fmt.Errorf("not darwin") }
func unregisterAutostartLinux() error      { return nil }
func unregisterAutostartDarwin() error     { return nil }

func updateMacAutostartEnv(string, string) error { return nil }
