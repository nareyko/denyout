//go:build windows

package desktop

import "fmt"

func registerAutostartLinux(string) error  { return fmt.Errorf("not linux") }
func registerAutostartDarwin(string) error { return fmt.Errorf("not darwin") }

func updateMacAutostartEnv(string, string) error { return nil }
