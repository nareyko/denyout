//go:build darwin

package desktop

import "fmt"

func registerAutostartLinux(string) error   { return fmt.Errorf("not linux") }
func registerAutostartWindows(string) error { return fmt.Errorf("not windows") }
func unregisterAutostartLinux() error       { return nil }
func unregisterAutostartWindows() error     { return nil }

func writeWindowsUserProxy(string, string) error { return nil }
func clearWindowsUserProxy() error               { return nil }
