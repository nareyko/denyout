//go:build windows

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
)

func installCA(certPath string) error {
	if certPath == "" {
		return fmt.Errorf("empty CA path")
	}
	if _, err := os.Stat(certPath); err != nil {
		return err
	}
	// Current User Root store (UAC still often required for Local Machine; user store works for many apps).
	cmd := exec.Command("certutil", "-user", "-addstore", "Root", certPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Fallback Local Machine
		cmd = exec.Command("certutil", "-addstore", "Root", certPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err2 := cmd.Run(); err2 != nil {
			return fmt.Errorf("certutil: %v / %v", err, err2)
		}
	}
	return nil
}
