package desktop

import (
	"os/exec"
	"runtime"
)

func certutilAvailable() bool {
	_, err := exec.LookPath("certutil")
	return err == nil
}

func clipboardAvailable() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		for _, bin := range []string{"wl-copy", "xclip", "xsel"} {
			if _, err := exec.LookPath(bin); err == nil {
				return true
			}
		}
		return false
	}
}
