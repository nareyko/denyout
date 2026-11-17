//go:build linux

package hostguard

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const helperTrustedDir = "/usr/lib/denyout"

// pathChainRootOwned reports whether path and every parent directory are owned
// by root and not writable by group/other (so an unprivileged user cannot
// swap the binary that a root service executes).
func pathChainRootOwned(path string) bool {
	p := filepath.Clean(path)
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if fi.Mode()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return false
		}
		parent := filepath.Dir(p)
		if parent == p {
			return true
		}
		p = parent
	}
}

// trustedHelperExe returns a path that is safe to put in a root systemd unit.
// If exe lives somewhere a non-root user can modify, a root-owned copy is
// installed under /usr/lib/denyout and used instead.
func trustedHelperExe(exe string) (string, error) {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if pathChainRootOwned(exe) {
		return exe, nil
	}
	if err := os.MkdirAll(helperTrustedDir, 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(helperTrustedDir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(helperTrustedDir, "denyout-cli")
	tmp, err := os.CreateTemp(helperTrustedDir, ".denyout-cli-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	src, err := os.Open(exe)
	if err != nil {
		tmp.Close()
		return "", err
	}
	defer src.Close()
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return "", fmt.Errorf("install trusted helper binary: %w", err)
	}
	return dst, nil
}
