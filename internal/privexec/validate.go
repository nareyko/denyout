package privexec

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
)

var ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// ValidIface checks a Linux network interface name (IFNAMSIZ-1 characters).
func ValidIface(s string) error {
	if !ifaceRE.MatchString(s) {
		return fmt.Errorf("invalid interface name %q", s)
	}
	return nil
}

// ValidUID checks a non-root numeric uid.
func ValidUID(uid int) error {
	if uid <= 0 || uid > 4294967294 {
		return fmt.Errorf("invalid uid %d", uid)
	}
	return nil
}

// ValidPort checks a TCP/UDP port.
func ValidPort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %d", p)
	}
	return nil
}

// ValidAbsPath requires a clean absolute path without NUL.
func ValidAbsPath(p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("invalid path %q", p)
	}
	if _, err := strconv.Unquote(`"` + p + `"`); err != nil { // rejects control characters
		return fmt.Errorf("invalid path %q", p)
	}
	return nil
}
