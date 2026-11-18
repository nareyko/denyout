//go:build !windows

package hostguard

import "syscall"

// auditNoFollow keeps the root helper from appending through a planted symlink.
const auditNoFollow = syscall.O_NOFOLLOW
