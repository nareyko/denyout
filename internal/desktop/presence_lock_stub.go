//go:build !linux

package desktop

// probeScreenLocked: non-Linux — idle-only Away until platform lock is wired.
func probeScreenLocked() (locked bool, ok bool) {
	return false, false
}
