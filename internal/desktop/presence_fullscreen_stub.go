//go:build !linux

package desktop

// probeFullscreen: non-Linux — no detector yet (idle/Away still apply).
func probeFullscreen() (fullscreen bool, ok bool) {
	return false, false
}
