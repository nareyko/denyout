//go:build !linux && !darwin && !windows

package hostguard

func applyRedirect(spec Spec) error {
	_ = spec
	return ErrUnsupported
}

func removeRedirect(spec Spec) error {
	_ = spec
	return ErrUnsupported
}
