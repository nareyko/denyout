//go:build !linux && !darwin && !windows

package hostguard

func installCA(certPath string) error {
	_ = certPath
	return ErrUnsupported
}
