//go:build !linux

package hostguard

// ReadQUICDropStats is Linux nft-only for now (pf/WinDivert counters are a later track).
func ReadQUICDropStats() (QUICDropStats, error) {
	return QUICDropStats{}, nil
}
