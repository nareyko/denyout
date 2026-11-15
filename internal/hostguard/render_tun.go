package hostguard

import "github.com/nareyko/denyout/internal/tun"

func renderTUNPreview(uid int) string {
	return tun.RenderT1SteerTable(uid)
}
