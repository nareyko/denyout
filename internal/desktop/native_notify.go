package desktop

import "github.com/nareyko/denyout/internal/notify"

func init() {
	setNotifyEnabled = notify.SetEnabled
}
