package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSanitizeDesktopEnvDropsTempXDG(t *testing.T) {
	tmp := filepath.Clean(os.TempDir())
	env := []string{
		"HOME=/home/u",
		"XDG_STATE_HOME=" + filepath.Join(tmp, "do-st"),
		"XDG_CONFIG_HOME=" + filepath.Join(tmp, "do-cfg"),
		"XDG_STATE_HOME=/home/u/.local/state",
		"PATH=/bin",
	}
	got := sanitizeDesktopEnv(env)
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, filepath.Join(tmp, "do-st")) || strings.Contains(joined, filepath.Join(tmp, "do-cfg")) {
		t.Fatalf("temp XDG should be dropped: %v", got)
	}
	if runtime.GOOS != "windows" && !strings.Contains(joined, "XDG_STATE_HOME=/home/u/.local/state") {
		t.Fatalf("real XDG_STATE_HOME should keep: %v", got)
	}
}
