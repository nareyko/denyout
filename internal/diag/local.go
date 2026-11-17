package diag

import (
	"os"
	"time"

	"github.com/nareyko/denyout/internal/appdata"
	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/threatlists"
)

// LocalInputs fills Inputs from this user's default desktop locations and the
// read-only helper probes. Callers add what only they know (ProtectionOn,
// ProxyPort, LastError).
func LocalInputs(version string) Inputs {
	home, _ := os.UserHomeDir()
	return Inputs{
		Version:   version,
		Now:       time.Now(),
		Home:      home,
		CADir:     appdata.CADir(),
		AuditPath: audit.DefaultDesktopPath(),
		ThreatDir: threatlists.DefaultDir(),
		Helper: HelperInfo{
			Present:  hostguard.HelperAvailable(),
			Degraded: hostguard.HelperDegraded(),
		},
	}
}
