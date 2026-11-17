package desktop

import (
	"github.com/nareyko/denyout/internal/appdata"
	"github.com/nareyko/denyout/internal/appstate"
)

// Persisted state lives in internal/appstate; these aliases keep the desktop API stable.
type (
	State     = appstate.State
	TimedRule = appstate.TimedRule

	ThreatSyncPrefs = appstate.ThreatSyncPrefs
)

// Protection scope and policy profiles.
const (
	ScopeOff            = appstate.ScopeOff
	ScopeComputer       = appstate.ScopeComputer
	ScopeSession        = appstate.ScopeSession
	PolicyProfileAgent  = appstate.PolicyProfileAgent
	PolicyProfileBrowse = appstate.PolicyProfileBrowse
)

var (
	DefaultState = appstate.DefaultState
	LoadState    = appstate.LoadState
	SaveState    = appstate.SaveState

	ExportSyncDocument      = appstate.ExportSyncDocument
	ApplySyncSettings       = appstate.ApplySyncSettings
	ThreatPrefsFromSettings = appstate.ThreatPrefsFromSettings

	normalizePolicyProfile      = appstate.NormalizePolicyProfile
	effectiveNotifyLevel        = appstate.EffectiveNotifyLevel
	effectiveDecisionTimeoutSec = appstate.EffectiveDecisionTimeoutSec
	effectiveReaskIntervalSec   = appstate.EffectiveReaskIntervalSec
)

// StatePath returns the desktop state file path.
func StatePath() string { return appdata.StatePath() }

// ProfilesDir is ~/.config/denyout/profiles.
func ProfilesDir() string { return appdata.ProfilesDir() }

// CADir is the persistent desktop CA directory.
func CADir() string { return appdata.CADir() }
