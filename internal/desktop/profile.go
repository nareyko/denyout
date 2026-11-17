package desktop

import "github.com/nareyko/denyout/internal/profiles"

// Agent profiles live in internal/profiles; these aliases keep the desktop API stable.
type (
	AgentProfile = profiles.AgentProfile
	Learning     = profiles.Learning
)

var (
	NormalizeProfileName = profiles.NormalizeProfileName
	NewAgentProfile      = profiles.NewAgentProfile
	ListProfiles         = profiles.ListProfiles
	LoadProfile          = profiles.LoadProfile
	SaveProfile          = profiles.SaveProfile
	DeleteProfile        = profiles.DeleteProfile
	ValidProfileID       = profiles.ValidProfileID
)
