package desktop

import "github.com/nareyko/denyout/internal/profiles"

// Allow packs live in internal/profiles; aliases keep the desktop API stable.
type AllowPack = profiles.AllowPack

var (
	ListAllowPacks  = profiles.ListAllowPacks
	LookupAllowPack = profiles.LookupAllowPack
	SuggestPackID   = profiles.SuggestPackID
	ApplyPack       = profiles.ApplyPack
	UndoPack        = profiles.UndoPack
)
