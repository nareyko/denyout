package appstate

import "strings"

// CurrentSchemaVersion is the desktop.json schema version written by SaveState.
//
// History:
//
//	0  files written before versioning (no "schema_version" key)
//	1  adds schema_version; legacy defaults below are applied once on read
//
// To add a migration: bump CurrentSchemaVersion, add a `case` step to migrate
// that upgrades from the previous version, and add a fixture test in
// migrate_test.go. Steps must be idempotent and must never loosen a protection.
const CurrentSchemaVersion = 1

// migrate upgrades st (just unmarshalled from raw) to CurrentSchemaVersion in
// memory. The upgraded form is persisted on the next SaveState. Files with a
// newer version than this binary knows are loaded as-is (fields we do not know
// are ignored by encoding/json) and are never downgraded on read.
func migrate(st *State, raw []byte) {
	if st.SchemaVersion >= CurrentSchemaVersion {
		return
	}
	// 0 -> 1: legacy defaults that older builds applied inline in LoadState.
	if st.Scope == "" && st.ComputerEnabled {
		st.Scope = ScopeComputer
		st.ProtectionOn = true
	}
	if !jsonHasKey(raw, "computer_available") {
		st.ComputerAvailable = true
	}
	if !jsonHasKey(raw, "autostart") && !st.AutostartAsked {
		st.Autostart = true
	}
	// Legacy empty profile -> was agent; migration dialog handles switch to browse.
	if strings.TrimSpace(st.PolicyProfile) == "" {
		st.PolicyProfile = PolicyProfileAgent
	}
	st.SchemaVersion = CurrentSchemaVersion
}
