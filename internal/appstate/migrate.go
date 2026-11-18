package appstate

import "strings"

// CurrentSchemaVersion is the desktop.json schema version written by SaveState.
//
// History:
//
//	0  files written before versioning (no "schema_version" key)
//	1  adds schema_version; legacy defaults below are applied once on read
//	2  adds fail_policy (proxy-loss policy: ""|open|closed)
//
// To add a migration: bump CurrentSchemaVersion, add a `case` step to migrate
// that upgrades from the previous version, and add a fixture test in
// migrate_test.go. Steps must be idempotent and must never loosen a protection.
const CurrentSchemaVersion = 2

// migrate upgrades st (just unmarshalled from raw) to CurrentSchemaVersion in
// memory. The upgraded form is persisted on the next SaveState. Files with a
// newer version than this binary knows are loaded as-is (fields we do not know
// are ignored by encoding/json) and are never downgraded on read.
func migrate(st *State, raw []byte) {
	if st.SchemaVersion >= CurrentSchemaVersion {
		return
	}
	if st.SchemaVersion < 1 {
		migrateV0toV1(st, raw)
	}
	// 1 -> 2: fail_policy is new. Files from older builds do not have it (empty = open,
	// the long-standing default); a hand-edited value is canonicalised and can only
	// become stricter, never looser.
	st.FailPolicy = NormalizeFailPolicy(st.FailPolicy)
	st.SchemaVersion = CurrentSchemaVersion
}

// migrateV0toV1: legacy defaults that older builds applied inline in LoadState.
func migrateV0toV1(st *State, raw []byte) {
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
}
