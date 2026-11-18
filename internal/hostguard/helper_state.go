package hostguard

import (
	"encoding/json"
	"fmt"

	"github.com/nareyko/denyout/internal/protectstate"
)

// persistedHelperState is the helper's desired state, kept on disk so a crashed or
// restarted helper can restore full protection instead of leaving whatever partial
// ruleset (e.g. the TUN-suppressed one) was in the kernel.
type persistedHelperState struct {
	Version int  `json:"version"`
	Spec    Spec `json:"spec"`
	// FailPolicy is the user's proxy-loss setting ("open"|"closed"|""), kept so a helper
	// restart keeps enforcing it. Additive field: version stays 1.
	FailPolicy string `json:"fail_policy,omitempty"`
}

const helperStateVersion = 1

// encodeHelperState stores only the user-intent part of the spec (never the TUN
// suppression flags: those describe a transient data-plane state).
func encodeHelperState(spec Spec) ([]byte, error) {
	return encodeHelperStatePolicy(spec, "")
}

// encodeHelperStatePolicy is encodeHelperState plus the configured fail policy
// (anything other than open|closed is dropped).
func encodeHelperStatePolicy(spec Spec, policy protectstate.FailPolicy) ([]byte, error) {
	spec.TunTCP, spec.TunV6Guard, spec.TunV6DropQUIC, spec.DryRun = false, false, false, false
	st := persistedHelperState{Version: helperStateVersion, Spec: spec}
	if protectstate.ValidFailPolicy(string(policy)) {
		st.FailPolicy = string(policy)
	}
	return json.Marshal(st)
}

// decodeHelperFailPolicy extracts the persisted fail policy ("" when absent or invalid).
// A tampered value can only ever be ignored, never widen anything.
func decodeHelperFailPolicy(b []byte) protectstate.FailPolicy {
	var st persistedHelperState
	if len(b) == 0 || len(b) > 64<<10 || json.Unmarshal(b, &st) != nil {
		return ""
	}
	if protectstate.ValidFailPolicy(st.FailPolicy) {
		return protectstate.FailPolicy(st.FailPolicy)
	}
	return ""
}

// decodeHelperState parses and validates a persisted state against the configured owner.
// Anything suspicious yields an error and the state is ignored (fail safe: no re-apply).
func decodeHelperState(b []byte, ownerUID int) (Spec, error) {
	if len(b) == 0 || len(b) > 64<<10 {
		return Spec{}, fmt.Errorf("helper state: bad size")
	}
	var st persistedHelperState
	if err := json.Unmarshal(b, &st); err != nil {
		return Spec{}, fmt.Errorf("helper state: %w", err)
	}
	if st.Version != helperStateVersion {
		return Spec{}, fmt.Errorf("helper state: unsupported version %d", st.Version)
	}
	s := st.Spec
	if ownerUID <= 0 || s.UID != ownerUID {
		return Spec{}, fmt.Errorf("helper state: uid does not match owner")
	}
	if s.ProxyPort < 1 || s.ProxyPort > 65535 {
		return Spec{}, fmt.Errorf("helper state: bad proxy port")
	}
	if err := validateHelperCAPath(s.CACert, ownerUID); err != nil {
		return Spec{}, fmt.Errorf("helper state: %w", err)
	}
	s.TunTCP, s.TunV6Guard, s.TunV6DropQUIC, s.DryRun = false, false, false, false
	return s, nil
}
