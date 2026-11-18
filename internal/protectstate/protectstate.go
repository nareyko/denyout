// Package protectstate is the single source of truth for the protection state
// machine: which state DenyOut is in (off, protected, session, degraded, ...) and
// the human reason, computed by one pure function from plain inputs.
//
// It is a leaf package (stdlib only) so hostguard, desktop and the tray can all
// share it without import cycles. Callers gather the inputs (live processes,
// helper state file, CA presence, pause intent, status text) and call Compute.
package protectstate

import "strings"

// State is the user-visible protection state.
type State string

const (
	Off            State = "off"
	Protected      State = "protected"       // live proxyd, browse/safe profile
	AgentsOnly     State = "agents"          // live proxyd, whole-PC Agents profile
	Session        State = "session"         // live in-process session proxy
	Paused         State = "paused"          // off with an active pause
	Degraded       State = "degraded"        // helper watchdog removed the redirect (fail-soft)
	NeedsAttention State = "needs_attention" // intended on but broken
)

// Reason codes explain why a state was chosen (stable identifiers for UX/logs).
const (
	ReasonNone           = ""
	ReasonStatusError    = "status_error"
	ReasonNotRunning     = "not_running"
	ReasonHelperDegraded = "helper_degraded"
	ReasonCAMissing      = "ca_missing"
	ReasonPaused         = "paused"
	// ReasonTampered: the helper audit trail shows another program lowered protection
	// (remove, teardown, fail-policy open, ...). Detection only; see docs/10-security-boundaries.md.
	ReasonTampered = "tampered"
)

// Inputs are the facts the state is derived from.
type Inputs struct {
	// Intent: user wants protection on (ComputerEnabled || ProtectionOn persisted flags).
	Intent bool
	// ProxydLive / SessionLive: live protector processes.
	ProxydLive  bool
	SessionLive bool
	// AgentsProfile: policy profile is whole-PC Agents (affects the live label only).
	AgentsProfile bool
	// Status is the app's free-text status line; an "error" or "Needs" marks failure.
	Status string
	// HelperDegraded: helper watchdog state is "degraded" (redirect removed).
	HelperDegraded bool
	// CAPresent: the MITM CA certificate exists on disk.
	CAPresent bool
	// Paused: an active (unexpired) pause or "off until you turn it on" is in effect.
	Paused bool
	// FailPolicy is the effective proxy-loss policy ("" = unknown; messages then stay
	// generic). It only changes the wording of Message, never the State.
	FailPolicy FailPolicy
	// Tampered is set while an unacknowledged suspicious helper change is on record;
	// TamperNote is its one-sentence description ("Protect was changed by ...").
	Tampered   bool
	TamperNote string
}

// Result is the computed state.
type Result struct {
	State State
	// Mode is the live protector only: "safe", "agents", "session" or "off".
	Mode string
	// NeedsAttention: intended On but broken (Home/tray "Needs attention").
	NeedsAttention bool
	// Reason is a stable code; Message is the human sentence.
	Reason  string
	Message string
}

// Compute derives the state. It is pure: no I/O, no clock.
func Compute(in Inputs) Result {
	r := Result{Mode: liveMode(in)}
	wantOn := in.Intent || in.ProxydLive || in.SessionLive
	if wantOn {
		switch {
		case in.Tampered:
			r.NeedsAttention, r.Reason = true, ReasonTampered
			r.Message = tamperMessage(in.TamperNote)
		case isErrorStatus(in.Status):
			r.NeedsAttention, r.Reason = true, ReasonStatusError
			r.Message = "Protection reported an error."
		case !in.ProxydLive && !in.SessionLive:
			r.NeedsAttention, r.Reason = true, ReasonNotRunning
			r.Message = "Protection is meant to be on but is not running." + policyNote(in.FailPolicy, false)
		case in.ProxydLive && in.HelperDegraded:
			// Watchdog pulled the redirect (proxy stopped answering): traffic is unfiltered.
			r.NeedsAttention, r.Reason = true, ReasonHelperDegraded
			r.Message = "The proxy stopped answering; traffic is unfiltered until it recovers." + policyNote(in.FailPolicy, true)
		case !in.CAPresent:
			r.NeedsAttention, r.Reason = true, ReasonCAMissing
			r.Message = "The DenyOut certificate is missing."
		}
	}
	switch {
	case r.NeedsAttention && r.Reason == ReasonHelperDegraded:
		r.State = Degraded
	case r.NeedsAttention:
		r.State = NeedsAttention
	default:
		switch r.Mode {
		case "safe":
			r.State = Protected
		case "agents":
			r.State = AgentsOnly
		case "session":
			r.State = Session
		default:
			if in.Paused {
				r.State, r.Reason, r.Message = Paused, ReasonPaused, "Protection is paused."
			} else {
				r.State = Off
			}
		}
	}
	return r
}

func tamperMessage(note string) string {
	if note = strings.TrimSpace(note); note != "" {
		return note
	}
	return "Protect was changed by another program."
}

// policyNote says which proxy-loss policy is active ("" when unknown).
func policyNote(p FailPolicy, degraded bool) string {
	switch p {
	case FailOpen:
		if degraded {
			return " Your setting keeps the internet working when the proxy stops."
		}
		return " Your setting keeps the internet working when the proxy stops, so traffic may be unfiltered."
	case FailClosed:
		return " Your setting blocks web traffic until the proxy recovers."
	}
	return ""
}

func liveMode(in Inputs) string {
	switch {
	case in.ProxydLive && in.AgentsProfile:
		return "agents"
	case in.ProxydLive:
		return "safe"
	case in.SessionLive:
		return "session"
	}
	return "off"
}

func isErrorStatus(status string) bool {
	return strings.Contains(strings.ToLower(status), "error") || strings.Contains(status, "Needs")
}

// ModeLabel is the pill text for a live mode ("safe", "agents", "session", other).
func ModeLabel(mode string) string {
	switch mode {
	case "safe":
		return "Protected"
	case "agents":
		return "Agents only"
	case "session":
		return "Session"
	default:
		return "Off"
	}
}

// HelperStateDegraded reports whether helper state-file content means degraded
// (the file holds one word plus optional detail, e.g. "degraded proxy_down").
func HelperStateDegraded(content string) bool {
	return strings.HasPrefix(strings.TrimSpace(content), "degraded")
}
