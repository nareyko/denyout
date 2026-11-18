# Open security decisions (owner input needed)

Context: `docs/security-review-2026-11.md`.

## 1. Owner-uid trust boundary

Today any process running as the owner uid, including the sandboxed agent, can call the root helper (verbs are validated and closed, but `remove`/`teardown` still lets the agent switch Protect off). Options:

| Option | Idea | Pros | Cons |
| --- | --- | --- | --- |
| A. Per-session token | Helper requires a token the desktop app holds in memory/keychain; agent cannot read it | small change, no new uid | same-uid agent can often read process memory/env; weak on Linux without ptrace limits |
| B. Run the agent as a separate uid | `denyout run` drops to an `agent` uid; nft redirect keyed on that uid; helper accepts only the owner uid | real boundary; also fixes "other uids out of scope" for the agent | install needs a second user, file access/HOME story, macOS/Windows equivalents differ |
| C. Split verbs by privilege | Agent-reachable read-only verbs (`caps`, stats) vs. mutating verbs needing interactive polkit/Touch ID style confirmation | good UX for deliberate changes | prompts on every toggle; cannot stop a determined same-uid agent from clicking if UI is automatable |
| D. Accept + detect | Keep the model, audit every mutating verb and surface "Protect turned off by <pid>" | cheap, honest | detection, not prevention |

Suggestion: D now, B as the real fix for agent-mode (Linux first), A only combined with B.

Status: **D is implemented** (helper audit trail, `audit-tail` verb, desktop "Protect was changed" detection; see `docs/10-security-boundaries.md`). **B is worked out as a design** in [`docs/design-agent-uid-split.md`](design-agent-uid-split.md), pending an owner decision. Section 2 below is still design only.

## 2. IPv6 and DNS in the TUN data plane

Today IPv6 relies on the nft redirect + QUIC drop; DNS/DoH is out of scope.

| Option | Pros | Cons |
| --- | --- | --- |
| IPv6 through TUN (dual-stack gVisor stack) | one data plane, closes the gap structurally | more code in the root path, MTU/NAT64 edge cases |
| Disable IPv6 for the protected uid (drop v6 egress except loopback) | trivial, fail-closed | breaks v6-only destinations; surprising for users |
| DNS interception (local resolver, deny by name before connect) | enables name-level policy for non-HTTP, kills DNS-tunnel basics | DoH/DoT bypass remains unless blocked by IP lists; resolver compatibility risk |
| Block known DoH endpoints by IP | cheap | list maintenance; non-claim stays |

Suggestion: ship "drop IPv6 egress for the owner uid" as an opt-in strict mode first; revisit TUN IPv6 once the uid split (1.B) lands.
