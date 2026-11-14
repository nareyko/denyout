# Changelog

## 0.1.9 — Agent seatbelt default (breaking)

### Breaking

- **Computer / Session default policy** is no longer “allow the web + block secrets”. Default is **enforce + `agent` allowlist** (models, package registries, git/CDN, Cursor hosts). Unknown hosts deny (or Ask when Ask mode is on).
- Legacy “browse the web” behavior moves to the **Browse** policy profile (`denyout.whole_device_browse.yaml`, tray/Activity toggle).
- New installs default **Ask mode on**. Existing installs keep saved Ask/AlwaysAllow; empty `policy_profile` migrates to `agent` on load.

### Added

- Signed-URL / session precision: tiered named query params; carve-outs for GitHub release-assets and AWS SigV4; plain `session=` without token shape allowed.
- Redirect hygiene: absolute `Location` hosts re-evaluated; denied destinations stripped before clients follow.
- Audit: optional `policy_profile`, `process`; Activity reason filter.
- Lab suites: `fp_signed`, `fp_session`, `agent_egress`, `exfil_true`, `browse_compat`, `redirect_policy`, `trifecta_smoke`.
- Docs: Rule of Two framing in `docs/07-desktop.md`; `docs/qa-agent-seatbelt.md`.

### Explicit non-goals (this release)

- Kernel connection escrow / eBPF LSM
- DNS rebinding pin for generic FetchURL tools
- OS filesystem sandbox for agents
- Prompt-level GenAI DLP / CASB
- Observe-only secret severity (deny vs warn)
