# Changelog

## Unreleased

## 0.2.1 — Safe desktop Cursor/API auth headers (2026-11-14)

### Fixed

- **Safe desktop** no longer treats normal `Authorization` / API-key headers to ordinary sites (e.g. `api2.cursor.sh`) as `secret_in_header` exfil. Blocklist mode allows auth headers except toward explicit deny hosts / canaries.

## 0.2.0 — Safe desktop, profiles, wrap learning, srt (2026-11-14)

### Changed

- **Safe desktop default:** Protect computer uses the browse policy (web works; secrets/canaries/SSRF still block). Host Ask is off for Safe desktop. Whole-PC **Agents only** requires an explicit confirm (default No) with a messengers warning.
- **No silent Session:** admin failure and restore no longer fall back to Session mode (stays Off). Legacy Session preference is cleared on restore with a toast. Session remains an internal/advanced path only — not a tray peer.
- **First-run / tray:** Protect computer · My agents… · Agents only (whole PC)… · Off; Help & logs; Test; DenyOut version footer; Quit leaves Protect-on for next login. Soft Not-now nudge; upgrade migration dialog for old Agents-only defaults.
- **Ask UX:** urgent toast “DenyOut needs a decision” then dialog; default button Keep blocked; ~2 min timeout → blocked; global Ask queue; pause after Ask storm + Resume asks; sound on Ask only. Secret toast: “Blocked a link that looked like it contained a secret” (coalesced).
- **Native Ask / Activity (no web):** Ask uses a 3-button OS dialog (Allow once / Always allow / Keep blocked); concurrent Ask prompts coalesce per host; short suppress after Keep blocked.
- **Open activity…** opens a native denial list. Tray **Always-allow list…** + Undo last always-allow. Proxyd loopback JSON IPC unchanged.
- **IP literals:** hard-deny (no Ask). Prefer Safe desktop for messengers that connect by IP.
- **Agent preset:** Cursor allowlist includes `*.cursor.sh` / `*.cursor.com`.

### Added

- **Named agent profiles** (`~/.config/denyout/profiles/*.yaml`): My agents wizard; CLI `denyout profile create|list|run|pin|discard|delete`; `denyout run --profile <id>`.
- **Learning:** Once → `pending_once`; Pin all / Discard; counter in tray; after Pin, learning defaults off.
- **Stronger isolation:** real `--sandbox=srt` wrap via Anthropic `srt` (fail closed if required / missing); wrap without srt prints an honest residual line.
- Docs: `docs/qa-desktop-ux.md`; README / 06 / 07 updated for Safe desktop vs wrap.

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
