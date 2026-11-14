# Changelog

## Unreleased

## 0.3.0 - Uninstall + install/quit hygiene (2026-11-14)

### Added

- **`denyout uninstall`**: full local tear-down - stop tray/proxyd, `hostctl teardown` (redirect + system CA, one admin prompt), NSS untrust, autostart, XDG data, binaries in install dir. Flag `--keep-config`. Docs: [`docs/07-desktop.md`](docs/07-desktop.md) §6.
- Install upgrade hygiene: harder stop of previous desktop/proxyd, PATH stale warnings.
- **Optional Account + sync** (Settings -> Advanced): magic-link sign-in / sign out. **Sync now** pull/push with last-write-wins. **Delete cloud data** (server account + blob). Local-only when signed out. Protect never requires an account. UX: [`docs/07-desktop-ux.md`](docs/07-desktop-ux.md), [`docs/cloud-sync.md`](docs/cloud-sync.md).
- **Cloud sync schema** (`internal/cloudsync` + desktop export/apply map): versioned settings blob for optional signed-in sync. Never includes audit/secrets.
- **App updates (no account):** `internal/updates` public JSON client + desktop **Check for updates** (Settings -> Diagnostics). Home/Problems tip when newer. Fail-open if offline. Example: [`docs/updates/desktop.example.json`](docs/updates/desktop.example.json).
- **Threat lists (Book C):** Phishing Army + URLhaus (on after first good fetch) + optional Stronger (HaGeZi TIF medium). Settings Basic toggles, poll interval, Refresh now. Reason `threat_list` -> post-block HITL. Advanced optional OISD / StevenBlack (off). Product unbreak (Book D) + read-only Product exceptions. Plan/QA: [`docs/ux-iters/threat-lists-plan.md`](docs/ux-iters/threat-lists-plan.md), [`docs/ux-iters/threat-lists-qa.md`](docs/ux-iters/threat-lists-qa.md).
- **Agent allow packs:** `cursor-starter` / `claude-starter`. Ask on new agent. Undo pack in My agents.
- Docs: normative desktop UX inventory [`docs/07-desktop-ux.md`](docs/07-desktop-ux.md) (install, tray, menu, every screen).
- **`denyout-desktop`** (Wails v2 + React/TS): Activity / My agents / Settings / Problems. Tray **Open DenyOut...**. Close hides to tray.
- Dual artifacts: static **`denyout`** (CLI/proxy) + CGO **`denyout-desktop`**. `Install.sh` fetches both when present. Autostart prefers desktop binary.
- **Your setup** dialog after first-run / install (mode, what to expect, Activity / Problems pointers).
- **Post-block confirm** on Safe desktop clear threats: 15s **Keep blocked** / **Allow this site**. Keep remembered per host+reason.
- **Activity:** Time / Site / Why. Drawer URL + codes. Always allow / Allow this site.
- Post-block / deny toasts include **redacted URL** when known (secrets -> `***`).

### Changed

- Tray **Quit DenyOut** fully unloads hostguard (admin once if needed) and exits; no longer leave-on restore. Window close still hides to tray.
- **Desktop UX backlog:** compact tray. Left-click -> Activity. Toast **Keep blocked / Allow this site**. Settings **Basic | Advanced**.
- **UX2 polish:** nav **My agents**. Agents only -> Advanced. Tips one-at-a-time. Activity **Select...** + Group by host under Filters. Human reason labels. Your setup **Open DenyOut** / Got it. Tray My agents opens window. Top bar Needs attention. Empty Activity CTA. Settings find + Jump sections.
