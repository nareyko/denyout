# Changelog

## 0.4.2 - Quit unload, in-app Undo, quiet phrase (2026-11-15)

### Added

- **In-app Undo** after Allow (~10s) and after auto-resume from pause (~5s). No OS Undo button; tray shows `Undo available — open DenyOut`.
- **Quieting phrase** shared on Home, chrome, and tray: `Quiet · away` / `fullscreen` / `snoozed until …`, plus a slate-blue tray icon while quieting.
- **Fullscreen detect** chain: X11 → GNOME Eval/Introspect → Hyprland → Sway; Settings warns when detection is unavailable (common on locked-down GNOME Wayland).

### Changed

- **Quit** always fully unloads (no “keep protection on”); cancelled admin password keeps the tray running. OS DenyOut banners dismissed on Quit/uninstall (`CloseAll`).
- Desktop/notify tests stub `notify-send` so suites do not litter the notification shade.
- Docs: D19 / desktop UX match unload-only Quit; OS toast whitelist no longer promises Undo.

### Fixed

- **Uninstall:** always stop/remove Linux `denyout-hostguard.service` (helper-serve). Previously, if the helper was up, teardown could leave the unit running after binaries were deleted.

## 0.4.0 - Quiet while away + honest desktop (2026-11-15)

### Added

- **Stay quiet while away** (default on): while the screen is locked or idle, DenyOut keeps protecting but does not spam OS notifications; the tray shows a quiet count.
- **While you were away** return summary in DenyOut (one in-app card, not a lock-screen wall). Soft “Open DenyOut” nudge only when Quiet/Normal allows and the app is closed.
- Settings knobs for quiet-while-away, return digest, snooze, night quiet, sound-only-when-answer, silent-when-focused, respect fullscreen.

### Changed

- Screens and tray name **Protect / Agents only / Session** consistently (pause, quit, Jump, Off copy, History empty states).
- History and Settings honesty: Needs attention, filter empty vs truly empty, threat lists hidden until loaded (Retry load), Allowed-site changes confirm restart when proxy is live.
- Pause-blocked buttons explain why (Ask/block or tray pause open). Find no longer confuses `log` with Autostart.

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
