# Changelog

## Unreleased

### Fixed

- **Google browser API keys:** `AIza...` in query on first-party Google hosts (`*.google.com`, `*.googleapis.com`, `*.gstatic.com`, ...) no longer trips `secret_in_url`. Same key on a non-Google host still denies.

### Added

- **QUIC drop counters:** nft UDP/443 drop rule now has a `counter`; `denyout-cli hostctl quic-stats` and an `events.jsonl` `quic_drop_stats` line on Protect Off (before rules are removed).
- **Cursor TLS passthrough:** `*.cursor.sh` / `*.cursor.com` skip MITM under Protect (HTTP/2 agent APIs); L1 host/threat policy still applies. MITM handshake / HTTP/2 mismatches now audit as verdict `error` instead of silent close.

## 0.4.6 - Block browser QUIC + diagnostics (2026-11-15)

### Added

- **Protect offer on every launch:** window always shows; if Protect is Off (and not paused / first-run), opens the existing enable-protect confirm.
- **Diagnostics JSONL:** `notify.jsonl` (every toast attempt, shown or suppressed), `events.jsonl` (lifecycle: protect on/off, pause, restore skip, quit, setup), `blocks.jsonl` (every deny from proxyd/session/wrap + user Ask/Keep/Allow/timed/undo decisions - not routine allows). Mirrored as `INFO event=` / `INFO block=` in `desktop.log`.
- **History "This week":** local analytics from `blocks.jsonl` / `events.jsonl` (blocked / you allowed / asked, Protect timeline, banner quieting) - stays on this computer.
- **Block browser QUIC:** Protect On drops UDP/443 (IPv4+IPv6) for the user UID so Chrome falls back to TCP MITM; cleared on Off/Quit. Default on; **Settings → Advanced → Browser QUIC** to allow HTTP/3. Pre-QUIC helpers are refreshed on the next elevated Protect On (password once).

### Changed

- **Binary names:** Wails tray/UI is now **`denyout`**; CLI/proxy/hostctl is **`denyout-cli`** (was `denyout` + `denyout-desktop`). Fallback shell: `denyout-cli desktop`.
- **Linux Protect CA paths:** `denyout.crt` / `denyout.pem` (was `denyout-desktop.*`); NSS nickname `DenyOut CA`. User systemd unit `denyout.service`.

### Fixed

- **Tray Open / Quit:** raise hidden window (Unminimise + brief always-on-top) before navigate so Home and Quit modal appear after the window was closed to tray.
- **Quit while Ask is open:** toast instead of silent no-op; Quit modal notes when the helper means no password.
- **Tray menu:** Open DenyOut... first (GNOME often maps left-click to the menu, not OnClick).
- **Quit left tray icon:** `runtime.Quit` was caught by Hide-to-tray `OnBeforeClose` after unload succeeded - process stayed. Quit now sets a flag, cancels the tray loop, allows close, and `os.Exit` fallback.
- **Terminal launch:** `denyout` from a TTY now detaches to the background (tray) and returns the shell; use `--foreground` to keep logs in the terminal.

## 0.4.5 - Upgrade install + obsolete last-error (2026-11-15)

### Fixed

- **Upgrade install** keeps `setup_done` and soft prefs (Quiet / Stay quiet / tips); still forces Protect Off. No longer re-opens first-run on every `install.sh --desktop`.
- **Obsolete last-error** from fixed elevate bugs (`--action-id=…`, test/CI skip) cleared on install and desktop start so Problems stays honest.

## 0.4.4 - pkexec Protect fix (2026-11-15)

### Fixed

- **Protect computer elevate:** when `com.denyout.hostctl.policy` is installed, DenyOut no longer passes invalid `pkexec --action-id=…` (polkit treats it as the program → “Cannot run program --action-id=…”). Plain `pkexec <denyout> hostctl …` again shows the password dialog.

## 0.4.3 - Elevate-skip honesty + URLhaus mirror (2026-11-15)

### Fixed

- **Test/CI elevate skip** (`DENYOUT_TEST_NO_ELEVATE` / `GITHUB_ACTIONS`) no longer sticky **Off (unavailable)** or claim a password window appeared — that path never shows pkexec.
- **Block known malware** feed: abuse.ch keyless URLhaus hostfile returns HTTP 410; switched to the maintained `urlhaus-filter` hosts mirror (no Auth-Key). Settings label: **URLhaus filter (malware)**.

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
