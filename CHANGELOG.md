# Changelog

## Unreleased

### Security

Full code review (stability + security); details and residual risks in [`docs/security-review-2026-11.md`](docs/security-review-2026-11.md).

- **Root helper (Linux):** `vpn-egress-apply` no longer shell-executes the interface name (root command injection); helper socket is owner-only with deny-by-default peer auth; redirect rules always target the configured owner uid; `apply` only reads a plain PEM CA certificate owned by the owner/root; the systemd unit runs a root-owned copy of the binary; nft replace is one atomic transaction; SIGTERM removes rules.
- **Proxy/policy:** body scanning no longer skips multipart/octet-stream/ndjson/gzip; all headers are scanned; token-as-username URLs and `custom_regex` are enforced; dials are pinned to validated IPs (DNS-rebinding SSRF); transparent HTTP scans headers/body; Host header must match the tunnel host (domain fronting); handshake/idle deadlines; port range check; CGNAT/metadata/NAT64/multicast IPs blocked; QUIC-MITM verifies upstream certificates (`DENYOUT_TLS_INSECURE_UPSTREAM=1` only for the lab); data race between `Evaluate` and `AllowHost/RevokeHost` fixed.
- **Privacy:** tokens are redacted from audit paths, URL userinfo and `blocks.jsonl`.
- **Sync/updates:** remote sync settings are validated and can no longer switch off BodyPureA/AntiChunk; cloud API and update manifest require https; update links open only trusted https hosts; truncated threat feeds are rejected; corrupt threat cache self-heals; state files are written atomically; profile ids cannot escape the profiles dir.
- **IPv6 / fail-safe:** the transparent proxy also listens on `[::1]`; under TUN the IPv6 redirect and IPv6 QUIC drop stay in place (IPv6 was a full bypass); a helper **watchdog** removes the redirect when the proxy is down for ~6s (no more orphan-REDIRECT blackhole) and re-applies on recovery, never after Protect Off. `DENYOUT_FAIL_CLOSED=1` keeps rules (strict).
- **Release integrity:** `SHA256SUMS` is signed with keyless cosign in CI; `install.sh` verifies it (`DENYOUT_VERIFY_SIG=auto|require|skip`), validates the tag and `DENYOUT_BASE_URL`, and matches checksums by exact name.
- **Follow-ups:** desktop release archives are cosign-signed and `install.sh` verifies the GUI archive (it was installed unverified before); a `degraded` helper (proxy down, redirect removed) now shows as *Needs attention* in tray/Home; protocol-relative / backslash `Location` redirects are re-evaluated; audit sink reopens its file after a failed rotation; `TailEvents` is O(limit) memory and skips oversized lines; IDN hosts compare in punycode and multiple trailing dots are stripped; "Always allow" on a bare TLD wildcard (`*.com`) no longer grants blanket trust.
- **Local web UI:** Host/Origin/Content-Type guard (DNS rebinding / cross-site POST).
- **Dependencies:** `x/net`, `x/crypto`, `x/sys`, `x/text` bumped; `govulncheck` clean.
- **Tests (Docker only):** `scripts/security-helper-regression-docker.sh`, `scripts/watchdog-e2e-docker.sh`, `scripts/install-verify-test-docker.sh`; fuzz tests for scanners and feed parsing.

### Behaviour changes to know about

- Header and body scanning is broader; expect a few more denies on APIs that put tokens in custom headers toward hosts that are not user-allowed.
- If the proxy dies the helper now *opens* the redirect after ~6s (state `degraded`) instead of blackholing HTTPS; set `DENYOUT_FAIL_CLOSED=1` for the old strict behaviour.
- The helper needs a non-root owner uid (`/var/lib/denyout/owner_uid`); Docker labs set it.

### Added

- **Platform seams:** new `internal/platform` interfaces (`Redirector`, `TrustStore`, `Autostart`) with `platformtest` contract suites and fakes; `hostguard.Apply/Remove/Teardown` and desktop autostart go through them (no behaviour change, signatures unchanged). CI now runs platform-neutral unit tests on `macos-15` and `windows-latest` and compiles all test binaries there. Docs: [`docs/platform-packaging.md`](docs/platform-packaging.md) (incl. missing Apple notarization / Windows Authenticode plan).
- **Threat lists: Block ads & trackers (default OFF):** Basic toggle gates Advanced OISD / StevenBlack. Category-specific deny reasons (`threat_phishing` / `threat_malware` / `threat_ads`) so tracker hits no longer read as phishing/malware. Legacy `threat_list` still accepted.

### Fixed

- **Allow this site = allow-all for that host:** Book B Always / Once (`user_always` / `user_once`) now skips non-canary secret scanners (Cookie/Bearer/URL/body) as well as threat lists. Fixes Claude.ai and similar sites where session cookies looked like secrets after Allow. Canaries still deny. Pack/preset allows unchanged.
- **`denyout version` no longer starts a second tray:** GUI handles `version` / `--version` / `-V` / `help` before detach; CLI verbs (`check`, `run`, `hostctl`, …) and unknown bare words print a `denyout-cli …` hint and exit instead of launching Wails.
- **desktop.log no longer doubles every line** after tray detach (stderr was redirected to the same file as AppendDesktopLog).
- **Richer Protect/deny diagnostics:** `protect_on` events include Always-allow host list; header secret hits tag detectors as `header:<name>:<detector>` (e.g. `header:cookie:…`) without values.

## 0.4.12 - Experimental Settings + TUN G6 (2026-11-16)

### Added

- **Settings → Advanced → Experimental (Linux):** toggles for `TunDataplane` and `QuicMITM` (same gates as `DENYOUT_TUN_E2E` / `DENYOUT_QUIC_MITM`; default off).
- **DenyOut → VPN egress (locked):** [`docs/design-vpn-egress.md`](docs/design-vpn-egress.md) — policy first, then VPN via mark `0x646e79` → table `646`. `hostctl vpn-egress-plan` (render) + `vpn-egress-apply` / `vpn-egress-remove` behind `DENYOUT_VPN_EGRESS_E2E=1`.
- **TUN G2–G5:** [`docs/tun-implementation-plan.md`](docs/tun-implementation-plan.md) — real `denyout0` + UDP/443 steer/drop in helper (`tun-start --real`); Protect On gated by `DENYOUT_TUN_E2E=1` or `TunDataplane` pref (default off); `hostctl tun-device-plan` / `caps` / `helper-install`.
- **TUN G6 epic (opt-in):** gVisor TCP-via-TUN (T3); QUIC SNI sighting (Q1); `quic-go` MITM skeleton + HTTP/3 policy hook (Q2); prefs `TunDataplane` / `QuicMITM` (default off); Cursor never QUIC-MITM.
- **Docker G6 lab dogfood:** `scripts/closed-loop-tun-g6-docker-dogfood.sh` (TCP HTTPS via TUN, QUIC sight/`tun-stats`, QuicMITM HTTP/3, teardown invariants). Defaults stay off.
- **Helper refresh:** Protect On runs `EnsureHelperFresh` so stale helpers pick up `quic1`/`tun1`/`vpn1` caps.

### Fixed

- **Orphan redirect blackhole:** uninstall and Protect Off no longer kill proxyd before removing nft/pf redirects (HTTPS `connection refused` to e.g. `api.github.com`). Concurrent `denyout uninstall` processes are excluded from the kill list.
- **Cross-OS build:** non-Linux `helperTunCall` uses `tun.HelperReply` (was undefined `tunHelperReply`, breaking darwin/windows release builds).

## 0.4.11 - Cursor passthrough tunnel half-close (2026-11-16)

### Fixed

- **Cursor silent under Protect:** TLS passthrough tunnels now wait for both copy directions and half-close with `CloseWrite` instead of RSTing the peer after the first EOF (api2 reconnect storm). Dial failures audit as `passthrough_dial_*` / `passthrough_tunnel_error`.

## 0.4.10 - TUN VM preflight (closed-loop) (2026-11-16)

### Added

- **TUN VM dogfood preflight:** [`docs/tun-vm-dogfood.md`](docs/tun-vm-dogfood.md) + `scripts/closed-loop-tun-preflight.sh` (CI); invariant that stubs never claim `enabled=true`.
- **`hostctl tun-rollback-plan`:** prints T1→T0 restore steps (not executed).

## 0.4.9 - TUN reasons + closed-loop CI smoke (2026-11-16)

### Added

- **TUN helper reasons:** `tun-start|stop|stats` replies include `reason=flag_off` (default) or `reason=stub_no_device` when `DENYOUT_TUN_E2E=1` but no real device yet.
- **Closed-loop release smoke:** `scripts/closed-loop-release-smoke.sh` (supports `DENYOUT_BIN`) verifies a release tree or local build without touching `~/.local` or elevating Protect; wired into CI.

## 0.4.8 - TUN T1 closed-loop (no device) (2026-11-16)

### Added

- **TUN T1 closed-loop:** `internal/tun` IPv4/IPv6 UDP classify, DropLog counter (`source=tun`), nft steer table render + helper verb lines — still no `/dev/net/tun` or Protect default change ([design](docs/design-tun-egress.md)).
- **TUN helper stubs:** `hostctl tun-start|tun-stop|tun-stats` and helper verbs reply `OK tun1 enabled=false` (no device). `quic-stats` lines now include `source=nft`.
- **TUN Protect lifecycle:** Protect Off emits `tun_drop_stats` + `tun_stop`; Protect On emits `tun_start_skipped` unless `DENYOUT_TUN_E2E=1`. `hostctl render --tun` previews the T1 nft table without applying it.
- **TUN coexistence denylist:** `tun.ShouldSkipIface` for docker/WireGuard/WARP/Tailscale/ZeroTier-style names (string contract only).

## 0.4.7 - AIza FP, QUIC stats, Cursor passthrough (2026-11-15)

### Fixed

- **Google browser API keys:** `AIza...` in query on first-party Google hosts (`*.google.com`, `*.googleapis.com`, `*.gstatic.com`, ...) no longer trips `secret_in_url`. Same key on a non-Google host still denies.

### Added

- **QUIC drop counters:** nft UDP/443 drop rule now has a `counter`; `denyout-cli hostctl quic-stats` and an `events.jsonl` `quic_drop_stats` line on Protect Off (before rules are removed).
- **Cursor TLS passthrough:** `*.cursor.sh` / `*.cursor.com` skip MITM under Protect (HTTP/2 agent APIs); L1 host/threat policy still applies. MITM handshake / HTTP/2 mismatches now audit as verdict `error` instead of silent close.
- **TUN egress spike (docs + plan only):** [`docs/design-tun-egress.md`](docs/design-tun-egress.md) and `internal/tun` decision helpers - no real TUN device in CI or default Protect.

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
