# DenyOut

**Free seatbelt for your laptop or AI agents: Protect this computer (outbound web while On) or wrap one process - secret-looking URLs and unsafe destinations blocked.**

Site: [https://denyout.com](https://denyout.com) - Canon GitHub (planned): [`nareyko/denyout`](https://github.com/nareyko/denyout)

Agents that can read untrusted text, see sensitive data, and reach the network form a [lethal trifecta](https://arviser.com/guides/lethal-trifecta). DenyOut puts a local policy proxy on the path: **Protect computer** defaults to **Safe desktop** (web works. Secret-looking links blocked). **My agents** wraps python/CLI tools under an allowlist with rare Ask. Whole-PC **Agents only** is intentional (confirm). Audit stays on-device. See [CHANGELOG](CHANGELOG.md).

```bash
# Linux / macOS - silent; auto-detects Desktop (GUI) vs Server (headless)
curl -fsSL https://raw.githubusercontent.com/nareyko/denyout/main/install.sh | sh
# force:
# curl ... | sh -s -- --desktop
# curl ... | sh -s -- --server
# DENYOUT_INSTALL_MODE=desktop|server sh install.sh

# Desktop: Safe desktop + tray (admin once; stays Off if admin fails - no Session fallback)
denyout              # tray + Wails UI (Activity / My agents / Settings / Problems)
denyout-cli desktop  # CLI fallback tray (native dialogs)
denyout-cli profile create --name bot -- python app.py
denyout-cli run --profile bot
# denyout-cli desktop --web-ui # optional localhost UI for tests only

# Advanced / CI - wrap one process
denyout-cli run -- curl -I https://api.anthropic.com
denyout-cli run --sandbox=srt -- python app.py # Stronger isolation (requires srt)

# from this repo (dev)
go run ./cmd/denyout-cli version
go run ./cmd/denyout-cli check 'https://evil.example/x?api_key=DENYOUT_CANARY_LAB'
```

**Tray (compact):** Status - **Protect computer** - **My agents...** - **Off** - **Open DenyOut...** - **Quit**.
Left-click opens Activity. **Agents only (whole PC)** lives under Settings -> Advanced (confirm). Full inventory: [`docs/07-desktop-ux.md`](docs/07-desktop-ux.md).

Windows: download `denyout-cli_<version>_windows_amd64.zip` from [Releases](https://github.com/nareyko/denyout/releases) and follow [`docs/install-windows.md`](docs/install-windows.md).

## Status

**Protect computer (Safe desktop)** is the primary desktop path. **My agents** wraps AI/tools. Admin failure stays Off (no silent Session). Remaining for the Dec 1 bet: timed **M4** install on three OS (the `m4-smoke` workflow measures it on hosted runners). See [Platform support](#platform-support).

## Platform support

| OS | `denyout-cli run` (wrap one command) | Protect this computer |
| --- | --- | --- |
| Linux (Ubuntu) | Supported, timed | Supported |
| macOS | Timed in CI on a hosted runner (install to first protected run: seconds); not yet verified by hand on a Mac | Preview: not verified on a real Mac |
| Windows | Timed in CI on a hosted runner, with `curl.exe --cacert` (the system curl does not trust the session CA otherwise, see `docs/install-windows.md`); not yet verified by hand | Not available (WinDivert bridge not packaged) |

Release binaries are not signed with Developer ID or Authenticode (cosign proves provenance only), so macOS and Windows may show a warning on first run. See [known issues](docs/known-issues.md).

**Language:** English only - **License:** Apache-2.0 - **Platforms:** Ubuntu, macOS, Windows.

**Install:** GitHub Releases + SHA256SUMS. Linux/macOS [`install.sh`](install.sh) -> `~/.local/bin` (`denyout-cli` + `denyout` GUI when published). Windows zip + [`docs/install-windows.md`](docs/install-windows.md). See [`docs/07-desktop.md`](docs/07-desktop.md).

**Uninstall:** `denyout-cli uninstall` (removes processes, hostguard, CA trust, config, binaries). See [`docs/07-desktop.md`](docs/07-desktop.md) §6.

| Doc | Contents |
| --- | --- |
| [docs/REPO.md](docs/REPO.md) | Repository layout |
| [docs/SPEC.md](docs/SPEC.md) | Master index, normative rules, glossary |
| [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) | Public engineering checklist |
| [docs/design-decisions.md](docs/design-decisions.md) | Locked technical decisions |
| [docs/01-vision.md](docs/01-vision.md) | Problem, positioning, personas, brand |
| [docs/02-threat-model.md](docs/02-threat-model.md) | Assets, attackers, R-20 cases |
| [docs/03-architecture.md](docs/03-architecture.md) | Components, data flows, trust boundaries |
| [docs/04-policy-engine.md](docs/04-policy-engine.md) | Modes, allowlists, evaluation order |
| [docs/05-secret-detection.md](docs/05-secret-detection.md) | URL/header/body scanners, canaries |
| [docs/06-cli-and-ux.md](docs/06-cli-and-ux.md) | CLI, notifications, zero-config UX |
| [docs/07-desktop.md](docs/07-desktop.md) | Laptop install, child-process proxy, CA |
| [docs/install-windows.md](docs/install-windows.md) | Windows zip + PATH (M4) |
| [install.sh](install.sh) | Linux/macOS installer |
| [docs/08-server.md](docs/08-server.md) | Sidecar, NetworkPolicy, systemd |
| [docs/09-audit-and-ops.md](docs/09-audit-and-ops.md) | Logs, metrics, kill switch, SIEM |
| [docs/10-security-boundaries.md](docs/10-security-boundaries.md) | What we claim / do not claim |
| [docs/11-config-reference.md](docs/11-config-reference.md) | Config schema, examples |
| [docs/12-mvp-and-roadmap.md](docs/12-mvp-and-roadmap.md) | MVP scope and phases |
| [docs/13-competitors.md](docs/13-competitors.md) | Landscape and differentiation |
| [docs/14-testing.md](docs/14-testing.md) | Test plan, canaries, CI gates |

Examples: [`examples/`](examples/). Schema: [`schemas/`](schemas/).

## Security boundaries

Normative claims: [`docs/10-security-boundaries.md`](docs/10-security-boundaries.md).

- **May claim:** with Protect computer **On** (Safe desktop), DenyOut protects **this user's outbound web (HTTP/HTTPS)** against secret-looking links / canaries / hard SSRF. Agents only / wraps limit destinations to an allowlist (Ask when enabled).
- **Must not claim:** unbypassable, prompt-injection cure, phone coverage, or protection while Off / when hostguard failed. Without Stronger isolation (`srt`), some tools can bypass the proxy.
- Residual: UDP, DoH, custom stacks. Windows needs WinDivert bridge for computer mode.

## One-line pitch

> DenyOut is a free seatbelt for your computer or AI agents: secret-looking URLs and unsafe destinations are blocked while protection is On.

## Author

**Vadim Nareyko** - founder of [Arviser](https://arviser.com). 
DenyOut (https://denyout.com) is a separate product brand. Arviser may recommend it as an egress control (e.g. R-20).

## License

**Apache License 2.0** - [`LICENSE`](LICENSE), [`NOTICE`](NOTICE). 
Copyright 2026 Vadim Nareyko. SPDX: `Apache-2.0`.
