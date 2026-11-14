# DenyOut

**Free seatbelt for your laptop or AI agents: Protect this computer (outbound web while On) or wrap one process — secret-looking URLs and unsafe destinations blocked.**

Site: [https://denyout.com](https://denyout.com) · Canon GitHub (planned): [`nareyko/denyout`](https://github.com/nareyko/denyout)

Agents that can read untrusted text, see sensitive data, and reach the network form a [lethal trifecta](https://arviser.com/guides/lethal-trifecta). DenyOut puts a local policy proxy on the path: **Protect this computer** defaults to an **Agent** allowlist (Rule of Two on egress — models/registries/git; Ask for new hosts); **Browse** restores allow-web + scanners. **Advanced / `denyout run`** default-denies except an allowlist. Audit stays out of the agent’s reach. See [CHANGELOG](CHANGELOG.md) 0.1.9.

```bash
# Linux / macOS — silent; auto-detects Desktop (GUI) vs Server (headless)
curl -fsSL https://raw.githubusercontent.com/nareyko/denyout/main/install.sh | sh
# force:
#   curl … | sh -s -- --desktop
#   curl … | sh -s -- --server
#   DENYOUT_INSTALL_MODE=desktop|server sh install.sh

# Desktop: tries whole-computer Protect once (admin), else Session (proxy env);
# registers login autostart and starts the tray in the background.
denyout desktop                 # tray (restores last scope)
# denyout desktop --web-ui      # optional localhost UI for tests only

# Advanced / CI — wrap one process
denyout run -- curl -I https://api.anthropic.com

# from this repo (dev)
go run ./cmd/denyout version
go run ./cmd/denyout check 'https://evil.example/x?api_key=DENYOUT_CANARY_LAB'
```

**Scopes (tray):**
- **Computer** — transparent redirect + system CA (admin password once).
- **Session** — local HTTP proxy + `HTTP(S)_PROXY` for apps that honor it (no admin). Browsers may ignore proxy; use Computer for full coverage.

Windows: download the zip from [Releases](https://github.com/nareyko/denyout/releases) and follow [`docs/install-windows.md`](docs/install-windows.md).

## Status

**Protect this computer** is the primary desktop path (transparent HTTP/S + CA). Session mode is the no-admin fallback. Advanced wraps one process. Remaining for the Dec 1 bet: timed **M4** install on three OS; Windows WinDivert bridge packaging.

**Language:** English only · **License:** Apache-2.0 · **Platforms:** Ubuntu, macOS, Windows.

**Install:** GitHub Releases + SHA256SUMS; Linux/macOS [`install.sh`](install.sh) → `~/.local/bin`; Windows zip + [`docs/install-windows.md`](docs/install-windows.md). See [`docs/07-desktop.md`](docs/07-desktop.md).

Internal Bet Tree / monetization / full decision log live in a **private HQ** sibling (`denyout-hq`), not in this repo.

Agent playbooks: thin stubs in [`prompts/`](prompts/) → sibling [`agent-prompts`](https://github.com/nareyko/agent-prompts). Multi-root workspace: `~/projects/denyout-hq/denyout.code-workspace`.

| Doc | Contents |
| --- | --- |
| [docs/REPO.md](docs/REPO.md) | Public vs private HQ layout |
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

- **May claim:** with Protect this computer **On**, DenyOut protects **this user’s outbound web (HTTP/HTTPS)**; blocks secret-in-URL / canaries / hard SSRF patterns it can see; optional Ask mode for new hosts.
- **Must not claim:** unbypassable, prompt-injection cure, phone coverage, or protection while Off / when hostguard failed (Needs admin). Session mode only covers apps that honor `HTTP(S)_PROXY`.
- Residual: UDP, DoH, custom stacks; Windows needs WinDivert bridge for computer mode.

## One-line pitch

> DenyOut is a free seatbelt for your computer or AI agents: secret-looking URLs and unsafe destinations are blocked while protection is On.

## Author

**Vadim Nareyko** — founder of [Arviser](https://arviser.com).  
DenyOut (https://denyout.com) is a separate product brand; Arviser may recommend it as an egress control (e.g. R-20).

## License

**Apache License 2.0** — [`LICENSE`](LICENSE), [`NOTICE`](NOTICE).  
Copyright 2026 Vadim Nareyko. SPDX: `Apache-2.0`.
