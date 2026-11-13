# DenyOut

**Free seatbelt for AI agents: outbound denied by default, secret-looking URLs blocked — on your laptop or beside your server process.**

Site: [https://denyout.com](https://denyout.com) · Canon GitHub (planned): [`nareyko/denyout`](https://github.com/nareyko/denyout)

Agents that can read untrusted text, see sensitive data, and reach the network form a [lethal trifecta](https://arviser.com/guides/lethal-trifecta). DenyOut removes the easy outbound path: every connection goes through a local policy proxy that **denies by default**, blocks secret-bearing URLs, and leaves an audit trail the agent cannot edit.

```bash
denyout run -- claude
denyout run -- cursor-agent
denyout run -- python my_agent.py
```

## Status

**Spec-first.** This repository is the **public** product tree: technical specification, examples, and (soon) code. Implementation has not started.

**Language:** English only.

**MVP intent:** Simple install on **Ubuntu, macOS, and Windows**; CLI + GUI; Go binary; Apache-2.0. See [`docs/12-mvp-and-roadmap.md`](docs/12-mvp-and-roadmap.md) and [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

Internal Bet Tree / monetization / full decision log live in a **private HQ** sibling (`denyout-hq`), not in this repo.

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
| [docs/08-server.md](docs/08-server.md) | Sidecar, NetworkPolicy, systemd |
| [docs/09-audit-and-ops.md](docs/09-audit-and-ops.md) | Logs, metrics, kill switch, SIEM |
| [docs/10-security-boundaries.md](docs/10-security-boundaries.md) | What we claim / do not claim |
| [docs/11-config-reference.md](docs/11-config-reference.md) | Config schema, examples |
| [docs/12-mvp-and-roadmap.md](docs/12-mvp-and-roadmap.md) | MVP scope and phases |
| [docs/13-competitors.md](docs/13-competitors.md) | Landscape and differentiation |
| [docs/14-testing.md](docs/14-testing.md) | Test plan, canaries, CI gates |

Examples: [`examples/`](examples/). Schema: [`schemas/`](schemas/).

## One-line pitch

> DenyOut is a free seatbelt for AI agents: outbound network is denied by default, and secret-looking URLs are blocked — on your laptop or beside your server process.

## Author

**Vadim Nareyko** — founder of [Arviser](https://arviser.com).  
DenyOut (https://denyout.com) is a separate product brand; Arviser may recommend it as an egress control (e.g. R-20).

## License

**Apache License 2.0** — [`LICENSE`](LICENSE), [`NOTICE`](NOTICE).  
Copyright 2026 Vadim Nareyko. SPDX: `Apache-2.0`.
