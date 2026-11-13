# Design decisions (public)

Technical locks for implementers and users. Strategic bets, monetization, and capacity planning live in the **private** HQ tree (`denyout-hq`), not here.

Updated: 2026-11-13.

| Topic | Decision |
| --- | --- |
| License | Apache-2.0 |
| Implementation language | **Go** (shipped MVP binary) |
| Policy format | YAML `denyout/v1` only for MVP (OPA/Rego later optional) |
| Default TLS mode | **`intercept`**; `passthrough` = degraded mode with explicit warning |
| OS sandbox | **Optional** (`--sandbox`); desktop “supported” documents proxy-bypass residual |
| Wrap model | One binary: `denyout run -- <command>`; deep editor hooks later |
| UX | CLI **and** GUI; simplicity first-class |
| Platforms (MVP) | Ubuntu, macOS, Windows **desktop** |
| Phone / mobile | Out of scope for MVP |
| Server identity | One proxy instance = one policy (sidecar-per-workload) |
| Release checksums | SHA256SUMS with releases; SBOM/cosign recommended when time allows |
| Preset `models` | Versioned in-repo; changelog on host changes; no silent cloud updates |
| GitHub canon | `nareyko/denyout` |
| Author | Vadim Nareyko — [Arviser](https://arviser.com) |

## Positioning

> DenyOut is the free, local-first egress seatbelt you wrap around any agent in minutes — default-deny plus secret-in-URL blocking — not an enterprise access platform you buy to replace your SWG.

## Claims

See [`10-security-boundaries.md`](10-security-boundaries.md). Never claim unbypassable desktop protection, prompt-injection prevention, or phone coverage in MVP marketing.
