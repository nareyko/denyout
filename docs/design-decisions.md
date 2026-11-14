# Design decisions (public)

Technical locks for implementers and users.

Updated: 2026-11-13.

| Topic | Decision |
| --- | --- |
| License | Apache-2.0 |
| Implementation language | **Go** (shipped MVP binary) |
| Policy format | YAML `denyout/v1` only for MVP (OPA/Rego later optional) |
| Default TLS mode | **`intercept`**. `Passthrough` = degraded mode with explicit warning |
| OS sandbox | **Optional** (`--sandbox`). Residual UDP/DoH/custom stacks always documented |
| Wrap model | Advanced/CLI: `denyout run -- <command>`. Deep editor hooks later |
| UX | GUI primary for P1. CLI for power users |
| GUI stack (MVP) | **`denyout desktop`**: **Protect this computer** (transparent HTTP/HTTPS redirect + CA trust) + tray + notifications + simple settings. Advanced = protect one program. `denyout gui` = technical panel. |
| Hostguard | Linux nftables + pkexec. MacOS pf + admin Keychain. Windows WinDivert companion + UAC (`denyout hostctl`) |
| Whole-device policy | Default **allow web** + secret/canary/SSRF hard denies + notify. Optional **Ask before new sites** |
| Platforms (MVP) | Ubuntu, macOS, Windows **desktop** (computer mode on all three. Mark OS unsupported if divert missing - no fake On) |
| Install (MVP) | Releases + SHA256SUMS. `Install.sh` -> `~/.local/bin` (Linux/macOS). Windows zip + short EN doc. CA installed when Protect computer is enabled. Homebrew/winget stretch - [`07-desktop.md`](07-desktop.md) §3 |
| Phone / mobile | Out of scope for MVP |
| Server identity | One proxy instance = one policy (sidecar-per-workload) |
| Release checksums | SHA256SUMS with releases. SBOM/cosign recommended when time allows |
| Preset `models` | Versioned in-repo. Changelog on host changes. No silent cloud updates |
| GitHub canon | `nareyko/denyout` |
| Author | Vadim Nareyko - [Arviser](https://arviser.com) |

## Positioning

> DenyOut is the free, local-first egress seatbelt for your laptop (Protect this computer) or a single agent process - secret-in-URL and unsafe destination blocking while On - not an enterprise SWG replacement.

## Claims

See [`10-security-boundaries.md`](10-security-boundaries.md). Never claim unbypassable desktop protection, prompt-injection prevention, or phone coverage in MVP marketing.
