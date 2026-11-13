# Implementation checklist (public)

Engineering tasks for the DenyOut MVP. Product deadlines and internal bets are tracked in private HQ (`../denyout-hq/docs/CHECKLIST.md`).

**Stack:** Go · YAML `denyout/v1` · TLS intercept default · Apache-2.0  
**Target platforms:** Ubuntu, macOS, Windows  
**Read first:** [`SPEC.md`](SPEC.md), [`design-decisions.md`](design-decisions.md), [`10-security-boundaries.md`](10-security-boundaries.md)

## A. Skeleton

- [x] Go module `github.com/nareyko/denyout`
- [x] `cmd/denyout` with `version`, `help`, `check`, `policy validate`
- [x] Layout started: `internal/policy`, `internal/secrets`, `internal/lab`, `internal/check` (`proxy` / `audit` next)
- [x] CI on Linux: build + unit tests + canary check (`.github/workflows/ci.yml`)

## B. Policy + scanners

- [x] Load/validate `denyout/v1` (see `schemas/denyout-config.v1.json`; embedded copy under `internal/policy/schema/`)
- [x] Modes `enforce` / `audit` (+ blocklist/ask without UI); evaluation order per [`04-policy-engine.md`](04-policy-engine.md)
- [x] Preset `presets/models.yaml` (versioned)
- [x] Scanners: canaries, named query params, token prefixes, JWT-ish (high entropy off)
- [x] Redaction in `denyout check` / audit
- [x] Unit tests without sockets (`check` / `policy` / `lab` / proxy L1 deny)

## C. Proxy + CLI

- [x] Localhost HTTP proxy; CONNECT; intercept CA for child env
- [x] `--tls-mode=passthrough` with warning
- [x] SSRF / unsafe IP hard denies
- [x] `denyout run -- <cmd>`
- [x] `denyout check`, `policy validate`, `init`
- [x] Optional `--sandbox=` stub (documented; not required)

## D. Lab tests

- [x] SQLite schema + seed (`internal/lab`; primary `r20-01-canary-query`)
- [x] SQLite fixture DB + ≥20 R-20 / secret-URL cases (`r20_url` suite, 22 cases)
- [x] `denyout test` / acceptance AT-01…AT-09 (`internal/accept`, CI)
- [x] Examples under `examples/canaries/` (pre-existing)
- [x] M3 false-deny script (`scripts/m3-false-deny.sh` + `examples/m3/urls.txt`, CI)

## E. Audit + UX

- [x] JSONL audit schema v1 ([`09-audit-and-ops.md`](09-audit-and-ops.md))
- [x] Minimal GUI: `denyout gui` localhost web UI (start/stop wrap, mode/preset, check, recent denials) — same engine; no extra install deps
- [x] Denial copy never prints raw secrets

## F. Install + release

Locked recipes: [`07-desktop.md`](07-desktop.md) §3.

- [x] `install.sh` (Linux/macOS → `~/.local/bin`, fetch Release + SHA256)
- [x] Windows zip + short EN `docs/install-windows.md` (winget optional stretch)
- [x] Cross-build linux / darwin / windows (`.goreleaser.yaml` + `release` workflow on `v*` tags)
- [ ] GitHub Release + SHA256SUMS (M6 must) — tag `v*` to publish; SBOM/cosign SHOULD if time
- [ ] Timed M4 install smoke on each OS; failed OS → preview/unsupported in notes
- [ ] Homebrew formula **after** first Release (not M4 blocker)

## G. Server (after desktop skeleton)

- [ ] `denyout serve`
- [ ] Examples in `examples/k8s/` + NetworkPolicy docs

## Non-goals for MVP code

Phone clients · MCP tool firewall · credential vault injection · hosted SaaS · OPA requirement · mandatory OS sandbox · paywalled binary.
