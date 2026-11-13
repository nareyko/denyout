# Implementation checklist (public)

Engineering tasks for the DenyOut MVP. Product deadlines and internal bets are tracked in private HQ (`../denyout-hq/docs/CHECKLIST.md`).

**Stack:** Go · YAML `denyout/v1` · TLS intercept default · Apache-2.0  
**Target platforms:** Ubuntu, macOS, Windows  
**Read first:** [`SPEC.md`](SPEC.md), [`design-decisions.md`](design-decisions.md), [`10-security-boundaries.md`](10-security-boundaries.md)

## A. Skeleton

- [ ] Go module `github.com/nareyko/denyout`
- [ ] `cmd/denyout` with `version`, `help`
- [ ] Layout: `internal/proxy`, `internal/policy`, `internal/secrets`, `internal/audit`
- [ ] CI on Linux: build + unit tests

## B. Policy + scanners

- [ ] Load/validate `denyout/v1` (see `schemas/denyout-config.v1.json`)
- [ ] Modes `enforce` / `audit`; evaluation order per [`04-policy-engine.md`](04-policy-engine.md)
- [ ] Preset `presets/models.yaml` (versioned)
- [ ] Scanners: canaries, named query params, token prefixes, JWT-ish ([`05-secret-detection.md`](05-secret-detection.md))
- [ ] Redaction in logs/UI
- [ ] Unit tests without sockets

## C. Proxy + CLI

- [ ] Localhost HTTP proxy; CONNECT; intercept CA for child env
- [ ] `--tls-mode=passthrough` with warning
- [ ] SSRF / unsafe IP hard denies
- [ ] `denyout run -- <cmd>`
- [ ] `denyout check`, `policy validate`, `init`
- [ ] Optional `--sandbox=` (documented; not required)

## D. Lab tests

- [ ] SQLite fixture DB + ≥20 R-20 / secret-URL cases
- [ ] `denyout test` / acceptance AT-01…AT-09 ([`14-testing.md`](14-testing.md))
- [ ] Examples under `examples/canaries/`

## E. Audit + UX

- [ ] JSONL audit schema v1 ([`09-audit-and-ops.md`](09-audit-and-ops.md))
- [ ] Minimal GUI (same engine as CLI; keep install simple)
- [ ] Denial copy never prints raw secrets

## F. Install + release

- [ ] `install.sh` (Linux/macOS); Windows zip + short doc
- [ ] Cross-build linux / darwin / windows
- [ ] GitHub Release + SHA256SUMS
- [ ] Timed install smoke on each OS

## G. Server (after desktop skeleton)

- [ ] `denyout serve`
- [ ] Examples in `examples/k8s/` + NetworkPolicy docs

## Non-goals for MVP code

Phone clients · MCP tool firewall · credential vault injection · hosted SaaS · OPA requirement · mandatory OS sandbox · paywalled binary.
