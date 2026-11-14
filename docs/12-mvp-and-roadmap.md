# D12 — MVP scope and roadmap

## 1. MVP definition (v0.1)

**Goal:** By **1 December 2026**, a user can wrap an agent in ≤5 minutes on **Ubuntu, macOS, and Windows** (simple install) and get default-deny egress + secret-in-URL blocking + JSONL audit, with CLI + GUI, Go binary, and release artifacts for all three OS.

**Public engineering checklist:** [`IMPLEMENTATION.md`](IMPLEMENTATION.md).  
**Acceptance tests:** [`14-testing.md`](14-testing.md).  
Internal success metrics (M1–M6) and Bet Tree sheets live in private HQ (`denyout-hq`).

### In scope

| Item | Notes |
| --- | --- |
| CLI `run`, `check`, `policy validate`, `version`, `init` | D06 |
| **Simple install on Ubuntu, macOS, Windows** | install script / package managers; `denyout version` on all three |
| HTTP/HTTPS proxy with CONNECT | |
| TLS intercept with session CA | Windows CA UX may be the hard part of M4 |
| Modes: enforce, audit | ask optional stretch |
| Presets: models, strict | |
| Scanners: canaries, named query, token prefixes, jwt-ish | |
| SSRF unsafe IP defaults | |
| JSONL audit + stderr denials | |
| SQLite lab fixture DB + `denyout test run` | M1 corpus |
| Notifications on Linux/macOS (best-effort); Windows best-effort | |
| Docs site on denyout.com (install, trust, modes, why-it-blocks, known issues) | English only; private `denyout-web` repo |
| Examples + acceptance tests for R-20 canaries | |

### Out of MVP

| Item | Phase |
| --- | --- |
| OS sandbox integration | 1.5 |
| SOCKS5 | 1.1 |
| `denyout serve` + Helm chart | 1.1 |
| Credential injection | 2 |
| Path/method allow rules polished | 1.1 |
| Windows polish beyond M4 install path | 1.1 (MVP requires M4 install path) |
| Control plane / SaaS | 3 |
| Browser extension for human rendering | 3 |
| Hash-chained audit | 2 |
| MCP-aware tool filtering (non-HTTP) | 2 (complement AgentFence) |

## 2. Success criteria for MVP ship

1. `denyout check` denies canary URL 100% in CI.  
2. `denyout run -- curl https://example.com` denies in enforce+models.  
3. `denyout run -- curl https://api.anthropic.com` allow attempt reaches network layer (may 401 without key — not DENY from DenyOut).  
4. Security boundaries section present in README.  
5. No default telemetry.

## 3. Roadmap

### Phase 0 — Spec (this repo now)

- Complete docs.  
- Config schema.  
- Examples.

### Phase 1 — MVP binary

- Implement proxy+policy+CLI.  
- GitHub Actions CI.  
- install.sh + releases.

### Phase 1.1 — Server ready

- `serve`, Docker image, k8s examples, NetworkPolicy tests (kind).  
- Metrics endpoint.  
- Path/method rules.

### Phase 1.5 — Hardening desktop

- `--sandbox` integration with at least one of srt/fence/nono.  
- Documented matrix of bypass tests.

### Phase 2 — Secrets & identity

- Credential injection + response scrub.  
- Optional mTLS agent→proxy.  
- Windows support.

### Phase 3 — Productize

- Optional hosted policy sync (still local enforce) — **scaffold shipped**: desktop Account + sync client; interim API in private HQ `services/denyout-api`; production site/API stay in the **private denyout.com web repo**.  
- Public app update manifest client + Settings check (no account).  
- Browser helper for R-20 in human UIs.  
- Commercial support / Arviser bundling.

## 4. Open questions

| # | Question | Options | Owner |
| --- | --- | --- | --- |
| Q1 | Implementation language | **Go** (decided 2026-11-13) | Done |
| Q2 | License | **Apache-2.0** (decided 2026-11-13) | Done |
| Q3 | Trademark “DenyOut” | file or not | TBD |
| Q4 | Relationship to Arviser legal entity | same / spin | TBD |
| Q5 | Default TLS mode | **intercept**; passthrough = degraded + warning | Done |
| Q6 | Ship `ask` in 0.1? | yes/no | Prefer yes if TTY |
| Q7 | Wildcard policy for Azure OpenAI | how wide | Careful |

## 5. Staffing sketch (informative)

- 1 engineer × 3–6 weeks for MVP Go binary + tests if scoped tightly.  
- Spec authoring: done in this repo.
