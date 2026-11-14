# DenyOut - Master Specification

| Field | Value |
| --- | --- |
| Product | DenyOut |
| Domain | https://denyout.com |
| Spec version | 0.1.0-draft |
| Status | Draft - normative for implementation planning |
| Date | 2026-11-13 |
| Author | Vadim Nareyko - founder, [Arviser](https://arviser.com) |
| Copyright | © 2026 Vadim Nareyko |
| License | Apache-2.0 (see `LICENSE`, `NOTICE`) |
| Related | Arviser AI security risk catalog (R-20, lethal trifecta). Internal bets/HQ: sibling `denyout-hq` (private). |

## 1. Purpose of this document set

This repository defines **what DenyOut is**, **what threats it addresses**, **how it is built**, and **what it must never over-claim**. Implementers treat rules marked **MUST / SHOULD / MAY** (RFC 2119) as binding for the named version.

If a later code change conflicts with this spec, either update the code or revise the spec in the same change set. Silent drift is a defect.

## 2. Document map

| ID | File | Normative? |
| --- | --- | --- |
| D01 | [01-vision.md](01-vision.md) | Product intent (informative + some MUST for positioning honesty) |
| D02 | [02-threat-model.md](02-threat-model.md) | **Normative** threat coverage for MVP+ |
| D03 | [03-architecture.md](03-architecture.md) | **Normative** component boundaries |
| D04 | [04-policy-engine.md](04-policy-engine.md) | **Normative** decision algorithm |
| D05 | [05-secret-detection.md](05-secret-detection.md) | **Normative** scanner contracts |
| D06 | [06-cli-and-ux.md](06-cli-and-ux.md) | **Normative** CLI surface. UX informative |
| D07 | [07-desktop.md](07-desktop.md) | **Normative** desktop deployment / binaries |
| D07-UX | [07-desktop-ux.md](07-desktop-ux.md) | **Normative** install/tray/menu/screens inventory |
| D07-UX-CAT | [07-desktop-ux-catalog.md](07-desktop-ux-catalog.md) | Catalog of all screens & user-visible messages |
| D07-UX-SIMPLE | [07-desktop-ux-simplicity.md](07-desktop-ux-simplicity.md) | Simplicity review: home dashboard, friction, gaps |
| D08 | [08-server.md](08-server.md) | **Normative** server deployment |
| D09 | [09-audit-and-ops.md](09-audit-and-ops.md) | **Normative** audit fields |
| D10 | [10-security-boundaries.md](10-security-boundaries.md) | **Normative** claims / non-claims |
| D11 | [11-config-reference.md](11-config-reference.md) | **Normative** config keys |
| D12 | [12-mvp-and-roadmap.md](12-mvp-and-roadmap.md) | Planning (informative) |
| D13 | [13-competitors.md](13-competitors.md) | Informative |
| D14 | [14-testing.md](14-testing.md) | **Normative** acceptance tests for MVP |
| - | [updates/README.md](updates/README.md) | Public app update manifest (no account) |
| - | [cloud-sync.md](cloud-sync.md) | Optional account settings sync schema (no secrets) |
| - | [design-decisions.md](design-decisions.md) | Locked technical decisions (public) |
| - | [IMPLEMENTATION.md](IMPLEMENTATION.md) | Public engineering checklist |

## 3. Glossary

| Term | Definition |
| --- | --- |
| **Agent** | Any process that uses an LLM and may call tools, fetch URLs, or otherwise cause network I/O (CLI coding agents, custom scripts, MCP clients, browser tools). |
| **Guard / DenyOut process** | The privileged (relative to the agent) process that terminates or mediates egress and evaluates policy. |
| **Child / workload** | The agent process tree started under `denyout run`, or the app container paired with a DenyOut sidecar. |
| **Egress** | Any outbound network attempt from the workload toward a non-loopback destination (or toward loopback ports that forward off-box). |
| **Policy** | Declarative rules: mode, host allow/deny, secret scanners, rate limits, approval hooks. |
| **Verdict** | `allow`, `deny`, `ask` (desktop only), or `audit-only` (log as if deny but forward). |
| **Allowlist** | Explicit set of destinations (and optional method/path) that may pass in `enforce` mode. |
| **Secret-in-URL** | Credential, token, canary, or high-entropy secret embedded in URL path, query, userinfo, or fragment-derived leakage. |
| **R-20** | Catalog risk: the answer (or tool output) itself exfiltrates data via link/image/HTML that causes a client to request an attacker-controlled URL. |
| **Lethal trifecta** | Untrusted input + sensitive access + outbound channel present together. |
| **Fail-closed** | On policy/engine/config error, deny (or refuse to start) rather than forward open. |
| **MITM / intercept mode** | TLS terminated at DenyOut with a local CA so path/query/headers/body are visible. |
| **Passthrough mode** | CONNECT/SNI or destination-IP based decisions without decrypting TLS (weaker inspection). |
| **Canary** | Planted secret/marker used to detect exfiltration if it appears in egress. |

## 4. Product one-pager (normative summary)

### 4.1 MUST solve

1. **Default-deny outbound** for agent workloads that opt in (desktop wrap) or are forced (server network).
2. **Block secret-bearing URLs** and obvious exfil patterns even toward otherwise-allowed hosts when configured.
3. **Audit** every decision out-of-band from the agent's writable filesystem where deployment allows.
4. **Same policy language** for laptop CLI and server sidecar.
5. **Honest boundaries**: document bypasses. Never market as "unbypassable" without OS-level enforcement.

### 4.2 MUST NOT claim (see D10)

- Full OS sandbox / filesystem isolation (out of MVP core. May integrate later with SRT/Fence/nono).
- Prompt-injection prevention inside the model.
- Protection when the user runs the agent **outside** DenyOut without network backstops.
- Stopping exfiltration to an **already-allowed** host via clever body encoding without intercept + scanners (best-effort only).

### 4.3 Primary UX

**Desktop (P1):** silent install -> tray icon + compact menu -> left-click opens **Home**. Clear blocks as **Keep blocked** / **Allow this site**. Power in Settings tabs. Full surface inventory (install / tray / menu / every screen): [`07-desktop-ux.md`](07-desktop-ux.md).

**CLI / wrap:**

```text
denyout run [--policy PATH] [--mode MODE] -- <command> [args...]
```

Zero-thinking wrap path: install -> `denyout run -- <agent>` -> first denials as notifications + log. Expand allowlist only as needed.

## 5. High-level decision flow (normative sketch)

```text
outbound request from workload
 │
 ▼
┌───────────────────┐
│ Authenticate path │ (desktop: child-only listener; server: mesh/SA token - phase-dependent)
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ Parse destination │ host, port, SNI, (if intercept) method/path/headers/body
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ SSRF / unsafe IP │ deny link-local, metadata, loopback-escape, RFC1918 unless explicitly allowed
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ Secret scanners │ URL -> headers -> body (config order); any hit -> deny (enforce) or log (audit)
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ Mode + allowlist │ enforce | audit | blocklist | ask
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ Rate / budget │ optional per-host and global caps
└─────────┬─────────┘
 ▼
┌───────────────────┐
│ Emit audit event │ then allow or deny response to client
└───────────────────┘
```

Exact order is specified in [04-policy-engine.md](04-policy-engine.md) (including Books A-D: agent allow, personal decisions, threat intel, product unbreak). Secret scanners **MUST** run before allowlist success is finalized so that `api.evil.com` is not required for blocking `https://cdn.allowed.example/x?token=SECRET`. Desktop threat-list UX: [ux-iters/threat-lists-plan.md](ux-iters/threat-lists-plan.md).

## 6. Deployment shapes

| Shape | Entry | Hardening |
| --- | --- | --- |
| **Desktop wrap** | `denyout run -- cmd` | Env proxy + optional OS sandbox integration later |
| **Desktop daemon** | system proxy for selected apps | Stronger, higher friction |
| **Server sidecar** | localhost proxy | **MUST** pair with NetworkPolicy / host firewall deny-other-egress |
| **Node / host proxy** | transparent or explicit | Multi-tenant care |

## 7. Versioning

- Spec versions: semver. Breaking policy semantics bump **minor** while pre-1.0, **major** after 1.0.
- Config `apiVersion: denyout/v1` freezes keys in [11-config-reference.md](11-config-reference.md).
- Audit log `schema_version` integers. Additive fields OK. Renames need new version.

## 8. Open questions (tracked)

See end of [12-mvp-and-roadmap.md](12-mvp-and-roadmap.md). Critical ones:

1. Exact v1 vs later cut during build (private HQ `decisions.md` §1 - in process). 
2. GUI: `denyout gui` localhost web UI locked for Dec 1 (see [`design-decisions.md`](design-decisions.md)). Deeper screens later. 
3. Language **Go**, license **Apache-2.0**, TLS default **intercept** - [`design-decisions.md`](design-decisions.md).

## 9. Change control

- Spec PRs must update this index if files are added.
- Security-claim changes require updating D10 and D14 tests in the same PR.
