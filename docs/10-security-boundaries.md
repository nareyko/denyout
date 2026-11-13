# D10 — Security boundaries (claims & non-claims)

This document is **normative for marketing, README badges, and sales talk tracks**. Violating it is a product bug.

## 1. Allowed claims

DenyOut **may** claim that, when used as documented:

1. It **default-denies** outbound network from workloads that correctly send traffic through it **and** (on server) cannot bypass it due to network policy.  
2. It **blocks** destinations not on the allowlist in `enforce` mode.  
3. It **blocks** configured secret-in-URL / canary patterns visible at the configured inspection depth.  
4. It **emits** an audit event for each decision.  
5. It **reduces** blast radius for R-20-style exfiltration from **agent processes under DenyOut**.

## 2. Forbidden claims

DenyOut **must not** claim that it:

1. “Makes agents safe” / “stops prompt injection.”  
2. Is “unbypassable” on a desktop without an OS sandbox.  
3. Protects a **human browser** rendering markdown outside DenyOut.  
4. Detects **all** secrets or all DLP cases.  
5. Replaces IAM, vault, endpoint security, or corporate SWG for all traffic.  
6. Guarantees integrity of audit logs if the attacker has root on the host.  
7. Stops exfiltration to an **allowlisted** host when TLS passthrough is used and body scanners cannot see ciphertext.

## 3. Honest comparison statements

| Phrase | OK? |
| --- | --- |
| “Seatbelt for agent egress” | Yes |
| “Zero-trust for agents” | Only with qualification (egress layer, not full ZT) |
| “Firewall for MCP” | Only if MCP traffic actually traverses DenyOut |
| “Military-grade” | No |
| “AI-powered detection” | No for MVP regex/canary engine |

## 4. Severity of bypass classes

| Bypass | Desktop MVP | Server hardened |
| --- | --- | --- |
| Ignore `HTTPS_PROXY` | Likely works | Should fail (no route) |
| Secret in body to allowed host, passthrough | Not stopped | Not stopped |
| Secret in URL, intercept | Stopped | Stopped |
| User allowlists attacker | Allowed (user action) | Same |
| Agent kills DenyOut | Possible | Hard if RBAC + separate container |

## 5. Disclosure requirements

README **MUST** include a “Security boundaries” section linking here.  
`denyout run` first-use warning **SHOULD** mention desktop bypass residual.

## 6. Vulnerability reporting

Planned: `security@denyout.com` (or GitHub Security Advisories).  
Fix policy: fail-closed bugs prioritized over UX bugs.
