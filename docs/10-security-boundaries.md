# D10 — Security boundaries (claims & non-claims)

This document is **normative for marketing, README badges, and sales talk tracks**. Violating it is a product bug.

## 1. Allowed claims

DenyOut **may** claim that, when used as documented:

1. With **Protect this computer** On, it protects **this user’s outbound web (HTTP/HTTPS)** via transparent redirect into DenyOut for the duration of the session.  
2. It **blocks** configured secret-in-URL / canary patterns and hard SSRF/unsafe destinations visible at the configured inspection depth.  
3. In **Ask** mode (optional), it **denies unknown hosts** until the user allows once/always.  
4. For `denyout run` / Advanced wrap, it **default-denies** destinations not on the allowlist (models preset) for that process tree.  
5. On server, with NetworkPolicy, workloads that cannot bypass the sidecar are constrained accordingly.  
6. It **emits** an audit event for each decision.  
7. It **reduces** blast radius for R-20-style exfiltration on traffic that actually traverses DenyOut.

## 2. Forbidden claims

DenyOut **must not** claim that it:

1. “Makes agents safe” / “stops prompt injection.”  
2. Is “unbypassable” (UDP, DoH, custom stacks, root killers, and missing divert drivers remain residual).  
3. Protects traffic when Protect this computer is **Off**, or when hostguard failed and the tray shows Needs admin / Error.  
4. Detects **all** secrets or all DLP cases.  
5. Replaces IAM, vault, endpoint security, or corporate SWG for all traffic.  
6. Guarantees integrity of audit logs if the attacker has root on the host.  
7. Stops exfiltration to an **allowlisted** / allowed-web host when TLS passthrough is used and body scanners cannot see ciphertext.

## 3. Honest comparison statements

| Phrase | OK? |
| --- | --- |
| “Seatbelt for agent egress” | Yes |
| “Zero-trust for agents” | Only with qualification (egress layer, not full ZT) |
| “Firewall for MCP” | Only if MCP traffic actually traverses DenyOut |
| “Military-grade” | No |
| “AI-powered detection” | No for MVP regex/canary engine |

## 4. Severity of bypass classes

| Bypass | Protect computer On | Process wrap only | Server hardened |
| --- | --- | --- | --- |
| Ignore `HTTPS_PROXY` | Closed for TCP 80/443 via redirect (when hostguard active) | Likely works | Should fail (no route) |
| UDP / DoH / non-HTTP | Residual | Residual | Residual |
| Secret in body to allowed host, passthrough | Not stopped | Not stopped | Not stopped |
| Secret in URL, intercept | Stopped | Stopped | Stopped |
| User allowlists attacker / Ask Always | Allowed (user action) | Same | Same |
| Agent kills DenyOut / turns Off | Possible | Possible | Hard if RBAC + separate container |
| Windows without WinDivert bridge | Must show unsupported / Needs setup — never fake On | N/A | N/A |

## 5. Disclosure requirements

README **MUST** include a “Security boundaries” section linking here.  
`denyout run` first-use warning **SHOULD** mention desktop bypass residual.

## 6. Vulnerability reporting

Planned: `security@denyout.com` (or GitHub Security Advisories).  
Fix policy: fail-closed bugs prioritized over UX bugs.
