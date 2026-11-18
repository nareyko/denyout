# D10 - Security boundaries (claims & non-claims)

This document is **normative for marketing, README badges, and sales talk tracks**. Violating it is a product bug.

## 1. Allowed claims

DenyOut **may** claim that, when used as documented:

1. With **Protect this computer** On (Agent profile), it **default-denies** this user's outbound HTTP/HTTPS except the agent allowlist (or Ask), via transparent redirect into DenyOut - Rule of Two on the egress leg. Browse profile restores allow-web + scanners. 
2. It **blocks** configured secret-in-URL / canary patterns and hard SSRF/unsafe destinations visible at the configured inspection depth. 
3. In **Ask** mode (default on for new installs), it **denies unknown hosts** until the user allows once/always. 
4. For `denyout run` / Advanced wrap, it **default-denies** destinations not on the allowlist (models/agent preset) for that process tree. 
5. On server, with NetworkPolicy, workloads that cannot bypass the sidecar are constrained accordingly. 
6. It **emits** an audit event for each decision. 
7. It **reduces** blast radius for R-20-style exfiltration on traffic that actually traverses DenyOut.

## 2. Forbidden claims

DenyOut **must not** claim that it:

1. "Makes agents safe" / "stops prompt injection." 
2. Is "unbypassable" (UDP, DoH, custom stacks, root killers, and missing divert drivers remain residual). 
3. Protects traffic when Protect this computer is **Off**, or when hostguard failed and the tray shows Needs admin / Error. 
4. Detects **all** secrets or all DLP cases. 
5. Replaces IAM, vault, endpoint security, or corporate SWG for all traffic. 
6. Guarantees integrity of audit logs if the attacker has root on the host. 
7. Stops exfiltration to an **allowlisted** / allowed-web host when TLS passthrough is used and body scanners cannot see ciphertext.

### Residual limits added by the 2026-11 review

- The helper is fail-soft by default: after ~6s with a dead proxy the redirect is removed (state `degraded`) to avoid blackholing HTTPS. Strict users pick "Block web traffic until it recovers" in Settings (`fail_policy`), or set `DENYOUT_FAIL_CLOSED=1` / `DENYOUT_FAIL_POLICY=closed` for the helper; the tray notifies when the state enters `degraded`.
- Any process running as the *owner uid* (including a sandboxed agent) can talk to the helper; its verbs are validated and constrained, but the owner uid is inside the trust boundary of the helper API.
- IPv6 is protected via the nft redirect + QUIC drop, not through the TUN data plane. DNS (and DoH), non-80/443 TCP and other UIDs are out of scope.
- Release authenticity needs the cosign signature check (`DENYOUT_VERIFY_SIG=require`); a bare checksum only detects corruption.

## 3. Honest comparison statements

| Phrase | OK? |
| --- | --- |
| "Seatbelt for agent egress" | Yes |
| "Zero-trust for agents" | Only with qualification (egress layer, not full ZT) |
| "Firewall for MCP" | Only if MCP traffic actually traverses DenyOut |
| "Military-grade" | No |
| "AI-powered detection" | No for MVP regex/canary engine |

## 4. Severity of bypass classes

| Bypass | Protect computer On | Process wrap only | Server hardened |
| --- | --- | --- | --- |
| Ignore `HTTPS_PROXY` | Closed for TCP 80/443 via redirect (when hostguard active) | Likely works | Should fail (no route) |
| UDP / DoH / non-HTTP | Residual | Residual | Residual |
| Secret in body to allowed host, passthrough | Not stopped | Not stopped | Not stopped |
| Secret in URL, intercept | Stopped | Stopped | Stopped |
| User allowlists attacker / Ask Always | Allowed (user action) | Same | Same |
| Open-redirect hop1->evil hop2 | Absolute Location re-eval strips hop2 (0.1.9+). Relative/open-fetch proxies on allowlisted hosts remain residual | Same | Same |
| Agent kills DenyOut / turns Off | Possible | Possible | Hard if RBAC + separate container |
| Windows without WinDivert bridge | Must show unsupported / Needs setup - never fake On | N/A | N/A |

## 5. Disclosure requirements

README **MUST** include a "Security boundaries" section linking here (ship-check M5). 
`denyout run` **SHOULD** print a one-line residual when wrapping without an OS sandbox. 
Marketing one-liners **MUST** match §1-§2 (no "unbypassable").

## 6. Vulnerability reporting

GitHub Security Advisories on [`nareyko/denyout`](https://github.com/nareyko/denyout). Mailbox `security@denyout.com` (forwarding live). 
Fix policy: fail-closed bugs prioritized over UX bugs.

## 7. Ship-check (M5)

Last verified against public tree: 2026-11-13.

- [x] README links this doc and states Protect-On / not-unbypassable 
- [x] Pitch lines do not claim unbypassable or prompt-injection cure 
- [x] Process wrap vs Protect this computer claims distinguished 
- [x] Windows WinDivert residual documented 
- [x] Forbidden browser claim removed for Protect-On (browser is in scope when On)

## 8. Trust boundaries and what covers each

| # | Boundary (untrusted -> trusted) | Attacker controls | Enforced by | Covered by |
| --- | --- | --- | --- | --- |
| B1 | Agent process -> network egress | any outbound TCP 80/443, headers, bodies, URLs | transparent redirect / TUN, `internal/proxy`, `internal/policy`, `internal/secrets`, `internal/inspect` | `internal/accept` (AT-01..09), `internal/proxy` tests, `FuzzScanAndRedact`, `FuzzScanRedactInvariant`, `FuzzHostMatch` |
| B2 | Destination name -> dial | hostnames, DNS answers, redirects, Host vs SNI | pinned dials, `UnsafeIP`, Host/SNI check, absolute and relative `Location` re-evaluation | `internal/policy` and `internal/proxy` tests, `FuzzHostMatch` (normalisation/IDNA) |
| B3 | Owner-uid process -> root helper socket | one request line (legacy or JSON) | owner-only socket, peer auth, closed verb set, `ParseRequest` validation, CA PEM checks | `FuzzParseRequest`, `scripts/security-helper-regression-docker.sh`, `scripts/docker/helper-exploits.sh` |
| B4 | Helper -> kernel rules | interface name, port, CA path | no shell, `privexec.Valid*`, atomic nft transaction, watchdog | `scripts/watchdog-e2e-docker.sh`, rules unit tests (Docker only) |
| B5 | Remote service -> client (cloud sync, update manifest, threat feeds) | JSON bodies, feed bytes, redirects, truncation | https-only bases, size caps, `internal/httpsafe` (no https->http redirects), tighten-only sync validation, link allow-list | unit tests in `internal/cloudsync`, `internal/updates`, `internal/threatlists`, `internal/httpsafe`, `FuzzParse` |
| B6 | Browser/web page -> local web UI / desktop API | Host/Origin/Content-Type, request size | `guardLocal`, body caps, JSON-only | `internal/gui` tests |
| B7 | Release artifact -> installed binary | download mirror, archive | SHA256SUMS + keyless cosign, installer verification | `scripts/install-verify-test-docker.sh` |
| B8 | Dependencies / CI -> repository | upstream modules, actions | `go mod verify`, `govulncheck`, SHA-pinned actions, Dependabot, least-privilege `permissions:` | `.github/workflows/ci.yml` (`supply-chain`), `fuzz.yml` (scheduled) |

Not a boundary DenyOut defends (see §2 and `docs/security-review-2026-11.md`): the owner uid itself, other uids, DNS/DoH, non-80/443 TCP, UDP other than QUIC, a root attacker.
