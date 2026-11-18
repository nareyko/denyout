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
- Any process running as the *owner uid* (including a sandboxed agent) can talk to the helper; its verbs are validated and constrained, but the owner uid is inside the trust boundary of the helper API. **This is now detected, not prevented**: see "Owner-uid detection" below. A separate-uid design that would prevent it is in [`docs/design-agent-uid-split.md`](design-agent-uid-split.md) (not implemented).
- IPv6 is protected via the nft redirect + QUIC drop, not through the TUN data plane. DNS (and DoH), non-80/443 TCP and other UIDs are out of scope.
- Release authenticity needs the cosign signature check (`DENYOUT_VERIFY_SIG=require`); a bare checksum only detects corruption.

### Owner-uid detection (helper audit trail)

Detection, not prevention. A process running as the owner uid can still ask the root helper to turn Protect off or weaker; what changed is that it can no longer do so unnoticed.

- **What is recorded.** Every request the helper handles: mutating verbs (`apply`, `remove`, `teardown`, `fail-policy`, `uninstall-helper`, `tun-start`, `tun-stop`, `vpn-egress-*`) and every refused request become one JSONL event in `/var/lib/denyout/helper_audit.jsonl`; read-only verbs (`caps`, `version`, `fail-status`, `quic-stats`, `tun-stats`, `audit-tail`) are only counted. An event holds: time, verb, result (`ok` / `denied` / `error`), peer pid, ppid, uid, executable path (`readlink /proc/<pid>/exe`, `unknown` if the peer already exited), process name (`comm`), an exe class (`helper`, `system`, `user_install`, `other`, `unknown`) and the validated effective values for `apply` / `fail-policy` / `vpn-egress-apply` (port, fail policy, allow_quic, iface). It never holds command lines, environment, the raw request line or a CA path; the event type has no field that could carry them.
- **File.** Mode `0600`, owner root. The `audit-tail N` verb is the one read path: it is peer-authorized like every other verb, and its reply is redacted by construction. A group-readable file would only add a second read path for every process in the owner's group and gain nothing, because the owner can already call the verb. The file is capped at 1 MiB with one rotated copy (`.1`); the last events are reloaded after a helper restart. A failed write is counted and never breaks the helper (the in-memory ring keeps serving). Denied (bad request) events are limited to 30 per minute so garbage cannot churn the trail, and lowering events are kept in a separate ring so a flood of other requests cannot push a `remove` out before the desktop polls.
- **Trusted peer.** The exe is trusted if it is the very file the helper runs, or `denyout` / `denyout-cli` in a root-owned non-writable directory chain (for example `/usr/lib/denyout`), or in the owner's `~/.local/bin` / `~/bin` (where `install.sh` puts it). The last class is writable by the owner, so it is only a hint; the desktop-pid rule below is the stronger check. Reading a peer's exe needs `CAP_SYS_PTRACE` (the systemd unit is full root, so it has it); without it events degrade to `exe_class=unknown`, which is treated as untrusted.
- **Suspicious.** A request that lowers protection (`remove`, `teardown`, `uninstall-helper`, `tun-stop`, `fail-policy open` while the effective policy is not already open, or an `apply` that moves the redirect to another port / newly allows QUIC / opens a closed policy) and did not fail authorization. With a desktop running, it is suspicious unless the peer is the desktop process itself or a direct child of it with a trusted exe (agents run as descendants of the desktop, so "any descendant" would exempt exactly what this exists to catch). `hostctl audit-tail` has no desktop to compare with and marks `SUSPICIOUS:untrusted_exe` only.
- **What the user sees.** While Protect is on the desktop polls `audit-tail` every 5 s (one local socket call; nothing otherwise). A suspicious event raises a notification that passes quiet mode ("Protect was changed by <exe> (pid N) at <time>") and the `tampered` reason in `protectstate`, so Home / Problems / tray show Needs attention with a **Restore protection** button and an **It was me** dismiss. The note clears when the desktop re-applies Protect. `denyout-cli hostctl audit-tail [N] [--json]` prints the trail.
- **What it does not do.** It does not stop the change. A same-uid process can run the trusted binary itself (caught only while a desktop is running, as `not_from_desktop`), can wait for the desktop to be closed (events from before the desktop started are not judged, and the note is in memory only, so a desktop restart forgets it, though the file keeps the trail), can kill the desktop, and can alter anything else running as the owner. Root can edit the file. Tests: `internal/hostguard/audit*_test.go`, `internal/desktop/tamper_test.go`, `scripts/docker/helper-exploits.sh` (T8), `scripts/docker/watchdog-e2e.sh`.

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
| B3 | Owner-uid process -> root helper socket | one request line (legacy or JSON) | owner-only socket, peer auth, closed verb set, `ParseRequest` validation, CA PEM checks; **detection**: audit trail + desktop "Protect was changed" (owner uid itself stays inside the boundary) | `FuzzParseRequest`, `scripts/security-helper-regression-docker.sh`, `scripts/docker/helper-exploits.sh` (incl. T8 audit), `internal/hostguard/audit*_test.go`, `internal/desktop/tamper_test.go` |
| B4 | Helper -> kernel rules | interface name, port, CA path | no shell, `privexec.Valid*`, atomic nft transaction, watchdog | `scripts/watchdog-e2e-docker.sh`, rules unit tests (Docker only) |
| B5 | Remote service -> client (cloud sync, update manifest, threat feeds) | JSON bodies, feed bytes, redirects, truncation | https-only bases, size caps, `internal/httpsafe` (no https->http redirects), tighten-only sync validation, link allow-list | unit tests in `internal/cloudsync`, `internal/updates`, `internal/threatlists`, `internal/httpsafe`, `FuzzParse` |
| B6 | Browser/web page -> local web UI / desktop API | Host/Origin/Content-Type, request size | `guardLocal`, body caps, JSON-only | `internal/gui` tests |
| B7 | Release artifact -> installed binary | download mirror, archive | SHA256SUMS + keyless cosign, installer verification | `scripts/install-verify-test-docker.sh` |
| B8 | Dependencies / CI -> repository | upstream modules, actions | `go mod verify`, `govulncheck`, SHA-pinned actions, Dependabot, least-privilege `permissions:` | `.github/workflows/ci.yml` (`supply-chain`), `fuzz.yml` (scheduled) |

Not a boundary DenyOut defends (see §2 and `docs/security-review-2026-11.md`): the owner uid itself (detected after the fact, see "Owner-uid detection"), other uids, DNS/DoH, non-80/443 TCP, UDP other than QUIC, a root attacker.
