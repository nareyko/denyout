# D04 — Policy engine

## 1. Modes

| Mode | Forward when | Block when | Typical use |
| --- | --- | --- | --- |
| `enforce` | Host (and L2 path/method if present) matches allow rules **and** scanners clean | Else | Production default |
| `audit` | Always (except hard SSRF denies — see below) | Never (except hard SSRF) | Build allowlist |
| `blocklist` | Always except listed deny hosts / scanner hits | Listed / scanner | Soft posture |
| `ask` | Allow rules **or** interactive approval | Deny / timeout | Desktop only |

**Hard denies** (apply in **all** modes including `audit`):

- Destination IP in default unsafe ranges (metadata, link-local, default deny private unless `allow_private: true`).
- Malformed / non-resolvable with `deny_on_dns_failure: true` (default true in enforce).

Rationale: audit mode must not become an SSRF open redirect into cloud metadata.

## 2. RequestView (logical schema)

```text
RequestView {
  session_id: string
  agent_id: string?              # server
  timestamp: time
  network: {
    server_name: string?         # SNI / CONNECT host
    dest_host: string            # hostname requested
    dest_port: uint16
    dest_ips: [ip]               # after resolution
    protocol: http|https|tcp
  }
  http?: {                       # present in L2 or cleartext
    method: string
    path: string
    raw_query: string
    headers: map[string][]string
    body_prefix: bytes           # up to N KB scanned
  }
  inspection: passthrough|intercept|cleartext
}
```

## 3. Evaluation order (normative)

Given `RequestView` R and `Policy` P:

1. **Normalize host** (lowercase, strip trailing dot; IDNA to ASCII).  
2. **DNS resolve** (unless IP literal).  
3. **Unsafe IP check** on all resolved addresses → if any unsafe and not explicitly allowed → `deny` reason `unsafe_ip`.  
4. **Port check** — if `allowed_ports` set and port ∉ set → deny `port_not_allowed`.  
5. **Secret scanners** on available fields (D05) → on hit:  
   - `enforce` / `ask` / `blocklist`: `deny` reason `secret_*`  
   - `audit`: do **not** forward if `audit.hard_secrets: true` (default **true** for URL secrets); else log `would_deny` and forward.  
6. **Mode branch:**
   - `enforce`: match allow rules; else deny `host_not_allowed` (or `path_not_allowed`).  
   - `blocklist`: match deny hosts → deny; else allow (scanners already applied).  
   - `audit`: allow (unless hard denies). Log `would_deny` if enforce would deny.  
   - `ask`: if allow match → allow; else prompt; on approve → allow once/session; on deny/timeout → deny.  
7. **Rate limits** → deny `rate_limited`.  
8. **Emit audit** with final verdict.  
9. Return decision to proxy.

**Invariant:** Scanner deny in enforce cannot be overridden by a wide host allow rule.

## 4. Allow rule schema

```yaml
allow:
  - host: api.anthropic.com          # exact
  - host: "*.github.com"             # suffix match; see rules
  - host: registry.npmjs.org
    ports: [443]
  - host: api.example.com            # L2 only enrichment
    methods: [GET, POST]
    paths:
      - prefix: /v1/
      - regex: "^/public/.*"
```

### 4.1 Host matching rules

| Pattern | Meaning |
| --- | --- |
| `example.com` | Exact host match |
| `*.example.com` | One or more labels under `example.com` (**MUST NOT** match `example.com` itself unless `include_apex: true`) |
| `*`, `*.*` | **Forbidden** in enforce without `insecure_allow_all: true` |

IP literals are **hard-denied** when `allow_ip_literals` is false (default): evaluation stops immediately; Ask / Always-allow cannot bypass. Desktop shows a rate-limited toast instead of an Ask dialog. Use **Browse** profile for apps that connect by raw IP (e.g. some messengers).

### 4.2 Path matching (L2)

- If rule has `paths` / `methods` and inspection is passthrough → treat as **host-only** match and SHOULD log `degraded_path_policy`.  
- Prefer failing closed for rules marked `require_intercept: true`.

## 5. Deny rules

```yaml
deny:
  - host: pastebin.com
  - host: "*.ngrok-free.app"
  - reason: "known exfil paste"
```

Deny list evaluated in enforce **after** scanners? → Actually: deny list **SHOULD** be checked before allow to provide clear reasons. Normative addition:

Between steps 5 and 6: **explicit deny host match → deny `host_denied`.**

## 6. Private / metadata ranges (default unsafe)

DenyOut **MUST** treat as unsafe unless explicitly allowed per CIDR:

- `169.254.0.0/16` (link-local / metadata)  
- `fd00:ec2::254` and cloud metadata equivalents documented in config  
- `127.0.0.0/8`, `::1` as **destination via proxy toward upstream** (proxy listening local is fine)  
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` — default deny in desktop `models` preset; server preset may set `allow_private: true` for in-cluster APIs via explicit hosts

**DNS rebinding:** After CONNECT, if upstream IP changes on reconnect mid-session, re-check. For each new dial, resolve + unsafe check again.

## 7. Rate limits

```yaml
limits:
  per_host_rpm: 120
  global_rpm: 600
  per_host_burst: 40
```

Counters in memory per session (desktop) or per agent_id (server). Exhaustion → deny.

## 8. Approval (`ask`) semantics

Desktop only in MVP.

- Channel: terminal TUI prompt and/or OS notification action.  
- Timeout default 30s → deny.  
- Approvals: `once` | `session` | `remember_host` (writes to user config with confirmation).  
- **MUST** show full host + redacted URL.  
- **MUST NOT** auto-approve scanner hits (`secret_*`).

## 9. Policy reload

- `SIGHUP` or file watch reloads policy.  
- Invalid new policy: **keep old**, log error (availability); optional `strict_reload: true` → fail closed new connections.  
- Audit event `policy_reload` with hash of policy bytes.

## 10. Determinism

Same `(Policy, RequestView, rate-state)` → same verdict. Timeouts in `ask` are non-deterministic by nature; record timeout reason.

## 11. Reason codes (stable strings)

| Code | Meaning |
| --- | --- |
| `allow` | Permitted |
| `host_not_allowed` | Enforce miss |
| `host_denied` | Explicit deny |
| `path_not_allowed` | L2 path miss |
| `method_not_allowed` | L2 method miss |
| `unsafe_ip` | SSRF/metadata/private |
| `port_not_allowed` | Port |
| `secret_in_url` | Scanner |
| `secret_in_header` | Scanner |
| `secret_in_body` | Scanner |
| `canary_detected` | Scanner |
| `rate_limited` | Limits |
| `dns_failure` | Resolution |
| `ask_denied` | User |
| `ask_timeout` | User |
| `policy_error` | Internal fail closed |
| `would_deny` | Audit mode annotation |

New codes require spec bump note in changelog.
