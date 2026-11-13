# D03 — Architecture

## 1. Design goals

1. One **policy engine** shared by desktop and server adapters.  
2. **Fail closed.**  
3. Minimal moving parts in MVP: CLI + proxy + config + audit sink.  
4. Clear process boundaries: agent never loads policy code that can be talked into “allow all.”  
5. Pluggable later: OS sandbox, credential injection, control plane — without rewriting policy semantics.

## 2. Logical components

```text
┌──────────────────────────────────────────────────────────┐
│                     denyout CLI                          │
│  parse args → load config → start proxy → spawn child    │
│  optional: install CA into child env only                │
└───────────────┬───────────────────────────┬──────────────┘
                │                           │
                ▼                           ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│  Proxy runtime            │   │  Workload (child/sidecar  │
│  - HTTP/HTTPS listener    │◄──┤    peer)                  │
│  - CONNECT / MITM         │   │  HTTPS_PROXY=...          │
│  - SSL bump (optional)    │   │  SSL_CERT_FILE=...        │
└─────────────┬─────────────┘   └───────────────────────────┘
              │
              ▼
┌───────────────────────────┐
│  Policy engine            │
│  - mode                   │
│  - host/path rules        │
│  - secret scanners        │
│  - SSRF guards            │
│  - rate limits            │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│  Audit sink               │
│  - stdout / file / webhook│
│  - outside agent FS       │
└───────────────────────────┘
```

## 3. Component responsibilities

### 3.1 CLI (`denyout`)

**MUST:**

- Provide `run`, `check`, `version`, `policy validate`, `audit tail` (MVP subset OK; see D06).
- Load config from flag, env, or default search path.
- Bind proxy to **localhost** (or abstract UDS on Linux) by default.
- Spawn child with proxy-related env vars set.
- Tear down proxy when child exits (desktop).
- Exit non-zero if config invalid and mode is enforce-oriented.

**MUST NOT:**

- Embed “phone home” by default.
- Install a **system-wide** trusted CA without an explicit, scary subcommand (`denyout ca install-system` — post-MVP, documented danger).

### 3.2 Proxy runtime

**MUST:**

- Accept HTTP proxy protocol from clients (`HTTP CONNECT` for HTTPS).
- Apply policy **before** bytes are forwarded to an unapproved destination.
- Support at least two inspection depths:
  - **L1 passthrough:** decide on destination host/SNI/IP (and CONNECT target).
  - **L2 intercept:** terminate TLS with DenyOut CA; inspect method/path/query/headers/body.
- Default MVP desktop preset: L2 for HTTP cleartext + L1 or L2 for HTTPS configurable; **recommend L2** when blocking secret-in-URL is a goal.
- Enforce SSRF IP rules after DNS resolution (see D04) — **resolve then check**, never check hostname only.

**SHOULD:**

- Support SOCKS5 for non-HTTP TCP with host allowlist (phase 1.1).
- Re-apply policy on HTTP redirects when in L2.

### 3.3 Policy engine

Pure library relative to I/O:

- Input: `RequestView` + `Policy` + `RuntimeState` (rate counters).
- Output: `Decision { verdict, reasons[], rule_id?, redactions[] }`.

**MUST** be unit-testable without opening sockets (D14).

### 3.4 Secret scanners

See D05. Invoked by policy engine with fields available at current inspection depth.

### 3.5 Audit sink

**MUST** record decisions with required fields (D09).  
**SHOULD** support JSONL file and stdout.  
**MAY** support webhook / OTLP later.

### 3.6 Notifier (desktop)

**SHOULD** show OS notification on deny in `enforce`/`ask`.  
**MUST NOT** include raw secrets in notification body (show redacted URL).

## 4. Process models

### 4.1 Desktop: supervisor model (MVP)

```text
User shell
  └─ denyout run -- agent ...
       ├─ proxy goroutine/thread on 127.0.0.1:PORT
       └─ child agent (process group)
            └─ grandchildren (tools)
```

- Proxy lifetime = supervisor lifetime.  
- Port: ephemeral or stable under XDG runtime dir lockfile.  
- Child env:
  - `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (as applicable)
  - `NO_PROXY=localhost,127.0.0.1,::1` (+ user config)
  - `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` pointing at DenyOut CA for L2
  - `DENYOUT_SESSION_ID`

### 4.2 Server: sidecar model (MVP+)

```text
Pod
  ├─ container: agent (NO egress except to sidecar)
  └─ container: denyout proxy (egress to world via NAT)
```

Agent points to `http://127.0.0.1:8080` or link-local sidecar IP.  
Cluster NetworkPolicy: agent egress only to sidecar; sidecar egress as needed.

### 4.3 Server: host / gateway model (later)

Shared DenyOut per node or central egress gateway with mTLS from workloads — phase 3 control plane.

## 5. Ports & sockets

| Binding | Default | Notes |
| --- | --- | --- |
| HTTP proxy | `127.0.0.1:0` (ephemeral) written to env | Desktop |
| HTTP proxy server | `0.0.0.0:8080` or localhost only | Sidecar; prefer localhost + shared emptyDir network namespace |
| Admin / metrics | localhost only | Disabled by default in desktop |
| UDS | `$XDG_RUNTIME_DIR/denyout.sock` | Optional Linux hardening |

**MUST NOT** listen on `0.0.0.0` on a developer laptop without explicit flag.

## 6. TLS / CA architecture

### 6.1 CA generation

On first desktop use (or per session — configurable):

- Generate ephemeral **session CA** (preferred for paranoia) **or** persistent user CA under `~/.config/denyout/ca/`.
- Private key permissions `0600`.
- Certificate distributed **only** to child env trust variables when possible.

### 6.2 Intercept handshake

1. Client CONNECT `host:443`.  
2. Policy L1 on host — deny early if host forbidden.  
3. If L2 required (secret scanning / path rules): MITM, present cert for `host` signed by DenyOut CA.  
4. Inspect request; policy L2; then dial upstream with normal WebPKI (system roots), unless enterprise custom roots configured.

### 6.3 Certificate pinning / broken clients

Some agents use custom HTTP stacks that ignore env CA. Document failures; offer `denyout run --tls-mode=passthrough` with reduced guarantees.

## 7. Config load order

1. Built-in defaults (model provider allowlist preset).  
2. System config `/etc/denyout/denyout.yaml` (server).  
3. User config `~/.config/denyout/denyout.yaml`.  
4. Project config `./denyout.yaml` / `./.denyout.yaml`.  
5. `--policy` / `--config` flag.  
6. Env `DENYOUT_*` overrides for a small safe subset (mode, log level) — **MUST NOT** allow env to set `allow_hosts: ['*']` without explicit `DENYOUT_ALLOW_INSECURE_OVERRIDE=1`.

Merge semantics: deep-merge maps; lists for allow hosts **replace** by default at the highest layer (document clearly). Optional `extra_allow_hosts` additive key.

## 8. Presets

| Preset | Intent |
| --- | --- |
| `models` | Allow major LLM APIs only |
| `models+pkg` | + npm/pypi/crates/github |
| `dev` | models+pkg + common docs CDNs (careful) |
| `strict` | empty allowlist except what user adds |
| `audit` | forward all, log would-denies |

MVP ships `models` and `strict`. Others follow.

## 9. Extension points (non-MVP but designed-in)

| Hook | Use |
| --- | --- |
| `BeforeDial` | Custom SSRF |
| `CredentialInject` | Replace placeholders with vault secrets |
| `Approval` | Desktop ask / server ticket |
| `SandboxWrapper` | Call out to `srt` / `fence` / `nono` |
| `Sink` | Extra audit backends |

Interfaces SHOULD be defined in code as stable Go/Rust traits even if only one implementation exists.

## 10. Technology recommendation (informative, decision pending)

| Option | Pros | Cons |
| --- | --- | --- |
| **Go** | Single static binary, easy cross-compile, good HTTP ecosystem | MITM libs less mature than mitmproxy |
| **Rust** | Strong safety, performance | Slower MVP |
| **Python + mitmproxy addon** | Fastest secret URL MVP | Packaging/heavier runtime; harder “one binary” |
| **Hybrid** | mitmproxy for L2 lab; Go for production | Two stacks |

**Spec suggestion:** MVP prototype in Python/mitmproxy or Go; production target **single static binary (Go)**. Final choice recorded in D12 open questions.

## 11. Repository layout (planned implementation)

```text
denyout/
  docs/           # this spec
  cmd/denyout/
  internal/proxy/
  internal/policy/
  internal/secrets/
  internal/audit/
  schemas/
  examples/
  test/e2e/
```

## 12. Dependencies philosophy

- Prefer stdlib + small audited deps.  
- No mandatory cloud SDK.  
- Vendoring or lockfile required before 0.1 binary release.
