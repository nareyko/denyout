# D09 — Audit, metrics, operations

## 1. Principles

1. Every decision produces an event (allow, deny, would_deny, policy_reload, session_start/end).  
2. Events are structured JSON (JSONL).  
3. Secrets are redacted before persistence.  
4. Agent MUST NOT be able to edit the authoritative audit stream in supported server mode.

## 2. Event schema (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "ts": "2026-11-13T16:00:00.000Z",
  "session_id": "uuid",
  "agent_id": null,
  "verdict": "deny",
  "reasons": ["secret_in_url"],
  "rule_id": null,
  "mode": "enforce",
  "inspection": "intercept",
  "network": {
    "dest_host": "evil.example",
    "dest_port": 443,
    "dest_ips": ["203.0.113.5"],
    "protocol": "https",
    "server_name": "evil.example"
  },
  "http": {
    "method": "GET",
    "path": "/c.png",
    "query_redacted": "api_key=***"
  },
  "detectors": ["named_query_params"],
  "bytes_out": 0,
  "latency_ms": 2,
  "policy_hash": "sha256:abcd…",
  "denyout_version": "0.1.9",
  "policy_profile": "agent",
  "process": "proxyd"
}
```

### Required fields

`schema_version`, `event_id`, `ts`, `session_id`, `verdict`, `reasons`, `mode`, `network.dest_host`, `network.dest_port`, `policy_hash`, `denyout_version`.

### Optional attribution (0.1.9+)

| Field | Meaning |
| --- | --- |
| `policy_profile` | `agent` \| `browse` (desktop seatbelt profile) |
| `process` | Best-effort client label (e.g. `proxyd`, `desktop-session`); empty OK |

Activity UI can filter denials by reason (`host_not_allowed` vs `secret_in_url`).

### Forbidden by default

Raw `Authorization` values, raw query secrets, request bodies.

## 3. Sinks

| Sink | MVP | Notes |
| --- | --- | --- |
| stderr (human) | yes | denials |
| JSONL file | yes | path configurable |
| stdout JSONL | yes | containers |
| Webhook | later | HMAC-signed |
| OTLP logs/metrics | later | |
| hash-chain file | later | tamper evidence |

## 4. Metrics (phase 1.1)

Prometheus-style:

- `denyout_decisions_total{verdict,reason}`  
- `denyout_proxy_inflight`  
- `denyout_dns_failures_total`  
- `denyout_mitm_handshakes_total`

## 5. Retention

Default desktop: rotate `audit.jsonl` at ~32 MiB; keep the last 3 rotated `*.bak` files.  
CLI: `denyout audit tail [-n N] [--denials] [--path FILE]`.  
Server: rely on platform logging stack; local file optional.

## 6. Operational runbooks (outline)

### 6.1 False deny on model provider

1. `denyout audit tail` → confirm host.  
2. Add host to allow.  
3. Or `--mode=audit` temporarily (warn).  

### 6.2 Suspected exfil attempt

1. Filter `verdict=deny` + `secret_*` / `canary_*`.  
2. Capture `session_id`, agent version, policy_hash.  
3. Preserve audit file; rotate credentials that appeared in canary tests only if real secrets used (lab should use fakes).

### 6.3 Proxy down in server

Readiness fails → kube stops sending traffic; with NetworkPolicy agent cannot bypass → fail closed. Alert on CrashLoop.

## 7. Policy change audit

On reload:

```json
{
  "verdict": "info",
  "reasons": ["policy_reload"],
  "policy_hash": "sha256:…",
  "policy_hash_previous": "sha256:…"
}
```

## 8. Privacy

- No cloud telemetry default.  
- If future “phone home” crash reports: opt-in, scrub hosts to eTLD+1 only, never URLs with query.
