# D11 — Configuration reference

## 1. Format

- YAML preferred; JSON accepted.  
- `apiVersion: denyout/v1` required for non-empty files after 0.1.  
- Schema file: [`schemas/denyout-config.v1.json`](../schemas/denyout-config.v1.json).

## 2. Full example

See also [`examples/policies/denyout.enforce.models.yaml`](../examples/policies/denyout.enforce.models.yaml).

```yaml
apiVersion: denyout/v1
kind: Config

metadata:
  name: laptop-default

mode: enforce            # enforce | audit | blocklist | ask
preset: models           # models | models+pkg | strict | none | dev | agent

tls:
  mode: intercept        # intercept | passthrough
  session_ca: true

listen:
  host: 127.0.0.1
  port: 0                # 0 = ephemeral

allow_private: false
allow_ip_literals: false
deny_on_dns_failure: true
insecure_allow_all: false

allowed_ports: [443, 80]

allow:
  - host: api.openai.com
  - host: api.anthropic.com
  - host: generativelanguage.googleapis.com
  - host: api.github.com
    ports: [443]

deny:
  - host: pastebin.com

scanners:
  hard_secrets_in_audit_mode: true
  body_scan_max_bytes: 65536
  min_value_len: 6
  named_query:
    enabled: true
  high_entropy:
    enabled: false
  canaries:
    - "DENYOUT_CANARY_"
    - "ARVISER_CANARY_"
  custom_regex: []
  # credential_destinations: hosts where Authorization is expected
  credential_destinations:
    - api.openai.com
    - api.anthropic.com

limits:
  per_host_rpm: 120
  global_rpm: 600

audit:
  jsonl_path: "~/.local/state/denyout/audit.jsonl"
  stdout: false
  include_headers: false

ui:
  notify: true
  show_bypass_warning: true
  ask_timeout_seconds: 30

server:
  agent_id_header: "X-DenyOut-Agent"   # untrusted unless mesh-injected
  metrics_listen: ""                   # e.g. 127.0.0.1:9090
```

## 3. Field dictionary

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `apiVersion` | string | — | `denyout/v1` |
| `kind` | string | `Config` | |
| `mode` | enum | `enforce` | |
| `preset` | enum | `models` | Applied before `allow` merge; `none` = no preset; `agent` = desktop seatbelt allowlist (0.1.9+) |
| `tls.mode` | enum | `intercept` | |
| `tls.session_ca` | bool | true | |
| `listen.host` | string | `127.0.0.1` | |
| `listen.port` | int | 0 | |
| `allow_private` | bool | false | |
| `allow_ip_literals` | bool | false | |
| `deny_on_dns_failure` | bool | true | |
| `insecure_allow_all` | bool | false | Required for `*` hosts |
| `allowed_ports` | [int] | `[443,80]` | Empty = all ports (discouraged) |
| `allow` | [Rule] | [] | |
| `deny` | [Rule] | [] | |
| `scanners.*` | object | see above | |
| `limits.*` | object | see above | 0 = disabled |
| `audit.*` | object | | |
| `ui.*` | object | | desktop |
| `server.*` | object | | |

### Rule object

| Key | Type | Notes |
| --- | --- | --- |
| `host` | string | required |
| `ports` | [int] | optional subset |
| `methods` | [string] | L2 |
| `paths` | [PathRule] | L2 |
| `require_intercept` | bool | default false |
| `include_apex` | bool | for `*.domain` patterns |
| `reason` | string | documentation / audit |

### PathRule

| Key | Type |
| --- | --- |
| `prefix` | string |
| `exact` | string |
| `regex` | string |

Exactly one matcher key per PathRule.

## 4. Preset contents (informative; pin in code)

### `models` (MVP)

Exact hosts (illustrative — maintain in code with tests):

- `api.openai.com`
- `api.anthropic.com`
- `api.groq.com`
- `api.mistral.ai`
- `generativelanguage.googleapis.com`
- `api.cohere.ai`
- `api.fireworks.ai`
- `*.openai.azure.com` (careful wildcard policy)

### `models+pkg`

Adds: `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `crates.io`, `static.crates.io`, `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `registry.yarnpkg.com`.

### `strict`

No preset hosts; only explicit `allow`.

### `agent` (0.1.9+ desktop default)

Models + registries (`proxy.golang.org`, `sum.golang.org`, `registry.npmjs.org`, `pypi.org`, …) + git/CDN (`github.com`, `api.github.com`, `raw.githubusercontent.com`, `release-assets.githubusercontent.com`, …) + Cursor runtime hosts (`api2.cursor.sh`, …). See `presets/agent.yaml`.

## 5. Env overrides

| Env | Maps to |
| --- | --- |
| `DENYOUT_MODE` | `mode` |
| `DENYOUT_CONFIG` | config path |
| `DENYOUT_TLS_MODE` | `tls.mode` |
| `DENYOUT_LISTEN_PORT` | `listen.port` |
| `DENYOUT_AUDIT_PATH` | `audit.jsonl_path` |
| `DENYOUT_POLICY_PROFILE` | desktop proxyd: `agent` \| `browse` |
| `DENYOUT_ALWAYS_ALLOW` | comma-separated always-allow hosts |
| `DENYOUT_KILL` | if `1`, all verdicts deny |
| `DENYOUT_ALLOW_INSECURE_OVERRIDE` | gates dangerous env merges |

## 6. Validation rules

Config load **MUST** fail if:

- Unknown `apiVersion`.  
- `insecure_allow_all` false but allow contains `*`.  
- Invalid regex in scanners or paths.  
- `mode=ask` on `denyout serve` without `--allow-ask` (ask not for headless).  
- `listen.host` is `0.0.0.0` without `--expose`.
