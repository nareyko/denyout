# D05 - Secret & exfiltration detection

## 1. Goal

Catch **obvious outbound exfiltration** of credentials and planted canaries, especially in URLs (R-20), with low false-negative on known patterns and tunable false-positives.

This is **not** a general DLP product. It is a high-precision seatbelt for agent egress.

## 2. Scan surfaces (by inspection depth)

| Surface | Passthrough L1 | Intercept L2 / cleartext |
| --- | --- | --- |
| Host | ✓ | ✓ |
| URL path (CONNECT target path N/A) | ✗ | ✓ |
| Query string | ✗ | ✓ |
| Userinfo (`user:pass@host`) | if present in URL | ✓ |
| Headers (`Authorization`, `Cookie`, `X-Api-Key`, ...) | ✗ | ✓ hard deny (`secret_in_header`); auth-like headers to **allowlisted** hosts allowed (API calls); canaries always deny |
| Body prefix | ✗ | ✓ hard deny (`secret_in_body`), first `body_scan_max_bytes` of json/form/text |

Fragment (`#...`) is not sent to servers; **MAY** still appear in some client logs - out of scope unless visible to proxy.

## 3. Detector pipeline

Ordered, short-circuit on first **blocking** hit (configurable `scan_all: true` to collect all for audit).

1. `canary` 
2. `userinfo` 
3. `named_query_params` 
4. `header_credentials` 
5. `known_token_prefixes` 
6. `jwt_ish` 
7. `cloud_key_shapes` 
8. `high_entropy` (optional, off by default in MVP) 
9. `custom_regex` (user)

Each detector returns `{ hit: bool, detector, evidence_redacted, span? }`.

## 4. Detectors (normative MVP set)

### 4.1 Canary

Policy:

```yaml
scanners:
 canaries:
 - "ARVISER_CANARY_"
 - "DENYOUT_CANARY_"
 - "SECRET_MARKER_"
```

Match substring in URL (path+query), headers values, body prefix -> reason `canary_detected`.

### 4.2 Userinfo

Any URL with `userinfo` containing password-like form -> `secret_in_url`.

### 4.3 Named query parameters

**Tiers (0.1.9+):**

| Tier | Names (examples) | Behavior |
| --- | --- | --- |
| High-confidence | `api_key`, `password`, `client_secret`, `aws_secret_access_key`, `private_key`, `authorization`, ... | Deny when value length ≥ min |
| Context-sensitive | `session`, `session_id`, `token`, `sig`, `signature`, `hmac` | Deny only when value matches token shape / high-risk prefix |

**Structural carve-outs** (no `secret_in_url` from JWT/sig noise alone): GitHub `release-assets.githubusercontent.com` signed query; AWS SigV4 when all required `X-Amz-*` present once. Hard secrets (`sk-`, `ghp_`, canaries, userinfo) still deny on any host.

**Prefix pack (0.1.9+):** Stripe `sk_live_`/`rk_live_`, SendGrid `SG....`, GitLab `glpat-`/`glrt-`/..., HuggingFace `hf_`, npm `npm_`, Slack webhooks/`xoxt-`, Telegram/Discord (M/N/O...), DigitalOcean `dop_v1_`, Shopify `shp*`, AWS `AKIA`/`ASIA` (+ access-key/secret **pair**), DB URIs with `user:pass@`, `Authorization: Basic ...`, Azure `AccountKey=`, PEM after query-decode. Named high-confidence: `dd_api_key`/`database_url`/... - not bare `auth`/`key`. Still **not** Twilio bare SIDs, AROA, generic passwords / raw high-entropy.

Case-insensitive param names in:

`password`, `passwd`, `secret`, `token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `apikey`, `api-key`, `auth`, `authorization`, `session`, `session_id`, `private_key`, `client_secret`, `aws_secret_access_key`, `sig`, `signature`, `hmac`

**Behavior:** If value length ≥ `min_value_len` (default 6) -> hit. 
**Allow exception:** params listed in `scanners.query_allowlist` for specific hosts (e.g. OAuth `state` on known IdP) via per-host overrides.

### 4.4 Header credentials

Header names (case-insensitive):

`Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`, `Cookie` (optional, default **scan Cookie only for canaries** to reduce noise)

For `Authorization`: values matching `Bearer eyJ...`, `Bearer sk-...`, raw keys -> hit when destination host is **not** in `credential_destinations` allowlist.

**Important MVP policy:** Sending `Authorization` to an **allowed** model API is normal -> **MUST NOT** deny solely because Authorization exists toward allowlisted API hosts. Deny when:

- Header present **and** host not allowed, or 
- Header value matches canary, or 
- `scanners.forbid_authorization_to_non_allowlisted: true` (default true) - already covered by host enforce; this matters in `blocklist`/`audit`.

### 4.5 Known token prefixes

Examples (extensible table in code):

| Prefix / pattern | Label |
| --- | --- |
| `sk-` + `[A-Za-z0-9_\-]{20,}` | openai-ish |
| `sk-ant-` | anthropic |
| `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | github |
| `xox[baprs]-` | slack |
| `AKIA[0-9A-Z]{16}` | aws access key id |
| `AIza[0-9A-Za-z\-_]{35}` | google api key-ish |
| `-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----` | pem |

Match in URL and body prefix -> `secret_in_url` / `secret_in_body`.

### 4.6 JWT-ish

Regex: `eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}` 
In query/path -> hit. In Authorization toward allowlisted host -> OK.

### 4.7 High entropy (optional)

Shannon entropy over URL path segments / query values longer than N. 
Default **off** (false positives on UUIDs). When on, require entropy ≥ threshold AND length ≥ 24 AND not matching UUID/hex-date allow patterns.

### 4.8 Custom regex

User-provided patterns with `id` and `redact: true`. Invalid regex -> policy load failure (fail closed).

## 5. Redaction rules

Audit and notifications **MUST** redact evidence:

- Replace matched secret spans with `***`. 
- For query params, replace values of sensitive keys with `***`. 
- Preserve host, path structure, param **names**.

Example:

```text
https://evil.test/c.png?api_key=sk-live-abc123&x=1
-> https://evil.test/c.png?api_key=***&x=1
```

## 6. Body scanning limits

- Default `body_scan_max_bytes: 65536`. 
- Content-Types scanned by default: `application/json`, `application/x-www-form-urlencoded`, `text/*`, `application/javascript`. 
- Multipart: scan text parts only best-effort. 
- Streaming request bodies: scan first N bytes; document residual risk.

## 7. False positive management

| Knob | Default |
| --- | --- |
| `scanners.named_query.enabled` | true |
| `scanners.high_entropy.enabled` | false |
| `scanners.min_value_len` | 6 |
| Per-host `scanners.ignore` | empty |

Project-level overrides in `denyout.yaml` committed to repo for team agents.

## 8. Test canaries (lab)

Ship under `examples/canaries/`:

1. Markdown image URL with `DENYOUT_CANARY_ABC` in query. 
2. `sk-denyouttest000000000000000` in path. 
3. JWT-ish in query. 
4. Metadata IP fetch. 
5. Unknown host without secrets.

Expected verdicts documented in D14.

## 9. Explicit non-goals

- Client-side steganography detection. 
- Encrypted blob DLP inside allowlisted SaaS APIs. 
- Stopping screenshots / human copy-paste. 
- Replacing vaults or secret scanners for repos at rest (e.g. gitleaks) - complementary.
