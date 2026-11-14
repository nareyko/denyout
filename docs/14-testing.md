# D14 - Testing and acceptance

## 1. Layers

| Layer | What |
| --- | --- |
| Unit | Policy engine decisions. Scanners. Host matching. IP unsafe |
| Integration | Proxy CONNECT + intercept with local upstream |
| E2E | `denyout run -- curl ...` scripts |
| Bypass | Documented residual. Server NetworkPolicy tests in kind |
| Supply chain | `govulncheck` / dep audit before release |

## 2. Normative acceptance tests (MVP)

Each test has id, setup, action, expected.

### AT-01 Allow model host

- Config: preset `models`, mode `enforce`, tls intercept. 
- Action: GET `https://api.anthropic.com/` via proxy. 
- Expect: verdict `allow` (HTTP status from upstream may be 401/403).

### AT-02 Deny unknown host

- Action: GET `https://example.com/` 
- Expect: deny `host_not_allowed`. No upstream TCP to example.com (verify with packet counter or fake resolver).

### AT-03 Secret in query

- Action: GET `https://api.anthropic.com/v1/x?api_key=sk-denyouttest000000000000000` 
- Expect: deny `secret_in_url` even though host allowlisted.

### AT-04 Canary

- Action: GET `https://api.anthropic.com/?q=DENYOUT_CANARY_TEST` 
- Expect: deny `canary_detected`.

### AT-05 Metadata SSRF

- Action: GET `http://169.254.169.254/` 
- Expect: deny `unsafe_ip` in all modes.

### AT-06 Audit mode would_deny

- Mode audit. GET `https://example.com/` 
- Expect: forward + event with `would_deny` / reasons include `host_not_allowed`. 
- Exception: AT-05 still hard deny.

### AT-07 Redaction

- Trigger AT-03. Read audit JSONL. 
- Expect: raw key material absent; `***` present.

### AT-08 Config fail closed

- Invalid regex in config. 
- Expect: `denyout run` exit code 2. Child not started.

### AT-09 check CLI

- `denyout check` URL from AT-03 -> non-zero + deny reason.

### AT-10 Session teardown

- Start run, kill child. Proxy port closed. Lockfile removed.

## 3. Server acceptance (phase 1.1)

### AT-S1 NetworkPolicy bypass

- In kind: agent pod tries `curl --noproxy '*' https://example.com`. 
- Expect: failure (timeout/unreachable), not 200.

### AT-S2 Policy volume readonly

- Agent cannot write ConfigMap-mounted policy.

## 4. Lab canaries for demos

Files in `examples/canaries/`:

| File | Purpose |
| --- | --- |
| `r20-image.md` | Markdown with image URL canary |
| `urls.txt` | List of URLs for `denyout check` loop |
| `expected.json` | Expected verdicts |

## 5. M3 false-deny script

Metric: model-only traffic false-deny ≤ **1/10** scripted runs need an allowlist edit.

- URL list: [`examples/m3/urls.txt`](../examples/m3/urls.txt) (exactly 10 clean model-host paths).
- Runner: [`scripts/m3-false-deny.sh`](../scripts/m3-false-deny.sh) -> `denyout check` (no dial).
- Pass if ≤1 of 10 returns deny (would require allowlist/policy edit).
- Wired in Linux CI and `make m3`.

## 6. Performance smoke

- 100 sequential GETs to allowlisted host through proxy. P95 overhead < 50ms local (informal until measured).

## 7. Security regression

Any change to evaluation order or scanner defaults **MUST** update this file and unit snapshots in the same PR.
