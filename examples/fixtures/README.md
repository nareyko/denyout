# Lab fixtures

SQLite lab DB is created/seeded by `denyout test` (or `internal/lab.OpenSeeded`).

YAML under `suites/` mirrors the seeded cases for human review (SoT remains `internal/lab/seed.go`).

```bash
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite --suite r20_url
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite --suite fp_signed
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite --suite agent_egress
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite --suite redirect_policy
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite
```

## Suites

| Suite | Purpose |
| --- | --- |
| `r20_url` | ≥20 secret-URL / canary deny fixtures (**M1**) |
| `ssrf` | Metadata / private / loopback hard denies |
| `allow_models` | Allowlisted model hosts + unknown host deny / audit would_deny |
| `fp_signed` | Signed-URL carve-outs (GitHub release-assets, SigV4, alive session) |
| `fp_session` | Context-sensitive `session=` / token shape |
| `agent_egress` | Agent allowlist allow/deny (Rule of Two on egress) |
| `exfil_true` | Secrets/canaries/userinfo still deny on allowlisted hosts |
| `browse_compat` | Legacy blocklist Computer behavior |
| `redirect_policy` | Hop2 destination re-eval |
| `trifecta_smoke` | Unknown host + canary vs clean unknown |

Primary canary id: `r20-01-canary-query`  
URL: `https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB`

Acceptance AT-01…AT-09: `go test ./internal/accept/`

## Large external corpora

See [`corpus/README.md`](corpus/README.md). Full Prowl (~503k, CC BY-NC local cache) + agent-egress-bench:

```bash
python scripts/fetch_corpus.py
denyout test --quiet --metrics --corpus-jsonl examples/fixtures/corpus/prowl_corpus.jsonl --suite prowl_corpus
```
