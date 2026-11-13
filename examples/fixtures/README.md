# Lab fixtures

SQLite lab DB is created/seeded by `denyout test` (or `internal/lab.OpenSeeded`).

```bash
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite --suite r20_url
go run ./cmd/denyout test --db examples/fixtures/denyout-lab.sqlite
```

## Suites

| Suite | Purpose |
| --- | --- |
| `r20_url` | ≥20 secret-URL / canary deny fixtures (**M1**) |
| `ssrf` | Metadata / private / loopback hard denies |
| `allow_models` | Allowlisted model hosts + unknown host deny / audit would_deny |

Primary canary id: `r20-01-canary-query`  
URL: `https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB`

Acceptance AT-01…AT-09: `go test ./internal/accept/`
