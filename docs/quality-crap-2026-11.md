# Code quality snapshot (CRAP), 2026-11

CRAP = cyclomatic complexity² × (1 − coverage)³ + complexity, per function
(`gocyclo` joined with `go test -coverprofile`, Docker, `./internal/... ./cmd/denyout-cli/...`).

- Functions measured: 797. Total statement coverage: 44.6%.
- CRAP > 30: 151 functions. CRAP > 100: 59 functions.

## Worst offenders (0% unit coverage; orchestration that changes host state)

| CRAP | cc | Function |
|---:|---:|---|
| 8190 | 90 | `cmd/denyout-cli` `cmdHostctl` |
| 4422 | 66 | `internal/desktop` `(*App).runTray` |
| 1806 | 42 | `cmd/denyout-cli` `cmdHostctlProxyd` |
| 1260 | 35 | `cmd/denyout-cli` `cmdRun` |
| 1167 | 43 | `cmd/denyout-cli` `cmdProfile` (15%) |
| 1122 | 33 | `cmd/denyout-cli` `cmdTest` |
| 600 | 24 | `internal/tun` `StartRealOpts`, `readLoop` |

These are exercised by the Docker harnesses (`scripts/*-docker.sh`, soak, G6 lab)
rather than unit tests, because they mutate nft/ip/TUN state. They are the next
refactor targets: split flag parsing (pure, unit-testable) from effects behind the
`internal/platform` interfaces, then cover the pure half.

## Done in this release

- `parseSNI` (cc 16, was 4% covered): real ClientHello table test, truncation and
  byte-corruption sweeps, and `FuzzParseSNI`.
- Large `desktop` files split by topic (postblock, agents, first_run, ui_api).
