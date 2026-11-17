# Security & stability review - 2026-11

Scope: all Go packages (`internal/*`, `cmd/denyout-cli`), the Wails desktop shell, `install.sh`. Method: automated tools in Docker (`go vet`, `staticcheck`, `govulncheck`, `gosec`, `go test -race`, fuzz) plus manual review of proxy/policy/secrets, tun/hostguard/run, and desktop/cloudsync/updates. No test touched the host network; labs ran in Docker with `NET_ADMIN`.

## Fixed (one commit per topic on PR #43)

| # | Finding | Severity | Fix | Proof |
|---|---|---|---|---|
| 1 | `vpn-egress-apply`: iface name interpolated into `sh -c` as root | critical | validate name, argv exec, gate inside function | Docker exploit replay |
| 2 | Helper socket 0666; owner 0 / failed SO_PEERCRED = everyone; client-chosen uid; arbitrary root file read via CA path | critical | deny-by-default, owner-only 0600, uid forced to owner, PEM-only CA path | Docker exploit replay (T2-T5) |
| 3 | Root unit runs binary from a user-writable path | critical | install root-owned copy under `/usr/lib/denyout` | unit test |
| 4 | Non-atomic nft replace; orphan REDIRECT on helper stop | high | one `nft -f` transaction; SIGTERM cleanup; watchdog | Docker nft + watchdog e2e |
| 5 | IPv6 bypass under TUN; no `[::1]` listener | high | IPv6 guard rules kept; dual-stack transparent listener | rules test + Docker e2e |
| 6 | QUIC-MITM upstream `InsecureSkipVerify: true` | high | system roots; opt-in env for lab | G6 lab |
| 7 | Body scan allow-list (multipart/octet/ndjson/gzip bypass) | high | scan all non-media; decode gzip/deflate | unit tests |
| 8 | Secrets persisted in audit paths / userinfo / block logs | high | `RedactPath`, userinfo masking, all token shapes | unit + fuzz |
| 9 | DNS-rebinding SSRF (`DefaultTransport`, hostname dial); transparent HTTP unscanned | high | pinned dials; header/body scan | existing + new tests |
| 10 | Data race `Evaluate` vs `AllowHost/RevokeHost` | medium | locked snapshot; copy-on-revoke | `-race` test (fails on old code) |
| 11 | `custom_regex` validated but never applied; header scan limited to 7 names; token userinfo | medium | enforced / widened | unit tests |
| 12 | Cloud sync could loosen protection; http API base | medium | validation, tighten-only flags, https-only | unit tests |
| 13 | Profile id traversal; predictable `/tmp` dir | medium | slug check, private dir | unit test |
| 14 | Truncated feed accepted; corrupt cache disables protection; non-atomic state | medium | fail on cap, self-heal, atomic writes | unit tests |
| 15 | Update URL scheme unchecked; install.sh tag/BASE_URL/substring checksum | medium | allow-list, validation, exact match | Docker install test |
| 16 | Host header vs SNI (fronting); no handshake/idle deadlines; unbounded leaf cache; port wraparound | medium | 421, deadlines, cap, range check | unit tests |
| 17 | Web-UI DNS rebinding / cross-site POST; `notify-send` option injection; signals not forwarded | medium/low | guards, `--`, forwarding | unit tests |
| 18 | Unsigned releases | medium | keyless cosign + verifying installer | Docker (offline gates) |
| 19 | 3 module advisories | low | dependency bump | govulncheck clean |

## Tool results (before fixes)

`go build/vet`: clean. `go test -race -count=2`: all 17 packages pass. `govulncheck`: 0 called vulns (3 in required modules, fixed by bump). `staticcheck`: 12 style/dead-code items (not security). `gosec`: 173 findings, overwhelmingly G204/G301/G306 noise; the relevant ones (G402 TLS skip-verify, G118) were reviewed. `npm audit --omit=dev`: 0; dev-only vite/esbuild advisories (dev server). Fuzz: `FuzzScanAndRedact` 90s/380k execs and `FuzzParse` 60s/1M execs, no crashes.

## Follow-up: continuous assurance (security-1)

- CI: `supply-chain` job (`go mod verify`, tidy check, `govulncheck`, outdated-module report, `npm audit`), workflow `permissions: contents: read`, all actions pinned to commit SHAs, `staticcheck` pinned, Dependabot (gomod, actions, npm).
- `fuzz.yml` runs every `Fuzz*` target (auto-discovered by `scripts/fuzz-all.sh`) twice a week and uploads crashers. New targets: `FuzzParseRequest` (helper protocol), `FuzzHostMatch` (policy).
- Found by fuzzing: IDNA maps U+3002/U+FF0E/U+FF61 to `.`, so `normalizeHost("evil.com\uff61")` kept a trailing dot and missed a rule for `evil.com`. Fixed + regression test.
- Review of cloudsync/updates/threatlists/gui: redirects were unrestricted (an https endpoint could bounce the bearer token or manifest to plain http); added `internal/httpsafe` (no https->http, max 5 hops) to the default clients. `/api/check` body is now size-capped.
- Open (needs owner decision): [`docs/design-security-open-decisions.md`](design-security-open-decisions.md) (owner-uid trust, IPv6/DNS in TUN). Also open: a user-supplied `*http.Client` bypasses the redirect policy; `apiErr` echoes remote error text into the UI; `srt` read restrictions.

## Residual risk / backlog

1. **Owner-uid trust.** A sandboxed agent running as the owner uid can still call helper verbs (now validated). Longer term: split the agent into a different uid or require a per-session token.
2. **No IPv6 in the TUN data plane** (IPv6 relies on the nft redirect path).
3. **DNS / DoH and non-80/443 TCP** remain outside Protect (documented non-claim).
4. **Fail-soft default.** After a proxy outage the user is briefly uninspected (state `degraded`, ~6s). `DENYOUT_FAIL_CLOSED=1` gives strict mode; surfacing `degraded` in the tray is still to do.
5. **`srt` sandbox** defaults do not restrict file reads; `run.Exec` trusts the PATH lookup.
6. **Signing:** positive cosign verification path is untested until a tagged release runs the new workflow; `release-desktop.yml` assets are not signed yet.
7. Minor: protocol-relative redirect re-evaluation, audit sink silently stops if reopen fails after rotation, `TailEvents` loads the whole file, `UserAllowAll` disables all non-canary scanners for the host (consider keeping userinfo/PEM/AWS pair), IDN/trailing-dot normalisation, leftover staticcheck items.

## How to re-run (Docker only)

```sh
./scripts/security-helper-regression-docker.sh   # root-helper exploit replay
./scripts/watchdog-e2e-docker.sh                 # watchdog + IPv6 listener
./scripts/install-verify-test-docker.sh          # installer integrity gates
SOAK_SECONDS=60 ./scripts/soak-docker.sh         # concurrency + proxy/helper restart soak
./scripts/closed-loop-tun-g6-docker-dogfood.sh   # TUN/QUIC lab
```
