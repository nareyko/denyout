# D06 — CLI and UX

## 1. Design mantra

> First successful protected run in under five minutes. First denial is loud, clear, and actionable — not a stack trace.

## 2. Binary

- Name: `denyout`
- Install channels: see locked table in [`07-desktop.md`](07-desktop.md) §3 — **Must** for Dec 1: GitHub Releases + SHA256SUMS, `install.sh` (Linux/macOS), Windows zip + short doc. Homebrew / winget / apt / `go install` / container = later or stretch.

## 3. Command reference (MVP target)

### 3.1 `denyout run`

```text
denyout run [flags] -- <command> [args...]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--config`, `-c` | search path | Config file |
| `--mode` | from config / `enforce` | `enforce\|audit\|blocklist\|ask` |
| `--preset` | `models` | Built-in allowlist preset |
| `--policy` | — | Alias of config for policy-only file |
| `--tls-mode` | `intercept` | `intercept\|passthrough` |
| `--notify` | `true` on desktop | OS notifications on deny |
| `--print-env` | false | Print proxy env and exit (no run) |
| `--port` | `0` | Proxy port (0=ephemeral) |
| `--ca-dir` | XDG config | CA location |
| `--session-ca` | `true` | Ephemeral CA per run |
| `--verbose`, `-v` | false | Debug logs to stderr |

**Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | Child exited 0 |
| 1 | Child non-zero |
| 2 | Config/policy error |
| 3 | Proxy failed to start |
| 4 | Interrupted |

Child SIGINT/SIGTERM: supervisor forwards and waits.

### 3.2 `denyout check`

Validate that a URL **would** be allowed under current policy without running an agent.

```bash
denyout check "https://evil.test/x?api_key=sk-test"
# DENY secret_in_url
```

### 3.3 `denyout policy validate`

```bash
denyout policy validate -c denyout.yaml
```

### 3.4 `denyout audit tail`

```bash
denyout audit tail -f ~/.local/state/denyout/audit.jsonl
```

### 3.5 `denyout init`

Write a starter `denyout.yaml` in CWD with comments.

### 3.6 `denyout version` / `denyout help`

Standard.

### 3.7 `denyout gui`

Minimal desktop UI (localhost only, embedded in the same binary):

```bash
denyout gui [--config path] [--no-open]
```

Shows start/stop wrap, current mode/preset, URL check, and recent redacted denials. Same policy engine as CLI; does not bypass `denyout run`.

### 3.8 `denyout serve`

Long-running sidecar / compose / systemd proxy:

```bash
denyout serve --config /etc/denyout/denyout.yaml --listen 127.0.0.1:8080 \
  --health-listen 127.0.0.1:8081 [--metrics-listen 127.0.0.1:9090]
```

Same policy engine as `run`. `DENYOUT_KILL=1` refuses to start. Hardened claim requires NetworkPolicy — [`08-server.md`](08-server.md).

## 4. Zero-config happy path

```bash
# install (planned)
curl -fsSL https://denyout.com/install.sh | sh

# run
denyout run -- claude
```

On first run:

1. Generate session CA.  
2. Start proxy with preset `models`.  
3. Spawn child with env.  
4. Print one-line status: `denyout: enforce mode, preset=models, proxy=127.0.0.1:49152`.  
5. On first deny: notification + stderr line with reason and `denyout check` hint.

## 5. Denial UX copy (examples)

```text
denyout: DENY host_not_allowed  https://evil.example/collect
         allow it once:  denyout ask allow evil.example
         or add to denyout.yaml under allow:
           - host: evil.example
```

Secret case:

```text
denyout: DENY secret_in_url  https://cdn.example/p.png?api_key=***
         Secrets in URLs are blocked even on allowed hosts.
```

**MUST NOT** print the raw secret.

## 6. Notifications

| Platform | Mechanism |
| --- | --- |
| macOS | `osascript` / UNUserNotification (later) |
| Linux | `notify-send` if available |
| Windows | Toast (phase later) |

Title: `DenyOut blocked egress`  
Body: reason + redacted host/URL (≤ 120 chars).

## 7. Interactive `ask` mode

Terminal UI:

```text
DenyOut: allow outbound HTTPS to newhost.example:443 ?
  URL: https://newhost.example/v1/x?q=1
  [a] allow once  [s] allow for session  [n] deny  [r] remember host
```

Non-TTY: deny with `ask_unavailable` unless `--notify` approval bridge implemented.

## 8. Project vs user config UX

- Recommend committing `denyout.yaml` for team agents (shared allowlist).  
- User overrides in XDG for personal machine keys of policy (not secrets).  
- `denyout init` explains this in comments.

## 9. Help for “it broke my agent”

Common failures documented in `--help` troubleshooting:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| TLS errors | Client ignores CA | `--tls-mode=passthrough` or set framework CA env |
| Model calls fail | Missing host in preset | `audit` mode discover; add host |
| Package install fails | registry blocked | preset `models+pkg` |
| Everything denied | `strict` preset | switch preset |

## 10. Localization

MVP: English CLI messages. Russian docs may live on Arviser; product UI EN-first.

## 11. Accessibility / scripting

- All commands scriptable; no required GUI.  
- `--json` flag on `check` and denials to stdout for CI (phase 1).

```bash
denyout check --json URL
# {"verdict":"deny","reasons":["secret_in_url"],...}
```
