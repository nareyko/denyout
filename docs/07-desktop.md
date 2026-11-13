# D07 — Desktop deployment

## 1. Goals

- Protect P1 users who will not configure firewalls.  
- Scope trust to the **child process tree** when possible.  
- Avoid installing a system-wide root CA by default.

## 2. Supported platforms (MVP target)

| OS | MVP (bet 1 Dec 2026) | Notes |
| --- | --- | --- |
| Ubuntu / Linux x86_64 / arm64 | Yes | Primary CI |
| macOS Apple Silicon / Intel | Yes | Notifications + keychain later |
| Windows | Yes (M4 install path) | Proxy env works; CA / intercept UX is the risk; if M4 fails → mark preview/unsupported |

## 3. Install

Planned:

```bash
curl -fsSL https://denyout.com/install.sh | sh
# installs to ~/.local/bin/denyout
```

Also: Homebrew formula, GitHub Releases binaries.

## 4. Runtime algorithm (`denyout run`)

1. Parse args; find `--` command.  
2. Load policy (D03 order).  
3. Create session id (UUIDv4).  
4. Create or load CA (`--session-ca` default true).  
5. Bind `127.0.0.1:PORT`.  
6. Write lockfile under `$XDG_RUNTIME_DIR/denyout/<session>.json` with port, pid, policy hash.  
7. Build child env (section 5).  
8. Start proxy loop.  
9. Start child in new process group.  
10. Wait; on exit stop proxy; shred session CA if ephemeral.  
11. Exit with child’s code (or mapped codes).

## 5. Child environment

**MUST set:**

```text
HTTP_PROXY=http://127.0.0.1:PORT
HTTPS_PROXY=http://127.0.0.1:PORT
http_proxy=...
https_proxy=...
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=...
DENYOUT_SESSION_ID=...
DENYOUT_PROXY=http://127.0.0.1:PORT
```

**When `tls-mode=intercept` MUST also set (best-effort matrix):**

```text
SSL_CERT_FILE=<path-to-ca-or-bundle>
REQUESTS_CA_BUNDLE=<path>
CURL_CA_BUNDLE=<path>
NODE_EXTRA_CA_CERTS=<path>
GIT_SSL_CAINFO=<path>
```

Document that Node <20 may need additional flags; Python `httpx`/`requests` respect bundles; Go often uses system trust (macOS/Windows) — **Go children may need `SSL_CERT_FILE`** (crypto/x509 respects on Unix).

## 6. What desktop MVP does **not** enforce

Without OS sandbox integration (MVP: sandbox remains **optional**; desktop is still “supported” with this residual documented — see [`design-decisions.md`](design-decisions.md) and D10):

- Raw sockets bypassing proxy.  
- `curl --noproxy '*'`.  
- Binaries using hard-coded DoH / custom stacks.  
- Agents launched outside `denyout run`.

### 6.1 Opt-in hardening

```bash
denyout run --sandbox=srt -- claude
denyout run --sandbox=fence -- ...
```

When `--sandbox` set, DenyOut **SHOULD** wrap child with the external tool so that only localhost proxy is reachable (Anthropic `sandbox-runtime`, Fence, nono). Not required for M4. Deeper integration = phase 1.5.

## 7. CA UX policy

| Action | Default |
| --- | --- |
| System keychain install | Off |
| Session CA | On |
| Persistent user CA | Opt-in `--session-ca=false` |
| Print CA fingerprint at start | On when verbose |

`denyout ca install-system` (post-MVP) must require typing `INSTALL SYSTEM CA`.

## 8. File locations (XDG)

| Path | Use |
| --- | --- |
| `~/.config/denyout/denyout.yaml` | User config |
| `~/.config/denyout/ca/` | Persistent CA |
| `~/.local/state/denyout/audit.jsonl` | Default audit |
| `$XDG_RUNTIME_DIR/denyout/` | Session lockfiles |
| `./denyout.yaml` | Project config |

## 9. Integration snippets

### Shell alias

```bash
alias claude='denyout run -- claude'
alias agent='denyout run --'
```

### npm script

```json
"scripts": {
  "agent": "denyout run -- node dist/agent.js"
}
```

### systemd user unit (long-running local agent)

Example under `examples/` — `Environment=HTTPS_PROXY=...` pointing at a user-level `denyout serve` daemon (phase 1.1). MVP focuses on `run`.

## 10. Desktop threat residual

Documented banner on first run (once):

```text
Note: without an OS sandbox, some tools can bypass the proxy.
For stronger isolation, see docs: desktop hardening.
```

Suppressible via `ui.show_bypass_warning: false`.
