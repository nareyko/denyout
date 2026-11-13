# D07 — Desktop deployment

## 1. Goals

- Protect P1 users who will not configure firewalls: **Protect this computer** is the primary GUI mode.  
- Transparent redirect of this user’s HTTP/HTTPS into DenyOut while On (Linux nft / macOS pf / Windows WinDivert).  
- Install DenyOut CA into the trust store when enabling Protect computer (one admin prompt).  
- Advanced / CLI: scope trust to a **child process tree** via `denyout run` (no host redirect).

## 2. Supported platforms (MVP target)

| OS | MVP (bet 1 Dec 2026) | Notes |
| --- | --- | --- |
| Ubuntu / Linux x86_64 / arm64 | Yes | Primary CI |
| macOS Apple Silicon / Intel | Yes | Notifications + keychain later |
| Windows | Yes (M4 install path) | Proxy env works; CA / intercept UX is the risk; if M4 fails → mark preview/unsupported |

## 3. Install (locked for MVP / M4–M6)

**SoT of artifacts:** GitHub Releases (`nareyko/denyout`) with binaries for **linux, darwin, windows** + **SHA256SUMS** (goreleaser).  
**Default trust:** process wrap uses session CA via child env only. **Protect this computer** installs a persistent desktop CA into the OS trust store (kept until uninstall).

### 3.1 Canonical recipes (≤5 minutes — M4)

| OS | Canonical path | Fallback if M4 fails |
| --- | --- | --- |
| **Ubuntu / Linux** | `curl -fsSL https://denyout.com/install.sh \| sh` → `~/.local/bin/denyout` (script fetches Release + verifies SHA256) | Manual `.tar.gz` from Release |
| **macOS** | Same `install.sh` → `~/.local/bin` | Manual `.tar.gz`; Homebrew = **post–first release**, not required for M4 |
| **Windows** | `.zip` from Release + short EN install doc (PATH to `denyout.exe`) | Mark OS **preview / unsupported** in release notes; **winget = optional stretch** |

```bash
# Unix (Linux / macOS) — preferred (silent)
# Auto-detect: graphical session → Desktop; headless → Server (CLI).
# Desktop: binary + login autostart + try whole-computer once (admin) →
#   fallback Session (HTTP proxy env) → detach tray.
# Force: --desktop / --server, or DENYOUT_INSTALL_MODE=desktop|server
curl -fsSL https://denyout.com/install.sh | sh
curl -fsSL https://denyout.com/install.sh | sh -s -- --desktop
curl -fsSL https://denyout.com/install.sh | sh -s -- --server

denyout desktop                 # tray; restores last scope
denyout desktop --install       # silent register+start (used by install.sh)
# denyout desktop --web-ui      # optional / tests only
denyout version
denyout init                    # server / advanced path
denyout run -- curl -I https://api.anthropic.com
```

### Scopes

| Scope | Mechanism | Admin | Coverage |
| --- | --- | --- | --- |
| **Computer** | hostguard transparent redirect + system CA | Yes (once) | This user’s TCP 80/443 (OS-dependent) |
| **Session** | local proxy + `HTTP(S)_PROXY` / `environment.d` | No | Apps that honor proxy env; browsers may ignore |

Tray: **Computer** / **Session** / **Off** (active mode marked ✓; re-click is a no-op), settings toggles, **Open activity…** (loopback Activity/Settings page), **Open diagnostics…**, **Copy last error**.

- **Activity** (`http://127.0.0.1:…/activity`): mode, recent denials from `audit.jsonl`, notify/Ask, NSS/clipboard hints.
- **Diagnostics** folder: `~/.local/state/denyout/` (`desktop.log`, `last-error.txt`, `audit.jsonl`, `README.txt`). Elevation failures (pkexec/UAC) are in `last-error.txt` / `desktop.log` — not in audit.

Install elevates **at most once** (in the tray process). Turning protection off may ask once more to remove host rules.

```text
Windows (MVP):
1. Download denyout_*_windows_*.zip from GitHub Releases
2. Verify SHA256 against SHA256SUMS
3. Extract denyout.exe onto PATH (see docs/install-windows.md — short EN)
4. denyout version && denyout init && denyout run -- ...
```

### 3.2 Channels — status

| Channel | Dec 1 status |
| --- | --- |
| GitHub Releases + SHA256SUMS | **Must** (M6) |
| `install.sh` (Linux/macOS) | **Must** (M4) |
| Windows zip + short EN doc | **Must** (M4) |
| Homebrew | After first Release (nice-to-have) |
| winget | Optional stretch |
| `go install` | Contributors only (needs Go toolchain) |
| apt / yum / scoop / chocolatey | Deferred |
| Container image | Server path (`denyout serve`), not laptop M4 |
| denyout.com hosts `install.sh` | Same script as repo; site may redirect to GitHub raw/Release |

One release pipeline feeds every channel; package managers only re-point at Release assets.

## 3.3 Protect this computer (hostguard)

| OS | Redirect | CA | Elevation |
| --- | --- | --- | --- |
| Linux | nftables table `denyout` (UID filter, TCP 80/443 → local proxy) | `/usr/local/share/ca-certificates` + `update-ca-certificates` | `pkexec` / sudo |
| macOS | pf anchor `com.denyout` | System keychain `security add-trusted-cert` | admin osascript |
| Windows | WinDivert + `denyout-windivert.exe` — see [`hostguard-windows.md`](hostguard-windows.md) | `certutil` Root store | UAC |

CLI helper: `denyout hostctl render|apply|remove --port N --ca PATH --uid N`.  
Default policy: [`examples/policies/denyout.whole_device.yaml`](../examples/policies/denyout.whole_device.yaml) (allow web + scanners). Ask mode: `denyout.whole_device_ask.yaml`.

Proxy accepts **transparent** connections (TLS SNI / HTTP Host), not only HTTP-proxy CONNECT.

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
