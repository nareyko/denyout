# D07 - Desktop deployment

Normative deploy/build for desktop.

**User-visible surfaces (behavior):** [`07-desktop-ux.md`](07-desktop-ux.md). 
**Screens & message catalog:** [`07-desktop-ux-catalog.md`](07-desktop-ux-catalog.md).

## 1. Two binaries

| Binary | Role | Build |
| --- | --- | --- |
| **`denyout`** | Tray + Wails React UI (Home / History / My agents / Settings / Problems) | `CGO_ENABLED=1` + WebKit / WebView2 (`release-desktop` workflow) |
| **`denyout-cli`** | CLI, proxy, `hostctl proxyd`, `denyout-cli desktop` (native-dialog fallback shell) | `CGO_ENABLED=0` (GoReleaser) |

`install.sh --desktop` installs **denyout-cli** always and **denyout** (GUI) when the release asset exists. Autostart / detach prefer `denyout` when present beside `denyout-cli`.

Linux Protect CA paths: `/usr/local/share/ca-certificates/denyout.crt`, `/etc/ssl/certs/denyout.pem` (NSS nickname `DenyOut CA`).

### Build denyout (GUI) locally (Linux)

```bash
sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev
cd cmd/denyout/frontend && npm ci && npm run build && cd ../../..
CGO_ENABLED=1 go build -tags 'wails,production,webkit2_41' -ldflags "-X main.version=dev" -o denyout ./cmd/denyout
```

Plain `go build` **must** include the `production` tag (otherwise Wails links a stub). Close the window **hides to tray**. Quit only from the tray menu - see [`07-desktop-ux.md`](07-desktop-ux.md) §§2-5.

## 2. Modes (summary)

Full menu and screen inventory: [`07-desktop-ux.md`](07-desktop-ux.md) §§2-5.

| Mode | User expectation |
| --- | --- |
| Safe desktop | Web OK. Clear threats -> **Keep blocked** / **Allow this site** + URL |
| My agents (wrap) | Per-program proxy. Pre-act Ask on new hosts |
| Agents only (whole PC) | Settings -> Advanced (strong warn). Allowlist. Messengers may break |
| Off | No Protect computer mediation |

## 3. Install channels (Dec 1 must)

| Channel | Status |
| --- | --- |
| GitHub Releases + SHA256SUMS | Must |
| `install.sh` -> `~/.local/bin` (Linux/macOS) | Must |
| Windows zip + short EN doc | Must |
| Homebrew / winget / apt / `go install` | Later / stretch |

What the user **sees** during install (terminal lines, silent tray, Your setup): [`07-desktop-ux.md`](07-desktop-ux.md) §1.

## 4. HITL summary

| Mode | Clear threat | New host |
| --- | --- | --- |
| Safe desktop | Post-block Keep blocked / Allow this site ~15s + remember | Allow (browse) |
| Wrap / Agents only | Coalesced deny toast | Pre-act Ask |

Clear Safe threats: `secret_in_url` / header-body (when denied), `canary_detected`, `host_denied`, `unsafe_ip` (private/metadata). Public IP literals are allowed on Safe browse (`allow_ip_literals: true`). Normal API auth to ordinary web stays allowed.

**Browser QUIC:** Protect On also drops UDP/443 for the desktop UID (nft/pf) so Chrome HTTP/3 falls back to TCP MITM. Default on; Settings -> Advanced -> Browser QUIC to allow HTTP/3. Cleared on Protect Off / Quit.

## 5. Diagnostics paths

User state (Linux XDG): `~/.local/state/denyout/` — `audit.jsonl`, `desktop.log`, `last-error.txt`, plus `events.jsonl` (lifecycle), `blocks.jsonl` (deny/HITL), `notify.jsonl` (toast attempts). Opened from **Problems** and Settings -> Advanced -> Open diagnostics folder - see UX doc §5.3-§5.4.

## 6. Uninstall

Full local removal (not the same as upgrade):

```bash
denyout-cli uninstall          # stop processes, hostguard + system CA, NSS CA, autostart, XDG, binaries
denyout-cli uninstall --keep-config   # leave ~/.config/denyout and related state
```

| Upgrade (`install.sh`) | Uninstall |
| --- | --- |
| Stops old tray/proxyd, replaces binaries | Same stop, then **tears down** hostguard |
| Leaves CA + nft/pf for one Apply | Removes system CA + NSS + dangling `/etc/ssl/certs/denyout.pem` |
| Warns about other PATH copies | Deletes only `DENYOUT_INSTALL_DIR` bins; warns on other PATH hits |

Tray **Quit** unloads protection for this session and dismisses DenyOut OS banners. It does **not** delete binaries or config - use `uninstall` for that. Cancelled admin password keeps the tray running.

macOS/Windows CA untrust follows the reverse of install (Keychain / certutil) and is best-effort until field-verified.

Does not delete source trees or cloud account data (Settings -> Delete cloud data).
