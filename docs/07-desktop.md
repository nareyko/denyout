# D07 — Desktop deployment

Normative deploy/build for desktop.

**User-visible surfaces (behavior):** [`07-desktop-ux.md`](07-desktop-ux.md).  
**Screens & message catalog:** [`07-desktop-ux-catalog.md`](07-desktop-ux-catalog.md).

## 1. Two binaries

| Binary | Role | Build |
| --- | --- | --- |
| **`denyout`** | CLI, proxy, `hostctl proxyd`, `denyout desktop` (native-dialog fallback shell) | `CGO_ENABLED=0` (GoReleaser) |
| **`denyout-desktop`** | Tray + Wails React UI (Activity / My agents / Settings / Problems) | `CGO_ENABLED=1` + WebKit / WebView2 (`release-desktop` workflow) |

`install.sh --desktop` installs CLI always and **denyout-desktop** when the release asset exists. Autostart / detach prefer `denyout-desktop` when present beside `denyout`.

### Build denyout-desktop locally (Linux)

```bash
sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev
cd cmd/denyout-desktop/frontend && npm ci && npm run build && cd ../../..
CGO_ENABLED=1 go build -tags 'wails,production,webkit2_41' -ldflags "-X main.version=dev" -o denyout-desktop ./cmd/denyout-desktop
```

Plain `go build` **must** include the `production` tag (otherwise Wails links a stub). Close the window **hides to tray**; Quit only from the tray menu — see [`07-desktop-ux.md`](07-desktop-ux.md) §§2–5.

## 2. Modes (summary)

Full menu and screen inventory: [`07-desktop-ux.md`](07-desktop-ux.md) §§2–5.

| Mode | User expectation |
| --- | --- |
| Safe desktop | Web OK; clear threats → **Keep blocked** / **Allow this site** + URL |
| My agents (wrap) | Per-program proxy; Pre-act Ask on new hosts |
| Agents only (whole PC) | Settings → Advanced (strong warn); allowlist; messengers may break |
| Off | No Protect computer mediation |

## 3. Install channels (Dec 1 must)

| Channel | Status |
| --- | --- |
| GitHub Releases + SHA256SUMS | Must |
| `install.sh` → `~/.local/bin` (Linux/macOS) | Must |
| Windows zip + short EN doc | Must |
| Homebrew / winget / apt / `go install` | Later / stretch |

What the user **sees** during install (terminal lines, silent tray, Your setup): [`07-desktop-ux.md`](07-desktop-ux.md) §1.

## 4. HITL summary

| Mode | Clear threat | New host |
| --- | --- | --- |
| Safe desktop | Post-block Keep blocked / Allow this site ~15s + remember | Allow (browse) |
| Wrap / Agents only | Coalesced deny toast | Pre-act Ask |

Clear Safe threats: `secret_in_url` / header-body (when denied), `canary_detected`, `host_denied`, `unsafe_ip`. Normal API auth to ordinary web stays allowed (0.2.1 `blocklistHostOK`).

## 5. Diagnostics paths

User state (Linux XDG): `~/.local/state/denyout/` (`audit.jsonl`, `desktop.log`, `last-error.txt`). Opened from **Problems** and Settings → Advanced → Open diagnostics folder — see UX doc §5.3–§5.4.
