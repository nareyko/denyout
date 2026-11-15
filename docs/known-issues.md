# Known issues

Short honest list. Full discussion: [GitHub Issues](https://github.com/nareyko/denyout/issues).

## Current

1. **Windows packaging** for the Dec 1 install bet is still the hard path (WinDivert bridge packaging). Linux/macOS install scripts are ahead.
2. **Optional account sync** uses an interim API. Cloud sessions are not a substitute for local Protect. Settings sync needs a signed-in account. Protect does not.
3. **Threat list refresh** can lag offline. Protect keeps the last good cache and stays usable.
4. **Agents only (whole PC)** can break messengers and many sites - intentional confirm in Settings, Advanced. Prefer My agents for tools.
5. **Cursor "sometimes blocked" on Safe:** Protect computer (Safe browse) does **not** deny Cursor hosts by name - normal `*.cursor.sh` / `*.cursor.com` traffic is allowed. Blocks you may see are usually (a) **Agents only / My agents** allowlist (missing preset hosts like `metrics.cursor.sh`), or (b) scanners (`secret_in_url` / cookie / body / canary) or a threat-list hit. Check History / `blocks.jsonl` for `reason` + `profile` (`browse` vs agent). Safe does not secret-exempt Cursor.
6. **Chrome HTTP/3 (QUIC):** Without a UDP/443 drop, Chrome may bypass TCP MITM. Protect **defaults to blocking browser QUIC** (nft/pf drop UDP 443 for your UID). Turn off under **Settings -> Advanced -> Browser QUIC** if you need HTTP/3. Requires a current hostguard helper (reinstall/upgrade if an older helper ignored the flag).

## Reporting

Prefer GitHub Issues with OS, DenyOut version (`denyout version`), and whether Protect or wrap was on. Do not paste real secrets or full audit URLs.
