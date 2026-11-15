# Known issues

Short honest list. Full discussion: [GitHub Issues](https://github.com/nareyko/denyout/issues).

## Current

1. **Windows packaging** for the Dec 1 install bet is still the hard path (WinDivert bridge packaging). Linux/macOS install scripts are ahead.
2. **Optional account sync** uses an interim API. Cloud sessions are not a substitute for local Protect. Settings sync needs a signed-in account. Protect does not.
3. **Threat list refresh** can lag offline. Protect keeps the last good cache and stays usable.
4. **Agents only (whole PC)** can break messengers and many sites - intentional confirm in Settings, Advanced. Prefer My agents for tools.
5. **Cursor on Safe:** `*.cursor.sh` / `*.cursor.com` use **TLS passthrough** (no MITM) so HTTP/2 agent APIs work under Protect. L1 host/threat checks still apply; body/URL secret scanners do **not** see Cursor API traffic. Other apps still get MITM. QUIC/UDP 443 remains dropped for the whole UID (including Cursor) so HTTP/3 cannot bypass; Cursor must use TCP.
6. **Chrome HTTP/3 (QUIC):** Without a UDP/443 drop, Chrome may bypass TCP MITM. Protect **defaults to blocking browser QUIC** (nft/pf drop UDP 443 for your UID). Turn off under **Settings -> Advanced -> Browser QUIC** if you need HTTP/3. Requires a current hostguard helper (reinstall/upgrade if an older helper ignored the flag). QUIC drops are counted (`hostctl quic-stats` / `quic_drop_stats` on Protect Off).
7. **MITM HTTP/2:** Non-passthrough hosts that speak only HTTP/2 after TLS may log `mitm_http2_unsupported` (audit verdict `error`) instead of failing silently.

## Reporting

Prefer GitHub Issues with OS, DenyOut version (`denyout version`), and whether Protect or wrap was on. Do not paste real secrets or full audit URLs.
