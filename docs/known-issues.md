# Known issues

Short honest list. Full discussion: [GitHub Issues](https://github.com/nareyko/denyout/issues).

## Current

1. **macOS and Windows are behind Linux.** `denyout-cli run` is the supported path on both. **Protect this computer** is unavailable on Windows (the WinDivert bridge is not packaged) and is preview on macOS: the pf redirect has not been verified on a real Mac, and it appends rules to `/etc/pf.conf` that Protect Off does not remove. Release binaries are unsigned (no Developer ID, no Authenticode), so Gatekeeper or SmartScreen may warn on first run.
2. **Optional account sync** uses an interim API. Cloud sessions are not a substitute for local Protect. Settings sync needs a signed-in account. Protect does not.
3. **Threat list refresh** can lag offline. Protect keeps the last good cache and stays usable.
4. **Agents only (whole PC)** can break messengers and many sites - intentional confirm in Settings, Advanced. Prefer My agents for tools.
5. **Cursor on Safe:** `*.cursor.sh` / `*.cursor.com` use **TLS passthrough** (no MITM) so HTTP/2 agent APIs work under Protect. L1 host/threat checks still apply; body/URL secret scanners do **not** see Cursor API traffic. Other apps still get MITM. QUIC/UDP 443 remains dropped for the whole UID (including Cursor) so HTTP/3 cannot bypass; Cursor must use TCP. If the agent still looks silent under Protect, check `audit.jsonl` for many short `api2.cursor.sh` passthrough allows — that was a tunnel half-close bug (fixed in 0.4.11+); upgrade and retry.
6. **Chrome HTTP/3 (QUIC):** Without a UDP/443 drop, Chrome may bypass TCP MITM. Protect **defaults to blocking browser QUIC** (nft/pf drop UDP 443 for your UID). Turn off under **Settings -> Advanced -> Browser QUIC** if you need HTTP/3. Requires a current hostguard helper (reinstall/upgrade if an older helper ignored the flag). QUIC drops are counted (`hostctl quic-stats` / `quic_drop_stats` on Protect Off).
7. **MITM HTTP/2:** Non-passthrough hosts that speak only HTTP/2 after TLS may log `mitm_http2_unsupported` (audit verdict `error`) instead of failing silently.
8. **Orphan redirect blackhole (fixed in tree after 0.4.11; helper watchdog added after 0.4.12):** If nft/pf still **REDIRECT**s TCP 80/443 to the local proxyd port but proxyd is dead, HTTPS clients see `connection refused` (including `gh` / `api.github.com`). Cause was uninstall/Protect Off killing proxyd **before** removing rules (or stacked `denyout uninstall` processes killing each other). Recovery on an affected build: `denyout-cli hostctl teardown` (or `remove`) with admin, or upgrade and re-run uninstall. Fixed builds tear down rules first and keep proxyd until Remove succeeds.
9. **Experimental TUN / HTTP/3 MITM:** Settings → Advanced → **Experimental** (Linux) or env `DENYOUT_TUN_E2E` / `DENYOUT_QUIC_MITM`. Default off. QUIC MITM is early (`quic-go`); expect breakage on some sites. Cursor hosts are never QUIC-MITM’d. Dogfood on a VM first ([tun-vm-dogfood.md](tun-vm-dogfood.md)).

10. **Residual (see [security review](security-review-2026-11.md)):** no IPv6 inside the TUN data plane itself (IPv6 stays on the nft redirect path), DNS and non-80/443 TCP are not covered, Sigstore signature verification in `install.sh` needs `cosign` installed, `srt` sandbox does not restrict file reads by default.

## Reporting

Prefer GitHub Issues with OS, DenyOut version (`denyout version` or `denyout-cli version`), and whether Protect or wrap was on. Do not paste real secrets or full audit URLs.
