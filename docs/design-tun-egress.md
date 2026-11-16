# Design spike: TUN egress (Linux first)

Status: **spike / not shipping**. Closed-loop plan only — no production TUN device yet.
Depends on: nft TCP redirect + QUIC drop counters (shipped path), Cursor TLS passthrough.

## 1. Why

Current Protect:

| Path | Behavior |
| --- | --- |
| TCP 80/443 | nft REDIRECT → proxyd MITM (except Cursor passthrough hosts) |
| UDP 443 | nft DROP + counter (silent to apps; visible via `quic-stats`) |
| Other UDP / DoH | residual |

TUN would pull **L3** traffic into userspace so UDP is observable and policy can be one place. It does **not** by itself decrypt HTTP/3; QUIC MITM is a separate, expensive track.

## 2. Non-goals (spike)

- No HTTP/3 MITM in T1–T3.
- No wrapping the entire host (Docker/VPN breakage risk).
- No macOS Network Extension / Windows Wintun in the first Linux spike.
- No change to default Protect until T1 dogfood is green on a **VM**, not the owner laptop as first target.

## 3. Phases

| Phase | Deliverable | Kernel touch | Exit criteria |
| --- | --- | --- | --- |
| **T0** (done) | nft `counter` on QUIC drop; `hostctl quic-stats`; `quic_drop_stats` event | only existing apply/remove | counters readable |
| **T1** (closed-loop code) | Classify IPv4/IPv6 UDP; `DecideT1` + userspace `Counter`; helper + Protect lifecycle stubs; `DENYOUT_TUN_E2E` gate; iface denylist; `source=tun\|nft` | **no** device yet | unit tests green; VM dogfood still required before Protect default |
| **T2** | DNS awareness (fake-ip or resolved-name cache) for UDP policy | + DNS hijack care | host-labeled quic stats |
| **T3** | Optional full-UID TCP via TUN (replace redirect) | larger routing surface | parity with current MITM; VPN coexistence matrix |
| **T4** | QUIC MITM (optional) | QUIC+TLS stack | only if threat model demands decrypt |

## 4. T1 shape (Linux)

```text
UID traffic UDP/443
    → policy routing / nft to tun denyout0
    → userspace netstack reads packet
    → decision: DropLog (default) | (later) RelayOpaque
    → never hairpin: mark 0x646e79 skip (same as today)
```

Components:

1. **Device:** `ip tuntap add mode tun denyout0` + addr in `198.18.0.0/16` (Clash-like).
2. **Steer:** nft `meta skuid $UID udp dport 443` → tproxy/tun; exclude mark `0x646e79`.
3. **Engine:** gVisor netstack or equivalent — spike chooses one lib; must be pure-Go friendly for CI.
4. **Control:** helper verbs `tun-start` / `tun-stop` beside apply/remove; Protect Off always stops TUN.
5. **Telemetry:** reuse `quic_drop_stats` fields; add `source=tun|nft`.

Rollback: `tun-stop` + delete device + restore T0 nft-only rules in one elevate.

## 5. Threat-model honesty

| Goal | T0/T1 | T4 |
| --- | --- | --- |
| Stop Chrome HTTP/3 bypass | yes (drop) | decrypt optional |
| Stop Cursor HTTP/3 bypass | yes (drop; TCP passthrough for API) | same |
| See secret-in-URL on QUIC | **no** | only with QUIC MITM |
| See Cursor API body | **no** (passthrough) | still no unless MITM Cursor |

## 6. Coexistence risks

- WireGuard / Cloudflare WARP / Docker bridge: must exclude and document.
- Helper must own lifecycle; crash must not leave blackhole routes.
- First dogfood: **throwaway VM**, then owner laptop.

**VPN egress order (locked):** policy first, then VPN — see [design-vpn-egress.md](design-vpn-egress.md). Marked proxyd dials (`0x646e79`) may use `ip rule fwmark → table denyout-vpn → wg0` (etc.). Foreign VPN ifaces are egress targets, never stolen as `denyout0`.

## 7. Closed-loop until VM dogfood

Code under `internal/tun` may only:

- classify packets / decide DropLog vs Direct vs (future) MITM;
- format helper protocol lines + `source=` stats;
- render intended nft steer tables as strings;
- unit-test without opening `/dev/net/tun`.

Landed (string/unit only): `ClassifyIPPacket`, `Engine.Handle`, `RenderT1SteerTable`, `FormatDropStatsLine`.

Landed (helper protocol, still no device): helper verbs `tun-start` / `tun-stop` / `tun-stats` reply `OK tun1 enabled=false` (or `present=false source=tun`); `hostctl` exposes the same; `quic-stats` lines include `source=nft`.

Landed (Protect Off lifecycle): `logQuicDropStats` emits `source=nft`, `tun_drop_stats`, then best-effort `tun_stop` (stub). `hostctl render --tun` prints T1 steer preview after T0 rules (never applied by `apply`).

**Netstack choice (spike):** keep pure-Go classify/`Engine` until VM dogfood; do **not** vendor gVisor in CI for T1 stubs. Revisit when a real `denyout0` reader is required.

Opening a real TUN requires an explicit `DENYOUT_TUN_E2E=1` test tag and root — not CI default.

Release verify without dogfood: `scripts/closed-loop-release-smoke.sh /path/to/extracted/release` (or no arg to build local CLI).

VM gate (still no device on CI/laptop): `scripts/closed-loop-tun-preflight.sh` + [tun-vm-dogfood.md](tun-vm-dogfood.md).

Actionable gates G0–G6 (what to build next, what is blocked): [tun-implementation-plan.md](tun-implementation-plan.md).
G2: `hostctl tun-device-plan` / `tun-device-rollback-plan` (render only).

## 8. Decision lock (owner)

- Default Protect stays **nft redirect + QUIC drop** until T1 VM dogfood passes.
- Cursor remains **TCP passthrough + QUIC drop** (no browser-only QUIC exception).
- Protect On must **not** call `tun-start` until an explicit feature flag + VM green.
- Gate: `DENYOUT_TUN_E2E=1` (`tun.WantDevice`); otherwise Protect On emits `tun_start_skipped` and stays on T0 nft drop.
- Coexistence denylist: `tun.ShouldSkipIface` (`lo`, `docker0`, `br-*`, `veth*`, `wg*`, WARP/Tailscale/ZeroTier names).
- **DenyOut → then VPN:** locked in [design-vpn-egress.md](design-vpn-egress.md); kernel apply behind `DENYOUT_VPN_EGRESS_E2E=1`.
