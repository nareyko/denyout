# TUN implementation + test plan (actionable)

Status: **active**. Design: [design-tun-egress.md](design-tun-egress.md).
VM dogfood: [tun-vm-dogfood.md](tun-vm-dogfood.md). VPN: [design-vpn-egress.md](design-vpn-egress.md).

`TunDataplane` and `QuicMITM` default **false**. Prefer throwaway VM before laptop.

## Gates

| Gate | Deliverable | Status |
| --- | --- | --- |
| G0–G5 | T0 nft, stubs, device plan, real denyout0 UDP drop, Protect gate | shipped |
| **T3** | TCP 80/443 via `denyout0` + **gVisor** netstack → proxyd | **landed (gated)** |
| **Q1** | QUIC sighting (SNI best-effort) + audit/decide Drop/Sight | **landed** |
| **Q2a** | QUIC terminate+reencrypt skeleton (`quic-go` + DenyOut CA hook) | **landed (gated)** |
| **Q2b** | HTTP/3 into policy via `ServeHTTP3MITM` + `HTTP3PolicyFunc` | **landed (API+tests)** |
| **Q2c** | Pref UI `QuicMITM`, dogfood matrix, Cursor = no QUIC MITM | **landed (docs+pref)** |

## How to turn on (Linux)

1. Protect On (helper refresh).
2. Enable **TunDataplane** (Settings) or `DENYOUT_TUN_E2E=1`.
3. Optional MITM: **QuicMITM** pref or `DENYOUT_QUIC_MITM=1` (requires TunDataplane).
4. Cursor `*.cursor.sh` / `*.cursor.com`: QUIC MITM **refused** (drop/sight only).

## Closed-loop (CI)

```bash
go test ./internal/tun/ ./internal/hostguard/ ./internal/desktop/ -count=1
./scripts/closed-loop-tun-preflight.sh
```

Without `--real` / gates: no device, no MITM claims.

## VM / Docker dogfood (required before defaults)

See [tun-vm-dogfood.md](tun-vm-dogfood.md). Automated stand-in:

```bash
./scripts/closed-loop-tun-g6-docker-dogfood.sh
```

Covers TCP HTTPS via TUN, QUIC sight, QuicMITM lab HTTP/3, teardown. Chrome/Cursor still need a VM/laptop.
