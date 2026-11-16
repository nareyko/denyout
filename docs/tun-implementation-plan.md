# TUN implementation + test plan (actionable)

Status: **active**. Design intent: [design-tun-egress.md](design-tun-egress.md).
VM dogfood checklist: [tun-vm-dogfood.md](tun-vm-dogfood.md).
VPN after policy: [design-vpn-egress.md](design-vpn-egress.md).

Owner laptop stays on **T0** (nft redirect + QUIC drop) until G5. No real `denyout0` without `DENYOUT_TUN_E2E=1` on a throwaway VM.

## Gates

| Gate | Deliverable | Kernel | Where | Status |
| --- | --- | --- | --- | --- |
| **G0** | nft QUIC drop + counters; `quic-stats` | yes (existing Protect) | production | shipped |
| **G1** | Classify / DecideT1 / Engine; helper stubs; `DENYOUT_TUN_E2E`; iface denylist; Protect lifecycle skip | no | CI + laptop | shipped |
| **G2** | Device **plan** strings (`ip tuntap` add/del); `hostctl tun-device-plan`; preflight asserts | no | CI | this wave |
| **G3** | Real `ip tuntap` create/delete in helper when E2E=1 | yes | VM only | later |
| **G4** | Steer UDP/443 → `denyout0` + userspace DropLog counters | yes | VM | later |
| **G5** | Protect On may call real `tun-start` (still flag-gated) | yes | after VM matrix green | owner lock |
| **G6** | T2 DNS labels / T3 full-UID TCP / T4 QUIC MITM | later | out of scope now | — |

## Closed-loop test matrix (every PR)

```bash
go test ./internal/tun/ -count=1
./scripts/closed-loop-tun-preflight.sh
# optional release binary:
# DENYOUT_BIN=/path/to/denyout-cli ./scripts/closed-loop-tun-preflight.sh
```

Must hold:

1. `DENYOUT_TUN_E2E` unset → `WantDevice` false; Protect On would emit `tun_start_skipped`.
2. `hostctl tun-start|stop|stats` → `enabled=false` (`flag_off` or `stub_no_device`).
3. `hostctl render --tun` shows T0 + T1 preview (preview not applied by `apply`).
4. `hostctl tun-device-plan` / `tun-device-rollback-plan` print commands; never execute.
5. Coexistence denylist: `lo`, `docker0`, `br-*`, `veth*`, `wg*`, WARP/Tailscale/ZeroTier-style.
6. VPN egress plan (mark → table 646) remains render-only unless `DENYOUT_VPN_EGRESS_E2E=1`.

## VM dogfood (G3–G4)

Only after G2 preflight is green on the **same** binary:

1. Snapshot the VM.
2. Export `DENYOUT_TUN_E2E=1` for the dogfood shell only.
3. Helper creates `denyout0` (`198.18.0.1/16`); Protect Off always `tun-stop` + delete + T0 apply.
4. Matrix: plain eth, Docker bridge present, WireGuard up/down, WARP if available.
5. Easy rollback: `hostctl tun-stop` then T0 apply; if stuck, restore snapshot.

Exit to G5: preflight green in CI, VM matrix green, [design-tun-egress.md](design-tun-egress.md) §8 updated by owner.

## Non-goals until G5+

- Opening `/dev/net/tun` in CI or default Protect.
- Vendoring gVisor for T1 stubs.
- Stealing foreign VPN ifaces as ingress (`denyout0` is DenyOut-owned only).
- Making full-tunnel VPN the host default before DenyOut policy.
