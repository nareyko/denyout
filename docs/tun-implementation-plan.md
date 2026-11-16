# TUN implementation + test plan (actionable)

Status: **active**. Design intent: [design-tun-egress.md](design-tun-egress.md).
VM dogfood checklist: [tun-vm-dogfood.md](tun-vm-dogfood.md).
VPN after policy: [design-vpn-egress.md](design-vpn-egress.md).

Owner laptop stays on **T0** until `TunDataplane` pref or `DENYOUT_TUN_E2E=1`. Prefer a throwaway VM before flipping the pref.

## Gates

| Gate | Deliverable | Kernel | Where | Status |
| --- | --- | --- | --- | --- |
| **G0** | nft QUIC drop + counters; `quic-stats` | yes (existing Protect) | production | shipped |
| **G1** | Classify / DecideT1 / Engine; helper stubs; denylist; Protect lifecycle skip | no | CI + laptop | shipped |
| **G2** | Device **plan** strings; `hostctl tun-device-plan`; preflight | no | CI | shipped |
| **G3** | Real `denyout0` create/delete + TUN fd in helper when `--real` / gate | yes | VM / pref | **landed** |
| **G4** | Steer UDP/443 → `denyout0` + userspace DropLog counters | yes | VM / pref | **landed** |
| **G5** | Protect On → real `tun-start` when `DENYOUT_TUN_E2E=1` **or** `TunDataplane` pref (default pref **false**) | yes | gated | **landed** |
| **G6** | T2 DNS labels / T3 full-UID TCP / T4 QUIC MITM | later | out of scope | — |

Helper refresh: Protect On calls `EnsureHelperFresh` (caps `quic1`/`tun1`; `helper-install` if stale).

VPN egress apply: `DENYOUT_VPN_EGRESS_E2E=1` + `hostctl vpn-egress-apply --iface wg0` (helper or root).

## Closed-loop test matrix (every PR)

```bash
go test ./internal/tun/ ./internal/hostguard/ ./internal/desktop/ -count=1
./scripts/closed-loop-tun-preflight.sh
```

Must hold without root:

1. Gate off → `tun_start_skipped` / stub `enabled=false`.
2. `hostctl tun-start` **without** `--real` → stub (even if helper is installed).
3. `hostctl tun-device-plan` / `vpn-egress-plan` print only.
4. Coexistence denylist unchanged.

## VM dogfood (G3–G5)

1. Snapshot the VM; install this binary; ensure helper caps include `tun1` (`hostctl caps` after Protect On).
2. `DENYOUT_TUN_E2E=1 denyout-cli hostctl tun-start --real` **or** enable Settings → Advanced → TunDataplane then Protect On.
3. Confirm `denyout0` exists, `tun-stats` `present=true`, UDP/443 counted; TCP Protect still works.
4. Protect Off / `tun-stop --real` removes device + steer; T0 UDP drop restored.
5. Matrix: plain eth, Docker bridge, WireGuard up/down.
6. Optional: `DENYOUT_VPN_EGRESS_E2E=1 hostctl vpn-egress-apply --iface wg0` then remove.

## Non-goals until G6

- QUIC MITM / gVisor
- Full-UID TCP via TUN
- Enabling `TunDataplane` by default in releases before VM matrix sign-off
