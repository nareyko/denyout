# TUN T1 VM dogfood (not the owner laptop)

Status: **preflight only**. Real `denyout0` must first run on a **throwaway Linux VM**.
Closed-loop gates live in `scripts/closed-loop-tun-preflight.sh` and CI.
Roadmap gates G0–G6: [tun-implementation-plan.md](tun-implementation-plan.md).

## Why a VM first

- Creating a TUN + steering UDP/443 can blackhole routes if the helper crashes.
- WireGuard / Cloudflare WARP / Docker bridges must stay on the coexistence denylist.
- Owner laptop stays on **T0** (`nft` QUIC drop + TCP MITM) until this checklist is green.

## Preconditions (closed-loop, no root)

Run from a checkout or release tree:

```bash
./scripts/closed-loop-tun-preflight.sh
# or
DENYOUT_BIN=/path/to/denyout-cli ./scripts/closed-loop-tun-preflight.sh
```

Must pass:

1. `DENYOUT_TUN_E2E` unset → `tun.WantDevice` false / Protect On would emit `tun_start_skipped`.
2. `hostctl tun-start|stop|stats` → `enabled=false` with `reason=flag_off` (0.4.9+).
3. `hostctl render --tun` shows T0 `denyout-block-quic` **and** T1 preview `denyout-tun-quic` (preview not applied).
4. Coexistence names skipped: `lo`, `docker0`, `br-*`, `veth*`, `wg*`, WARP/Tailscale/ZeroTier-style.
5. Rollback plan lists `tun-stop` → delete `denyout0` → T0 `hostctl apply`.

## VM-only steps (root; not CI)

Only after preflight is green on the same binary:

1. Snapshot the VM.
2. Protect On once so helper refreshes (`hostctl caps` should list `quic1 tun1 vpn1`).
3. Real TUN: `DENYOUT_TUN_E2E=1 denyout-cli hostctl tun-start --real`  
   (or enable **TunDataplane** in Settings → Advanced, then Protect On).
4. Check: `ip link show denyout0`, `hostctl tun-stats` → `present=true`, TCP Protect still OK.
5. Confirm Protect Off / `tun-stop --real` deletes `denyout0` and restores T0 UDP drop.
6. Matrix: plain eth, Docker bridge present, WireGuard up/down, WARP if available.
7. Optional VPN egress: `DENYOUT_VPN_EGRESS_E2E=1 hostctl vpn-egress-apply --iface wg0` then `vpn-egress-remove`.
8. Easy rollback: `hostctl tun-stop --real` then T0 apply; if stuck, restore VM snapshot.

## Exit criteria to change Protect default

- Preflight green in CI on every PR.
- VM dogfood green for the matrix above.
- Owner decision lock in [design-tun-egress.md](design-tun-egress.md) §8 updated.
- Then — and only then — consider Protect On calling real `tun-start`.
