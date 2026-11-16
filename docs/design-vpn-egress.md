# Decision lock: DenyOut policy, then VPN egress

Status: **locked (owner)**. Plan + apply landed: `vpn-egress-plan` (render) and `vpn-egress-apply` / `vpn-egress-remove` (helper/root) behind `DENYOUT_VPN_EGRESS_E2E=1`. Not default Protect.

## 1. Goal

Traffic must hit **DenyOut policy first**, then leave via the user's VPN:

```text
App
  → DenyOut (nft redirect / future denyout0 → proxyd or drop)
  → upstream dial with SO_MARK 0x646e79 ('dny')
  → ip rule fwmark → table denyout-vpn
  → default via $VPN_IFACE (wg0, …)
  → Internet
```

VPN is **egress transport after allow/proxy**, not a bypass around Protect.

## 2. Non-goals

- DenyOut is not a VPN replacement.
- Do not steal or reconfigure foreign VPN interfaces (`wg*`, WARP, Tailscale, …).
- Do not make full-tunnel VPN the host default for raw UID traffic before DenyOut.
- No macOS/Windows policy-routing in this lock (Linux first).

## 3. Contract (Linux)

| Piece | Value |
| --- | --- |
| Mark | `0x646e79` (same as hostguard skip / proxyd `SO_MARK`) |
| Rule | `fwmark 0x646e79 lookup <table>` (priority reserved for DenyOut) |
| Table name/id | `denyout-vpn` / `646` (stable id; avoid clash with low system tables) |
| Route | `default dev <VPN_IFACE>` in that table (optional `via` later) |
| Iface denylist | never use `lo`, `docker0`, `br-*`, `veth*`, `denyout0` as VPN egress |

Proxyd already marks transparent upstream dials on Linux. This lock adds the **routing** half so marked packets prefer the VPN device.

## 4. Order with TUN

When `denyout0` exists (T1+):

1. Steer selected traffic into DenyOut userspace / proxyd.
2. Decisions that need Internet use the same marked dial path.
3. Marked dials follow the VPN egress table.

`denyout0` is an **ingress** path into policy; VPN ifaces remain **egress only**.

## 5. Rollout

| Step | Where | Kernel |
| --- | --- | --- |
| A (this PR) | `RenderVPNEgressPlan`, `hostctl vpn-egress-plan`, unit tests | no |
| B | Helper apply/remove behind `DENYOUT_VPN_EGRESS_E2E=1` | VM first |
| C | Optional Protect setting “send upstream via VPN iface” | after B green |

## 6. Test plan (closed-loop → VM)

1. Unit: plan text contains mark, table id, iface; rejects denylist ifaces.
2. `hostctl vpn-egress-plan --iface=wg0` prints commands (no exec).
3. VM: with WireGuard up, E2E apply → curl via Protect shows DenyOut audit and source IP = VPN.
4. VM: Protect Off / vpn-egress remove leaves no blackhole `ip rule`.
