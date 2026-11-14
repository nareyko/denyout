# Dashboard research - similar products (no clone)

Sources: GitHub READMEs / raw UI files / docs / DeepWiki (viewed via API & web; **no repo clones**).

## Peers surveyed

| Product | Kind | Primary "home" |
| --- | --- | --- |
| [Windows Security](https://support.microsoft.com/en-us/windows/windows-security-app-overview) | Mass-market endpoint | Security at a glance - status tiles |
| [Tailscale home-view](https://github.com/tailscale/tailscale/blob/main/client/web/src/components/views/home-view.tsx) | Network client | Device name + **Connected/Offline** + one control |
| [LuLu](https://objective-see.org/products/lulu.html) | App firewall | Tray-first; window = Rules / Settings (no heavy dashboard) |
| [OpenSnitch](https://github.com/evilsocket/opensnitch) | App firewall | Stats tabs (Events/Rules/...) + **Running** status |
| [Portmaster](https://docs.safing.io/portmaster/architecture/user-interface) | Privacy firewall | Opens on **Network Monitor**; tray = status colors |
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) | DNS protection | Protection toggle + counters + top blocked |
| [Pi-hole](https://github.com/pi-hole/web/blob/master/index.lp) | DNS protection | 4 stat tiles + charts + tops |
| [NextDNS](https://nextdns.io/) | DNS protection | Green "using NextDNS" + analytics/logs |

## What good homes put first

1. **Binary protection state** - Protected / Off / Needs attention (Win Security green/yellow/red; Tailscale Connected/Offline; AdGuard protectionEnabled; OpenSnitch Running).
2. **One primary control** - Turn protection on/off (or temporary disable). Everything else secondary.
3. **Proof it works** - last threat / last block / "0 threats" / blocked count (Win Current threats; AdGuard/Pi-hole blocked; DenyOut last block).
4. **Way into history** - not the table itself on home (LuLu/Portmaster keep logs elsewhere; Pi-hole/AdGuard are *admin* products so they put stats on home).
5. **Failure visibility** - tray color + in-window banner (OpenSnitch icons; Tailscale red error; Win red tile).

## What power tools put on home (avoid for Safe-first)

- Live connection grids (Portmaster Network Monitor as default).
- Multi-tab stats (OpenSnitch Events/Nodes/Rules/Hosts/Processes).
- Charts + top domains + clients (Pi-hole / AdGuard) - great for *operators*, noisy for *browse-and-forget*.
- Mode jargon (Safe desktop / Agents only) before status English.

## Pattern split

| Audience | Home content |
| --- | --- |
| **Consumer / Safe-first** (DenyOut target) | Status sentence + On/Off + last event + link to History |
| **Operator / homelab** (Pi-hole, AdGuard) | Stats tiles + charts + tops |
| **Power firewall** (OpenSnitch, Portmaster default) | Live monitor / rules as primary |

DenyOut should follow **consumer** (Win Security + Tailscale mini), borrow **one** operator cue (optional small "blocked today" count), never open as live monitor.

## Ideal simple DenyOut Home (synthesis)

**Normative requirements (authoritative):** [`home.md`](home.md) v2.

```text
[ Status: You are protected | Protection is off | Needs your help ]
[ one line of calm support ]
[ primary: Turn off | Turn on Protect computer ]

[ Last blocked ] or [ Nothing blocked yet - that is OK ]
 host - human why - Allow this site - See history

[ optional, quiet ] Blocked today: N
[ doors, not peers ] Settings - (For AI tools -> My agents)
```

**Must answer in 5 seconds:** Am I protected? What do I do? Did anything scary happen?

**Must not:** reason codes, Filters, Jump, Agents only, IPC/health grid, charts, equal-weight secondary screens.

## Takeaways for DenyOut

| Keep / strengthen | Avoid copying |
| --- | --- |
| Status-first hero (already) | Pi-hole 4-tile chart grid as default |
| Last-block decision card | OpenSnitch/Portmaster as home |
| Green/yellow/red urgency | Mode names as the headline |
| Tray = status; window = rare | Equal-weight nav of power screens |
| Empty = good news | Empty = "go test Advanced" |
