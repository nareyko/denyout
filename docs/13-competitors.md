# D13 - Competitive landscape (informative)

## 1. Positioning map

```text
 Prompt/tool policy Network egress
 ───────────────── ──────────────
Enterprise SaaS Zenity Boundaries Formal Endpoint
 Lasso Intent Deputy C1 Egress
 Pillar Agentic Endpoint Forcepoint Agent Gateway
 AppOmni AgentGuard Permit HTTP Egress Proxy

Local OSS AgentFence (MCP tools) Leash (egress audit proxy)
 Agent Guard (fs/MCP) Fence / srt / nono / hazmat
 Microsoft MCP gateway seekrit-proxy (cred broker)
```

DenyOut sits in **local + server egress**, consumer-simple UX, **secret-in-URL / R-20** emphasis, brand: default deny outbound.

## 2. Product notes

| Name | Overlap | Differentiation vs DenyOut |
| --- | --- | --- |
| **C1 Egress** | Deny-by-default egress, creds out of agent | Enterprise. DenyOut = OSS/local-first seatbelt |
| **Formal Endpoint** | Laptop+sandbox+pod egress MITM | Broad platform. DenyOut narrower & simpler |
| **Permit egress proxy** | Workflows, HITL, creds | AuthZ platform. DenyOut no account MVP |
| **seekrit-proxy** | Cred broker + allowlist | DenyOut focuses on deny/exfil. May integrate later |
| **Leash** | Agent egress audit/enforce | Similar. Compare UX/name. Avoid clone - emphasize R-20 scanners + `run` UX |
| **Fence / srt / nono** | OS sandbox + proxy | Complementary. DenyOut wraps/policy layer |
| **AgentFence** | MCP tool allow/deny | Complementary (tools vs raw HTTP) |
| **AgentGuard *** | Crowded name, varied scopes | Name avoided on purpose |
| **Zenity / Pillar / Lasso / Forcepoint** | Enterprise runtime | Different buyer. DenyOut can be control they lack on DIY agents |

## 3. Strategic implications

1. Do **not** compete on "full AI SPM platform" first. 
2. Do compete on **time-to-protected-run** and **honest R-20 story**. 
3. Integrate with sandbox runtimes rather than reimplementing seatbelt. 
4. Keep policy language compatible enough to map to enterprise proxies later.

## 4. Name collisions checked (2026-11-13)

- `denyout.com` - registered by us. 
- Sister TLDs appeared free at check time - consider defensive registration. 
- No major product branded DenyOut found in search.
