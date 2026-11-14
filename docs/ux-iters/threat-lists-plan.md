# Plan: Threat lists, allow packs & rule precedence

**Date:** 2026-11-14
**Status:** **Wave complete (LF green 2026-11-14).** §12 locked. L0-LF tested. Evidence: [`threat-lists-qa.md`](threat-lists-qa.md).
**Related:** [`../04-policy-engine.md`](../04-policy-engine.md), [`notifications-rework-plan.md`](notifications-rework-plan.md)

---

## 0. Goals / non-goals

### Goals

1. Complete the **list map** (what kinds of lists DenyOut needs). 
2. Subscribe to **concrete threat feeds**, update them reliably, expose **Phishing / Malware / (later) Telemetry** toggles. 
3. Fix **rule precedence** in product + code. 
4. Ship **agent allow packs** (Cursor / Claude starters) curated by DenyOut. 
5. Keep Safe desktop about **clear threats + optional threat intel**, not "become Pi-hole".

### Non-goals

- Replacing secret/canary scanners with domain lists. 
- Network-wide DNS adblocking as primary job. 
- Ingesting every Firebog list. 
- Country/ASN blocking in this wave.

---

## 1. List map (complete)

DenyOut keeps **four books**. Do not merge them into one UI dump.

| Book | Name | Who writes it | Default posture | Where it lives |
| --- | --- | --- | --- | --- |
| **A** | Agent allow | DenyOut presets + user Ask/Always + **starter packs** | Closed world for agents | Policy YAML / profile / packs |
| **B** | Personal decisions | User (Keep forever/timed, Allow forever/timed) | Overrides threat lists | Desktop state |
| **C** | Threat intel (subscriptions) | External feeds + optional stronger lists | Off or selective - see §5 | Cached list files + manifest |
| **D** | Product unbreak | DenyOut maintainers (tiny) | Always on, tiny | In-repo allow exceptions |

### Book A - Agent allow

- Purpose: "this agent may only talk to these hosts." 
- Sources: built-in presets (Agent+Cursor / Models only), Ask -> Always/timed, **starter packs** (§8). 
- Not sourced from ads blocklists.

### Book B - Personal decisions

- Purpose: remember human choices after HITL. 
- Always allow / timed allow / remembered Keep / timed deny. 
- **Always beats Book C** (same as Pi-hole/NextDNS allowlist-over-blocklist).

### Book C - Threat intel

- Purpose: known phishing / malware (/ later telemetry) domains. 
- Extra denies -> clear-threat HITL (`threat_list` / mapped post-block). 
- Applies in **all modes** (including Agents). Does **not** replace default-deny. Wide Book A pack allows do **not** bypass C. Only Book B **Always / timed allow on that host** does (§4, Q4).

### Book D - Unbreak

- Purpose: 10-50 domains DenyOut knows must not be killed by Book C (CDN/API breakage). 
- Maintained in-repo. Not a 5k community whitelist.

---

## 2. Sources - use the proposed set

### 2.1 Core threat subscriptions (Book C - product catalog)

| ID | Feed | Canonical URL(s) | Format | Refresh hint | Default (locked) | Category toggle |
| --- | --- | --- | --- | --- | --- | --- |
| `phishing-army` | Phishing Army domains | `https://phishing.army/download/phishing-army-domains.txt` (also hosts/adblock on same site) | one domain / line | author ~3-4 h. We poll **configurable, default 24 h** (+ on first install / Protect start) | **ON** | Phishing |
| `urlhaus-hosts` | abuse.ch URLhaus hostfile | `https://urlhaus.abuse.ch/downloads/hostfile/` | hosts (`127.0.0.1 domain`) | author ≥5 min. We poll **same interval** | **ON after first successful fetch** (if fetch fails, Protect still OK. Treat as not-yet-active) | Malware |
| `hagezi-tif-medium` | HaGeZi TIF medium | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.medium.txt` (or documented domains/adblock path) | domain / ABP | 1-4x / day | **OFF** - nested under Malware + first-enable size warning | Malware (stronger) |

**Do not** ship HaGeZi **full** TIF as default or silent upgrade (memory / breakage).

### 2.2 Good feeds - not DenyOut core (catalogued for optional / later)

Include in **docs + optional advanced catalog**, not day-1 defaults. Useful for specific jobs:

| Feed | What it's good for | When DenyOut might use it | Why not core |
| --- | --- | --- | --- |
| **OISD small** | Ads / app ads with "don't break" ethos | Optional "Cut ads & trackers" for power users who want Browse quieter | Wrong brand job. Competes with Pi-hole mental model |
| **OISD big** | Ads + phishing + malware + telemetry mix | Only if user explicitly wants aggressive DNS-style privacy | Mixes jobs. Higher FP. Heavy |
| **StevenBlack unified hosts** | Classic aggregated hosts. Wide recognition | Import/interop tests; "I already trust this file" advanced import | Ads-heavy. Duplicates other feeds |
| **Safing intel-data** (ads/analytics/telemetry/malware/unbreak/securedns) | Category taxonomy + unbreak + anti-DNS-bypass ideas | **Steal ideas**: categories, unbreak, securedns-bypass list - not wholesale dependency | Tied to Portmaster packaging. License/ops ownership |
| **Safing Unbreak** | Repair popular breakage from filter lists | Seed inspiration for Book D. Optionally mirror a few entries after review | Don't auto-subscribe without review |
| **Safing securedns / p2p lists** | Block DoH/DoT resolvers or STUN that bypass filters | Later "Prevent bypass" Advanced toggle | Needs careful UX (breaks legitimate DoH users) |
| **Firebog / mega-aggregators** | DIY maximal lists | Never as default. Maybe "add custom URL" | FP storm. Support hell |
| **Community AdGuard whitelists** | Fix broken streaming/login after ads lists | Not needed if we don't ship ads lists | Trust + size |

**Product rule:** Custom list URL **not this wave** (Q10). Day-1 Advanced = OISD small/big + StevenBlack (all OFF).

### 2.3 Agent packs (Book A) - curated by DenyOut

| Pack ID | Intent | Typical hosts (illustrative - finalize in impl) |
| --- | --- | --- |
| `cursor-starter` | Cursor / VS Code agent egress | Cursor/API/update CDNs, GitHub, common model APIs as needed |
| `claude-starter` | Claude / Anthropic-oriented agents | `api.anthropic.com`, related Anthropic endpoints, docs if required |

Packs are **YAML allow fragments** in-repo, versioned, English descriptions, applied on profile create or "Add pack..." in My agents. User can still Ask/Always beyond the pack.

---

## 3. How to update (requirements)

### Must

1. **Manifest** of subscriptions: `id`, `url`, `category` (`phishing`|`malware`|`telemetry`), `format`, `enabled`, `poll_hours`, `license_url`, `homepage`. 
2. **Refresh cadence (locked):** fetch on **new install / first Protect**, then every **`poll_hours` (default 24)**, plus **Refresh now**. `Poll_hours` editable in Settings (sensible min e.g. 6, max e.g. 168). 
3. Download -> validate (non-empty. Not &lt; 25% of previous size unless first fetch) -> store under state/cache dir -> **atomic swap**. 
4. On failure: keep last good cache. **Settings status only** (no OS toast spam). Do not crash Protect. If **all** enabled feeds stale **&gt; 7 days**, surface **Problems / needs attention**. 
5. Offline: use last good cache. 
6. Settings -> **Threat lists**: last success time, entry count, error, Refresh now, category toggles, poll interval. **Product exceptions (N)** read-only for Book D. 
7. Respect upstream rate hints (never hammer URLhaus every minute). 
8. Parse formats: plain domains, hosts file, simple ABP `||domain^` (ignore other ABP chrome). 
9. English UI copy. No raw "blacklist" jargon - prefer **Threat lists** / Block known phishing / malware. 
10. **URLhaus:** mark enabled-in-policy only after **first successful download**. Failed first fetch ≠ Protect broken.

### Must not

- Fetch on every request. 
- Truncate silently. 
- Enable OISD/StevenBlack/HaGeZi full by default. 
- Let Book C override Book B allows.

---

## 4. Rule precedence (locked)

Normative evaluation order after existing normalize/DNS (extend [`04-policy-engine.md`](../04-policy-engine.md) §3):

1. **Unsafe IP / hard SSRF** (unchanged). 
2. **Secret / canary scanners** (unchanged. Still cannot be overridden by wide host allow). 
3. **Book B - user Allow forever / timed allow** -> allow (skip threat lists). 
4. **Book D - product unbreak** -> allow for threat-list purposes only (scanners still apply). 
5. **Book C - enabled threat subscriptions** (Phishing / Malware / Stronger / later Telemetry) -> deny with reason `threat_list` / map to clear post-block HITL. 
6. **Book B - Remembered Keep / timed deny** -> quiet/throttled path as today. 
7. **Mode branch:** 
 - Browse/Safe: allow if not denied above. 
 - Agent enforce: Book A allow rules. Else deny `host_not_allowed`. 
 - Ask: Book A match or prompt. 
8. Rate limits -> audit.

**Invariant:** User Allow (B) and unbreak (D) beat threat lists (C). Scanners beat wide allows.

---

## 5. Defaults - locked (§12)

| Item | Default | Notes |
| --- | --- | --- |
| Phishing Army | **ON** | - |
| URLhaus | **ON after first successful fetch** | Protect OK if feed down |
| HaGeZi TIF medium | **OFF** | Nested under Malware + first-enable warning |
| HaGeZi TIF full | **Not offered** | - |
| OISD small / OISD big / StevenBlack | **OFF** in Advanced | Day-1 optional catalog |
| Custom list URL | **Not this wave** | Q10 |
| Telemetry category | **Hidden** | Later |
| Agent packs | Ask on create + Undo pack | - |
| Unbreak | ~15-30 seed + Product exceptions (N) | - |
| Agents + threat lists | Enforce. Always on host wins | Q4 |

---

## 6-8. Features in this wave

### §6 Stronger threat lists

- **Nested checkbox under Malware:** "Including stronger threat list (HaGeZi TIF medium)". 
- Default **off**. First enable -> warning about size / possible breakage -> then download. 
- Copy: may block more. Use Allow if something breaks.

### §7 Category toggles (Settings)

| Toggle | Controls | Default |
| --- | --- | --- |
| Block known phishing | `phishing-army` | ON |
| Block known malware | `urlhaus-hosts` (active after first OK fetch) | ON |
| └ Stronger... | `hagezi-tif-medium` | OFF + warning |
| Telemetry | - | **Hidden** this wave |

**Advanced (off):** OISD small, OISD big, StevenBlack unified - with copy that these are broader / ad-heavy, not DenyOut's core job. 
**Not this wave:** Custom list URL.

Also: poll interval hours. Product exceptions (N) read-only. Refresh now.

### §8 Agent allow packs

- Ship `cursor-starter` + `claude-starter` YAML packs. 
- On **new agent**: ask "Add recommended hosts?" (yes/no). 
- **Undo pack** removes hosts that pack added (track pack membership). 
- Idempotent merge. Show what was added. Versioned packs.

---

## 9. Requirements summary (MoSCoW)

### Must

- Books A-D model + precedence §4 in docs + code. 
- Subscriptions: Phishing Army + URLhaus + HaGeZi medium (optional). 
- Updater §3. 
- Settings toggles §7. 
- Threat hit -> existing decision dialog path (clear post-block). 
- Unbreak seed (~15-30) + Product exceptions (N) in Settings. 
- Tests §11. 

### Should

- Agent packs Cursor + Claude with ask + Undo pack. 
- Manifest license/homepage links in Settings "About lists". 
- Advanced optional: OISD small, OISD big, StevenBlack (all default off). 

### Could

- Safing securedns bypass prevention. 
- Telemetry category (next wave). 
- Custom list URL (next wave). 

### Won't (this wave)

- HaGeZi full. 
- Firebog bulk. 
- Custom list URL. 
- Ads-first positioning. 
- Freemium/ads monetization in product (see HQ monetization notes).

---

## 10. Workstreams (implementation)

| Id | Work |
| --- | --- |
| L0 | Lock §12 answers into this plan. Update `04-policy-engine.md` precedence |
| L1 | List cache + fetch + parse + atomic swap + manifest |
| L2 | Wire Book C into policy eval + reason + HITL |
| L3 | Settings Threat lists UI + toggles + refresh |
| L4 | Unbreak Book D |
| L5 | HaGeZi medium optional |
| L6 | Agent packs + My agents UI |
| L7 | Advanced optional: OISD small/big + StevenBlack (off). No custom URL |
| L8 | Docs + QA evidence |
| LF | Full regression |

---

## 11. Test plan

### Automated

| ID | Assert |
| --- | --- |
| TL1 | Precedence: user Allow beats threat list hit |
| TL2 | Unbreak beats threat list. Scanner still denies secret |
| TL3 | Parse domains + hosts + simple ABP |
| TL4 | Bad fetch keeps previous cache |
| TL5 | Undersized fetch rejected |
| TL6 | Disabled category -> no deny from that feed |
| TL7 | Pack merge idempotent |
| TL8 | Agent mode still default-denies unknown host without Ask approve |

### Manual

| ID | Scenario |
| --- | --- |
| M1 | Phishing ON -> known listed domain blocked -> decision dialog |
| M2 | Allow site -> same domain passes |
| M3 | URLhaus ON/OFF changes malware domain |
| M4 | Stronger OFF->ON downloads medium. Settings shows count |
| M5 | Refresh now + airplane mode uses cache |
| M6 | Add Cursor pack -> hosts appear on profile |
| M7 | Browse still works for normal sites with defaults ON |
| M8 | Agents Ask path unchanged for new host |

---

## 12. Owner decisions (locked 2026-11-14)

| # | Decision |
| --- | --- |
| 1 | Phishing ON. URLhaus ON **after first successful download**. Fetch fail ≠ Protect broken |
| 2 | Advanced catalog: OISD small + OISD big + StevenBlack (all OFF) + ad-job warning. **Custom URL deferred** (Q10 overrides Q2-D) |
| 3 | Stronger = nested under Malware + first-enable size/breakage warning (B+D) |
| 4 | Threat lists apply in **all modes**. Explicit Always on that host still allows |
| 5 | Packs: ask on new agent + **Undo entire pack** |
| 6 | Refresh: new install + every **24 h** (Settings-configurable hours) + manual Refresh |
| 7 | Unbreak: seed ~15-30 reviewed hosts + Settings **Product exceptions (N)** read-only |
| 8 | Telemetry UI hidden. Reserved for later |
| 9 | Failed/undersized fetch: keep cache. Settings only (no toast spam). Problems if all feeds &gt;7 days stale |
| 10 | No custom list URL this wave |

**Personal vs corporate / freemium:** out of this wave's code scope - recorded in HQ monetization notes (sibling repo. Not copied into public tree). Does not block L1+.

---

## 13. Ship checklist

- [x] §12 answers recorded 
- [x] Precedence in `04-policy-engine.md` 
- [x] Fetcher + cache + Phishing Army + URLhaus 
- [x] Wire Book C into eval + HITL (`threat_list`) 
- [x] Settings Threat lists (phishing/malware + poll + Refresh) 
- [x] Stronger (HaGeZi medium) 
- [x] Unbreak seed + Product exceptions 
- [x] Agent packs + Undo pack 
- [x] Advanced OISD/StevenBlack optional 
- [x] TL1-TL8 evidence (unit) + M1-M8 code (see [`threat-lists-qa.md`](threat-lists-qa.md)) 
- [x] Orchestrator Progress all `tested` (LF)