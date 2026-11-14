# Home dashboard - normative requirements (v2)

**Audience:** Safe-first, non-technical user. 
**Role of Home:** the *only* primary screen. Everything else is an **additional** door. 
**Research basis:** [`dashboard-research.md`](dashboard-research.md) (Windows Security - Tailscale - LuLu - OpenSnitch - Portmaster - AdGuard - Pi-hole - NextDNS).

---

## 1. Product rule

> Open DenyOut -> in **5 seconds** answer: *Am I protected? What should I do? Did anything scary happen?* 
> If they need more, they leave Home on purpose - History, Settings, Problems, My agents are **not peers of Home**.

Tray stays compact; window opens rarely; Home is the default open target.

---

## 2. Information architecture

```text
PRIMARY (always)
 Home -> emotional + functional center

ADDITIONAL (secondary doors)
 History - what was blocked (table + drawer)
 Settings - notify, autostart, allows, rare modes
 Problems - only when broken (also badge)
 My agents - For AI tools (demoted)
 Jump - power shortcut only (Ctrl+K), not nav chrome
```

| Screen | Job | When user goes there |
| --- | --- | --- |
| **Home** | Status + one action + last story | Every open |
| History | Review / allow many blocks | After scare or curiosity |
| Settings | Change how DenyOut behaves | Rare |
| Problems | Fix failed Protect | Only if red |
| My agents | Wrap an AI/tool | Power / AI users |

---

## 3. Home layout (maximum simplicity)

**Viewport budget - first screen must read as one composition, not a dashboard of widgets.**

```text
┌─────────────────────────────────────────┐
│ HEADLINE You are protected │
│ | Protection is off │
│ | Needs your help │
│ SUPPORT one short calm sentence │
│ PRIMARY [ Turn off ] │
│ | [ Turn on Protect... ] │
│ | [ Try again ]+[Problems]│
├─────────────────────────────────────────┤
│ STORY Last blocked │
│ host - human why │
│ [ Allow this site ] │
│ [ See history ] secondary│
│ or Nothing blocked yet - OK │
│ [ See history ] quiet │
└─────────────────────────────────────────┘
```

### 3.1 Must (on Home)

| # | Requirement |
| --- | --- |
| H1 | Default route + tray Open / left-click -> **Home** |
| H2 | Exactly **three** status headlines: protected / off / needs help (`problems_alert` wins) |
| H3 | Exactly **one** primary button for the healthy/off path (Turn on Protect computer **or** Turn off) |
| H4 | Needs-help: primary **Try Protect computer again** + secondary **Open Problems** |
| H5 | Last-block card when `last_deny_host` set: host + human why (+ URL muted optional) |
| H6 | Last-block actions: **Allow this site** (primary) - **See history** (secondary). No Keep on Home (toast already did Keep) |
| H7 | Empty story: **Nothing blocked yet - that is OK** + calm one-liner + quiet **See history** |
| H8 | Plain English only - no Safe desktop / Agents only / IPC / reason codes as headlines |
| H9 | After On/Off / Allow, refresh snapshot so status updates immediately |

### 3.2 Should (still simple)

| # | Requirement |
| --- | --- |
| S1 | Agents-only active -> treat as **not** everyday protected: headline steers to turn on Protect computer (or Switch) without teaching the mode |
| S2 | Optional **one quiet line** under story: `Blocked today: N` (no charts, no tops, no %) |
| S3 | At most **two** footer doors on Home: Settings - For AI tools (My agents) - text links, not equal nav weight |
| S4 | Visual urgency: needs-help card uses alert styling; protected stays calm |

### 3.3 Must not (on Home)

| # | Forbidden |
| --- | --- |
| X1 | Tables, Filters, Select, charts, top domains, live connection list |
| X2 | Reason codes, detectors, process, method, paths, health grid |
| X3 | Jump, Always allow lists, Remembered Keeps, Agents only enable |
| X4 | More than one competing primary CTA (except needs-help pair) |
| X5 | "Test Advanced" / operator empty copy that implies the user broke something |
| X6 | Expanding tray or changing HITL timing for this surface |

---

## 4. Copy (normative EN)

| State | Headline | Support |
| --- | --- | --- |
| Protected (safe + on + healthy) | You are protected | Browse as usual. We'll only interrupt for clear risks. |
| Off | Protection is off | Turn on Protect computer to block secret-looking links and clear threats while you browse. |
| Needs help | Needs your help | Something went wrong with protection. Try again, or open Problems. |
| Agents only (if shown) | Protection isn't set for everyday browsing | Turn on Protect computer for normal web use. AI tools belong under My agents. |

| Control | Label |
| --- | --- |
| Enable | Turn on Protect computer |
| Disable | Turn off |
| Retry | Try Protect computer again |
| Allow | Allow this site |
| History | See history |
| Problems | Open Problems |

Empty: **Nothing blocked yet - that is OK.** / When something is blocked, you'll get a short toast - and it will show up here.

---

## 5. Additional screens (explicitly *not* the dashboard)

These exist to deepen, not to compete with Home.

| Screen | May contain | Must not steal from Home |
| --- | --- | --- |
| **History** | Table, Filters, drawer, bulk allow, technical details | Default open; status On/Off as hero |
| **Settings** | Notify, autostart, allowed/silenced, Agents only | Everyday On/Off as the *main* story (mirror OK on Basic) |
| **Problems** | Fix-first summary, diagnostics under Details | Shown as home hero unless `problems_alert` |
| **My agents** | Agents list, Learning when pending | Equal nav weight; "you must set up an agent" |

Chrome: Home - History - Settings - Problems; My agents demoted. Status pill/top bar may echo Home, not replace it.

---

## 6. Acceptance (5-second test)

A non-technical user opening DenyOut can answer without reading History or Settings:

1. Am I protected? -> headline 
2. What do I do? -> the one primary button 
3. Anything scary? -> last-block card or "nothing blocked - OK"

If any answer requires another screen first, Home has failed.

---

## 7. Out of scope for Home requirements

HITL toast policy/timeouts; Electron; systray Linux epic; Pi-hole-style analytics; commit/PR.
