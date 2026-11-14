# D07 UX - simplicity review (non-technical user)

**Audience of this note:** product / design decisions. 
**Lens:** a normal person who installed DenyOut so the web stays safer - not an engineer. They rarely open the app; when they do, they want one clear answer: *Am I protected? What just happened? What should I do?*

Related: behavior [`07-desktop-ux.md`](07-desktop-ux.md) - copy catalog [`07-desktop-ux-catalog.md`](07-desktop-ux-catalog.md).

**Locked posture (already decided):** everyday **Protect computer / Safe desktop**; window opened rarely; power tools stay behind Filters / Advanced / Select.

---

## 1. Ideal "home" after open (main dashboard)

**Normative requirements:** [`ux-iters/home.md`](ux-iters/home.md) (v2). 
**Peer research:** [`ux-iters/dashboard-research.md`](ux-iters/dashboard-research.md).

Home is the **only primary screen**. History / Settings / Problems / My agents are **additional** - opened on purpose, never competing as equal "apps".

### What Home must answer in 5 seconds

1. **Am I protected?** - You are protected / Protection is off / Needs your help 
2. **What should I do next?** - one primary button 
3. **Did anything important happen?** - last block in human words, or "Nothing blocked yet - that is OK"

### Target layout (maximum simplicity)

```text
You are protected [ Turn off ]
Browse as usual. We'll only interrupt for clear risks.

Last blocked
 example.com - looked like a secret in a link
 [ Allow this site ] [ See history ]

 - or - 

Nothing blocked yet - that is OK.
 [ See history ]
```

Optional quiet: `Blocked today: N`. Footer doors (not peers): Settings - For AI tools.

**Principles:**

| Do | Don't |
| --- | --- |
| One status sentence in plain English | Mode jargon as the headline |
| One primary action | Pi-hole/AdGuard stat grids / charts |
| Last event as a story | Open as History table or live monitor |
| Problems only when broken | Equal-weight nav for power screens |

History stays as **History** - opened from "See history", never the emotional home.

---

## 2. What feels hard today (by surface)

### 2.1 Opening the window -> Activity as home

| Issue | Why it hurts a normal user |
| --- | --- |
| First view is a table + Filters + Select + drawer | Looks like an admin console, not "am I safe?" |
| Empty state talks about secrets/canaries/Test protection in Advanced | Jargon; "Advanced" sounds like they broke something |
| "Why" column + later "Reason codes" | Two layers of explanation without a single plain sentence |

### 2.2 Top bar & navigation

| Issue | Why it hurts |
| --- | --- |
| Mode pill **Safe desktop** / **Agents only** / **Off** | Three product modes before they understand one |
| Status string from the engine | Often technical or empty of meaning |
| Four nav peers: Activity, My agents, Settings, Problems | Equal weight implies equal importance; most users only need Home + Settings |
| **Jump Ctrl+K** in the nav | Power-user affordance on the primary chrome |

### 2.3 Settings

| Issue | Why it hurts |
| --- | --- |
| **Basic** still has Protect / Switch Safe / Off together | "Switch to Safe" is confusing if they think they are already Safe |
| **Advanced** mixes Always allow, Keeps, Asks, Agents only, paths | Good that danger is here; still a long scroll of concepts |
| Two memories: **Always allow** vs **Remembered Keeps** | Same human question ("why am I not asked again?") split into two lists |
| Paths under Diagnostics | Fine for support; scary as first Advanced content after Agents only |

### 2.4 My agents

| Issue | Why it hurts |
| --- | --- |
| Learning / Pin / Discard / Ask / srt | Necessary for power users; looks like a second product |
| "Agent" + command line | Expected for AI wrappers; not for the Safe-first persona |
| Learning card always on the screen | Permanent advanced concept on a list page |

### 2.5 Problems

| Issue | Why it hurts |
| --- | --- |
| Health rows: Control IPC, Proxyd, CA, clipboard | Support gold; user needs "Password failed - try Protect again" |
| Last error stack / elevation dump | Should be behind "Show details" / Copy |

### 2.6 Toasts & dialogs

| Issue | Why it hurts |
| --- | --- |
| Post-block is clear (**Keep blocked** / **Allow this site**) | Best current HITL - keep |
| Ask dialog: Allow once / Always / Keep blocked | Three outcomes; "Keep blocked" = deny - OK but dense |
| Some toasts still say "Tray -> ..." paths that no longer match compact tray | Broken wayfinding |
| Admin failure copy still mentions Help & logs as tray items | Out of date vs Settings / Problems |

### 2.7 Onboarding stack

| Issue | Why it hurts |
| --- | --- |
| Your setup -> checklist -> glossary -> screen tip | Correctly sequenced, but still four teaching layers |
| Glossary introduces three modes on day one | Safe-first users only need Safe + "AI tools later" |

---

## 3. What's missing (screens & messages)

### 3.1 Missing on home / chrome

| Gap | Suggestion |
| --- | --- |
| No plain "You are protected" | Home status sentence |
| No one-tap Turn on / Turn off on home | Primary control without hunting Settings |
| No friendly last-block card | Bridge from toast -> decision -> history |
| No "protection failed" story without opening Problems | Short banner: "Could not turn on - enter your password when asked" |

### 3.2 Missing on Activity / History

| Gap | Suggestion |
| --- | --- |
| No human one-liner per row | e.g. "Blocked a link that looked like it contained a secret" (toast already has this spirit) |
| Drawer leads with Reason codes | Put codes under "Technical details" |
| Always allow vs Allow this site both visible | One primary; explain the other in one short line |
| No "I don't understand this block" | Link to short help / How protection works |

### 3.3 Missing on Settings

| Gap | Suggestion |
| --- | --- |
| No single "sites I allowed" view | Merge Always allow + Keeps into one "Allowed / silenced sites" with simple filters |
| Switch to Safe unclear | Show only when Agents only is active |
| Test protection buried | From empty History / home: "Try a safe check" in plain words |

### 3.4 Missing in messages

| Gap | Suggestion |
| --- | --- |
| Stale tray directions in toasts | Point to Open DenyOut / Settings / Problems only |
| Admin fail | "A password window should have appeared. If you cancelled it, protection stayed Off." |
| Success after Protect | "You're protected. Browse as usual. We'll only interrupt for clear risks." |
| First empty History | Reassure: empty is good; not "go test Advanced" |

### 3.5 Missing for Safe-first vs agents

| Gap | Suggestion |
| --- | --- |
| My agents visible as peer nav always | Soft-hide or demote under "For AI tools" until first agent / user expands |
| Agents only discoverability vs safety | Keep in Advanced; add one plain sentence: "Almost nobody needs this" |

---

## 4. Simplicity scorecard (current -> target)

| Surface | Current feel | Target feel |
| --- | --- | --- |
| Tray | Good (few items) | Keep |
| Post-block toast | Good | Keep; polish follow-up toasts |
| Window home | Admin history | Status + last event + one action |
| Activity | Powerful log | Rename History; calmer empty; human why |
| Settings Basic | Slightly busy | Only On/Off + notify + autostart (+ Switch Safe when needed) |
| Settings Advanced | Long but OK | Group "My allowed sites"; details collapsed |
| My agents | Power tool | Secondary; Learning less prominent |
| Problems | Technician panel | Fix-first story; details collapsed |
| Onboarding | Four layers | Your setup + at most one tip |

---

## 5. Suggested change backlog (product, not eng detail)

Ordered for maximum simplicity gain:

1. **Home dashboard** - status, primary On/Off, last block card; Activity becomes History. 
2. **Message cleanup** - remove stale tray paths; admin/success/empty copy in plain English. 
3. **Activity drawer** - human why first; reason codes under details; one clear allow action. 
4. **Settings Basic trim** - conditional Switch Safe; Test protection from home/empty History. 
5. **Unify allow lists** (or one entry point) - Always allow + Keeps as one human concept. 
6. **Demote My agents / Jump** in chrome for Safe-first. 
7. **Problems** - friendly summary first; health grid secondary. 
8. **Shorten onboarding** - drop glossary of three modes for Safe-first installs (or fold into one tip).

Non-goals for this simplicity track: changing HITL timing policy, Electron, expanding the tray, teaching nft/CA to end users.

---

## 6. Full priority order - every window element & message (for UX refactor)

Priority = impact on a non-technical Safe-first user x how often they see it. 
**P0** = do first - **P1** = next - **P2** = after home/history feel right - **P3** = polish - **P4** = leave / lowest.

### P0 - Critical path (protection + interrupt + first open)

| # | Surface | Element / message | Refactor intent |
| --- | --- | --- | --- |
| 1 | **New: Home** | Status sentence ("You are protected" / "Protection is off" / "Needs your help") | Main answer on open |
| 2 | **New: Home** | Primary **Turn on Protect** / **Turn off** | One control, no hunting |
| 3 | **New: Home** | Last blocked card (site + plain why + Keep / Allow) | Close the loop after toast |
| 4 | Toast | **DenyOut blocked something** + **Keep blocked** / **Allow this site** | Keep; ensure body is human-only |
| 5 | Toast | Protect on success ("You're protected. Browse as usual...") | New/rewrite |
| 6 | Toast | Admin failed (password cancelled / failed) | Plain story; no "Help & logs" tray path |
| 7 | Modal | **Your setup** body + **Open DenyOut** / **Got it** | Shorten; Safe-first only |
| 8 | Tray | Tooltip `DenyOut - ...` + left-click open | Keep; tooltip in plain words if possible |
| 9 | Tray menu | **Protect computer** - **Off** - **Open DenyOut...** - **Quit** | Keep order; status line plainer |
| 10 | Chrome | Unhealthy: **Needs attention - open Problems** + badge | Keep; tie to Home banner too |

### P1 - History & wayfinding (what they open after a scare)

| # | Surface | Element / message | Refactor intent |
| --- | --- | --- | --- |
| 11 | Nav | Rename **Activity** -> **History** (or "What was blocked") | Matches mental model |
| 12 | Home | Link **See history** | Entry to table |
| 13 | Activity | Empty state ("Nothing blocked yet - that is OK") | Reassure; drop Advanced push |
| 14 | Activity | Table: Time - Site - Why (human one-liner) | Why = story, not code |
| 15 | Activity | Row **Always allow** | Keep secondary; less prominent than drawer primary |
| 16 | Activity drawer | Title + Site + human Why first | Lead with understanding |
| 17 | Activity drawer | **Allow this site** (primary) - **Always allow host** (secondary or merged) | One clear decision |
| 18 | Activity drawer | URL | Keep visible; secrets redacted note short |
| 19 | Activity drawer | Reason codes - Method - Process - Detectors | Collapse under **Technical details** |
| 20 | Activity | Toolbar **Filters** | Keep collapsed by default |
| 21 | Settings Basic | **Protect computer (Safe)** - **Off** | Align copy with Home |
| 22 | Settings Basic | **Notifications** - **Autostart** | Keep simple |
| 23 | Chrome | Mode pill | Prefer "Protected" / "Off" over Safe desktop jargon on Home |

### P2 - Reduce confusion & duplicate concepts

| # | Surface | Element / message | Refactor intent |
| --- | --- | --- | --- |
| 24 | Settings Basic | **Switch to Safe desktop** | Show **only** when Agents only is on |
| 25 | Settings Advanced | **Always allow** list + **Remembered Keeps** | Unify entry: "Sites I've allowed / silenced" |
| 26 | Settings Advanced | **Agents only (whole PC)** + confirm | Keep buried; add "Almost nobody needs this" |
| 27 | Settings Advanced | **Resume asks** | Keep; findable via Jump/Find |
| 28 | Activity | **Select...** / bulk Always allow | Keep power; not on Home |
| 29 | Activity | **Group by host** (under Filters) | Keep |
| 30 | Activity | Reason filter labels | Keep human labels |
| 31 | Onboarding | **Getting started** checklist | Merge into Home empty or drop if Home exists |
| 32 | Onboarding | Glossary tip (3 modes) | Drop or one Safe-only tip for Safe-first |
| 33 | Tips | activity / settings-basic tips | Rewrite after Home exists |
| 34 | Toast | Follow-ups `Always allow: host` / undid block | Align wording with drawer |
| 35 | Toast / dialog | Ask: **Allow once** - **Always allow** - **Keep blocked** | Keep policy; plainer title/body |
| 36 | Chrome | Nav weight: Settings vs My agents | Settings above; My agents demoted |

### P3 - Power / support (secondary users)

| # | Surface | Element / message | Refactor intent |
| --- | --- | --- | --- |
| 37 | Nav / screen | **My agents** list - **New agent** | Secondary "For AI tools" |
| 38 | My agents | Empty state | Softer; don't compete with Home |
| 39 | My agents | Modal New/Edit fields (Name, Command, Ask...) | Keep; wizard copy simpler |
| 40 | My agents | **Learning** card - Pin - Discard | Collapse / show when pending only |
| 41 | My agents | Require isolation (srt) | Advanced-only in modal |
| 42 | Problems | Friendly summary + **Retry Protect** - **Copy last error** | Fix-first |
| 43 | Problems | **Last blocked** -> Open in History | Keep |
| 44 | Problems | Health grid (IPC, Proxyd, CA, clipboard) | Under **Details** |
| 45 | Settings Advanced | Diagnostics paths - **Open diagnostics** - **Test protection** | Keep; Test also from Home empty |
| 46 | Settings | **Find a setting...** | Keep |
| 47 | Jump Ctrl+K | Jump list | Move out of primary nav chrome (shortcut only) |
| 48 | Tray | **My agents...** | Keep for power; opens agents screen |
| 49 | Toast | Ask storm pause / Resume | Keep |
| 50 | Toast | IP blocked | Keep; plain words |
| 51 | Dialog | Autostart prompt | Keep short |
| 52 | Dialog | UXv2 migration / unexpected quit | Rare; plain copy |

### P4 - Lowest / leave alone for now

| # | Surface | Element / message | Refactor intent |
| --- | --- | --- | --- |
| 53 | Tray | Separators / ✓ checkmarks | Fine |
| 54 | Chrome | Brand **DenyOut** | Fine |
| 55 | Chrome | **Refresh** | Fine / optional later |
| 56 | Privacy line | "Privacy: decisions stay on this computer." | Keep everywhere relevant |
| 57 | Install terminal lines | install.sh progress | Out of GUI refactor |
| 58 | Native fallback wizards | zenity lists when no Wails | Parity later; not P0 |
| 59 | Session mode labels | Limited (session) | Not user-facing primary |
| 60 | HITL timing / policy | 15s / 2min defaults | Non-goal this track |

### Reading the order as phases

```text
Phase A (P0): Home + toast truth + Your setup + Protect fail/success
Phase B (P1): History rename + table/drawer human why + Basic On/Off
Phase C (P2): Unify allows - trim Switch Safe - demote agents - cut glossary
Phase D (P3-P4): Problems details - Learning collapse - Jump demotion - leave tray core
```

---

## 7. One-sentence product rule

> If a normal person opens DenyOut, they should instantly see whether they are protected and what to do about the last scary moment - without learning the words Safe desktop, Agents only, proxyd, or Reason codes.
