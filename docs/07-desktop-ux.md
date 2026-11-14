# D07 UX - Desktop surfaces (normative)

User-visible desktop experience for DenyOut. **Product copy is English.**

Companion deploy/build notes: [`07-desktop.md`](07-desktop.md). 
**Copy catalog (every screen & message):** [`07-desktop-ux-catalog.md`](07-desktop-ux-catalog.md). 
**Simplicity review (non-technical lens):** [`07-desktop-ux-simplicity.md`](07-desktop-ux-simplicity.md). 
QA matrix: [`qa-desktop-ux.md`](qa-desktop-ux.md). 
Index: [`SPEC.md`](SPEC.md) (D07-UX).

| Shell | Binary | What the user gets |
| --- | --- | --- |
| **Primary** | `denyout-desktop` | System tray + Wails window (Home / History / My agents / Settings / Problems) |
| **Fallback** | `denyout desktop` | Same compact tray. Native OS dialogs instead of the Wails window |

This document is the **inventory of what the user sees**: install, tray icon, tray menu, every window screen/modal, and out-of-window toasts/dialogs.

**Product posture:** everyday Safe / Protect computer first. Window opened rarely. Power behind Filters / Select / Advanced.

---

## 1. Install - what the user sees

Install is **terminal-first**. There is no browser installer and no multi-page GUI wizard during `install.sh`.

### 1.1 Typical desktop install (GUI session or `--desktop`)

**What appears in the terminal (in order):**

1. Progress lines (`version`, fetch, checksum, installed `denyout`, optional `denyout-desktop`, `done`, `version` output).
2. Mode line: `denyout install: mode=desktop (...)`.
3. Banner: `Desktop install - silent: autostart, try Protect computer, tray in background.`
4. `denyout desktop --install`: Safe prefs, autostart, stop previous instances, detach tray.

**Outside the terminal after silent install:**

| Surface | When | What the user sees |
| --- | --- | --- |
| **System tray icon** | Immediately / next login | **DenyOut**. Tooltip `DenyOut - <mode>` (§2) |
| **Admin / elevation** | If Protect needs privileges | OS elevation dialog |
| **Your setup** | Once | Mode + 3 bullets. **Open DenyOut** (primary) - **Got it** (§4.4 / §5.5) |
| **Wails window** | Only if user chooses Open DenyOut (or later left-click) | Does not auto-open every login |

Silent install **does not** show the first-run three-way choice (§1.3).

### 1.2 Server / headless

Terminal only. No tray. Hints for `denyout init` / `run` / `serve`.

### 1.3 Optional install-type prompt

Desktop vs Server choice on TTY when `--prompt` / forced ask.

### 1.4 First interactive launch without silent `--install`

**Title:** DenyOut - How should DenyOut protect this computer? 
Controls: Protect computer - Protect AI agents - Not now. 
Then optional autostart. Then **Your setup** once. Protect AI agents + Wails -> My agents / New agent flow.

---

## 2. System tray icon

| Condition | Icon | Tooltip |
| --- | --- | --- |
| Off, no wraps | Idle | `DenyOut - Off` |
| Protect and/or wrap | On | `DenyOut - Protected` / `Agents only` / ... |
| Status error / Needs... | Alert | Same pattern |

| Click | Result |
| --- | --- |
| **Left-click** | Open window on **Home** (fallback: native denial list) |
| **Right-click** | Compact menu (§3) |

Linux caveat: some trays open the menu on left-click. **Open DenyOut...** remains available.

---

## 3. Tray menu (right-click. Compact)

```text
Protected | Off | Agents only -> disabled status line
────────────────
Protect computer [✓]
My agents...
Off [✓]
────────────────
Open DenyOut...
────────────────
Quit DenyOut
```

| Item | Behavior |
| --- | --- |
| Status | Disabled plain label (Off / Protected / Agents only / ...) |
| Protect computer | Enable Protect computer; ✓ when already Safe+Computer |
| **My agents...** | With Wails: open window on **My agents** screen. Fallback shell: native agent list / New / Start / Stop |
| Off | Turn Protect off |
| Open DenyOut... | Same as left-click -> Home |
| Quit DenyOut | Exit tray process |

**Not in tray:** What was blocked, Always-allow, Help, Notifications, Test, Agents only, Switch Safe, Resume asks, Learning primary, Last block, version footer.

---

## 4. Out-of-window surfaces

### 4.1 Post-block (Safe, clear threats)

**Title:** DenyOut blocked something 
**Body:** host - human why - optional URL - Keep blocked / Allow this site? 
**Actions:** **Keep blocked** - **Allow this site** - ~15s -> Keep. Remember on Keep. 
**Follow-ups:** `Allowed this site: <host>` - `Undid block for now: <host>` - quiet re-block -> History.

### 4.2 Pre-act Ask (wrap / Agents only)

Allow once - Always allow - Keep blocked (default).

### 4.3 Other toasts

Protect success: **You're protected. Browse as usual...** 
Admin fail: password-window story + Problems / retry (no Help & logs). 
Mode changes, Ask pause/resume, etc.

### 4.4 Your setup (native)

**Title:** DenyOut - Your setup 
Body: protected/off paragraph + three bullets (Keep/Allow. Open DenyOut Home. Problems if Protect failed) + privacy. 
**Buttons:** **Open DenyOut** (primary -> `OpenUI("home")`) - **Got it** (dismiss only).

---

## 5. Wails window - chrome

Close **X** = hide to tray. Quit only via tray.

### 5.0 Layout

| Region | Contents |
| --- | --- |
| Left nav | **DenyOut**. **Home**. **History**. **Settings**. **Problems** (+ badge). **My agents** demoted ("For AI tools"). Jump via **Ctrl+K** only |
| Top bar | Mode pill (**Protected** / Off / ...). Status text. If unhealthy: **Needs attention - open Problems** + **Open Problems** button. **Refresh** |
| Deep-links | `home`, `activity`/`history`, `profiles` / `profiles-new`, `settings`, `settings-advanced`, `problems` |

### 5.0.1 Onboarding sequence (one layer at a time)

Never stack these:

1. **Your setup** modal (if `your_setup_shown` false) - blocks other layers 
2. Else one **Protect** tip (`glossary`) until dismissed 
3. Else **per-screen** tip (History / My agents / Settings Basic|Advanced)

Getting started checklist is dropped (Home covers it).

### 5.0.2 Protect tip (`id=glossary`)

> Protect computer keeps everyday browsing safe. Open Home to see if you are protected - History shows what was blocked.

### 5.0.4 Jump (Ctrl+K only - not in nav chrome)

Home - History - My agents - New agent - Settings - Allowed / silenced sites - Resume asks - Agents only - Problems.

---

## 5.0.5 Screen: Home (default route) - **primary surface**

Normative detail: [`ux-iters/home.md`](ux-iters/home.md) (v2). Research: [`ux-iters/dashboard-research.md`](ux-iters/dashboard-research.md).

**Role:** the only primary screen. History / Settings / Problems / My agents are **additional** doors.

**Must show (and almost nothing else):**

1. Status headline - **You are protected** / **Protection is off** / **Needs your help**
2. One calm support sentence
3. One primary control - **Turn on Protect computer** / **Turn off** (needs-help: **Try Protect computer again** + **Open Problems**)
4. Story - **Last blocked** (host - human why - **Allow this site** - **See history**) or **Nothing blocked yet - that is OK**

**Must not on Home:** tables, Filters, charts, reason codes, health/IPC, Jump, allow-lists, Agents only.

Optional quiet lines: `Blocked today: N`. When a newer app build was detected - **Newer DenyOut available** - Open release - Settings (never asks to sign in). Footer text links at most: Settings - For AI tools.

---

## 5.1 Screen: History (route `activity`) - additional

**Tip** (only when onboarding sequence allows screen tips).

**Toolbar (default):** **Filters** (collapsed) - **Select...** - **Refresh** 
No persistent row checkboxes. **Select...** / **Done selecting** toggles selection mode. Then checkboxes + **Always allow selected (N)**.

**Filters (expanded):** search - reason (human label only, e.g. `Secret in link`. Code in `title` tooltip) - Remembered Keep only - **Group by host**.

**Table:** Time - Site - Why (human) - secondary Always allow.

**Empty:** **Nothing blocked yet - that is OK.** + **Try a safe check...**

**Drawer:** host title - human Why - URL - **Allow this site** (primary) - Always allow host - Copy URL - **Technical details** (reason codes, method, process, detectors, when).

---

## 5.2 Screen: My agents - additional (For AI tools)

User-facing name is **My agents** everywhere (internal route may remain `profiles`). Demoted in nav under **For AI tools**.

**Tip:** For AI tools... everyday browsing on Home.

**Toolbar:** **New agent** - **Refresh** 
**Learning** card only when pending Once hosts. 
**Modal:** simpler copy. Isolation under **Advanced options**. 
On **New agent** save: optional **Add recommended hosts?** (Cursor / Claude starter packs). Edit -> **Allow packs** (Add pack... / **Undo pack**). 
Empty: No AI agents yet - fine for everyday browsing.

Tray **My agents...** opens this list. **New agent** / Jump / first-run agents path may open create modal (`profiles-new`).

---

## 5.3 Screen: Settings - additional

**Find a setting...** search filters visible cards and may switch Basic/Advanced. 
**Tabs:** Basic - Advanced. 
Everyday On/Off may mirror Home on Basic. Home remains the emotional center.

### Basic

Tip: everyday protection. Agents only under Advanced. 
**Protection:** **Turn on Protect computer** - **Turn off** - Now: Protected/Off. **Switch to Protect computer** only when Agents only is on. 
**Notifications** - **Autostart**. 
**Threat lists:** Block known phishing - Block known malware - nested **Including stronger threat list** (confirm on first enable) - update interval - **Refresh now** - feed status - read-only **Product exceptions (N)**. 
*No Agents only on Basic. Telemetry category hidden.*

### Advanced

Tip: lists, diagnostics, whole-PC Agents only. 

**Account** (optional) - trust line: *Sign in to sync settings across computers. DenyOut works fully without an account.* Email one-time code - Sign in - Sign out - **Sync settings when signed in** - **Sync now** - **Delete cloud data** (cloud account only. Local Protect unchanged). API base under a collapsed advanced detail (local/stub). **Protect never requires an account.** Detail: [`cloud-sync.md`](cloud-sync.md).

**Sites I've allowed or silenced** - Allowed + Silenced (Keep blocked) + filter + Undo last allow. 

**Optional lists (not core)** - OISD small / OISD big / StevenBlack (default off. Ad/tracker warning on enable). Not network-wide adblocking. 

**Agents only (whole PC)** - "Almost nobody needs this" + confirm. 

**Asks** (Resume asks) - **Diagnostics** (version - logs - audit - Test protection - **Check for updates** / Open update - public manifest, no sign-in. Fail-open) - Privacy.

---

## 5.4 Screen: Problems - additional (when broken)

Fix-first summary - **Retry Protect computer** - **Copy last error** - Open diagnostics - optional **Update available** card (Open release. No sign-in) - Last blocked -> History - Health under **Details**. 
Surfaces on Home only via needs-help state + nav badge - not as a peer home.

---

## 5.5 Modal: Your setup (in-window)

When setup done and not shown. Body = `your_setup_text`. 
**Open DenyOut** (primary -> Home, mark shown) - **Got it** (mark shown only).

---

## 6. Native-only fallback

Same compact tray. My agents... uses native list. Your setup Open DenyOut -> Home / native denials. Left-click -> Home / native denials.

---

## 7. HITL matrix

Normative detail: [`ux-iters/notifications-rework-plan.md`](ux-iters/notifications-rework-plan.md).

| Mode | Clear threat (secrets, canary, deny host, **threat_list**) | New host |
| --- | --- | --- |
| Safe desktop | Compact decision dialog (Keep / Allow / timed / Decide later). Timeout ≠ Keep. | Browse allow |
| My agents wrap | Same decision dialog (no passive coalesced toast) | Ask dialog only (no teaser toast) |
| Agents only (whole PC) | Same decision dialog | Pre-act Ask |
| Off | - | - |

Threat-list hits use reason `threat_list`. User **Allow this site** / timed allow beats threat lists. Starter **packs** do not. Product unbreak (Book D) skips threat lists only - scanners still apply. Detail: [`ux-iters/threat-lists-plan.md`](ux-iters/threat-lists-plan.md).

**OS toasts (whitelist only):** Keep-repeat - Allow Undo - Protect pause ended - protection failure. 
**Notifications levels:** Quiet / Normal / Detailed (dialogs always when Protect on). 
**Protect Off:** pause presets (15m / 1h / tomorrow / forever). Home/tray truthful. No Off nags.

No false-deny of normal API auth on Safe (0.2.1).

---

## 8. Privacy

> Privacy: decisions stay on this computer.

Tips / Your setup / checklist in desktop state JSON. Logs under `~/.local/state/denyout/` (Linux XDG). 
Threat list cache: `~/.local/state/denyout/threatlists/` (feeds stay on this computer).

**Optional account:** signing in may sync a settings document (allows, keeps, toggles - never audit bodies or secrets) to `api.denyout.com`. App **update checks** use a public version file with no account. Signed-out users keep full Protect and local settings.
