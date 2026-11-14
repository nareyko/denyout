# D07 UX catalog - screens & user-visible messages

**English product copy only.** Companion to the normative behavior inventory [`07-desktop-ux.md`](07-desktop-ux.md). 
This file lists **what the user can see**: screens, chrome, tips, dialogs, toasts, and terminal install lines.

Shells: **`denyout-desktop`** (tray + Wails window) - **`denyout desktop`** (tray + native dialogs).

---

## 1. Install (terminal)

Typical desktop install lines the user may see:

| Message / line |
| --- |
| `denyout install: version=... os=... arch=...` |
| `denyout install: fetching ...` |
| `denyout install: checksum ok` |
| `denyout install: installed .../denyout` |
| `denyout install: installed .../denyout-desktop` **or** note that desktop asset is missing |
| `denyout install: done` |
| `denyout version` output |
| `denyout install: mode=desktop (...)` / `mode=server (...)` |
| `Desktop install - silent: autostart, try Protect computer, tray in background.` |
| Server: `Server install - no tray, no localhost web UI.` + hints for `init` / `run` / `serve` |

Optional prompt:

```text
Choose install type:
 1) Desktop - native tray + Protect this computer (no browser UI)
 2) Server - CLI only; no tray, no web services
Install type [1=Desktop / 2=Server]:
```

---

## 2. System tray

### 2.1 Icon & tooltip

| Condition | Tooltip |
| --- | --- |
| Off | `DenyOut - Off` |
| Protect / wrap on | `DenyOut - Protected` / `DenyOut - Agents only` / `DenyOut - Limited (session)` |
| Off, computer unavailable | Status may show `Off (unavailable)` |

App name: **DenyOut**.

### 2.2 Clicks

| Input | Result |
| --- | --- |
| Left-click | Open **Home** (or native denial list) |
| Right-click | Compact menu below |

### 2.3 Tray menu (exact labels)

| Label |
| --- |
| `Off` / `Protected` / `Agents only` / ... (disabled status line) |
| `Protect computer` or `Protect computer ✓` |
| `My agents...` |
| `Off` or `Off ✓` |
| `Open DenyOut...` |
| `Quit DenyOut` |

---

## 3. Wails window - shared chrome

| Element | Copy |
| --- | --- |
| Brand | **DenyOut** |
| Nav | **Home** - **History** - **Settings** - **Problems** - **My agents** (demoted) - Jump via Ctrl+K only |
| Problems badge | Red dot; title `Needs attention` |
| Mode pill | `Protected` (Safe on) / `Agents only` / `Off` / ... |
| Status (healthy) | `Protected` when Safe on; else live status |
| Status (unhealthy) | **Needs attention - open Problems** |
| Button | **Open Problems** (when unhealthy) |
| Button | **Refresh** |
| Window close (X) | Hides to tray (not Quit) |

### 3.1 Jump modal (`Ctrl+K`)

| Element | Copy |
| --- | --- |
| Title | Jump to |
| Placeholder | Type a screen... |
| Rows | Home - History - My agents - New agent - Settings - Allowed / silenced sites - Resume asks - Agents only - Problems |
| Footer | Esc to close - Ctrl+K to open |

---

## 4. Onboarding layers (one at a time)

### 4.1 Modal: Your setup

| Element | Copy |
| --- | --- |
| Title | Your setup |
| Body (safe) | You are protected. Browse as usual - we'll only interrupt for clear risks. |
| Body (agents) | Protect computer is off for now. Use My agents for AI tools, or turn on Protect computer from Home or the tray. |
| Body (off) | Protection is off. Turn on Protect computer from Home or the tray when you are ready. |
| Bullets | - When something is blocked: Keep blocked or Allow this site. |
| | - Open DenyOut (Home) to see if you are protected and what was blocked. |
| | - If Protect failed, open Problems. |
| Footer | Privacy: decisions stay on this computer. |
| Buttons | **Open DenyOut** (primary -> Home) - **Got it** |

Native title when shown outside Wails: **DenyOut - Your setup** (same body/buttons).

### 4.2 Card: Getting started

Dropped - Home covers first open.

### 4.3 Tip: Protect (`glossary`)

> **Protect computer** keeps everyday browsing safe. Open Home anytime to see if you are protected - History shows what was blocked. 
> Button: **Got it**

### 4.4 Per-screen tips (each: body + **Got it**)

| Tip id | Body |
| --- | --- |
| activity | This is your block history. Open a row to decide Allow this site - only when you trust it. |
| profiles | For AI tools: wrap one command... Everyday browsing stays on Home -> Protect computer. |
| settings-basic | Basic is On/Off, notifications, and autostart. Allowed sites and rare options live under Advanced. |
| settings-advanced | Advanced lists, diagnostics, and the whole-PC Agents only mode. Changes here affect what DenyOut allows permanently. |

---

## 4.5 Screen: Home (default) - **primary**; see [`ux-iters/home.md`](ux-iters/home.md)

| Region | Labels / copy |
| --- | --- |
| Protected | **You are protected** - Browse as usual. We'll only interrupt for clear risks. - **Turn off** |
| Off | **Protection is off** - Turn on Protect computer... - **Turn on Protect computer** |
| Needs help | **Needs your help** - Something went wrong... - **Try Protect computer again** - **Open Problems** |
| Last blocked | Host - human why - **Allow this site** (primary) - **See history** (secondary) |
| Empty | **Nothing blocked yet - that is OK.** - Toast expect copy - quiet **See history** |
| Agents only | **Protection isn't set for everyday browsing** - Turn on Protect... - **Turn on Protect computer** |
| Optional | Quiet `Blocked today: N` (when N>0) - no charts / tops |
| Footer doors | **Settings** - **For AI tools** (text links) |
| Not on Home | Tables, Filters, reason codes, health, Jump, allow-lists, Agents only |

---

## 5. Screen: History (nav label; route `activity`)

| Region | Labels / copy |
| --- | --- |
| Toolbar | **Filters** / **Hide filters** - **Select...** / **Done selecting** - **Always allow selected (N)** - **Refresh** |
| Filters | Placeholder `Search host, URL, why...` - reason options - **Remembered Keep only** - **Group by host** |
| Reason options | All reasons - Secret in link - Secret in header - Secret in body - Canary detected - Host denied - Unsafe IP - Host not allowed |
| Table headers | Time - Site - Why - (Always allow) |
| Row hints | Keep remembered - Latest for host |
| Row button | **Always allow** (secondary) |
| Empty | **Nothing blocked yet - that is OK.** Toast expect copy. |
| Empty CTA | **Try a safe check...** |
| Drawer | Host title - human Why - URL - **Allow this site** (primary) - **Always allow host** - **Copy URL** |
| Drawer details | **Technical details** - Reason codes - Method - Process - Detectors - When |
| Drawer note | Secrets in URLs are shown as ***. Allow this site matches the toast. |
| Empty drawer | Select a row to see why it was blocked and what you can do. |

---

## 6. Screen: My agents

| Region | Labels / copy |
| --- | --- |
| Toolbar | **New agent** - **Refresh** |
| Learning card | **Learning** - While learning is on, Allow once hosts... Pin / Discard... not a tray primary action. |
| Empty | No agents yet. Create one to wrap a command with Ask / learning. You can also start from the tray: My agents... |
| Table | Name - Command - Ask - Learning - Status - actions |
| Row actions | **Start** / **Stop** - **Edit** - **Pin** - **Discard** - **Delete** |
| Delete confirm | `Delete agent <name>?` |
| Modal titles | **New agent** / **Edit agent** |
| Fields | Name - Command (`claude or python app.py`) - Workdir - Ask before new hosts - Learning (Once -> Pin) - Require stronger isolation (srt) |
| Modal buttons | **Save** - **Cancel** |

---

## 7. Screen: Settings

| Shared | **Find a setting... (always allow, keeps, asks, agents only...)** - tabs **Basic** - **Advanced** |

### 7.1 Basic

| Card | Copy / controls |
| --- | --- |
| Protection | Turn Protect computer on to block... Prefer My agents... |
| | **Turn on Protect computer** - **Turn off** - (**Switch to Protect computer** only if Agents only) |
| | `Now: Protected` / Off / mode label |
| Notifications | **Show OS notifications for blocks and asks** |
| Autostart | **Launch DenyOut at login** |

### 7.2 Advanced

| Card | Copy / controls |
| --- | --- |
| Account | Sign in to sync settings across computers. DenyOut works fully without an account. |
| | Email - **Email me a code** - One-time code - **Sign in** - (signed in) Sync settings - **Sync now** - **Sign out** - **Delete cloud data** |
| Sites I've allowed or silenced | Allowed + Silenced (Keep blocked) - Filter - **Undo last allow** - Remove / Clear |
| Agents only (whole PC) | Almost nobody needs this... Prefer My agents. |
| | **Enable Agents only (whole PC)...** |
| Confirm | Turn on Agents only for the whole computer? Messengers... Prefer My agents... Only continue if you understand the risk. |
| Asks | After many Ask prompts... - **Resume asks** / **Asks not paused** |
| Diagnostics | Version - Logs - Audit - **Open diagnostics folder** - **Test protection...** - **Check for updates** - Open update |
| | Update checks use a public version file - no sign-in. Protect still works if the check fails. |
| | Privacy: decisions stay on this computer. |

---

## 8. Screen: Problems

| Card | Copy / controls |
| --- | --- |
| Summary | Fix-first headline - **Retry Protect computer** - **Copy last error** - **Open diagnostics** - error pre when present |
| Update available | DenyOut {version} is ready. No sign-in needed - **Open release** |
| Last blocked | Host / URL / summary - **Open in History** - Empty: No recent denial recorded. |
| Details | Health: Mode - Control IPC - Proxyd - Session proxy - CA - Clipboard - log path |

---

## 9. OS toasts & dialogs (outside the window)

### 9.1 Post-block (Safe desktop)

| Element | Copy |
| --- | --- |
| Title | DenyOut blocked something |
| Body | `<host>` - human why - optional URL - Keep blocked, or Allow this site? |
| Actions | **Keep blocked** - **Allow this site** (~15s -> Keep) |
| Follow-ups | `Allowed this site: <host>` - `Undid block for now: <host>` - quiet re-block -> History |

### 9.2 Pre-act Ask (wrap / Agents only)

| Element | Copy |
| --- | --- |
| Urgent toast | **DenyOut needs a decision** - Choose Allow once, Always allow, or Keep blocked. |
| Dialog | `<who> wants to reach <host>.` - human why - Allow once / Always allow / Keep blocked |
| Dialog actions | **Allow once** - **Always allow** - **Keep blocked** |
| Timeout | Permission timed out - still blocked: \<host\> |

### 9.3 Ask storm / IP

| Message |
| --- |
| Many permission prompts... **Pause asks** / **Keep asking** |
| Asks paused for 15 minutes... Resume from Settings -> Advanced. |
| Title **DenyOut blocked a direct IP** - Connections by raw IP are blocked in this mode... Prefer Protect computer... |

### 9.4 Protection / mode toasts (examples)

| Message |
| --- |
| You're protected. Browse as usual. We'll only interrupt for clear risks. |
| Protection is off. Running agents (if any) keep going - stop them from My agents. |
| A password window should have appeared. If you cancelled it, protection stayed Off... |
| Already protecting whole computer. |
| Protection is already off. (Running agents are separate - use My agents -> Stop.) |
| Agents only is on for the whole computer. Open DenyOut -> Settings to switch back to Safe desktop. |
| Safe desktop - web works as usual. |
| Could not enable Agents only (admin may be required). |
| Asks resumed. |
| Undid always-allow: \<host\> |
| Always-allow list is empty. |
| Test: open a browser and visit a normal site... Keep blocked / Allow this site for 15 seconds. |

### 9.5 First-run / migration dialogs

| Title | Body / buttons |
| --- | --- |
| DenyOut | How should DenyOut protect this computer? - **Protect computer** - **Protect AI agents** - **Not now** |
| DenyOut | Start DenyOut automatically when you log in? - Recommended... - Yes/No |
| DenyOut update | Earlier DenyOut versions defaulted to Agents only... - Switch to Safe / Keep Agents only |
| DenyOut - Agents only | Turn on Agents only for the whole computer? ... - **Turn on Agents only** / keep Safe |
| DenyOut | DenyOut closed unexpectedly. Some wrapped agents... Stop leftover processes? |

### 9.6 Native My agents (fallback shell only)

| Surface | Copy |
| --- | --- |
| List | DenyOut - My agents - Select an agent: - ➕ New agent... - Stop all agents |
| Wizard | DenyOut - new agent / command / working folder / allowlist / stronger isolation |
| Actions | Start - Stop - Edit... - Delete - Pin learning (N)... - Cancel |

---

## 10. Privacy line (recurring)

> Privacy: decisions stay on this computer.

---

## Related docs

| Doc | Role |
| --- | --- |
| [`07-desktop-ux.md`](07-desktop-ux.md) | Normative behavior / IA |
| [`07-desktop-ux-simplicity.md`](07-desktop-ux-simplicity.md) | Simplicity review (home, friction, gaps) |
| [`07-desktop.md`](07-desktop.md) | Build / deploy |
| [`qa-desktop-ux.md`](qa-desktop-ux.md) | QA matrix |
