# Plan: Notifications & HITL rework

Normative product decisions from the 2026-11-14 HITL questionnaire. Supersedes passive-info habits in [`toast-postblock.md`](toast-postblock.md), [`toast-protect.md`](toast-protect.md), and parts of [`ask-messages.md`](ask-messages.md). Update [`07-desktop-ux.md`](../07-desktop-ux.md) §7 when shipping.

**Priority when conflict:** cut noise for status & repeats; may interrupt for **first risk** and **end of Protect pause**.

---

## 0. Locked choices (decision log)

| Topic | Decision |
| --- | --- |
| First hard-block decision | Compact **decision dialog** (not full DenyOut). Link **Open DenyOut**. |
| App already open | Decision UI **inside** the app (modal/panel) - no second window. |
| App closed / minimized | Raise **compact dialog only**; full shell only via Open / tray. |
| Concurrent blocks | **One** dialog: start single-site; **from 2nd pending** -> same window becomes **site-grouped list**. |
| Hard-block actions | Keep forever - Keep timed - Allow forever - Allow timed - **Decide later** |
| Decide later / timeout | **Do not** write Remembered Keep; re-prompt ≤ interval (default **1 min**, configurable) per `site+reason`. |
| After several ignores | Soft batch: **list dialog**, grouped by site (cap how often it auto-opens). |
| After explicit Keep | OS toast on re-block ≤ same interval; can disable via Notifications level. |
| After Allow | OS banner ~**10s** with **Undo**. |
| Agents secret (no host Ask) | **Same** Keep/Allow/timed dialog; **no** extra OS info toast. |
| New host | Unchanged matrix: Browse allow / Agents **Ask** - not every DNS as hard-block dialog. |
| Ask + toast | **No duplicate**: dialog only; if Ask paused -> **one** reminder, not a storm. |
| Protect Off nags | None if user chose Off. Failures -> Problems / attention. Home always truthful. |
| Protect Off UX | On Off: Always / 15m / 1h / until tomorrow / custom; **remember last**; default ≠ forever. |
| Protect pause ends | Re-enable **silently** + calm OS banner **15s** with Undo -> pick another pause (15m / 1h / tomorrow / forever). |
| Timed site allow ends | **Ask again** (decision dialog). |
| Timed site deny ends | **Silent** back to policy (stay blocked if policy says so). |
| During decision timer | Network already blocked stays blocked until Allow (post-block). Ask path separate for new hosts. |
| OS toasts whitelist | **Only:** Keep-repeat - Allow Undo - Protect-pause-ended - **protection failure**. Else -> UI only. |
| Notifications setting | Levels **Quiet / Normal / Detailed** (default Normal); expand to per-type toggles. |
| Tray | Icon/label status - attention dot - click -> Home or "needs decision". No status spam toasts. |
| Teaching | Copy **inside** decision UI only; no separate educational OS banners. |

**§23 UX pick:** hybrid **A->list** - one site = simple dialog; second pending event in the same session morphs that window into a grouped list (never stack dialogs). After ignore-threshold with dialog closed, open **directly as list**.

---

## 1. Goals / non-goals

### Goals

1. Decisions are visible and actionable without relying on GNOME banner action buttons.
2. Stop nagging: no "Protection is off" / success / misc Info toasts.
3. Timed Protect and timed per-site allow/deny.
4. Predictable OS noise via whitelist + notification levels.

### Non-goals (this plan)

- Changing detection / policy engine rules (what counts as clear threat).
- Redesigning full Home/History chrome (only hooks: last blocked, queues, silenced/allows).
- Windows/macOS parity polish beyond "same product rules" (implement Linux-first; note gaps).

---

## 2. Surfaces

| Surface | Role |
| --- | --- |
| **Compact decision dialog** | Primary HITL for hard blocks (and agents secrets). Native or Wails mini-window - must work when main UI is closed. |
| **In-app decision modal** | Same choices when main window already open. |
| **Ask dialog** | New host (agents); never paired with a duplicate "needs a decision" toast. |
| **OS toast (whitelist)** | Keep-repeat, Allow Undo, pause-ended (+ Undo), protection failure. |
| **Tray** | On / Paused until ... / Off / Needs attention; click opens Home or decision queue. |
| **Home / History / Settings** | Truthful status; Allowed / Silenced / timed entries; notification level. |

### Hard-block vs new-host

| Event | Surface |
| --- | --- |
| Clear threat / deny-list / canary / agents secret (host already allowed or N/A) | Decision dialog (Keep/Allow/timed/later) |
| `host_not_allowed` + Ask mode | Ask dialog only |
| Browse new host (Safe) | Existing Browse allow - **no** hard-block dialog |
| Re-block after **explicit** Keep | Whitelist OS toast (throttled), not full dialog |
| Re-block after timeout/later (no Keep) | Decision dialog again (throttled) |

---

## 3. Decision dialog - UX spec

### Single-site (default)

- Title: plain ("DenyOut blocked something" / site name).
- Body: site - human why - redacted URL (no Host:/Why: jargon).
- Countdown: default **15s** (Settings: decision timeout).
- Actions:
 - **Keep blocked** (forever)
 - **Keep blocked for...** -> 15m / 1h / until tomorrow / custom
 - **Allow this site** (forever -> Always allow)
 - **Allow for...** -> same presets
 - **Decide later** (dismiss = timeout semantics)
 - Link: **Open DenyOut**
- Closing via DE close / timeout / Decide later -> **no** Remembered Keep.
- While open: traffic for that event stays **blocked** until Allow.

### Multi-site list (2+ pending or post-ignore batch)

- Group **by site**; reasons collapsed under site.
- Bulk: Keep selected / Allow selected / Decide later (all remaining).
- Per-row timed actions available (or "Keep/Allow..." opens same submenu).
- Auto-open frequency capped (e.g. at most once per decision-interval while queue non-empty) so list doesn't flap.

### Ignore -> soft C

- Count dismiss/timeouts per `site+reason` (and globally).
- After **N** ignores in a window (implement default **3 in 15 minutes**, configurable later if needed): next presentment is **list** mode with copy like "Several blocks are waiting for a choice".
- Between prompts: silence + History rows.

---

## 4. Memory model

| Memory | Written when | Effect | Ends |
| --- | --- | --- | --- |
| Remembered Keep | Explicit Keep forever | Throttled Keep-repeat toasts; Silenced list | User undoes in Settings |
| Timed deny | Keep for... | No re-ask until expiry; still blocked per policy | Expiry -> **silent** resume policy (no dialog) |
| Always allow | Allow forever | Host allowed | Undo / Settings |
| Timed allow | Allow for... | Host allowed until expiry | Expiry -> **decision dialog** again |
| Protect pause | Off with duration | Protect off until end | Expiry -> On + whitelist banner |
| Protect off forever | Off always | Off until user enables | Manual On |
| Ask pause | Existing pause asks | No Ask dialogs | Resume / timer |
| Last notification prefs | Levels + interval + decision timeout | Controls OS + dialog timing | - |

**Do not write Keep on timeout** (product rule).

Persist timed rules with absolute expiry in desktop state; show countdown in Settings lists.

---

## 5. OS toast whitelist

| Allowed | Content | Actions | Duration |
| --- | --- | --- | --- |
| Keep-repeat | "Blocked again: {site}" (+ open History) | none or Open | throttle = decision interval |
| Allow Undo | "Allowed this site: {site}" | **Undo** | ~10s |
| Protect resumed | "Protection is on again" | **Undo** -> pause presets | ~15s |
| Protection failed | Why + open Problems | Open DenyOut | until dismissed / short |

**Removed / forbidden as OS Info:** You're protected - Protection is off - misc learning - test chatter - coalesced secret info - Ask teaser when dialog will show - quiet "Blocked again" that isn't post-Keep - post-block action banners implemented only via `notify-send --action` without dialog fallback.

Implementation note: prefer **dialog** for first decision; do not depend on GNOME notification actions for Keep/Allow.

---

## 6. Settings - Notifications

**Level (default Normal):**

| Level | Decision dialogs | Keep-repeat OS | Allow Undo OS | Pause-ended OS | Failure OS |
| --- | --- | --- | --- | --- | --- |
| Quiet | Yes | No | No | No* | Yes |
| Normal | Yes | Yes | Yes | Yes | Yes |
| Detailed | Yes | Yes | Yes | Yes | Yes (+ optional future status) |

\*Quiet: pause still **re-enables** Protect; only the banner is suppressed - tray/Home show On. (Safe-first; matches "cut status noise".)

**Advanced toggles (under level):** Keep-repeat - Allow Undo - Pause-ended banner - (intervals)

**Also under Settings (near Notifications or Protect):**

- Decision timeout (default 15s)
- Re-ask / Keep-repeat interval (default 60s)
- Protect pause: last choice remembered

**Sites I've allowed or silenced:** show forever vs timed + remaining time; Undo.

---

## 7. Protect Off / pause

1. User chooses Off -> sheet: **15m / 1h / until tomorrow / custom / until I turn it on** (forever). Default = last used, else **1h** (not forever).
2. Tray + Home: "Paused until ..." / "Off".
3. No OS nag while intentionally off.
4. On expiry: set On; whitelist banner 15s; Undo opens pause presets again.
5. Failure to enable (admin/password): Problems + failure toast + tray attention - **not** the same as intentional Off.

---

## 8. Ask path (agents)

- Show **Ask dialog** only (Allow once / Always / Keep / timed if we align later).
- `notify=false` path: **no** teaser toast.
- If Ask paused: **one** OS or tray reminder ("Asks paused - open DenyOut"), not per host.
- IP blocked: keep non-jargon copy; prefer UI/dialog rules consistent with hard-block where applicable.

---

## 9. Tray

- States: Protected - Paused until T - Off - Needs attention (failure or pending decisions > 0).
- Menu stays compact; include Protect / Pause... / Open DenyOut.
- Left-click: Home; if pending decisions -> focus decision UI / queue.
- No HITL text walls inside tray menu.

---

## 10. Workstreams (implementation)

### P0 - Stop the wrong noise

1. Gate all `notify.Info` / passive `notify.Deny` through whitelist helper; delete or redirect Protect on/off success nags.
2. Ensure intentional Protect Off never schedules reminder toasts.
3. Docs: mark old toast unit musts obsolete where they conflict.

### P1 - Compact decision dialog

1. Replace post-block `notify-send --action` Keep/Allow as **primary** with compact dialog (+ in-app modal if window open).
2. Wire actions: Keep forever / timed, Allow forever / timed, Decide later; Open DenyOut.
3. Timeout/Decide later: no Remembered Keep; throttle map `site|reason` -> lastPromptAt.
4. Single->list morph when pending ≥ 2; ignore-threshold -> list presentment.
5. Agents secret coalesced path -> same dialog (drop passive coalesced toast).

### P2 - Timed rules + Protect pause

1. State: `TimedAllows[]`, `TimedDenies[]`, `ProtectPausedUntil`, `ProtectPauseLastChoice`.
2. Off UX sheet with presets + remember.
3. Expiry worker: allow->dialog; deny->silent; protect->On + banner.
4. Settings lists + Undo for timed and forever.

### P3 - Notifications levels + tray polish

1. Quiet / Normal / Detailed + toggles; migrate old boolean Notify.
2. Keep-repeat respects level + interval setting.
3. Allow Undo 10s banner.
4. Pause-ended banner + Undo presets.
5. Tray labels + attention dot + click target.

### P4 - Docs & QA

1. Update `07-desktop-ux.md` §7 HITL matrix + new § notifications.
2. Rewrite/retire conflicting bits in `toast-*.md`, `ask-messages.md`, `qa-desktop-ux.md`.
3. Execute test plan below; record evidence.

---

## 11. Test plan

### Automated

```bash
go test ./internal/desktop/ ./internal/notify/ ./internal/run/
# unit: whitelist allow/deny; timeout does not write Keep; throttle; timed expiry hooks
cd cmd/denyout-desktop/frontend && npm ci && npm run build
CGO_ENABLED=1 go build -tags 'wails webkit2_41' -o denyout-desktop ./cmd/denyout-desktop
```

Add/extend tests for:

| ID | Assert |
| --- | --- |
| T1 | Timeout / Decide later -> Keep list unchanged |
| T2 | Explicit Keep -> remembered; re-block within interval -> no second dialog |
| T3 | Keep-repeat toast suppressed on Quiet |
| T4 | Timed allow expiry -> enqueue decision; timed deny expiry -> no enqueue |
| T5 | Protect pause expiry -> On + (Normal) resume event |
| T6 | Whitelist rejects legacy "Protection is off" info |
| T7 | Ask path does not emit teaser toast when dialog shown |
| T8 | Pending ≥2 -> list payload shape (grouped by host) |

### Manual / DE (Linux GNOME first)

| # | Scenario | Expect |
| --- | --- | --- |
| M1 | Hard block, app closed | Compact dialog (not full shell); site blocked meanwhile |
| M2 | Same, app open on Home | In-app modal only; no second OS window storm |
| M3 | Dismiss / wait timeout | No Silenced entry; History has row; re-prompt after ≥ interval |
| M4 | Two hosts blocked quickly | One dialog grows to list; no stacked dialogs |
| M5 | Keep forever -> trigger again | Throttled OS toast only (Normal); no full dialog |
| M6 | Allow forever | Undo banner ~10s works; Settings Allowed |
| M7 | Allow 15m -> wait expiry | Decision dialog returns |
| M8 | Keep 15m -> wait expiry | Stays blocked quietly if policy says so; no dialog |
| M9 | Agents secret, host Ask N/A | Same decision dialog; no coalesced info toast |
| M10 | Agents new host Ask | Ask dialog; no duplicate toast |
| M11 | Ask paused + new hosts | One reminder max; queue in UI |
| M12 | Protect -> Off 1h | No off-nags; tray/Home show pause |
| M13 | Pause ends | On + banner; Undo -> choose another pause |
| M14 | Protect fails (admin) | Failure path + Problems; not treated as intentional Off |
| M15 | Notifications Quiet | Dialogs still; Keep-repeat/Undo/pause banners off; failure still on |
| M16 | Change interval to 2m | Re-ask and Keep-repeat honor 2m |
| M17 | Tray attention with pending | Dot/badge; click opens decision or Home queue |
| M18 | Open DenyOut from dialog | Full shell on decision context / History |

### Regression

- Browse Safe new host still not spammed with hard-block dialog.
- History / Allowed / Silenced wording matches dialog ("Allow this site", "Keep blocked").
- No educational OS banners on first run (Your setup / in-app copy only).

---

## 12. Ship checklist

- [x] P0 whitelist live; off-nags gone 
- [x] P1 dialog primary for hard block + agents secret 
- [x] P2 timed allow/deny + Protect pause 
- [x] P3 levels + tray 
- [x] Docs §7 + toast units updated 
- [x] Automated T1-T8 green 
- [x] Code/unit M1-M18 matrix recorded in `qa-desktop-ux.md` 
- [ ] Live DE dogfood with Protect On (user): real hard-block -> dialog -> Keep/Allow/pause end Undo

---

## 13. Open implementation details (not product forks)

Resolve during build without re-asking product:

- Compact dialog tech: zenity/yad vs small Wails/GTK window - pick what can show lists + timers reliably on GNOME.
- Exact N/window for ignore->list defaults (3 / 15m) unless UX feels wrong in dogfood.
- Whether timed Keep appears in Silenced with a clock vs separate "Paused blocks" subsection - prefer one list with expiry label.
