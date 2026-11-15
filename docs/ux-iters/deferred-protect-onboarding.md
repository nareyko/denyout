# Deferred Protect onboarding — analysis, UX spec & implementation plan

**Status:** Proposed — **all product/UX decisions locked** (§12 including D16–D20). Ready to implement.  
**Target:** post-0.3.x desktop install.  
**Product copy:** English.  
**Related:** [`../07-desktop-ux.md`](../07-desktop-ux.md) §1, [`your-setup.md`](your-setup.md), [`toast-protect.md`](toast-protect.md), [`../07-desktop.md`](../07-desktop.md) §3.

---

## 0. Verdict

**Yes — do this.** The user’s three-step model is the correct product posture:

1. **Install = user-space only** (no password, no hostguard, no “we already turned Protect on”).
2. **First open = informed mode choice** (explain *when* and *why* admin is needed).
3. **Enable = one intentional elevate** + persist prefs + register autostart / restore.

Today’s silent install does the opposite: it writes `ProtectionOn=true` and immediately restores Computer → **pkexec/osascript without context**, often while the terminal install is still finishing. That feels like a random root prompt and trains people to Cancel → Off forever.

This plan keeps Safe / Protect computer as the recommended everyday mode; it only **defers** privilege until the user opts in inside the app.

---

## 1. Problem (current behavior)

### 1.1 What happens now

| Step | Behavior | Privilege |
| --- | --- | --- |
| `install.sh` (desktop mode) | Fetch bins → `denyout desktop --install` | None |
| `Install()` | Sets `SetupDone`, `ProtectionOn`, `ComputerEnabled`, `Scope=computer`, Safe profile; registers autostart; detaches tray | None |
| Tray `Bootstrap` | Sees `SetupDone` → **skips** first-run wizard → `restoreProtection()` → `startComputer()` → `ElevateApply` | **Admin once** |
| After | Optional native **Your setup** (Open DenyOut / Got it) | None |

So the password dialog appears **because of restore**, not because the user just clicked “Protect computer”. Terminal text even says: `approve admin once if prompted`.

### 1.2 Why that hurts UX

- Password without a clear in-app “why” → Cancel → Protect stays Off; user thinks install failed.
- First-run mode choice (`Protect computer` / `Protect AI agents` / `Not now`) exists in code (`runFirstRunWizard`) but **silent install never shows it** (`SetupDone=true`).
- Agents / wrap path does **not** need hostguard admin; conflating “install” with “Protect computer” forces privilege for users who only wanted agents.
- Upgrade / reinstall can re-trigger elevate while the user only wanted a binary replace.

### 1.3 Privilege truth (keep this honest in UI)

| Action | Needs admin? | Mechanism |
| --- | --- | --- |
| Copy `denyout` / `denyout-desktop` to `~/.local/bin` | No | User-writable |
| Register login autostart (XDG / LaunchAgent / Run key) | No | User config |
| Trust CA in **user** NSS (Chrome/Chromium) | No | User DB |
| **Protect computer** (nftables/pf redirect + system CA trust) | **Yes** | `hostguard.ElevateApply` (pkexec / osascript / UAC) |
| Turn Protect **off** / Quit unload | Often **yes** (one `ElevateRemove`) | Same |
| **My agents** wrap (`denyout run` / profile) | No (user process) | No hostguard |
| Agents-only whole-PC (Advanced) | Yes | Same as Protect computer |

Claim carefully: **install never asks**; **first Protect** (and Off→On when helper missing) may ask once; **with helper installed, reboot restore does not ask**. Do not promise password-free restore on a platform until §8 helper ships there.

---

## 2. Goals & non-goals

### Goals

- G1. `curl | sh` / zip unpack never blocks on admin and never pops elevation.
- G2. First open shows **Home + required mode modal**; Protect computer is the large primary action.
- G3. Before every Off→On Protect (first run and later), DenyOut shows its own “password coming” confirm; then the OS password — **except** when the privileged restore helper can do the work without prompting (§8 / D10).
- G4. **After the first successful Protect computer, reboot/login restore must not ask for a password again.** Achieved by installing a privileged helper during that first approved Protect.  
- G4b. **Quit always fully unloads** (D19): no leftover redirects, proxyd, or mediation. Prefer helper; **if a password is required to finish unload, ask for it.** Never exit “protected but tray gone.”
- G5. Autostart is turned **on automatically** when setup finishes; mentioned in Your setup; user can disable in Settings (D9=C).
- G6. Works for both shells: `denyout-desktop` (primary) and `denyout desktop` (native fallback, same mode choices + Quit unload confirm).
- G7. Cancelled/failed password returns the user to **mode choice** (not a dead Off with SetupDone) on first-run (D6=B).

### Non-goals

- No browser-based installer wizard during `install.sh`.
- No multi-page “tour” after Your setup (still: one status + at most one tip — see `your-setup.md` / simplicity doc).
- No Session-scope surprise restore (already forbidden).
- No timed “Not now” nudges (D8=A).
- Terminal does **not** block on mode choice (D2=A).

---

## 3. Target user journey (locked to §12)

```text
[ Terminal install ]                         (D1=A, D2=A)
  bins only → start denyout-desktop → exit terminal
  NO password, NO Protect on
        │
        ▼
[ Home + required mode modal ]               (D3=B, D4=A)
  Protect computer (large primary)
  Protect AI agents (secondary)
  Not now (secondary)
        │
        ├─ Protect computer
        │     DenyOut confirm “password coming”   (D5=A)
        │     → OS password (first time / no helper yet)
        │     → Apply + install restore helper    (D10)
        │     → Your setup (once)                 (D13=A)
        │     → autostart ON (mention in Your setup) (D9=C)
        │     cancel/fail → back to mode modal    (D6=B)
        │
        ├─ Protect AI agents                      (D7=A)
        │     no password → agent create wizard
        │     if abandoned → My agents empty+Add
        │     → Your setup + autostart ON
        │
        └─ Not now                                (D8=A)
              Off → Your setup + autostart ON
              no later nudges
```

### 3.1 Screen A — Mode choice

**When:** Fresh install / after full uninstall (`!SetupDone`) — D15=A.  
**Shape:** Normal **Home**, with a **required modal** on top (D3=B).  
**Close without choosing (D16):** closing the window / Esc does **not** count as Not now. `SetupDone` stays false; next open (or left-click tray) shows the same modal again. No autostart registration until a real choice completes.  
**Primary:** large **Protect computer**; agents + Not now secondary (D4=A).

| Choice | Short | Admin note |
| --- | --- | --- |
| **Protect computer** | Browse as usual. We only interrupt for clear risks. | First enable needs your computer password once; after that, protection can return after restart without asking again. |
| **Protect AI agents** | Wrap tools you choose. Rest of the PC unchanged. | No admin password for wrapping an app. |
| **Not now** | Leave protection off. | None |

### 3.2 Screen B — Confirm before system password (always on Off→On)

D5=A, D12=A: every time the user turns Protect computer on from Off (onboarding, Home, or tray), show DenyOut confirm first:

> Protect computer will ask for your password so DenyOut can set system network rules.  
> After you approve once, DenyOut can restore protection after restart without asking again.  
> [Cancel] [Continue]

Then:

- If **restore helper already installed** → helper Apply **without** OS password (still show DenyOut confirm so the action is intentional).
- If **no helper** → OS password → on success, **install helper** as part of the same elevated session when possible (one prompt).

**First-run cancel/fail (D6=B):** return to mode modal (`SetupDone` stays false).  
**Later Off→On cancel/fail:** stay Off; Home/Problems retry (setup already done).

### 3.3 Agents path (D7)

1. Finish setup with computer Off.  
2. Open **new agent** wizard immediately.  
3. If they leave without creating → land on **My agents** empty state with Add.  
4. Your setup once + autostart on.

### 3.4 Autostart (D9=C)

- On any completed mode choice (including Not now): `RegisterAutostart()` automatically (prefer `denyout-desktop`).
- Your setup mentions: DenyOut will open when you log in; turn off in Settings.
- No separate Yes/No ask during onboarding.

### 3.5 Quit DenyOut (D19)

Tray **Quit DenyOut** = program unloaded (desktop canon). Confirm when protection / agents / leave-on intent is live:

| Choice | Behavior |
| --- | --- |
| **Turn off protection and quit** (wording varies: Agents only / Session / Clear intent / Stop agents) | Full unload: stop proxyd/wraps, hostguard Remove (helper first; OS password if needed), clear leave-on, dismiss DenyOut OS banners, exit |
| **Cancel** | Stay running |

There is **no** “Keep protection on and quit.” If unload needs a password and the user cancels: stay running and protected (do not pretend to have quit; do not leave tray).

### 3.6 Terminal install copy

```text
denyout install: version=…
denyout install: fetching …
denyout install: checksum ok
denyout install: installed …/denyout
denyout install: installed …/denyout-desktop
denyout 0.x.y
denyout install: done
denyout install: mode=desktop (…)
Desktop install — no password yet. Opening DenyOut to choose protection…
denyout install: started (protection off until you choose)
```

---

## 4. State model

### 4.1 Desired flags (minimal change)

Reuse existing `desktop` state JSON; change **what Install writes**:

| Field | Today (`Install`) | After install (new) |
| --- | --- | --- |
| `setup_done` | `true` | `false` until mode chosen **successfully** (Not now counts; failed Protect does **not** — D6=B) |
| `protection_on` | `true` | `false` |
| `computer_enabled` | `true` | `false` |
| `scope` | `computer` | `off` |
| `policy_profile` | browse | browse |
| `autostart` / `autostart_asked` | true / true | set true when setup completes (D9=C); `autostart_asked=true` so we do not re-prompt |
| `your_setup_shown` | false | false until Your setup once |

Also track helper presence (file/state): e.g. `hostguard_helper_ok` or detect installed unit/policy — used so restore skips OS password.

`Bootstrap`: if `!SetupDone` → Home + mode modal (Wails) or native three-choice (fallback). Restore Protect only if `SetupDone && ProtectionOn`, via **helper first**, pkexec only if helper missing.

### 4.2 Upgrade while broken / Off (D11=C)

- Healthy Protect on upgrade: quiet binary replace + helper-aware restore (no mode modal).
- Off or broken (no proxyd / last restore failed): show **Finish setup** / mode choice again.

### 4.3 Server / `--server` install

Unchanged: CLI only, no tray, no mode modal.

---

## 5. Code touch map (implementation plan)

### Phase 0 — Spec lock (docs)

- [x] This plan + §12 decisions
- [ ] Normative [`07-desktop-ux.md`](../07-desktop-ux.md) §1 when shipping
- [ ] Catalog + [`qa-desktop-ux.md`](../qa-desktop-ux.md)

### Phase 1 — Install user-space + open Home (P0)

`Install()` → Off, `SetupDone=false`; no elevate; detach `denyout-desktop`; **open UI once** (D1=A); terminal exits (D2=A).

### Phase 2 — Home + mode modal (P0)

Wails: required modal on Home (D3=B). Native fallback: same three choices (D14=A).  
Protect → always DenyOut confirm (D5=A). Cancel password → mode modal again (D6=B).  
Agents → wizard, abandon → My agents empty (D7). Not now → quiet (D8=A).  
Autostart ON on completed setup (D9=C) + Your setup once (D13=A).

### Phase 3 — Confirm on every Off→On (P0)

Home + tray: DenyOut confirm before enable (D12=A). Success: no success toast spam.

### Phase 4 — Passwordless restore helper (P0 for D10 — **required**)

See §8. Ship with the same release wave as Phases 1–3 if possible; otherwise do **not** claim “won’t ask after restart” in UI until helper works on the platform.

### Phase 5 — Upgrade semantics (P1)

D11=C: healthy Protect → quiet; Off/broken → Finish setup / mode choice. Fresh uninstall → mode choice (D15=A).

### Phase 6 — Polish (P2)

Logging, Windows/macOS copy, `DENYOUT_INSTALL_OPEN=0` for CI.

---

## 6. Design decisions & tradeoffs

### 6.1 Why not elevate during install?

Informed consent belongs in the app (D1–D5). Terminal must finish without password (D2=A).

### 6.2 Why does reboot ask for a password today — and how we stop that (D10)

**Why today:** Protect computer changes **system** network rules (and system trust). Those changes need administrator rights. Today DenyOut does that by popping the OS password dialog **every time** it runs `hostctl apply` (pkexec / macOS admin / UAC). After a restart the rules are gone or must be re-applied, so restore calls apply again → password again. Autostart alone cannot fix that: the tray runs as your user, not as admin.

Existing Linux polkit file (`contrib/polkit/…`) only says “ask admin, keep for a while in this session” (`auth_admin_keep`). It is also **not** installed by `install.sh` into system dirs (that itself needs admin). So reboot still asks.

**How to never ask again after the first success:** during the **first** approved Protect, in the same admin moment, also install a small **privileged restore helper** (system service / launchd daemon / Windows service, or a tightly scoped polkit rule that allows only DenyOut’s apply/remove for this machine). Later restores talk to that helper over a local, authenticated channel — **no password UI**. Turning Protect off/on later should use the same helper when present (DenyOut confirm still shows — D12 — but OS password stays away).

**Product rule:** UI may say “password once” / “won’t ask after restart” **only** on platforms where the helper is implemented and verified. Until then, do not over-promise.

### 6.3 Autostart

Locked D9=C: enable on completed setup; mention in Your setup; Settings can disable. Safe because Protect restore is helper-based (D10), not a surprise pkexec at login.

### 6.4 Open window after install

Locked D1=A: open once. While `!SetupDone`, Home shows required modal (D3=B).

### 6.5 Safe-first

Still: large Protect computer primary (D4=A), not forced during install.

---

## 7. Copy bank (draft EN)

**Mode choice — Protect computer footnote**  
`Needs your computer password once. After that, DenyOut can restore protection after restart without asking again.`

**Confirm (Off→On, every time)**  
`Turn on Protect computer? Your system may ask for a password so DenyOut can set network rules.`  
`(After the first success, restarts should not ask again.)`  
Buttons: `Cancel` · `Continue`

**Install banner**  
`Desktop install — no password yet. Opening DenyOut to choose protection…`

**Your setup (autostart line)**  
`DenyOut will open when you log in. You can turn that off in Settings.`

Reuse existing Your setup body / protect-failed strings where possible.

---

## 8. Privileged restore helper (required for D10)

### 8.1 User-facing promise

After the first successful Protect computer approval: **restart and login restore do not show a password dialog.**

### 8.2 Locked design (D17) — real helper, same model everywhere

**Choose a privileged helper service**, not “passwordless polkit for the whole action” as the primary design.

Why (UX + safety): one mental model on Linux/macOS/Windows; Off / Quit / restore all feel the same; narrower privilege than “this user may pkexec forever without a prompt.”

1. **First Protect** (user already in OS auth dialog): elevated `hostctl apply` **and** install helper in **one** admin moment.
2. Helper is a **system** component that only runs DenyOut apply / remove / teardown (fixed verbs).
3. User-session tray talks over a **local authenticated socket** (uid ownership + token).
4. **Uninstall** removes helper + rules (one OS password only if helper is already broken/missing).

Polkit policy file may still label the *first* install/apply; it is **not** the long-term “never ask again” mechanism.

### 8.3 Platform sketches (locked direction)

| OS | Helper |
| --- | --- |
| **Linux** | `denyout-hostguard.service` (systemd system unit) + root helper binary; tray → socket |
| **macOS** | Privileged LaunchDaemon / SMAppService helper; tray → XPC/socket |
| **Windows** | Small Windows service installed at first Protect; tray → named pipe/service API |

### 8.4 Security bar (must)

- Fixed verbs only; no shell; no arbitrary paths outside DenyOut-owned CA/state.
- Auth: socket only for the installing user’s uid (or equivalent).
- Upgrades replace helper safely in the same release train.
- Failure: fall back to OS password + Problems → “Repair protection”.

### 8.5 Sequencing (D18) — one release, honest copy

**Ship deferred onboarding + helper in the same release** for each platform you claim “no password after restart.”

- Do **not** ship the new install UX with marketing copy that promises password-free restore before the helper works on that OS.
- Roll out OS-by-OS if needed (e.g. Linux first): on platforms without helper yet, keep the new install/mode-choice UX but use confirm copy without the “won’t ask after restart” sentence.
- Do **not** ship “UI-only first” if that forces lying or a reboot surprise password after we already implied there wouldn’t be one.

---

## 9. Test plan (QA)

| # | Case | Expect |
| --- | --- | --- |
| 1 | Fresh desktop install | No pkexec/UAC/osascript during `install.sh` |
| 2 | First open | Mode choice; tray tooltip Off |
| 3 | Protect → Confirm → approve admin | On + helper installed; Your setup; autostart on |
| 4 | Protect → Cancel admin | Mode modal again (setup not done) |
| 5 | Agents → wizard; abandon | My agents empty + Add; no admin |
| 6 | Not now | Off; Your setup; autostart on; **no** later nudge |
| 7 | Reboot with Protect on + helper | Restore **without** password |
| 8 | Off→On from tray later | DenyOut confirm; helper apply (no OS password if helper ok) |
| 9 | Quit while Protect on | Full unload (nothing keeps mediating). Helper remove if possible; **if password required, ask** — never leave rules/proxyd half-alive. Leave-on cleared |
| 10 | Close window before mode choice | Next open shows mode modal again; no autostart yet |
| 11 | CLI tray only | Same three choices via system dialogs |
| 12 | Reinstall healthy Protect | Quiet; no mode modal |
| 13 | Reinstall while Off/broken | Finish setup / mode choice |
| 14 | Advanced → Reset setup | Confirm → first-run modal again |
| 15 | Server mode | No tray / no modal |

Unit: `Install()` state assertions; Bootstrap does not call `restoreProtection` when `!ProtectionOn`; onboarding API marks `SetupDone`.

---

## 10. Rollout

1. Same release: deferred onboarding **+** helper on the OS you ship the “no password after restart” promise for (D18). Linux dogfood first is fine; gate copy per OS.
2. CHANGELOG + install docs in that release.
3. Mark §1 of `07-desktop-ux.md` normative when behavior matches.

---

## 11. Summary checklist (engineering)

| Priority | Work item | Owner area |
| --- | --- | --- |
| P0 | `Install()` Off + open UI; no elevate | `install.go`, `install.sh` |
| P0 | Home + required mode modal; D6/D7/D8/D9/D13/D16 | frontend + `first_run` + `ui_api` |
| P0 | Confirm every Off→On (D5/D12) | frontend + tray |
| P0 | Privileged helper service (D10/D17/D18) | `hostguard` |
| P0 | Quit = full unload; helper first, else OS password (D19) | desktop + hostguard |
| P1 | Upgrade Finish-setup when broken (D11) | desktop |
| P1 | Advanced → Reset setup (D20) | Settings Advanced |
| P1 | Catalog + QA + normative UX §1 | docs |

**Bottom line:** Install never asks; app asks for a mode; Protect asks for a password once when enabling without a helper; helper makes restart restore password-free; Quit always fully unloads (password OK if required); incomplete onboarding resumes.

---

## 12. Product decisions (locked)

### 12.1 From user (2026-11-14)

| ID | Topic | Decision | Notes |
| --- | --- | --- | --- |
| D1 | Right after install | **A** | Auto-open DenyOut |
| D2 | Install terminal | **A** | Exits; app continues |
| D3 | First screen shape | **B** | Home + required mode modal |
| D4 | Recommended choice | **A** | Large Protect computer |
| D5 | DenyOut password confirm | **A** | Always before Off→On |
| D6 | Cancel / failed password | **B** | Back to mode choice (first run) |
| D7 | Protect AI agents | **A** (+ abandon → My agents empty) | Wizard first |
| D8 | Not now | **A** | No reminders |
| D9 | Autostart | **C** | On automatically; mention in Your setup |
| D10 | Password after reboot | **E (required)** | Must **not** ask again — helper (§8) |
| D11 | Update while protected | **C** | Quiet if healthy; Finish setup if Off/broken |
| D12 | Later Off→On | **A** | DenyOut confirm every time |
| D13 | Your setup | **A** | Once, as today |
| D14 | Tray-only fallback | **A** | Same three choices + password rules |
| D15 | Who sees first-run | **A** + **D20** | New install / uninstall; Reset in Advanced |

### 12.2 UX-practice defaults (agent-locked 2026-11-14)

| ID | Topic | Decision | Rationale |
| --- | --- | --- | --- |
| D16 | Close window before choosing | **Resume modal** | Incomplete setup must not silently become Not now; no autostart until a real choice |
| D17 | Helper mechanism | **System helper service** (not passwordless polkit as primary) | Same UX on all OSes; narrower privilege; Quit/Off/restore consistent |
| D18 | Ship order | **Same release** as onboarding for promised OS; gate copy per OS | Never promise password-free restore before it works |
| D19 | Quit while protected | **Confirm unload:** turn off + quit (full unload, password OK if needed) **or** Cancel | Never leave protection on without the tray; never pretend to quit if unload password was cancelled |
| D20 | Reset setup | **Yes, Settings → Advanced**, with confirm | Support/testing escape hatch without cluttering main UI |

### Locked answers (verbatim)

```text
D1: A
D2: A
D3: B
D4: A
D5: A
D6: B
D7: A (abandon wizard → My agents empty + Add)
D8: A
D9: C
D10: E — must not re-prompt after reboot; privileged restore helper required (§8)
D11: C
D12: A
D13: A
D14: A
D15: A (+ D20 Reset setup in Advanced)
D16: resume mode modal (do not treat close as Not now)
D17: system helper service (primary); not passwordless polkit
D18: same release as onboarding for any OS that promises no reboot password
D19: Quit confirms unload vs cancel; unload = full tear-down (password OK if needed); cancel / failed password = stay in tray
D20: Settings → Advanced → Reset setup (confirm)
```

### 12.3 Open questions remaining

**None** for product/UX. Remaining work is implementation detail inside §8.3 (socket protocol, unit file names, code signing), not user-facing choice.
