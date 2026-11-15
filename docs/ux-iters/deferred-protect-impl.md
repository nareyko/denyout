# Deferred Protect — detailed implementation & test plan

Companion to [`deferred-protect-onboarding.md`](deferred-protect-onboarding.md) (product lock §12).  
This file is the **engineering checklist**.

---

## 1. Work packages

| WP | Name | Depends | Platforms |
| --- | --- | --- | --- |
| WP0 | Docs / catalog / QA matrix updates | — | — |
| WP1 | Silent install → Off + open UI | — | all |
| WP2 | Onboarding API + Wails mode modal + confirm | WP1 | all (UI) |
| WP3 | Native tray first-run parity + tray confirm | WP2 | all |
| WP4 | Linux hostguard helper (passwordless restore/off/quit) | WP1 | linux first |
| WP5 | Wire Apply/Remove/Quit through helper-first | WP4 | linux; stubs elsewhere |
| WP6 | Autostart on setup complete; Advanced Reset setup | WP2 | all |
| WP7 | Tests + dogfood script | WP1–6 | — |

**Release rule (D18):** claim “no password after restart” only where WP4+WP5 pass.

---

## 2. WP1 — Install user-space

### Code

- `internal/desktop/install.go`
  - State after install: `SetupDone=false`, `ProtectionOn=false`, `ComputerEnabled=false`, `Scope=off`, Safe profile prefs, `Notify=true`, **do not** set autostart until setup completes (D9 happens after choice).
  - Still: `StopPreviousInstances`, `WarnStaleBinariesOnPATH`, `DetachDesktop`.
  - After detach: `RequestOpenUI` equivalent — call into opened process via existing OpenUI or spawn with flag. Practical: DetachDesktop then if sibling desktop, also signal open (Wails may need `--open` or second invocation). Check `denyout-desktop` flags; if none, document that first left-click opens — **prefer** passing env `DENYOUT_OPEN_UI=1` read at startup.
- `install.sh` desktop banner text per onboarding §3.6.
- `cmd/denyout-desktop`: if `DENYOUT_OPEN_UI=1` or `--open`, show window on start even with StartHidden tray mode.

### Tests

- Unit: `TestInstallLeavesProtectionOffAndSetupPending`.
- Manual: `install.sh` / `denyout desktop --install` → no pkexec; window or tray Off.

---

## 3. WP2 — Mode modal + confirm (Wails)

### Backend (`internal/desktop`)

- `UINeedsOnboarding() bool` / expose `setup_done` (already).
- `UICompleteOnboarding(choice string) error` with `computer|agents|notnow`:
  - `computer`: does **not** mark SetupDone until Protect succeeds; returns error on cancel → frontend keeps modal (D6).
  - Flow computer: frontend shows confirm → `UIEnableSafeDesktop` → on success mark setup + autostart + your setup.
  - Simpler split APIs:
    - `UIOnboardingNotNow()`
    - `UIOnboardingAgents()` → setup done Off + autostart + open profiles-new
    - Enable remains `UIEnableSafeDesktop`; on success if `!SetupDone` call `finishOnboardingAfterProtect()`.
- `finishOnboardingAfterProtect` / shared `completeSetupSideEffects()`: `SetupDone=true`, `RegisterAutostart`, `Autostart=true`, `AutostartAsked=true`.
- Skip native `runFirstRunWizard` when `opts.OpenUI != nil` (Wails).

### Frontend

- `App.tsx`: if `!snap.setup_done` → mode modal (required; backdrop not dismissible; Esc ignored for dismiss).
- Confirm modal before `enableSafe` (Home + onboarding + Problems retry).
- Copy from onboarding plan §7.
- Agents: call onboarding agents → navigate profiles-new; if user closes wizard without create → Profiles empty (existing empty state).

### Tests

- Frontend: manual / smoke.
- Go: `TestCompleteOnboardingNotNowRegistersAutostart`, `TestEnableSafeMarksSetupDone`.

---

## 4. WP3 — Native fallback + tray

- Update `nativeFirstRunChoice` copy (password footnote).
- Tray Protect computer: native confirm (zenity/kdialog/osascript) before `enableSafeDesktop` (D5/D12).
- Quit: see WP5 (must complete unload).

---

## 5. WP4 — Linux helper

### Design

- Subcommand: `denyout hostctl helper-serve` (root) listens on `/run/denyout-hostguard.sock` (0600 root; accept only uid in request + peercred).
- `denyout hostctl helper-install` (elevated once): install systemd unit `denyout-hostguard.service`, enable --now, copy/link binary path.
- Client: `hostguard.HelperApply/Remove/Teardown` dials socket; verbs `apply|remove|teardown` + port/ca/uid JSON.
- `ElevateApply`: try Helper first; on failure fall back to pkexec; after successful pkexec Apply, best-effort `helper-install` in same elevate by appending to elevated argv or second elevated call.

### macOS / Windows

- Stubs: `HelperAvailable() == false`; restore still uses OS password; UI omits “won’t ask after restart” when `helper_ok` false in snapshot.

### Tests

- Unit with fake socket (optional).
- Integration: root-only / manual dogfood.

---

## 6. WP5 — Wire helper + Quit

- `startComputer` / `stopComputerOpts` / `quitUnload`: helper-first.
- `quitUnload`: if remove fails and needs password → elevate; if user cancels → **do not** exit tray (return error to tray callback).
- Snapshot field `helper_ok` for UI copy.

---

## 7. WP6 — Reset setup

- Settings Advanced: “Reset setup…” confirm → clear `SetupDone`, `YourSetupShown`, turn Off if needed, show mode modal again.
- API: `UIResetSetup()`.

---

## 8. Test matrix (must pass before release claim)

| ID | Case | Expect |
| --- | --- | --- |
| T1 | Fresh `--install` | No elevation; `setup_done=false`; protection off |
| T2 | Open app | Mode modal on Home |
| T3 | Close window without choice | Modal again next open; no autostart unit yet |
| T4 | Not now | Setup done; autostart on; Your setup; no Protect |
| T5 | Agents | Wizard; no elevation |
| T6 | Protect → Cancel confirm | Still onboarding |
| T7 | Protect → Cancel OS password | Mode modal again |
| T8 | Protect → Approve | On + helper (linux); Your setup; autostart |
| T9 | Reboot (linux+helper) | Restore without password |
| T10 | Off→On later | DenyOut confirm; helper apply |
| T11 | Quit while on | Full unload; password if needed; cancel keeps running |
| T12 | Reset setup | Modal returns |
| T13 | Upgrade healthy | No mode modal |
| T14 | `go test ./internal/desktop/ ./internal/hostguard/` | Pass |

---

## 9. Suggested commit slices

1. WP1 install + open flag  
2. WP2 onboarding API + modal + confirm  
3. WP3 tray confirm + native copy  
4. WP4+WP5 helper linux + quit  
5. WP6 reset + docs/QA  

---

## 10. Implementation status

Tracked in this session:

- [x] WP1 — Install Off + open UI (`install.go`, `install.sh`, `--open`)
- [x] WP2 — Mode modal + confirm + onboarding APIs (Wails App/Home)
- [x] WP3 — Tray Protect confirm + Quit cancel-safe + native first-run copy
- [x] WP4 — Linux helper-serve + InstallHelper on first elevated apply
- [x] WP5 — Elevate* helper-first; Quit returns error if unload fails
- [x] WP6 — Autostart on setup complete; Settings → Reset setup
- [x] WP7 — `go test ./internal/desktop/ ./internal/hostguard/` green

**Follow-ups:** rebuild `denyout-desktop` frontend dist for release; dogfood T8–T11 with real pkexec; macOS/Windows helper still stub (`HelperAvailable=false`).
