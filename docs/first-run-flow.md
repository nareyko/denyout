# First-run flow

This page maps the first-run steps, which of them are consent and which are
convenience, and what the shortened flow looks like. Code: `internal/desktop/first_run.go`,
`onboarding_ui.go`, `setup_state.go`, `first_run_hooks.go`; UI: `cmd/denyout/frontend/src/App.tsx`.

## Rules that did not change

- Consent steps stay explicit: choosing Protect computer (what it changes: helper,
  certificate), the system password / elevation prompt, and the login-launch question.
  Steps may be merged into fewer screens, never defaulted on.
- "Not now" installs nothing: no helper, no certificate, no network rules, no login entry.
- Login launch is only ever turned on by an explicit Yes (checkbox or dialog button).
  With no dialog toolkit to ask, the answer is No.

## Before (windowed app, Wails)

| # | Screen | Kind |
|---|--------|------|
| 1 | Mode chooser: Protect computer / Protect AI agents / Not now, plus a "how chatty" question | Consent (the choice) plus convenience (chatty) |
| 2 | "Turn on Protect computer?" confirm modal (helper + certificate wording) | Consent |
| - | System password prompt (OS) | Consent (OS-owned) |
| 3 | "Your setup" modal with the self-check | Convenience / verification |

Autostart: left Off, only reachable in Settings. Not now also showed "Your setup" (4th screen on that path).
Counts: Protect computer 3 screens + password; Not now 2 screens.

## Before (native dialogs: zenity / kdialog / osascript)

| # | Dialog | Kind |
|---|--------|------|
| 1 | Choice dialog | Consent |
| - | System password prompt | Consent (OS-owned) |
| 2 | "Start at login?" | Consent |
| 3 | "Your setup" info dialog (Open DenyOut / Got it) | Convenience |

Windows had no native dialog and fell back to Not now.
Counts: 3 dialogs + password, on every path including Not now.

## After (windowed app)

| # | Screen | Kind |
|---|--------|------|
| 1 | One chooser. Choosing Protect computer expands, in place, a plain list of what changes (helper, certificate, stays local) with a single "Turn on Protect computer" button. That button is the combined consent. | Consent |
| - | System password prompt (OS) | Consent (OS-owned) |
| 2 | Final screen: "Protected and verified" from the self-check, each problem with a Fix button, and one optional checkbox "Start DenyOut when I log in" (unchecked) | Verification plus consent for autostart |

- The "how chatty" question left the first run (default Quiet, Settings keeps it).
- Not now: chooser only (1 screen). No final screen, nothing to verify.
- Protect AI agents: chooser, then the existing final screen, then New agent.
- Counts: Protect computer 2 screens + password (was 3); Not now 1 screen (was 2).

## After (native dialogs)

| # | Dialog | Kind |
|---|--------|------|
| 1 | Choice dialog. The text lists what Protect computer changes (helper, certificate, password) and says Not now installs nothing. | Consent |
| - | System password prompt | Consent (OS-owned) |
| 2 | One closing dialog: result, self-check summary (problems listed, fix in Problems), and the optional "Start at login" question | Verification plus consent for autostart |

- Not now: the choice dialog only (1 dialog, was 3). Autostart is recorded as asked and Off.
- Windows now uses a PowerShell Yes / No / Cancel box (Yes = Protect computer, No = Protect AI agents, Cancel = Not now).
- Counts: 2 dialogs + password (was 3 + password).

## Persisted state per outcome

| Outcome | SetupDone | ProtectionOn / ComputerEnabled | Scope | AutostartAsked | Autostart | YourSetupShown |
|---------|-----------|--------------------------------|-------|----------------|-----------|----------------|
| Protect computer, success (native) | true | true / true | computer | true | answer | true |
| Protect computer, success (windowed) | true | true / true | computer | true | false until the checkbox | false until the final screen is dismissed |
| Protect computer, password cancelled (windowed) | false (setup stays pending) | false / false | off | false | false | false |
| Protect computer, failed (native) | true | false / false | off | true | answer | true |
| Protect AI agents | true | false / false | off | true | answer (native) / false (windowed) | as above |
| Not now | true | false / false | off | true | false | true |

`NotNowAt` is set on Not now. Tests: `internal/desktop/first_run_flow_test.go`.
