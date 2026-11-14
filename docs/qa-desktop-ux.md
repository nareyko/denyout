# QA — Desktop UX (Safe desktop, profiles, wrap, learning, srt)

Success sentence:

> Ordinary day: Protect computer does not get in the way; agent/python runs under a profile with rare clear Ask; whole-PC Agents only cannot be turned on by accident; no morning silent Session surprise.

## Automated

```bash
go test ./internal/desktop/ ./internal/run/ ./internal/notify/
go test ./internal/policy/ ./internal/secrets/ ./internal/proxy/ ./internal/audit/
```

Expect: Safe desktop default (`browse`, Ask off); profile Pin/Discard; `WrapSandbox` fail-closed when `srt` missing; secret copy mentions “Blocked a link…”.

## Manual matrix (rounds 1–6)

| # | Path | Expect |
| --- | --- | --- |
| 1 | Fresh first-run → Protect computer | Safe desktop; web/Telegram OK; rare secret toast only |
| 2 | First-run → Protect AI agents | Wizard saves profile; Start wrap; Ask toast→dialog; default Keep blocked |
| 3 | First-run → Not now | Off; one soft nudge later (not hourly) |
| 4 | Tray → Agents only (whole PC) | Confirm default Keep Safe desktop; messengers warning |
| 5 | Admin deny / restore fail | Stays Off; no Session; toast + Help & logs |
| 6 | Legacy Session in state | Cleared on restore; toast |
| 7 | Upgrade from Agents-only default | Migration dialog → Safe desktop or keep |
| 8 | My agents Edit while running | Stop, save, start again? |
| 9 | Stop one agent / many | No confirm if one; confirm if many |
| 10 | Learning Once → Pin | Counter; Pin all → learning off; Discard |
| 11 | Ask timeout ~2 min | Keep blocked + timed-out toast |
| 12 | Ask storm | Pause asks offer; Resume asks menu |
| 13 | Quit tray | Protect stays preferred; wraps may prompt leftovers on next start |
| 14 | Off vs Stop | Off ≠ stop wraps |
| 15 | `--sandbox=srt` without binary | Fail closed error |
| 16 | Wrap without srt | Runs + residual stderr line |
| 17 | Headless / no zenity | No TTY wizard; CLI / Not now path |
| 18 | Secret block copy | “Blocked a link that looked like it contained a secret” |

## Cut order (if forced)

1. First-run + Safe default + hide Session + intentional Agents-only  
2. Profiles + wrap + same Ask  
3. Learning Pin + counter  
4. Real srt  
