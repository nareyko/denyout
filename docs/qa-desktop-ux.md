# QA - Desktop UX (Safe desktop, Wails shell, HITL, profiles)

Normative surface inventory: [`07-desktop-ux.md`](07-desktop-ux.md).

Success sentence:

> Everyday Safe use stays calm. Window opens when needed. My agents naming is consistent. Advanced holds dangerous/power tools. Tips appear one layer at a time.

## Automated

```bash
go test ./internal/desktop/ ./internal/run/ ./internal/notify/
cd cmd/denyout-desktop/frontend && npm ci && npm run build
CGO_ENABLED=1 go build -tags 'wails webkit2_41' -o denyout-desktop ./cmd/denyout-desktop
```

**Last run (2026-11-14 evening):** `go test ./internal/desktop/ ./internal/notify/ ./internal/run/` PASS - frontend build PASS - Wails binary -> `~/.local/bin/denyout-desktop`.

## Threat lists / packs (TL)

Normative: [`ux-iters/threat-lists-plan.md`](ux-iters/threat-lists-plan.md). 
Evidence matrix (TL1-TL8, M1-M8): [`ux-iters/threat-lists-qa.md`](ux-iters/threat-lists-qa.md).

```bash
go test ./internal/threatlists/ ./internal/policy/ ./internal/desktop/ ./internal/notify/
```

**Last run (2026-11-14):** TL1-TL8 unit **PASS**. M1-M8 code **PASS**. Live Protect dogfood **PENDING** user.

## Notifications / HITL rework (NF)

Normative: [`ux-iters/notifications-rework-plan.md`](ux-iters/notifications-rework-plan.md).

| ID | Check | Result (2026-11-14) |
| --- | --- | --- |
| T1 | Timeout / Decide later ≠ Keep | **PASS** unit `TestTimeoutDoesNotRememberKeep` / `TestNF_*` |
| T2-T3 | Keep + Quiet suppress keep-repeat | **PASS** code + `TestQuietBlocksKeepRepeat` |
| T4-T5 | Timed allow/deny + pause resume EmitAction | **PASS** unit + `timed.go` / `EmitAction` |
| T6-T8 | Whitelist / Ask no teaser / batch ≥2 | **PASS** unit + Ask dialog-only |
| M1-M2 | Compact dialog / in-app modal | **PASS** code (`PresentDecisionNative` / Wails `decision` event). **DE:** zenity+notify-send present. Live Protect block not exercised in agent |
| M3-M8 | later / Keep / Allow / timed | **PASS** unit `applyHardBlockDecision` |
| M9-M11 | Agents secret + Ask | **PASS** code (`handlePostBlockDeny`. No Ask teaser) |
| M12-M14 | Pause Off / resume Undo / fail | **PASS** code (`chooseProtectPause`, `EmitAction` Undo, `KindProtectFailed`) |
| M15-M18 | Quiet / interval / tray / Open | **PASS** code (Settings levels, tray labels, DecisionOpen->activity) |
| Live DE click-through | Full Protect On -> real secret URL | **PENDING** user dogfood (agent has no elevated Protect session) |

## Manual / evidence matrix

| # | Path | Expect | Result (2026-11-14) |
| --- | --- | --- | --- |
| 1 | Silent install -> Your setup | **Open DenyOut** + **Got it**. Window not forced every login | **PASS** (code: Wails modal + native `Open DenyOut`/`Got it`. SkipNativeYourSetup on desktop) |
| 2 | Left-click tray | Activity. Right-click ≤6 menu items | **PASS** code (`OnClick`->activity. Compact menu). **DE re-check:** some Linux trays may open menu on left-click (documented caveat) |
| 3 | Tray My agents... (Wails) | Opens **My agents** screen | **PASS** (`RequestOpenUI("profiles")`) |
| 4 | Nav label | **My agents** | **PASS** |
| 5 | Onboarding | Checklist -> glossary -> screen tip. Never stacked with Your setup | **PASS** (`showChecklist` / `showGlossary` / `tipsEnabled`) |
| 6 | Activity | No checkboxes until **Select...**. Group by host under Filters. Human reason labels | **PASS** |
| 7 | Settings Basic | No Agents only. Protect / Off / notify / autostart | **PASS** |
| 8 | Settings Advanced | Agents only warn + lists + Test. Find a setting... | **PASS** |
| 9 | Unhealthy | Top bar "Needs attention - open Problems" + badge | **PASS** |
| 10 | Empty Activity | "Nothing blocked yet" + Test protection CTA | **PASS** |
| 11 | Drawer | **Allow this site** | **PASS** |
| 12 | Ctrl+K | Always allow / Keeps / Agents only jumps | **PASS** |

Static evidence script: 18/18 checks against source. Interactive toast/elevation/live tray click on a physical DE was **not** exercised in this agent environment - re-verify #2 left-click on target desktop if needed.

## Cut order

1. UX2-A...C - done 
2. UX3-A docs sync - done 
3. UX3-B reason labels - done 
4. UX3-C QA evidence - this file
