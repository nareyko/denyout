# QA evidence - Threat lists, packs & precedence

**Plan:** [`threat-lists-plan.md`](threat-lists-plan.md) 
**Date:** 2026-11-14

## Automated gates

```bash
go test ./internal/...
cd cmd/denyout-desktop/frontend && npm run build
CGO_ENABLED=1 go build -tags 'wails webkit2_41' -o /tmp/denyout-desktop-wave ./cmd/denyout-desktop
go build -o /tmp/denyout-cli-wave ./cmd/denyout
```

**Last run (LF, 2026-11-14):** `go test ./internal/...` PASS - frontend build PASS - Wails + CLI build PASS. 
TL1-TL8 unit re-verified verbose PASS. M1-M8 remain code PASS. Live Protect dogfood still **PENDING** user (not blocking LF).

## Automated matrix (TL*)

| ID | Assert | Evidence | Result |
| --- | --- | --- | --- |
| TL1 | User Allow beats threat list | `TestUserAlwaysBeatsThreatList`, `TestUserOnceBeatsThreatList` | **PASS** |
| TL2 | Unbreak beats threat. Scanner still denies | `TestUnbreakBeatsThreatList`, `TestUnbreakDoesNotBypassScanner` | **PASS** |
| TL3 | Parse domains + hosts + ABP | `TestParseDomainsHostsABP` | **PASS** |
| TL4 | Bad fetch keeps cache | `TestBadFetchKeepsPreviousCache` | **PASS** |
| TL5 | Undersized fetch rejected | `TestUndersizedFetchRejected` | **PASS** |
| TL6 | Disabled feed -> no deny | `TestDisabledFeedNotInContains` | **PASS** |
| TL7 | Pack merge idempotent + Undo | `TestApplyPackIdempotentAndUndo`, `TestApplyPackDoesNotClaimPreexisting` | **PASS** |
| TL8 | Agent default-deny unknown | `TestWholeDeviceAgentDeniesUnknownAllowsModels` (unchanged) | **PASS** |

Related: pack allow does **not** beat threat (`TestPackAllowDoesNotBeatThreatList`). URLhaus inactive until first OK (`TestURLHausInactiveUntilFirstOK`).

## Manual matrix (M*)

| ID | Scenario | Result (2026-11-14) |
| --- | --- | --- |
| M1 | Phishing ON -> listed domain -> decision dialog | **PASS** code (`threat_list` in clear post-block. HITL path). Live Protect dogfood **PENDING** user |
| M2 | Allow site -> same domain passes | **PASS** code (Book B Always skips Book C) |
| M3 | URLhaus ON/OFF | **PASS** code (`UISetBlockMalware` + `Contains` Active) |
| M4 | Stronger OFF->ON + warning + count | **PASS** code/UI (nested checkbox + confirm. Settings feed row) |
| M5 | Refresh now + offline cache | **PASS** unit (cache keep) + `UIRefreshThreatLists` |
| M6 | Cursor pack -> hosts on profile | **PASS** unit + My agents UI / wizard ask |
| M7 | Browse normal sites with defaults ON | **PASS** code (blocklist + threat only on listed hosts) |
| M8 | Agents Ask for new host unchanged | **PASS** code (`host_not_allowed` Ask path separate from threat post-block) |

## Docs synced (L8)

- [`04-policy-engine.md`](../04-policy-engine.md) - Books A-D + `threat_list` (L0) 
- [`07-desktop-ux.md`](../07-desktop-ux.md) - Settings Threat lists / Advanced optional / My agents packs 
- [`qa-desktop-ux.md`](../qa-desktop-ux.md) - pointer to this file 
- [`CHANGELOG.md`](../../CHANGELOG.md) - Unreleased threat lists / packs 

## Not claimed

- Live elevated Protect session click-through on a physical DE (user dogfood). 
- Custom list URL (deferred Q10). 
- Telemetry category UI (hidden). 
- HaGeZi **full** TIF.
