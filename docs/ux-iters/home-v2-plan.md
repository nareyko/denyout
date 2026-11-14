# Plan: Home v2 UX alignment

Normative: [`home.md`](home.md). Goal: Home is the only primary surface; other screens stay additional. Implement → test → visual QA.

## Gaps vs current UI

| Req | Gap | Status |
| --- | --- | --- |
| H2/H8/S1 | Agents-only headline | Fixed |
| H7 | Empty “— that is OK.” | Fixed |
| H4 support | Needs-help copy | Fixed |
| S2 | `Blocked today: N` | Fixed |
| S3 | Home footer doors | Fixed |
| Layout | Compact chrome + History empty without empty drawer | Fixed |

## Workstreams

### A — Home composition (frontend)

1. Rewrite status copy matrix to v2 (incl. agents → “Protection isn’t set for everyday browsing”).
2. Empty story: **Nothing blocked yet — that is OK.**
3. Footer: muted text links Settings · For AI tools.
4. Quiet line: `Blocked today: N` when N > 0 (hide when 0 to stay calm).
5. Wire `onOpenSettings` / `onOpenAgents` from App.
6. CSS: footer links, keep one-composition hero (no widget grid).

### B — Snapshot field (Go)

1. Add `blocked_today int` to `UISnapshot` (count audit denials with today’s date).
2. Unit test for counter helper.
3. Expose in frontend `UISnapshot` type.

### C — Additional screens (light polish only)

1. History empty already calm — leave.
2. Top bar on Home: keep Protected pill; no new chrome clutter.
3. Do not re-promote My agents / Jump.

### D — Docs + preview

1. Update `ux-preview-home.html` for all 4 states + footer + blocked today.
2. Tracker note: Home v2 implement Done.

### E — Verify

1. `npm run build`
2. `go test ./internal/desktop/`
3. Visual: Vite preview snapshots (protected / off / last-block / needs-help / agents)

## Out of scope

HITL timing, tray expansion, Pi-hole charts, commit/PR.

## Status

| Stream | Status |
| --- | --- |
| A Home composition | Done |
| B blocked_today | Done |
| C additional polish | Done (no re-promote) |
| D preview/docs | Done |
| E verify | Done — `npm run build`, `go test ./internal/desktop`, visual preview states |
| F compact layout pass | Done — narrower nav, quieter topbar, tighter Home/cards/History/drawer, mobile nav fix |
| G layout bugfix | Done — History empty without drawer; Problems healthy CTAs; denser card type |
| H re-audit polish | Done — Profiles empty card; shorter Settings find; History Refresh kept (list reload) |
