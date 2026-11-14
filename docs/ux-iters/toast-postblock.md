# Unit `toast-postblock` — research & requirements

> **Superseded** by [`notifications-rework-plan.md`](notifications-rework-plan.md) (2026-11-14 HITL rework).  
> Do not implement against the Must/Must-not below when they conflict with that plan.

## User job

After a hard block, decide Keep / Allow (forever or timed) or Decide later — via **compact decision dialog** (not GNOME `notify-send` action banners).

## Legacy notes (obsolete)

~~Body Host:/Why: labels; quiet re-block → Activity; follow-up “Always allow: host”.~~

## Requirements (historical — see plan §0 / §3)

**Was Must:** human body; Keep / Allow; follow-ups; quiet toast → History.

**Was Must not:** change 15s timeout or HITL policy — **void**: plan changes timeout semantics (no Keep on timeout), primary surface = dialog, timed rules, throttle interval.
