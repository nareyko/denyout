# Unit `toast-protect` — research & requirements

> **Superseded** by [`notifications-rework-plan.md`](notifications-rework-plan.md).  
> Intentional Protect Off/On success must **not** use OS toasts. Failures may use whitelist `protect_failed`.

## User job

Know Protect state from **Home / tray** (and Problems on failure), without status spam.

## Requirements (historical — partly void)

**Was Must:** success ≈ “You’re protected…” OS toast — **void** (UI only).  
**Still Must:** admin fail ≈ password window story + Open DenyOut → Problems / retry Protect; no “Help & logs”.
