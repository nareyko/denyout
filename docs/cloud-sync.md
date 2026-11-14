# Cloud settings sync (optional account)

Signed-in users may sync a **settings document** across machines. Protect and local settings work **without** an account.

API (interim): private HQ `services/denyout-api` -> later private denyout.com web repo / `api.denyout.com`.

## Document shape

Go types: `internal/cloudsync`. Desktop map: `ExportSyncDocument` / `ApplySyncSettings` in `internal/desktop`.

| Field | Sync? |
| --- | --- |
| `schema_version` | yes (currently `1`) |
| `updated_at` | yes (last-write-wins) |
| `settings.notify_level` | yes |
| `settings.decision_timeout_sec` / `reask_interval_sec` | yes |
| `settings.always_allow_hosts` | yes |
| `settings.remembered_keeps` / `remembered_signal_allows` | yes (keys only) |
| `settings.block_phishing` / `block_malware` / `block_stronger` / `threat_poll_hours` | yes (toggles only, not feed files) |
| `settings.sensitive_*` / `body_pure_a` / `anti_chunk_enabled` | yes |
| `settings.applied_pack_ids` | yes (ids only) |
| Audit JSONL, raw secret URLs, canaries, wrap secrets, account tokens | **never** |

Example blob:

```json
{
 "schema_version": 1,
 "updated_at": "2026-11-14T12:00:00Z",
 "settings": {
 "notify_level": "normal",
 "always_allow_hosts": ["api.openai.com"],
 "block_phishing": true,
 "block_malware": true
 }
}
```

## Account UI

**Settings -> Advanced -> Account:** email one-time code sign-in / sign out / **Sync now** / **Delete cloud data**. 
Trust line: works fully without an account. Protect is never gated on login. 
**Delete cloud data** removes the server account + synced blob, then signs out locally. Protect settings on disk stay.

## Sync now

When signed in and **Sync settings** is on, **Sync now** pulls the cloud document, applies last-write-wins by `updated_at`, then pushes if local is newer (or cloud is empty).

Signed out or sync off -> **local only** (no upload).
