# Public app update manifest

DenyOut desktop can check for a newer **program** version without an account.

## Endpoint

Default URL: `https://denyout.com/updates/desktop.json` 
(Hosted by the private denyout.com web deploy - not this repo.)

Example shape: [`desktop.example.json`](desktop.example.json).

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Semver-like string (e.g. `0.3.0`) |
| `url` | yes | Release page or download URL |
| `channel` | no | `stable` / `beta` |
| `notes` | no | Short plain-language notes |
| `published_at` | no | RFC3339 |

## Client

Go package: `internal/updates`.

- **No** `Authorization` header; registration is never required for this check.
- **Fail-open:** network/HTTP/parse errors return `ErrUnavailable`. Protect and local settings keep working; UI must not block on a failed check.
- Local `dev` / empty versions never report "newer".

## Desktop UI

- **Settings -> Diagnostics -> Check for updates** (manual). 
- Non-blocking tip on **Home** / **Problems** when a newer version was last detected. 
- Copy never asks to sign in for updates.
