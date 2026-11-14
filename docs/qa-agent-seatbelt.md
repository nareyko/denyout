# QA checklist — Agent seatbelt (0.1.9)

Manual e2e after install / upgrade on a desktop machine with Computer or Session on.

| # | Step | Expect |
| --- | --- | --- |
| 1 | `curl -I https://api.anthropic.com` (via protected path) | Allow (or upstream 401/403 — not DenyOut deny) |
| 2 | Browse `https://example.com` | Deny `host_not_allowed` or Ask dialog (if Ask on) |
| 3 | `install.sh` / GitHub release-asset download | Completes; no audit deny `secret_in_url` for `release-assets.githubusercontent.com` signed URL |
| 4 | Request with `?api_key=sk-…` on allowlisted host | Deny `secret_in_url` |
| 5 | Ask → Always allow for a host, retry | Allow |
| 6 | Activity → enable Browse profile, retry `example.com` | Allow (legacy blocklist) |
| 7 | Activity denials / audit.jsonl | Events include `policy_profile=agent` (or `browse`); filter by reason works |
| 8 | Follow HTTP redirect from allowlisted hop1 to evil hop2 | Location stripped / hop2 denied |

Automated:

```bash
denyout test --suite fp_signed
denyout test --suite agent_egress
denyout test --suite redirect_policy
denyout test
go test ./internal/secrets/ ./internal/policy/ ./internal/lab/ ./internal/proxy/ ./internal/audit/
```
