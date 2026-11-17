# Configuration reference (single source)

Every place DenyOut reads configuration from, in one page. The policy-file
format itself is specified in [D11 - Config reference](11-config-reference.md);
cloud sync in [cloud-sync.md](cloud-sync.md). Typed settings live in
`internal/settings`; a test fails if a setting or a `DENYOUT_*` variable used in
the tree is missing from this page.

Inspect your effective values (secrets redacted, source of each value shown):

```
denyout-cli config show [--json]
denyout-cli policy check <file>          # validate a policy YAML with line context
denyout-cli profile export <id> <file>
denyout-cli profile import [--force] <id> <file>
```

## 1. Sources and precedence

| Source | Where | Notes |
| --- | --- | --- |
| Policy YAML | `--config`, `denyout.yaml`, built-in presets | Validated against `schemas/denyout-config.v1.json` (fail closed). Section 4. |
| Desktop state file | `~/.config/denyout/desktop.json` (0600) | Versioned (`schema_version`, section 2). Written atomically. |
| Agent profiles | `~/.config/denyout/profiles/<id>.yaml` | Section 5. |
| Environment | `DENYOUT_*` | Section 3. Overrides the state file. |
| CLI flags | per command | Override everything for that run. |
| Cloud sync | optional account | Writes a subset of the state file; section 6. |

Precedence for a setting: **flag > env > state file > default**. Two documented
exceptions keep legacy behaviour (an explicit state value wins over env):
`update_manifest_url` and `account_api_base`. Env switches for experimental
gates (`DENYOUT_TUN_E2E`, `DENYOUT_QUIC_MITM`) can only switch a feature **on**,
never off.

Settings that weaken inspection (`allow_private`, `tls_insecure_upstream`) are
**environment only**: they are not read from the state file, so neither a synced
nor a tampered state file can enable them.

## 2. State file and schema version

`desktop.json` carries `schema_version` (current: **1**). Files without it are
version 0 (written by older builds) and are migrated on read in
`internal/appstate/migrate.go`: legacy defaults are applied in memory and the
file is rewritten at the next save. A file with a *newer* version than the
binary knows is loaded as-is and never downgraded. Adding a migration: bump
`CurrentSchemaVersion`, add a step, add a fixture under
`internal/appstate/testdata`.

### 2.1 Settings (typed, in `internal/settings`)

| Key | Type | Default | State key | Env | Flag | Security note |
| --- | --- | --- | --- | --- | --- | --- |
| `notify_level` | string | `quiet` | `notify_level` | | | quiet / normal / detailed |
| `decision_timeout_sec` | int | 15 | yes | | | 1-3600 |
| `reask_interval_sec` | int | 60 | yes | | | 1-86400 |
| `policy_profile` | string | `browse` | yes | `DENYOUT_POLICY_PROFILE` | | `agent` = default-deny |
| `ask_mode` | bool | false | yes | | `--ask` (proxyd) | |
| `allow_browser_quic` | bool | false | yes | | | true lets HTTP/3 bypass interception |
| `tun_dataplane` | bool | false | yes | `DENYOUT_TUN_E2E` (enable only) | | experimental |
| `quic_mitm` | bool | false | yes | `DENYOUT_QUIC_MITM` (enable only) | | experimental |
| `body_pure_a` | bool | false | yes | none | | sync can raise, never lower |
| `anti_chunk_enabled` | bool | false | yes | none | | sync can raise, never lower |
| `sensitive_sinks_enabled` | bool | true | yes | | | absent = on |
| `sensitive_writes_enabled` | bool | true | yes | | | absent = on |
| `always_allow_hosts` | list | empty | yes | | | plain DNS names only when synced |
| `update_manifest_url` | string | built-in | yes | `DENYOUT_UPDATE_MANIFEST_URL` | | https only; state wins |
| `account_api_base` | string | built-in | yes | `DENYOUT_API_BASE` | | https only; state wins |
| `account_email` | string | empty | yes | | | redacted in output |
| `account_token` | string | empty | yes | | | never synced, never printed |
| `custom_command` | string | empty | yes | | | may embed credentials; redacted |
| `allow_private` | bool | false | no | `DENYOUT_ALLOW_PRIVATE` | | env only; opens SSRF paths to the LAN |
| `tls_insecure_upstream` | bool | false | no | `DENYOUT_TLS_INSECURE_UPSTREAM` | | env only; lab use |
| `always_allow_env` | list | empty | no | `DENYOUT_ALWAYS_ALLOW` | | env only; set by the desktop for the root helper |
| `fail_closed` | bool | false | no | `DENYOUT_FAIL_CLOSED` (`1`) | | tightens only |
| `kill` | bool | false | no | `DENYOUT_KILL` | | refuses `serve`; tightens only |

Validation (`settings.Validate`, shown by `config show`): enum values, numeric
ranges, https for URLs, RFC3339 timestamps, host shape of `always_allow_hosts`.
The app tolerates and clamps bad values; the check only reports them.

### 2.2 Other state-file fields (UI-managed, not user settings)

Written by the desktop app; edit through the UI. `setup_done`, `notify`,
`scope`, `protection_on`, `computer_enabled`, `computer_available`, `autostart`,
`autostart_asked`, `ux_v2_migrated`, `active_profile_id`, `preferred_agent`,
`quiet_*_off` / `respect_fullscreen_off` / `silent_when_open_off` /
`sound_only_answer_off` / `system_banners_off` (notification etiquette),
`notify_snooze_until`, `ask_paused_until`, `protect_paused_until`,
`protect_pause_last`, `timed_allows` / `timed_denies`, `remembered_keeps`,
`remembered_signal_allows`, `away_unread_*`, `wrap_pids`, `last_deny_*`,
`not_now_*`, `post_block_taught`, `your_setup_shown`, `pending_your_setup`,
`dismissed_tips`, `update_available_*`, `update_checked_at`,
`config_updated_at`, `sync_enabled`, `sync_enabled_set`.

Extension point: new boolean/enum settings (for example a fail-soft policy
switch) are added as one `State` field plus one entry in `settings.Specs`; the
docs test then forces a row here.

## 3. Environment variables

User-facing (resolved by `internal/settings`): see the Env column above.
Everything else:

| Variable | Read by | Purpose | Security note |
| --- | --- | --- | --- |
| `DENYOUT_NOTIFY` | `denyout-cli run` | `0` suppresses CLI notifications | |
| `DENYOUT_DESKTOP_NOTIFY` | `denyout-cli run` | `1` also raises desktop notifications | |
| `DENYOUT_OPEN_UI` | desktop | `1` opens the window at start | |
| `DENYOUT_DETACHED` | desktop | internal re-exec marker | |
| `DENYOUT_TUN_E2E` | tun gate | enables experimental TUN data plane | experimental |
| `DENYOUT_QUIC_MITM` | tun gate | enables experimental HTTP/3 decryption | experimental |
| `DENYOUT_VPN_EGRESS_E2E` | tun gate | VPN-egress lab path | lab only |
| `DENYOUT_FAIL_POLICY` | helper watchdog | `open` | `closed`: proxy-loss behaviour (`DENYOUT_FAIL_CLOSED=1` always wins) | `closed` blocks HTTPS while the proxy is down |
| `DENYOUT_DEBUG_STATS` | denyout-cli proxyd | `1` prints goroutine/fd counts on SIGUSR1 (soak test) | diagnostics only |
| `DENYOUT_TEST_NO_ELEVATE` | hostguard | tests never prompt for elevation | tests only |
| `DENYOUT_UNINSTALL_NO_ELEVATE` | uninstall | skip elevated uninstall step | |
| `DENYOUT_INSTALL_DIR` | reinstall, `install.sh` | install directory | |
| `DENYOUT_VERIFY_SIG` | `install.sh` | `auto` / `require` / `skip` | `skip` disables cosign verification |
| `DENYOUT_BASE_URL` | `install.sh` | release base URL (validated) | https only |
| `DENYOUT_VERSION` | `install.sh` | pin a release tag (validated) | |
| `DENYOUT_INSTALL_MODE` | `install.sh` | install mode | |
| `DENYOUT_REPO` | `install.sh` | GitHub repo slug | |
| `DENYOUT_NO_DESKTOP` | `install.sh` | skip desktop app | |
| `DENYOUT_INSTALL_PROMPT` | `install.sh` | control the prompt | |
| `DENYOUT_INSTALL_OPEN` | `install.sh` | open app after install | |
| `DENYOUT_BIN`, `DENYOUT_G6LAB_BIN` | scripts/tests | binary under test | tests only |
| `DENYOUT_LAB_IP`, `DENYOUT_DOGFOOD_IMAGE` | scripts/lab | lab addressing and image | lab only |
| `DENYOUT_E2E`, `DENYOUT_E2E_SKIP_ELEVATE` | scripts/tests | e2e switches | tests only |
| `DENYOUT_FETCH_RETRIES`, `DENYOUT_FETCH_RETRY_SECS` | scripts/tests | lab retries | lab only |
| `DENYOUT_ALLOW_INSECURE_OVERRIDE` | scripts/tests | lab override of safety checks | never set in production |
| `DENYOUT_CA_CERT` | desktop session env file | output only: session CA path for child tools | |
| `DENYOUT_PROXY`, `DENYOUT_CACERT`, `DENYOUT_SNI`, `DENYOUT_SESSION_ID`, `DENYOUT_CONFIG`, `DENYOUT_MODE`, `DENYOUT_TLS_MODE`, `DENYOUT_LISTEN_PORT`, `DENYOUT_PROFILE_ID` | lab scripts | lab client parameters | lab only |

Also honoured (not `DENYOUT_*`): `XDG_CONFIG_HOME`, `XDG_STATE_HOME`,
`XDG_DATA_HOME`, `XDG_CACHE_HOME` (file locations), `SystemRoot`,
`ProgramData`, `LOCALAPPDATA` (Windows paths).

## 4. Policy YAML (`denyout/v1`)

Loaded by `policy.LoadFile`; validated by `denyout-cli policy check <file>`
(same code path, reports every schema problem with its line, exit 2 on any
problem). Authoritative schema: `schemas/denyout-config.v1.json`.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `apiVersion` | string | required | must be `denyout/v1` |
| `kind` | string | required | must be `Config` |
| `mode` | enum | `enforce` | `enforce` / `audit` / `blocklist` / `ask` |
| `preset` | enum | | `models` / `models+pkg` / `strict` / `none` / `dev` / `agent` |
| `allow`, `deny` | list of `{host, reason}` | empty | host patterns |
| `allow_private` | bool | false | allows RFC1918/loopback targets; security-relevant |
| `allow_ip_literals` | bool | false | |
| `deny_on_dns_failure` | bool | true | |
| `insecure_allow_all` | bool | false | disables enforcement; audit-style |
| `allowed_ports` | int list | `[443, 80]` | |
| `limits.per_host_rpm`, `limits.global_rpm` | int | 0 (off) | |
| `audit.jsonl_path`, `audit.stdout` | string / bool | | |
| `tls.mode` | enum | `intercept` | `passthrough` disables body scanning |
| `tls.session_ca` | bool | | |
| `listen.host`, `listen.port` | string / int | 127.0.0.1 / 0 | |
| `server.agent_id_header`, `server.metrics_listen`, `server.health_listen` | string | | `serve` only |
| `scanners.min_value_len` | int | 6 | |
| `scanners.body_scan_max_bytes` | int | 65536 | negative disables body scan |
| `scanners.named_query.enabled`, `scanners.high_entropy.enabled` | bool | true / | |
| `scanners.hard_secrets_in_audit_mode` | bool | | |
| `scanners.canaries` | string list | | |
| `scanners.custom_regex` | list of `{id, pattern, redact}` | | invalid regex fails load (fail closed) |

## 5. Agent profiles

`~/.config/denyout/profiles/<id>.yaml`, ids match `^[A-Za-z0-9_-]{1,64}$` and can
never leave the profiles directory.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `id`, `name` | string | | name clamped to 40 runes |
| `command` | string list | required | |
| `workdir` | string | | |
| `preset` | `models` / `agent` / `none` | `agent` | imports accept only `models` / `agent` |
| `extra_allow`, `pending_once` | host list | | imports reject `*`, `*.tld`, IPs, URLs |
| `applied_packs` | list | | |
| `ask_mode`, `notify` | bool | true | |
| `tls_mode` | string | `intercept` | imports accept only `intercept` |
| `require_isolation`, `sandbox` | bool / `srt` | | imports accept only `srt` |
| `learning.*` | | on, 24h | |

`profile import <id> <file>`: the id comes from the argument (an `id:` inside the
file is ignored), unknown keys are rejected, the file is size-capped (256 KiB),
and the profile must pass `profiles.ValidateImport`: it cannot carry anything the
UI would not let you create (no TLS passthrough, no unknown preset/sandbox, no
blanket wildcard allow). Existing ids are only replaced with `--force`.

## 6. Cloud sync (remote settings)

Optional and account-gated. Remote documents are untrusted: lists are sanitised
and capped, numbers are clamped, and `body_pure_a` / `anti_chunk_enabled` can
only be kept or raised, never lowered (`appstate.ApplySyncSettings`, asserted by
tests in `internal/appstate` and `internal/settings`). Synced keys: see
[cloud-sync.md](cloud-sync.md). Never synced: audit, URLs with tokens, canaries,
wrap secrets, file contents, account tokens.

## 7. CLI flags

Flags are per command; `denyout-cli <command> --help` prints them. The ones that
map to settings: `run --tls-mode`, `run --notify/--no-notify`, `hostctl proxyd
--ask`. Policy file selection: `--config` on `check`, `run`, `serve`, `gui`,
`desktop`.
