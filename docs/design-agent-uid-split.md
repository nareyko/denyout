# Design: running agents under a separate uid

Status: **design only, nothing here is implemented.** Owner decision needed (see section 15). Context: option B of [`design-security-open-decisions.md`](design-security-open-decisions.md) section 1; option D (audit + detect) already ships, see [`10-security-boundaries.md`](10-security-boundaries.md) "Owner-uid detection".

## 1. Problem and goal

Today the agent and the human are the same uid. The root helper authorizes by SO_PEERCRED uid == owner, so any process the agent starts can call `remove`, `teardown` or `fail-policy open` and switch Protect off or weaker. It can also read the owner's SSH keys, browser profile, cloud credentials and tokens, and it can kill or ptrace the desktop. The audit trail only tells the owner afterwards.

Goal: processes started by `denyout run` (and the whole-PC "Agents only" profile) run as a dedicated, unprivileged uid, so that

1. the helper can refuse mutating verbs from them by uid (a real boundary, not a heuristic);
2. the nft/pf rules that force their web traffic through DenyOut are keyed on a uid they cannot become, and cannot signal, ptrace or reconfigure the desktop that serves them;
3. their file access is an explicit allow-list instead of "everything the human can read".

Non-goals: stopping a root attacker, stopping kernel exploits, stopping data leaving through channels DenyOut never covered (DNS, non-80/443 TCP, UDP other than QUIC), protecting processes that are not started through `denyout run`.

## 2. Terms

| Name | Meaning |
| --- | --- |
| owner | the human's login uid; today's `owner_uid` in `/var/lib/denyout/owner_uid` |
| agent uid | new system user `denyout-agent` (Linux), `_denyoutagent` (macOS), `DenyOutAgent` (Windows) |
| launcher | the small program that becomes the agent uid and execs the command |
| split mode | opt-in feature in this document; off means today's behaviour exactly |

## 3. Linux: user and group creation

- Name `denyout-agent`, primary group `denyout-agent`, **system** uid (below `UID_MIN`, so it never appears on a login screen), home `/var/lib/denyout-agent/home` (owned by it, mode 0700), shell `/usr/sbin/nologin`, no password, locked (`!`), not in `sudo`, `wheel`, `docker`, `video`, `render` or any other group.
- Preferred creation: a packaged `sysusers.d` fragment (`/usr/lib/sysusers.d/denyout.conf`: `u denyout-agent - "DenyOut agent" /var/lib/denyout-agent /usr/sbin/nologin`), applied with `systemd-sysusers`. Fallback when systemd-sysusers is missing: `useradd --system --user-group --no-create-home --home-dir ... --shell /usr/sbin/nologin denyout-agent`.
- Who creates it: **never `install.sh`** (it runs unprivileged into `~/.local/bin`). The user turns the feature on once in Settings > Advanced ("Run agents as a separate user"), which runs `denyout-cli hostctl agent-user-install` through the existing one-time admin prompt (the same path that installs the helper). That command creates the user, the home, the launcher policy (section 4) and writes `/var/lib/denyout/agent_uid` next to `owner_uid`. The helper reads both at start.
- Removal: `hostctl helper-uninstall` keeps the user (files owned by it may exist in project directories); `hostctl agent-user-remove --purge` deletes user, group and home and prints `find / -xdev -uid <n>` for leftovers.
- Uid stability: the uid is stored in `agent_uid` and re-resolved by name on helper start; a missing user turns split mode off (fail to today's behaviour, loudly: Problems entry), never to uid 0.

## 4. Linux: how `denyout run` drops privileges (options evaluated)

| Option | How | Verdict |
| --- | --- | --- |
| A. `sudo` rule | `/etc/sudoers.d/denyout-agent`: `<owner> ALL=(denyout-agent) NOPASSWD: /usr/lib/denyout/denyout-agent-launch`; `denyout run` execs `sudo -n -u denyout-agent -- /usr/lib/denyout/denyout-agent-launch ...` | **Phase 1 choice.** Reuses the most reviewed setuid component on the system; DenyOut ships no setuid code; tty, signals and job control work; the agent uid has no sudo rights so it cannot go back. Needs sudo (absent on some minimal/NixOS systems; the rule is a harmless allow of a fixed program to a fixed user). |
| B. helper verb `agent-exec` | root helper forks, `setgroups`, `setresgid`, `setresuid`, `PR_SET_NO_NEW_PRIVS`, drop all caps, close fds, exec; the caller passes tty fds with SCM_RIGHTS | **Phase 2 fallback** for systems without sudo. Adds about 80 lines of privilege-dropping code in the root process and "execute an owner-chosen program" to the verb table (as the agent uid, never as root). It is the less conservative option, so it is built second, with its own fuzz/Docker tests, and only if sudo is unavailable. |
| C. `systemd-run --uid=` | transient unit as the agent user | **Rejected.** Authorizing it through polkit cannot restrict unit properties, so the same authorization allows `--uid=root`. A fixed template unit (`denyout-agent@.service`) avoids that but has no usable interactive tty story. |
| D. user namespaces with a subuid range (`newuidmap`, `unshare`) | no new user; run in a userns mapped into the owner's `/etc/subuid` range, nft keyed on the range (`meta skuid 100000-165535`) | **Rejected as primary.** Needs no root install, but Ubuntu 24.04+ restricts unprivileged userns by default (AppArmor), file ownership inside appears as `nobody`, setuid tools and sudo break, and subuid presence varies. Kept as the model for the Docker test (section 11) and as a possible container-based variant later. |

The launcher (`/usr/lib/denyout/denyout-agent-launch`, root-owned, part of the trusted dir that already exists) runs as the agent uid and does only: validate it is that uid and not root, build a **fresh environment** (section 6), `chdir` to the requested directory after checking the ACL grant (section 5), set `umask 002`, `PR_SET_NO_NEW_PRIVS`, set the proxy and CA variables, then `exec` the command. It never trusts the caller's environment, cwd or fds other than 0-2.

## 5. Files, HOME and working directory

- `HOME=/var/lib/denyout-agent/home`. Caches (`~/.cache`, npm, pip, cargo registry) live there; the first run of a toolchain is slower because nothing is shared with the owner's caches.
- The agent starts in a **granted directory**. `denyout run --dir <path>` (default: the current directory) adds POSIX ACL entries on that tree: `setfacl -R -m u:denyout-agent:rwX,d:u:denyout-agent:rwX <path>` plus `d:u:<owner>:rwX` so files the agent creates stay editable by the owner, and mode `umask 002`. Grants are recorded in `/var/lib/denyout/agent_grants.json` (root-written via the helper verb `agent-grant`, validated: absolute clean path, must be owned by the owner, not `/`, not `$HOME` itself, not a parent of `$HOME`, no symlink components) and removed by `agent-revoke` or `denyout run --revoke`.
- Filesystems without ACLs (NFS, FAT, some FUSE): fall back to a shared group `denyout-share` with setgid directories; if neither works, `denyout run` refuses split mode for that directory and says why.
- Everything else under the owner's `$HOME` stays closed by the usual `0700` home. Read-only toolchains (`~/.nvm`, `~/.cargo/bin`, `~/.local/bin`) need either a grant (`--allow-ro <path>`: `r-X` ACL **plus** `--x` on every parent, including `$HOME`) or installing the tool for the agent. Be aware of the cost: `--x` on `$HOME` lets the agent open any world-readable file under it by exact path (for example a `0644` `~/.gitconfig` or `~/.npmrc` holding a token). Phase 1 therefore does not grant traversal on `$HOME` by default; the supported path is system toolchains (`/usr`, `/opt`) or tools installed into the agent home (`denyout run --install-tool node` documents the commands, it does not automate them).
- git: the owner owns the repository, the agent runs git, so git reports "dubious ownership". The launcher writes `safe.directory` entries for granted directories into the agent's own `~/.gitconfig`. Commits made by the agent carry the agent's configured identity, not the owner's.
- Secrets the agent no longer sees by default: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, browser profiles, `ssh-agent` socket, GPG agent, desktop keyrings, the owner's shell history. That is the point. It also means `git push` over SSH, cloud CLIs and signed commits do not work until the user provides a credential on purpose (deploy key in the agent home, a scoped token through `denyout run --env NAME` which passes one variable by name, or `--forward-ssh-agent`, which ACL-grants the socket and is documented as weakening the isolation).

## 6. Environment

The launcher builds the environment from an allow-list: `TERM`, `LANG`, `LC_*`, `TZ`, a minimal `PATH` (`/usr/local/bin:/usr/bin:/bin` plus the agent home bin), `HOME`, `USER`, `LOGNAME`, plus DenyOut's `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`/`SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS` values and variables passed explicitly with `--env NAME`. Dropped: everything else, in particular `SSH_AUTH_SOCK`, `GNUPGHOME`, `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, cloud and token variables. The DenyOut CA must be readable by the agent uid: it is installed into the system trust store already (helper `apply`), and a copy is placed at `/usr/local/share/ca-certificates/denyout.crt`-derived path readable by all for tools that need a file path.

## 7. Network rules keyed on the agent uid

Spec gains `AgentUID int` and `ProtectOwner bool`; `renderLinuxNFT` emits a uid set:

```
meta skuid { 1500 } tcp dport { 80, 443 } ip daddr != 127.0.0.0/8 redirect to :PORT
meta skuid { 1500 } tcp dport { 80, 443 } ip6 daddr != ::1 redirect to :PORT
meta skuid { 1500 } udp dport 443 counter drop comment "denyout-block-quic"
```

- `ProtectOwner` (default true for the "Protect computer" profile, false for the "Agents only" profile in split mode) adds the owner uid to the set, so browser protection is unchanged for users who have it today.
- Marked upstream dials (`meta mark 0x646e79 return`) stay first, as now. The proxy (`denyout-cli hostctl proxyd`) keeps running as the owner uid and listens on loopback, as now; the agent reaches it through the redirect or the proxy variables.
- Rules key on a uid the agent cannot change (no `CAP_SETUID`, `no_new_privs`). Loopback services of the owner are reachable from the agent uid (see section 12).
- IPv6 and QUIC handling is identical to today, only the uid set differs. TUN mode follows the same uid set once the data plane takes a uid list (Phase 1 supports the nft path only; TUN with split mode is Phase 2).
- macOS `pf` already uses `user <uid>` and Windows needs a different primitive (section 10).

## 8. Helper authentication changes

Today `helperPeerAuthorized` accepts `peer == owner || peer == 0`. In split mode:

| Peer | Allowed |
| --- | --- |
| root (0) | everything (unchanged) |
| owner | everything (unchanged), including mutating verbs |
| agent uid | only the read-only subset flagged `agentOK` in the verb table: `caps`, `version`, `fail-status`, `quic-stats`, `tun-stats`. Everything else is answered `ERR unauthorized` |
| any other uid | refused (unchanged) |

- The socket is created owner-only today; split mode needs the agent uid to connect for the read-only subset, so the socket becomes mode `0666` **only if** that subset is kept. Recommendation: do not give the agent any helper access at all in Phase 1 (keep `0600` owner), because the agent has no need for stats and the only effect of the connection is a larger attack surface. The verb-level table change is still made so a later decision costs nothing.
- Any connection from the agent uid that asks for a mutating verb is, by definition, a tamper attempt. It is recorded (audit event `result=denied`, `reason=agent_uid`) and raises the same "Protect was changed ..." style notice ("A program running as the agent user asked DenyOut to turn protection off"). This reuses the audit trail that ships with option D.
- New verbs for split mode are owner-only: `agent-grant`, `agent-revoke`, `agent-exec` (Phase 2). They are added to the closed verb table with parsers that reuse `privexec.ValidAbsPath`, and the `TestEveryMutatingVerbHasAuditDecision` guard forces an audit decision for each.
- The desktop's own process, which the agent can no longer signal, becomes the stronger half of the "from the desktop" rule used by option D.

## 9. What breaks, what to say about it

| Thing | Effect in split mode | Mitigation |
| --- | --- | --- |
| ssh-agent, GPG agent, keyrings, cloud credentials | not available to the agent | by design; explicit `--env` / deploy key / `--forward-ssh-agent` |
| Toolchains installed in the owner's home (nvm, cargo, pyenv) | not found or not executable | system toolchains, or install into the agent home; no automatic `$HOME` traversal grant (section 5) |
| Editors and IDEs | an IDE-hosted agent (Claude Code inside VS Code, JetBrains AI) runs as the owner and is **not** covered; only processes started through `denyout run` are | document it; a later IDE remote-server profile can run the server under the agent uid |
| GUI apps, browsers started by the agent | no display, no Wayland or X11 auth, no D-Bus | `--gui` is out of scope for Phase 1; it needs an explicit, per-session grant |
| git | "dubious ownership", different identity | launcher writes `safe.directory`; identity is configured for the agent |
| Process attribution | the proxy finds the calling process through `/proc/<pid>/fd` of the owner's processes; the agent's are unreadable by the owner | helper-side lookup (`ss -p` equivalent by root) or log "agent uid" without a pid; denial UX says "an agent" instead of a program name |
| Docker, Podman, systemd user units, `sudo` | unavailable to the agent | by design |
| Build outputs | owned by the agent uid unless the default ACL grants the owner rwx | default ACL in section 5; `umask 002` |
| Disk and CPU | quotas and cgroups not provided | out of scope |

## 10. macOS and Windows sketches

**macOS.** Hidden role user `_denyoutagent` created with `sysadminctl -addUser` (or `dscl`), uid in the 400-499 service range, `/usr/bin/false` shell, home `/var/lib/denyout-agent` (or `/Users/_denyoutagent`), not an admin, hidden from the login window. Privilege drop through `sudo -u _denyoutagent` with the same sudoers fixture, or a root LaunchDaemon helper that spawns with `UserName`. `pf` rules already filter by `user <uid>` and just take the agent uid. ACLs via `chmod +a "_denyoutagent allow read,write,..."`. The login keychain is already inaccessible to another user, which removes a large part of the credential exposure for free; TCC prompts and Xcode toolchains tied to the owner's home are the main breakage. The macOS helper itself is not implemented yet (see `docs/platform-packaging.md`), so this follows it.

**Windows.** Local non-admin user `DenyOutAgent`, launched with `CreateProcessWithLogonW` or a scheduled task using a stored credential in LSA secrets. WinDivert has no uid concept, so uid-keyed rules need Windows Filtering Platform filters with `FWPM_CONDITION_ALE_USER_ID` (or app-container SID conditions) instead; this replaces the WinDivert path for split mode and is the long pole. File access through `icacls` grants. Helper authentication would use the named-pipe client token instead of SO_PEERCRED. Not started; see `docs/hostguard-windows.md`.

## 11. Opt-in, migration and rollback

- Off by default. Setting: `agent_uid_split` (state schema bump, default false), switch in Settings > Advanced, `denyout-cli hostctl agent-user-install|agent-user-remove`. Env override for CI/labs: `DENYOUT_AGENT_SPLIT=0|1`.
- Turning it on never changes an already running Protect session; it takes effect for the next `denyout run` and the next Protect On (the nft set is rewritten by `apply` with the new `AgentUID`).
- Existing profiles keep working: without the agent user, or with split mode off, `denyout run` is exactly today's same-uid behaviour. A missing agent user, a revoked grant or an unsupported filesystem is a Problems entry with a fix button, never a silent fallback to the owner uid for a session the user asked to isolate (that case refuses to start and says so).
- Rollback: toggle off; grants are revoked; `agent-user-remove --purge` is optional.
- Caps: the helper advertises `agent1` when it understands the split verbs and uid set; the desktop checks it the way it already checks `quic1`/`tun1`.

## 12. Residual risks (what this does NOT protect)

1. **Shared project files are an escalation path back to the owner.** The agent can write hooks and scripts in the directory it is granted (`.git/hooks`, `Makefile`, `package.json` scripts, `.envrc`, shell rc files, `.vscode/tasks.json`, CI configs) that the owner later runs. That gives the agent code execution as the owner the first time the human builds, tests or opens the project. The split narrows what a *running* agent can reach, not what a *cooperating* human executes. Mitigations are review habits and the audit trail from option D, not this design.
2. **Same-uid processes that are not wrapped.** Anything the owner runs outside `denyout run`, including IDE-hosted agents, behaves exactly as today.
3. **Loopback and local services.** The agent uid can connect to every listening loopback port: databases, dev servers, the Docker TCP socket if enabled, and DenyOut's own control endpoints. Those must authenticate with a secret in an owner-only file, not rely on "it is only localhost". Abstract unix sockets (for example the X11 abstract socket) ignore file permissions; with X access granted (`xhost +local:`) keystroke injection into owner windows is possible.
4. **Information leaks through `/proc`.** Without `hidepid=2`, the agent can list the owner's processes and read their command lines (tokens passed as arguments). Recommend mounting `/proc` with `hidepid=2`; DenyOut cannot do it for the user.
5. **Kernel and local privilege escalation bugs**, setuid binaries with flaws, and a world-writable path the owner trusts (`/tmp` symlink races) are not addressed.
6. **Coverage is unchanged:** DNS and DoH, non-80/443 TCP, UDP other than QUIC, passthrough TLS to allowlisted hosts, and secrets in bodies sent to allowed hosts stay residual (see `10-security-boundaries.md` sections 1 and 2).
7. **Root.** A root attacker (or a compromised helper) is out of scope; so is anything that can obtain the owner's polkit authorization.
8. **Resource abuse.** The agent can fork-bomb, fill the disk or burn CPU; no cgroup or quota is configured.
9. **Detection is still needed.** The owner can still switch Protect off deliberately or by mistake; the boundary is only against the agent.

## 13. Test plan (Docker only; two uids)

A new script `scripts/agent-uid-docker.sh` in the style of `security-helper-regression-docker.sh`, run through the existing harness pattern (NET_ADMIN containers only via the script; never the host network). Container has owner uid 1000, agent uid 1500, a dummy interface with a fake "internet" listener on port 443, and the built `denyout-cli`.

1. Helper auth: agent uid cannot call `remove`, `teardown`, `fail-policy`, `apply`, `tun-*`, `vpn-*`, `uninstall-helper`, `agent-*` (refused, audited with `reason=agent_uid`, flagged); owner still can; unknown uid refused; table test that every verb has an explicit `agentOK` value.
2. Rules: `nft list ruleset` contains the agent uid set; a TCP 443 connect from the agent uid reaches the proxy (counter on the redirect rule), the same connect from the owner uid does not when `ProtectOwner=false` and does when true; QUIC drop counters move only for the set.
3. Privilege drop: inside the launched process `/proc/self/status` shows `Uid/Gid` = agent, `CapEff` and `CapPrm` all zero, `NoNewPrivs: 1`, `Groups` only the agent group, no fds beyond 0-2, cwd as requested, environment equals the allow-list; `sudo -u root` and `su` fail.
4. Files: with a granted directory the agent writes a file the owner can read and edit; it cannot read `/home/owner/.ssh/id_test` (0700 home) or `/proc/<owner pid>/environ`; `kill -0` and `ptrace` against an owner process fail; grant validation rejects `/`, `$HOME`, relative paths, symlink components and paths not owned by the owner.
5. Sudo path: sudoers fixture allows exactly the launcher; any other command or user fails; `denyout run` refuses to start when the agent user or grant is missing (no silent same-uid fallback).
6. Regression: split mode off leaves `hostctl render` output byte-identical to today (golden test), and the existing `helper-exploits.sh`, `watchdog-e2e.sh` and `soak-docker.sh` still pass.
7. Unit tests in `internal/hostguard`: rule rendering for uid sets (including `ProtectOwner` on/off and QUIC), `helperPeerAuthorized` matrix, verb-table `agentOK` guard, grant validation, launcher environment builder (fuzzed), state schema migration.
8. A userns variant (`unshare --user --map-users` with a subuid range) proves the rules keyed on a uid range work without creating a user; it runs in a container with relaxed seccomp and is optional.
9. macOS and Windows cannot be tested in Docker: a manual VM checklist per phase, and CI jobs on the real runners for the pure parts (pf rendering, WFP filter description).

## 14. Phased rollout

| Phase | Scope | Exit criteria |
| --- | --- | --- |
| P0 | `Spec.AgentUID/ProtectOwner`, uid-set rendering, `agentOK` in the verb table, golden test that off-mode output is unchanged. No user is created. | all existing tests unchanged; new unit tests green |
| P1 | Linux, opt-in, sudo launcher, ACL grants, nft path only (no TUN), no helper access for the agent uid, Settings switch, Problems entries, audit `agent_uid` events | Docker plan items 1-6 green; dogfooded on one machine for two weeks |
| P2 | `agent-exec` fallback for systems without sudo, TUN with uid sets, optional agent read-only helper access, `--allow-ro` with the traversal warning, IDE remote-server notes | fuzz + Docker tests for the new verbs; no regression in soak |
| P3 | Default for the "Agents only" profile when the agent user already exists; `denyout run --strict` requires split mode | one release with no open isolation bugs |
| P4 | macOS (after the macOS helper exists) | VM checklist |
| P5 | Windows (WFP, separate effort) | design review first |

## 15. Decision needed from the owner

1. Go or no-go on split mode as the real fix for agent-mode (Linux first)?
2. Primary launcher: sudo (recommended, Phase 1) or the helper `agent-exec` verb (adds privilege-dropping code to the root process)?
3. Should the agent uid get any helper access (read-only stats) in Phase 1? Recommendation: none.
4. Default for `ProtectOwner` in "Agents only": off (agents isolated, human unfiltered) or on?
5. Accept the toolchain-in-`$HOME` limitation (no automatic traversal grant) for Phase 1?
