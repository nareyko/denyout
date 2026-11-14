# D01 - Vision, positioning, personas, brand

## 1. Problem

People and teams increasingly run **AI agents** that:

1. Read untrusted content (web, tickets, PDFs, repo files, tool output).
2. Have access to sensitive context (code, `.env`, customer data, chat history).
3. Can open the network (HTTP tools, browsers, `curl`, package installs, webhooks, markdown image loads).

When (1)+(2)+(3) coexist, a single injected instruction can cause **silent exfiltration** - classic example: a markdown image or link whose URL contains a secret (`R-20`). Most agent users do not configure egress policy. Enterprise SWG/CASB rarely sits in front of a laptop `claude` session or a hobby VPS bot.

## 2. Insight

Security that requires the user to "think like a CISO" will not be used by the people who need it most.

DenyOut's bet: **make the safe outcome the default outcome** when someone wraps their agent (or when ops installs a sidecar). Policy starts at **deny outbound**, not "trust the model."

## 3. Positioning

| | DenyOut |
| --- | --- |
| Category | Agent egress control / default-deny outbound proxy |
| Not | Prompt firewall, full EDR, LLM gateway for prompts, password manager |
| Promise | Agents don't talk to the world unless policy allows it. Secret-looking URLs die loudly |
| Tone | Straight, slightly stern, honest about limits - matches the name |
| Brand domain | https://denyout.com |

### 3.1 Elevator pitches

**10 seconds:** "Seatbelt for AI agents - deny outbound by default."

**30 seconds:** "DenyOut wraps your agent so every network call hits a local proxy. Unknown hosts are blocked, URLs with secrets are blocked, and you get a log you can actually read. Same policy on a laptop and in Kubernetes."

**Technical:** "Identity-agnostic MVP: process-scoped HTTPS proxy + policy engine (enforce/audit/ask) + secret-in-URL scanners + out-of-band audit. Server mode requires network backstop so bypass fails closed."

### 3.2 Taglines (candidates)

- Deny by default. Allow what you need.
- Outbound is a privilege.
- Your agent's leash.
- Quiet agents. Loud denials.

## 4. Personas

### P1 - Curious builder (primary desktop)

- Runs Claude Code / Cursor agent / OpenClaw / custom Python on a laptop.
- Does not read security blogs.
- Will tolerate one install command and `denyout run -- ...`.
- Will abandon anything that needs "write a NetworkPolicy first."

**Job to be done:** Don't leak API keys / customer snippets via dumb tool calls or poisoned docs.

### P2 - Indie hacker / small SaaS

- Runs an agent as a systemd service or single Docker Compose stack on a VPS.
- Can paste a compose snippet. Cannot staff a security team.

**Job to be done:** Sleep at night knowing the bot can't POST to random domains.

### P3 - Platform / security engineer (server)

- Owns agent runtimes in Kubernetes.
- Needs audit for compliance, kill switch, GitOps policy.
- Will reject products that only work as a browser extension.

**Job to be done:** Enforce egress per agent identity with SIEM-ready logs.

### P4 - Arviser / auditor (channel)

- Uses DenyOut as a **concrete control** recommended after AI Security Review findings (especially R-20 / trifecta).

**Job to be done:** Point customers at something installable, not only advice.

## 5. Jobs / use cases

| ID | Use case | Success look |
| --- | --- | --- |
| U1 | Wrap coding agent on laptop | Model API works. Random URL fetch denied. Notify shown |
| U2 | Block R-20 style image URL with canary | Request never reaches attacker. Audit has reason `secret_url` |
| U3 | Discover needed allowlist | `audit` mode for a day -> export allowlist candidates |
| U4 | Sidecar in front of agent service | NetworkPolicy + DenyOut. Curl to evil fails |
| U5 | Incident kill switch | Flip mode or empty allowlist remotely / via file. New calls deny |
| U6 | Demo for executives | One terminal: poisoned markdown -> blocked |

## 6. Product principles

1. **Fail closed.** Misconfig or engine error -> deny or refuse start.
2. **Honest scope.** Prefer a narrow true claim over a wide false one.
3. **One policy language** across desktop and server.
4. **Friction on first deny, not on first run.** First run works for common model APIs out of the box.
5. **Audit lives outside the agent's reach** whenever the deployment can ensure it.
6. **Secrets never required in the agent env for third-party APIs** (phase 2: credential injection). MVP may still use env keys for model providers - document the residual risk.
7. **Local-first OSS core.** No account required for Protect or app update checks. Optional account only for settings sync. Telemetry off by default.

## 7. Brand & naming

| Item | Value |
| --- | --- |
| Product name | DenyOut |
| CLI binary | `denyout` |
| Config file | `denyout.yaml` (or `.denyout.yaml`) |
| Env prefix | `DENYOUT_` |
| Audit logger name | `denyout.audit` |
| Docker image (planned) | `denyout/denyout` or `ghcr.io/...` |
| Policy API group (K8s, later) | `policy.denyout.com` (optional CRD phase) |

### 7.1 Why "DenyOut" works

- Encodes the default stance (deny + outbound).
- Short, spellable, domain owned.
- Differentiates from crowded "AgentGuard" namespace.
- Risk: sounds absolute - mitigated by tagline and D10 claims doc.

### 7.2 Visual direction (informative)

- High contrast, monospace-friendly docs.
- Avoid purple-glow "AI security" clichés.
- Denial events: clear red/amber in CLI. No alarmist emoji spam.

## 8. Success metrics (product)

| Metric | MVP target |
| --- | --- |
| Time to first protected run | < 5 minutes on macOS/Linux |
| False-deny rate on "model chat only" preset | < 5% of sessions need allowlist edit in first hour |
| R-20 canary catch rate in lab | 100% for documented URL patterns |
| Bypass without OS backstop | Documented. Server guide **MUST** require NetworkPolicy |

## 9. Relationship to Arviser

DenyOut may be:

- Referenced from Arviser guides (R-20 remediation).
- Packaged as recommended control in AI Security Review reports.
- Optionally co-branded later (`denyout` by Arviser) without requiring Arviser account for OSS use.

This repo stays **product-owned**. Arviser site content is a separate concern.

## 10. Non-goals for vision (see also D10, D12)

- Replacing corporate SWG for all employee browser traffic.
- Being the system of record for IAM.
- Guaranteeing model alignment or stopping all prompt injection.
