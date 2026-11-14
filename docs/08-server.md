# D08 - Server deployment

## 1. Goals

- Same policy semantics as desktop. 
- **Bypass fails closed** via network controls DenyOut does not solely rely on env vars. 
- Ops-friendly: logs, metrics, kill switch, GitOps config.

## 2. Reference architecture: Kubernetes sidecar

```text
┌──────────────── Pod ─────────────────┐
│ agent container │
│ HTTPS_PROXY=http://127.0.0.1:8080 │
│ egress NetworkPolicy -> only sidecar│
│ │
│ denyout container │
│ listen 127.0.0.1:8080 │
│ policy from ConfigMap │
│ audit to stdout -> cluster logging │
│ egress -> Internet / APIs │
└──────────────────────────────────────┘
```

### 2.1 MUST requirements for "supported server mode"

A deployment MAY claim "DenyOut server hardened" only if:

1. Agent network namespace cannot reach non-DenyOut egress (NetworkPolicy, Cilium, iptables, cloud SG). 
2. Policy is not writable by the agent container. 
3. Audit stream is not on a volume the agent can truncate. 
4. DenyOut runs as non-root with drop capabilities where possible.

Examples: [`examples/k8s/`](../examples/k8s/).

### 2.2 NetworkPolicy sketch

- Agent: allow egress TCP to DenyOut port on localhost / pod; allow DNS to cluster DNS; deny the rest. 
- DenyOut: allow egress HTTPS to needed CIDRs or unrestricted as org policy dictates; still enforce app-level allowlist.

## 3. `denyout serve`

Long-running mode for containers:

```bash
denyout serve --config /etc/denyout/denyout.yaml --listen 127.0.0.1:8080
```

| Flag | Description |
| --- | --- |
| `--config`, `-c` | **Required** policy file |
| `--listen` | Bind address (default from config `listen`, else `127.0.0.1:8080`) |
| `--metrics-listen` | Optional `127.0.0.1:9090` (`/metrics`; also `/healthz` if health unset) |
| `--health-listen` | Optional `/healthz` `/readyz` `/livez` |
| `--tls-mode` | `intercept` (default) or `passthrough` |
| `--ca-dir` | Where to write session CA cert for agent trust (intercept) |

**Readiness:** `/readyz` -> 200 when proxy is accepting + policy loaded. 
**Liveness:** `/healthz` / `/livez`. 
**Kill switch:** `DENYOUT_KILL=1` refuses to start (fail closed).

Without NetworkPolicy / host firewall, `serve` is **not** a hardened deployment - agents can ignore `HTTP(S)_PROXY`.

## 4. Docker Compose (indie P2)

```yaml
services:
 agent:
 image: my-agent
 environment:
 HTTPS_PROXY: http://denyout:8080
 HTTP_PROXY: http://denyout:8080
 depends_on: [denyout]
 # recommend custom network + egress firewall via wrapper
 denyout:
 image: denyout/denyout:latest
 command: ["serve", "-c", "/config/denyout.yaml"]
 volumes:
 - ./denyout.yaml:/config/denyout.yaml:ro
```

Compose **without** extra firewall is weaker (agent could ignore proxy). Document clearly; provide `examples/compose/nftables` notes for VPS.

## 5. systemd (VM)

- Unit `denyout.service` runs `serve`. 
- Agent unit `EnvironmentFile=` sets proxy. 
- Host `iptables`/`nftables` owner-only egress for agent UID -> proxy UID (recommended guide).

## 6. Identity (phases)

| Phase | Identity |
| --- | --- |
| MVP | Single policy per proxy instance |
| 1.1 | `agent_id` from header `X-DenyOut-Agent` set by mesh (spoofable if agent can set it - only trust if injected by sidecar iptables / envoy) |
| 2 | mTLS from workload to DenyOut; map SPIFFE / K8s SA to policy bundle |
| 3 | Central control plane issues short-lived proxy tokens (cf. Permit-style) |

MVP **MUST NOT** pretend header-based agent_id is authentic without network isolation.

## 7. Credential injection (phase 2)

Align with seekrit/C1 pattern:

- Agent holds placeholder `{{denyout:NAME}}`. 
- Proxy injects real secret only toward allowlisted hosts. 
- Scrub echoes on response.

Out of MVP; interfaces reserved in D03.

## 8. Kill switch

Mechanisms:

1. ConfigMap `mode: enforce` + empty allow list. 
2. `denyout` admin endpoint localhost `POST /v1/kill` (mTLS/token) - phase 1.1. 
3. Scale DenyOut to 0 **and** keep NetworkPolicy deny -> agent dark (safe). 
4. Feature flag via `DENYOUT_KILL=1` env on DenyOut container (fail closed).

## 9. Multi-tenancy

- One DenyOut per agent/tenant pod preferred. 
- Shared node proxy only with strong identity (phase 2+). 
- Audit events MUST include `namespace`, `pod`, `agent_id` when known.

## 10. Resource sizing (informative)

| Load | CPU | Memory |
| --- | --- | --- |
| Light coding agent | 50m | 64-128Mi |
| Busy multi-tool agent + intercept | 200m-1c | 256-512Mi |

Body scan caps protect memory.

## 11. Upgrades

- Image digests pinned. 
- Policy `apiVersion` compatible. 
- CA rotation: restart pod with new session CA; agents may need reconnect.
