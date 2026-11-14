# Contributing

This repository is the **public** DenyOut product tree (spec-first until the MVP binary lands).

1. Prefer improving clarity and testability of docs under `docs/`.  
2. Any change to policy evaluation order, reason codes, or security claims **MUST** update `docs/04-policy-engine.md`, `docs/10-security-boundaries.md`, and `docs/14-testing.md` together.  
3. Config key changes **MUST** update `docs/11-config-reference.md` and `schemas/denyout-config.v1.json`.  
4. Do not weaken fail-closed behavior without an explicit ADR in `docs/adr/` (create when needed).  
5. Keep this tree focused on the shippable product. Do not add internal strategy, pricing, or capacity planning notes.

## RFC 2119

In normative docs, `MUST` / `SHOULD` / `MAY` are binding for implementers.

## License / DCO

Apache-2.0. Prefer commits with `Signed-off-by` (DCO).

## Security

Do not file public issues that include real secrets. Use fake canaries from `examples/canaries/`. Prefer GitHub Security Advisories when the remote exists.
