# API And Contract Guide

UHost `v0.1 beta` publishes one checked-in control-plane contract in two forms:

- [`openapi/control-plane-v1.yaml`](../../openapi/control-plane-v1.yaml)
- [`proto/control-plane-v1.proto`](../../proto/control-plane-v1.proto)

Those files are the external contract surface. This guide explains how to read
them, how the runtime treats routes, and what beta-level compatibility means in
the current codebase.

## Contract Shape

The contract is centralized on purpose.

- OpenAPI is the primary HTTP-facing specification.
- Protobuf mirrors the same platform model for clients, tooling, and future
  decomposition work.
- Route publication is startup-validated instead of being discovered
  opportunistically at runtime.
- Snapshot tests in
  [`cmd/uhostd/tests/contract_snapshots.rs`](../../cmd/uhostd/tests/contract_snapshots.rs)
  guard against silent surface drift.

The important beta property is not just breadth. It is that the surface is
explicit, versioned, and checked.

## How To Navigate The Contract

Use the documents in this order:

1. Read [`../architecture.md`](../architecture.md) for the current system
   shape.
2. Use the OpenAPI file for route-level HTTP behavior and model naming.
3. Use the protobuf file when you need a wire-friendly model of the same
   domains.
4. Use service-local `README.md` files under [`../../services`](../../services)
   when you need bounded-context implementation details.
5. Use [`../generated/release-state.md`](../generated/release-state.md) only as
   generated status and evidence, not as the contract definition.

## Runtime-Owned Routes

Some routes belong to the runtime kernel rather than to any service. They are
reserved and cannot be shadowed by service registration.

Representative runtime-owned routes:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /runtime/topology`
- `POST /runtime/participants/tombstone`
- `GET /runtime/participants/tombstone-history`
- `GET /runtime/participants/tombstone-history/aggregated`

The manifest for those routes is declared in
[`cmd/uhostd/src/activation.rs`](../../cmd/uhostd/src/activation.rs) and
enforced by
[`crates/uhost-runtime`](../../crates/uhost-runtime).

## Surface And Access Model

Every path is attached to a surface and enforced with a caller model.

Surface classes:

- `public`: narrow unauthenticated or carefully limited entry points
- `tenant`: tenant and workload-facing routes
- `operator`: administrative and operational routes
- `internal`: runtime-only or explicitly internal paths

Current beta posture:

- public routes are open by design,
- workload bearer tokens can access only workload-safe tenant routes,
- operator and runtime routes remain tightly protected,
- internal routes are not part of the public API promise.

This means the published contract is wider than the workload-safe surface.
Clients should not assume that every published route is intended for the same
caller type.

## Domain Coverage

The current contract spans most of the repository's bounded contexts:

- core control-plane: `identity`, `tenancy`, `control`, `scheduler`, `node`,
  `observe`, `policy`, `governance`, `lifecycle`, `ha`, `console`
- network and edge: `ingress`, `dns`, `mail`, `netsec`
- data and workload state: `storage`, `data`, `stream`, `container`
- commercial and operator support: `billing`, `notify`, `abuse`, `secrets`
- UVM: control, image, node, observe, summary, evidence, and related routes

That breadth should still be read as beta software. Some families are newer or
less mature than others even though they share the same contract discipline.

## Change Rules

If a code change affects externally visible behavior, treat it as contract work.

Expected workflow:

1. Update the owning service and, if needed, the runtime activation manifest.
2. Update [`openapi/control-plane-v1.yaml`](../../openapi/control-plane-v1.yaml).
3. Update [`proto/control-plane-v1.proto`](../../proto/control-plane-v1.proto).
4. Run:

```bash
cargo test -p uhostd --test contract_snapshots
```

5. If published summaries or evidence changed, refresh:

```bash
bash scripts/generate-release-state.sh
```

If handler code changes but the checked-in contract does not, the change is
probably incomplete.

## Beta Compatibility Expectations

`control-plane-v1` is versioned, but this is still beta software.

Reasonable expectations today:

- additive growth is normal,
- model cleanup is still possible,
- published route families should not disappear casually,
- contract drift should be intentional and reviewable,
- consumers should pin to the checked-in contract, not to screenshots or ad hoc
  examples.

That is stricter than an internal prototype and looser than a GA compatibility
promise.

## Related Docs

- [`../README.md`](../README.md) for the curated docs index
- [`../architecture.md`](../architecture.md) for system structure
- [`../runbooks/README.md`](../runbooks/README.md) for operator procedures
- [`../../README.md`](../../README.md) for repo-level beta scope and verification
  commands
