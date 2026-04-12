# Runbooks

These runbooks cover the current `v0.1 beta` operating model: one primary
same-host [`uhostd`](../../cmd/uhostd) deployment shape with local durable
state and explicit operator-owned recovery and validation flows.

Use this index as the operator front door. The runbooks here are practical
procedures for the current codebase, not generic cloud operations advice.

## Before You Start

- Read [`../architecture.md`](../architecture.md) for the system shape.
- Read [`../api/README.md`](../api/README.md) if you need route and surface
  context.
- Use [`host-readiness.md`](host-readiness.md) before claiming that a host can
  run validation, supply-chain, or UVM evidence workflows.

## Recommended Reading Order

1. [`bootstrap.md`](bootstrap.md)
   Bring up the all-in-one beta safely.
2. [`managed-uvm-dev-quickstart.md`](managed-uvm-dev-quickstart.md)
   Launch one UHost-managed software UVM session with generated tokens and a
   reusable shell env file plus guest-owned usernet-style NAT, managed HTTP
   and TCP/UDP ingress, and guest-owned TCP/UDP/web egress.
3. [`beginner-maintenance-guide.md`](beginner-maintenance-guide.md)
   Conservative daily checks for first-time operators.
4. [`on-call.md`](on-call.md)
   Shift-based operating loop and routine escalation paths.
5. [`incident-response.md`](incident-response.md)
   Coordinated response when the platform is unhealthy, degraded, or suspected
   to be compromised.

## Runbook Catalog

### Bring-up and readiness

- [`bootstrap.md`](bootstrap.md)
- [`managed-uvm-dev-quickstart.md`](managed-uvm-dev-quickstart.md)
- [`host-readiness.md`](host-readiness.md)

### Routine operations

- [`beginner-maintenance-guide.md`](beginner-maintenance-guide.md)
- [`on-call.md`](on-call.md)
- [`event-delivery.md`](event-delivery.md)

### Recovery and resilience

- [`backup-restore.md`](backup-restore.md)
- [`failover-drill.md`](failover-drill.md)
- [`incident-response.md`](incident-response.md)
- [`routed-secret-reveal.md`](routed-secret-reveal.md)

### Release and integrity

- [`supply-chain-release-gate.md`](supply-chain-release-gate.md)

### UVM evidence

- [`uvm-host-vs-guest-unixbench.md`](uvm-host-vs-guest-unixbench.md)

That last runbook is evidence-oriented. It does not by itself establish
production readiness, certification, or hypervisor parity.

## Scope Notes

- The default assumption is a same-host beta deployment using a checked-in
  config template plus deploy-time secret injection.
- Some procedures reference generated evidence under [`../generated`](../generated)
  or [`../benchmarks/generated`](../benchmarks/generated). Treat those as
  artifacts produced by commands, not as the primary source of architectural
  truth.
- When a runbook depends on a stronger host class, it should say so explicitly.

## Related Docs

- [`../README.md`](../README.md) for the curated docs index
- [`../architecture.md`](../architecture.md) for system structure
- [`../api/README.md`](../api/README.md) for route and contract behavior
- [`../status.md`](../status.md) for the current beta scope and boundaries
