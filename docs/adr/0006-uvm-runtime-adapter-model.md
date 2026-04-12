# ADR 0006: UVM Runtime Adapter Model

## Status

Accepted on March 19, 2026.

## Context

The UVM control plane already models VM lifecycle intent (`/uvm/instances`) but
node-plane execution needs explicit contracts for:

- backend compatibility by host family (`kvm`, `hyperv_whp`, `apple_virtualization`, `bhyve`)
- legal guardrails for Apple guest workloads
- runtime session state transitions with deterministic recovery paths
- checkpoint envelope integrity for migration/restore workflows

## Decision

Introduce a shared `uhost-uvm` crate and use it from `uhost-svc-uvm-node`:

- `uhost-uvm` owns backend compatibility, launch command construction, runtime
  state transitions, and migration envelope hashing.
- `uhost-svc-uvm-node` persists runtime sessions, preflight reports, and
  checkpoint records behind `/uvm/runtime/*` endpoints.
- Runtime state mutations are constrained by a finite state machine and emit
  versioned outbox events for observability and replay.

## Consequences

Positive:

- Shared invariants are centralized and testable.
- Control plane and node plane can evolve independently with stable contracts.
- Admission failures are operator-readable through persisted preflight reports.

Tradeoffs:

- Runtime command generation is currently adapter-contract level and does not
  yet include direct syscall-level hypervisor drivers in this repository.
- Additional state collections increase operational data to retain and back up.
