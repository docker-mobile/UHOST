# UVM Virtualization Stack Architecture

This document explains the current UVM stack as it exists in the repository for
the beta release. The stack is designed to preserve real VM contracts across
accelerated hosts and restricted hosts without pretending that unsupported
environments provide hardware-backed virtualization.

## Positioning

The current UVM track is not a container substitute and it is not yet a
hyperscaler-grade hypervisor platform. What it does provide today is:

- explicit VM lifecycle contracts,
- durable control-plane and node-plane state,
- execution-plan synthesis before launch,
- evidence and compatibility reporting,
- restricted-environment validation paths that stay honest about missing host
  primitives.

Release-facing generated status remains in `docs/generated/release-state.md`.

## Architectural Layers

### Control Plane

`uhost-svc-uvm-control` owns:

- templates,
- instances,
- snapshots,
- migrations,
- reconciliation between desired and observed runtime state.

Every lifecycle action is explicit and durable so the platform can recover
intent after process restart without needing an external database.

### Node Plane

`uhost-svc-uvm-node` owns:

- host capability declarations,
- device profiles,
- runtime preflight reports,
- runtime sessions,
- checkpoints,
- heartbeats,
- health summaries,
- migration execution state.

Admission happens before launch and normalizes topology, memory, secure-boot
constraints, migration budgets, and backend compatibility.

### Image And Firmware Plane

The image plane persists artifacts, firmware bundles, and compatibility
metadata. Firmware policy is not just a path pointer; it records secure-boot
posture, signer lineage, and policy revision so later compatibility decisions
can cite explicit policy instead of raw artifact location.

### Execution Libraries

The `uhost-uvm`, `uhost-uvm-machine`, and `uhost-uvm-softvm` crates provide:

- backend compatibility guardrails,
- deterministic runtime state transitions,
- CPU topology and NUMA planning,
- launch command construction and digests,
- migration and checkpoint hashing,
- validation and reporting for restricted environments,
- benchmark and stress evidence helpers.

### Runner

`uhost-uvm-runner` is the concrete execution entrypoint. It is responsible for
honoring the runner contract, producing execution evidence, and preserving the
same high-level orchestration shape whether the backend is accelerated or
software-backed.

## Execution Modes

### Accelerated Hosts

On suitable hosts, the stack is prepared for:

- KVM-backed Linux execution,
- QEMU-backed evidence and comparison,
- host-specific privileged paths where the required primitives exist.

### Restricted Hosts

When the host lacks `/dev/kvm`, platform-specific APIs, or the required device
access, the stack does not silently mutate into a different workload model.
Instead it:

- keeps the same VM-oriented contracts,
- records exact blockers,
- continues with deterministic validation and evidence generation where that is
  still honest,
- leaves direct performance or isolation claims gated on the correct host
  class.

## Execution-Plan Synthesis

Before registration or migration commit, the runtime synthesizes a first-class
execution plan. That plan includes:

- execution class such as `latency_optimized`, `balanced`, or
  `density_optimized`,
- boot path such as `microvm`, `general_purpose`, or `apple_vm`,
- memory backing mode,
- device model,
- sandbox layers,
- mandatory telemetry streams.

Those decisions are persisted into runtime session records so operators can
inspect what was intended, not just what binary happened to start.

## Security Model

The current UVM security posture relies on:

- deny-by-default backend selection,
- secure-boot-aware admission,
- launch command canonicalization,
- explicit restricted-environment blocker reporting,
- checkpoint and migration digesting,
- heartbeat and reconciliation visibility.

This does not yet amount to third-party-certified isolation. The stack is
designed to make such claims evidence-gated rather than assumed.

## Reliability Model

The reliability story is built from:

- deterministic runtime state transitions,
- explicit recovery paths,
- migration-budget gating,
- checkpoint verification,
- heartbeat staleness detection,
- restart budgets,
- reconciliation between control-plane and node-plane state.

## Evidence Model

The stack can publish:

- host capability observations,
- restricted-environment blockers,
- benchmark scenario matrices,
- comparison reports,
- generated release-facing status.

Use these as engineering evidence, not as automatic certification.

## Current Limits

The beta release still has clear boundaries:

- host-side performance claims remain evidence-gated,
- unsupported hosts do not become real accelerated hypervisors by documentation
  alone,
- the broader platform is still not a completed distributed cloud backend,
- some release and validation paths still depend on the exact host class and a
  clean working tree.

## Related Docs

- [Host Readiness](runbooks/host-readiness.md)
- [UVM Host-vs-Guest UnixBench Runbook](runbooks/uvm-host-vs-guest-unixbench.md)
- [Threat Model](threat-model.md)
- [Dependency Ledger](dependency-ledger.md)
