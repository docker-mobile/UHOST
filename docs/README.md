# UHost Documentation

This directory is the curated documentation surface for `v0.1 beta`.

The current beta is intentionally narrow:

- one primary deployment shape centered on [`uhostd`](../cmd/uhostd),
- explicit service boundaries and route ownership,
- file-backed local durability,
- generated contracts and evidence,
- a software-first UVM stack with conservative claims.

If you are new to the repository, read in this order:

1. [`../README.md`](../README.md)
2. [`architecture.md`](architecture.md)
3. [`api/README.md`](api/README.md)
4. [`runbooks/README.md`](runbooks/README.md)
5. [`status.md`](status.md)
6. [`roadmap.md`](roadmap.md)

## Documentation Map

### Core platform

- [`architecture.md`](architecture.md): runtime model, service domains, and beta boundaries.
- [`api/README.md`](api/README.md): route ownership, access surfaces, and contract workflow.
- [`config/overview.md`](config/overview.md): config shape, schema, and environment overlays.

### Operator docs

- [`runbooks/README.md`](runbooks/README.md): curated runbook index.
- [`runbooks/bootstrap.md`](runbooks/bootstrap.md): all-in-one bring-up.
- [`runbooks/managed-uvm-dev-quickstart.md`](runbooks/managed-uvm-dev-quickstart.md): one-command managed UVM dev bring-up with generated tokens, guest-owned usernet-style NAT, managed HTTP plus TCP/UDP ingress, and guest-owned TCP/UDP/web egress.
- [`runbooks/on-call.md`](runbooks/on-call.md): operational loop and escalation.
- [`runbooks/supply-chain-release-gate.md`](runbooks/supply-chain-release-gate.md): release integrity gate.

### Engineering reference

- [`dependency-ledger.md`](dependency-ledger.md): dependency policy and supply-chain stance.
- [`extensions.md`](extensions.md): extension and compatibility posture.
- [`threat-model.md`](threat-model.md): trust boundaries and abuse paths.
- [`uvm-virtualization-stack.md`](uvm-virtualization-stack.md): current UVM architecture and evidence posture.

### ADRs

- [`adr`](adr): architecture decision records for major design choices.

### Status and roadmap

- [`status.md`](status.md): the current shipped beta shape and its boundaries.
- [`roadmap.md`](roadmap.md): the next technical phases after the current beta.

## Generated Evidence

Generated files under [`generated`](generated) and [`benchmarks/generated`](benchmarks/generated) are supporting artifacts, not the primary explanation of the product.

- [`generated/release-state.md`](generated/release-state.md) and [`generated/release-state.json`](generated/release-state.json) are the release-facing generated status surface.
- [`generated/storage-drill-evidence.md`](generated/storage-drill-evidence.md) and [`generated/storage-drill-evidence.json`](generated/storage-drill-evidence.json) support the storage-drill evidence gate.
- [`benchmarks/generated`](benchmarks/generated) contains the checked-in UVM benchmark and validation bundle required by current tests and scripts.

Treat those artifacts as host-specific engineering evidence. They are useful annexes, not the front door.
