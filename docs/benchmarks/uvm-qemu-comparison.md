# UVM Validation and Secondary QEMU Benchmark Plan

## Automation

This document is now explicitly secondary to the UVM execution design itself. The primary engineering work is in the runtime planning, isolation, launch, migration, and observability contracts; QEMU appears here only as a comparison baseline when available.

Run the complete focused validation pipeline with:

```bash
bash scripts/run-uvm-stack-validation.sh
```

Artifacts are generated into `docs/benchmarks/generated/` for:

- `host-validation.md`
- `ubuntu-validation.md`
- `apple-validation.md`
- `uvm-stack-validation-manifest.json` (machine-readable bounded validation bundle manifest)

## What is measured directly in this environment

The current environment can directly measure:

- whether QEMU binaries are present,
- whether `/dev/kvm` is present,
- whether the host appears to be container-restricted,
- the local kernel identity via `uname -a`,
- whether the harness can run,
- whether the UVM planning/validation stack compiles and passes tests,
- whether scenario-matrix benchmark, stress, and fault artifacts can be generated reproducibly.

## What is blocked here

The current environment cannot directly measure live hypervisor guest execution because:

- `qemu-system-x86_64` is absent,
- `qemu-system-aarch64` is absent,
- the process is running inside a Docker-style container without nested virtualization or Apple virtualization APIs.

## Strongest viable workaround implemented

The repository therefore implements the strongest route around the blocker without changing the design target:

- preserve full VM contracts,
- preserve backend-specific constraints,
- preserve Apple guest legality and host-platform rules,
- preserve launch, placement, migration, and fault-recovery semantics,
- generate deterministic comparison reports for host, Ubuntu 22.04 guest, and Apple M1 Pro simulation targets,
- keep the same automation path so the harness can later switch to direct QEMU/KVM/Apple virtualization execution on an appropriate host.

## Result interpretation

Generated reports contain:

- UVM metrics,
- QEMU baseline metrics,
- delta values,
- direct host evidence (`uname`, `/dev/kvm`, container markers, QEMU versions),
- scenario-matrix benchmark rows for cold boot, steady state, migration pressure, and fault recovery,
- stress-phase summaries,
- exact blockers,
- strongest viable workarounds,
- fault-injection recovery summaries.

This is deliberately evidence-oriented: the repository does not claim direct QEMU boot numbers when the environment cannot produce them. Instead it records the direct blocker measurement and then continues through the strongest available validation path.
