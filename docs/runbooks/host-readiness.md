# Host Readiness

This runbook explains how to check whether the current machine can honestly run
the repository's validation, evidence, and virtualization workflows.

## Purpose

- Distinguish local exploration from release-grade validation.
- Prevent false claims caused by missing host primitives.
- Give operators one place to check whether a host is suitable for a given
  workflow.

## Command

```bash
bash scripts/host-capability-preflight.sh
bash scripts/host-capability-preflight.sh --profile rust-ci
bash scripts/host-capability-preflight.sh --profile wave-evidence --deep
bash scripts/host-capability-preflight.sh --profile supply-chain
bash scripts/host-capability-preflight.sh --profile qemu-evidence --profile kvm-native
```

## Profiles

1. `all-in-one-dev`
   Minimal local exploration of the single-process control plane.
2. `rust-ci`
   Formatting, linting, and test execution on the pinned Rust toolchain.
3. `wave-evidence`
   Readiness for evidence-generation gates and freshness checks.
4. `perf-gate`
   Rust validation plus benchmark-capable tooling and evidence prerequisites.
5. `supply-chain`
   SBOM, provenance, vulnerability, signature, and release verification work.
6. `qemu-evidence`
   QEMU and guest-image evidence generation.
7. `kvm-native`
   Native Linux KVM-backed UVM validation.

## Result Meanings

- `ready`
  Hard blockers for that profile are cleared.
- `limited`
  Hard blockers are cleared, but runtime conditions still reduce confidence or
  reachability.
- `blocked`
  One or more non-negotiable requirements are missing.

## Interpretation Rules

- A visible CPU virtualization flag does not mean native virtualization is
  usable if `/dev/kvm` is absent or the process is container-restricted.
- `qemu-evidence` and `kvm-native` only check host suitability. They do not by
  themselves prove benchmark freshness, security posture, or release honesty.
- `--deep` enables more expensive checks such as evidence freshness or
  fetchability.

## Recommended Usage Sequence

1. Run `--profile rust-ci` before compile, lint, or test work.
2. Run `--profile wave-evidence --deep` before refreshing published evidence.
3. Run `--profile supply-chain` before a release build or provenance pass.
4. Run `--profile qemu-evidence` before QEMU probe or guest-control work.
5. Run `--profile kvm-native` before making or validating hardware-backed UVM
   claims.

## Common Failure Modes

- missing linker or C toolchain,
- missing QEMU binaries,
- missing `/dev/kvm`,
- dirty working tree for clean-tree release gates,
- stale or missing generated evidence.

## Related Docs

- [Supply-Chain Release Gate](supply-chain-release-gate.md)
- [UVM Host-vs-Guest UnixBench Runbook](uvm-host-vs-guest-unixbench.md)
- [UVM Virtualization Stack Architecture](../uvm-virtualization-stack.md)
