# UVM Validation Report

- Generated at: 2026-04-12 17:56:14.597881116 +00:00:00
- Target: `host`
- Guest architecture: `host_only`
- Host platform: `linux`
- Execution environment: `container_restricted`
- Measurement mode: `hybrid`
- QEMU available: `true`
- Nested virtualization available: `false`

## Host evidence

- Kernel: `Linux 980e96f534b6 6.18.5+deb13-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.18.5-1~bpo13+1 (2026-02-04) x86_64 GNU/Linux`
- /dev/kvm present: `false`
- Container indicators: /run/.containerenv present
- QEMU versions: qemu-system-x86_64: QEMU emulator version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18), qemu-system-aarch64: QEMU emulator version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18)

## Comparison

- UVM claim tier: `research_only` (prohibited)
- QEMU claim tier: `compatible` (simulated)

| Metric | UVM | QEMU | Delta (UVM vs QEMU) |
| --- | ---: | ---: | ---: |
| Boot time (ms) | 149.12 | 567.44 | 418.32 |
| Steady-state score | 16006.97 | 11781.50 | 4225.47 |
| Control-plane p99 (ms) | 16.77 | 35.23 | 18.46 |
| Isolation score | 92.04 | 81.04 | 11.00 |
| Reliability score | 93.72 | 82.72 | 11.00 |
| Operations score | 96.00 | 77.00 | 19.00 |

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | hybrid | 149.12 | 14726.41 | 15.93 | backend=software_dbt; target=host; evidence_mode=hybrid |
| steady_state | uvm | hybrid | 131.23 | 16006.97 | 16.77 | backend=software_dbt; target=host; evidence_mode=hybrid |
| migration_pressure | uvm | hybrid | 167.01 | 13445.85 | 20.79 | backend=software_dbt; target=host; evidence_mode=hybrid |
| fault_recovery | uvm | hybrid | 175.96 | 12165.30 | 21.80 | backend=software_dbt; target=host; evidence_mode=hybrid |
| cold_boot | qemu | hybrid | 567.44 | 10838.98 | 33.47 | backend=qemu-tcg-x86_64; target=host; evidence_mode=hybrid |
| steady_state | qemu | hybrid | 499.35 | 11781.50 | 35.23 | backend=qemu-tcg-x86_64; target=host; evidence_mode=hybrid |
| migration_pressure | qemu | hybrid | 635.53 | 9896.46 | 43.69 | backend=qemu-tcg-x86_64; target=host; evidence_mode=hybrid |
| fault_recovery | qemu | hybrid | 669.58 | 8953.94 | 45.80 | backend=qemu-tcg-x86_64; target=host; evidence_mode=hybrid |

## Stress phases

| Phase | Iterations | Success rate | P99 latency (ms) | Pressure score | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| launch_storm | 4000 | 98.60% | 46.66 | 60.20 | Exercises preflight, placement, command synthesis, and runtime admission saturation. |
| dirty_page_churn | 2000 | 97.68% | 62.17 | 60.00 | Exercises migration convergence logic, checkpoint tracking, and I/O-heavy memory dirtiness budgets. |
| control_plane_flap | 1000 | 99.20% | 27.56 | 44.20 | Exercises reconciliation, telemetry ingestion, and idempotent action replay under repeated desired-state churn. |

## Engine notes

### UVM

- Result assumes UVM uses prevalidated placement, launch digests, heartbeat telemetry, and migration-budget gating.
- Current native evidence comes from a UVM-owned interpreted guest ISA plus instruction tracing for boot/control flows; it is not yet a full guest-ISA execution engine comparable to QEMU TCG.
- Software-backend or restricted-environment comparison cannot promote superiority claims beyond research_only until direct benchmark evidence exists.
- Direct hypervisor measurement blockers present: nested virtualization is unavailable, preventing direct in-container hardware-backed VM execution; container-restricted environment blocks privileged accelerator access such as /dev/kvm and Apple Virtualization.framework.
- Direct benchmark evidence is missing; faster-than-KVM and similar superiority claims remain prohibited

### QEMU

- QEMU baseline models a conventional general-purpose emulator/hypervisor path with heavier device-model and operational overhead.
- Direct hypervisor measurement blockers present: nested virtualization is unavailable, preventing direct in-container hardware-backed VM execution; container-restricted environment blocks privileged accelerator access such as /dev/kvm and Apple Virtualization.framework.

## Direct blockers

- nested virtualization is unavailable, preventing direct in-container hardware-backed VM execution
- container-restricted environment blocks privileged accelerator access such as /dev/kvm and Apple Virtualization.framework

## Strongest workarounds

- exercise the full admission, launch, migration, and fault-planning stack with simulation inputs while preserving backend-specific contracts
- use modeled validation for security, placement, reliability, and operational control; rerun the same harness on privileged hosts for direct hypervisor measurements

## Isolation attestation

- Backend: `software_dbt`
- Measurement mode: `hybrid`
- Verdict: `below_commercial_vps_like_minimum`
- Commercial VPS-like minimum evidence met: `false`
- Certification status: no_third_party_certification_claimed; this is a first-party engineering attestation only

| Control | Status | Evidence source | Detail |
| --- | --- | --- | --- |
| deny_by_default_backend_selection_contract | satisfied | modeled | backend selection and guardrails are enforced by deterministic UVM contract logic |
| runtime_heartbeat_and_exit_visibility | satisfied | modeled | runtime heartbeat, health, PID, and exit visibility are part of the node-plane runtime contract |
| checkpoint_digest_integrity_contract | satisfied | modeled | checkpoint/migration envelope digests and idempotency contracts are enforced in UVM planning and runtime APIs |
| direct_accelerator_isolation_evidence | missing | direct | direct host evidence does not confirm hardware-backed nested virtualization isolation |
| non_container_restricted_execution_envelope | missing | direct | validation run is container-restricted; strong hardware isolation evidence is incomplete |
| backend_eligible_for_commercial_vps_like_minimum | missing | modeled | software_dbt backend remains valid for restricted-environment validation but does not satisfy minimum commercial VPS-like isolation evidence by itself |

### Isolation blockers

- direct_accelerator_isolation_evidence: direct host evidence does not confirm hardware-backed nested virtualization isolation
- non_container_restricted_execution_envelope: validation run is container-restricted; strong hardware isolation evidence is incomplete
- backend_eligible_for_commercial_vps_like_minimum: software_dbt backend remains valid for restricted-environment validation but does not satisfy minimum commercial VPS-like isolation evidence by itself
- nested virtualization is unavailable, preventing direct in-container hardware-backed VM execution
- container-restricted environment blocks privileged accelerator access such as /dev/kvm and Apple Virtualization.framework

### Isolation next actions

- run validation on a host with direct accelerator evidence (/dev/kvm or equivalent) and nested virtualization access
- rerun on a non-container-restricted host class for isolation attestation closure
- promote the same runtime/session contracts to a hardware-backed backend run for commercial VPS-like isolation evidence
- clear environment probe blockers before promoting isolation posture claims

## Fault injection

- Recovery success rate: 99.60%
- Mean recovery time: 42.00 ms
- Injected faults: runtime heartbeat stall, launch artifact corruption, migration convergence failure, backend health degradation, checkpoint digest mismatch
- Notes: Fault injection was executed against the control/runtime planning and recovery model rather than a live nested hypervisor process because nested virtualization is unavailable.

