# UVM Validation Report

- Generated at: 2026-04-12 17:56:14.926392123 +00:00:00
- Target: `apple_mac_studio_m1_pro_sim`
- Guest architecture: `aarch64`
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
| Boot time (ms) | 515.98 | 2478.38 | 1962.40 |
| Steady-state score | 5270.06 | 2917.80 | 2352.26 |
| Control-plane p99 (ms) | 32.55 | 68.39 | 35.84 |
| Isolation score | 92.04 | 81.04 | 11.00 |
| Reliability score | 92.53 | 81.53 | 11.00 |
| Operations score | 96.00 | 77.00 | 19.00 |

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | hybrid | 515.98 | 4848.46 | 30.92 | backend=apple_virtualization; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| steady_state | uvm | hybrid | 454.06 | 5270.06 | 32.55 | backend=apple_virtualization; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| migration_pressure | uvm | hybrid | 577.89 | 4426.85 | 40.36 | backend=apple_virtualization; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| fault_recovery | uvm | hybrid | 608.85 | 4005.25 | 42.32 | backend=apple_virtualization; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| cold_boot | qemu | hybrid | 2478.38 | 2684.38 | 64.97 | backend=qemu-tcg-aarch64; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| steady_state | qemu | hybrid | 2180.97 | 2917.80 | 68.39 | backend=qemu-tcg-aarch64; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| migration_pressure | qemu | hybrid | 2775.78 | 2450.96 | 84.81 | backend=qemu-tcg-aarch64; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |
| fault_recovery | qemu | hybrid | 2924.48 | 2217.53 | 88.91 | backend=qemu-tcg-aarch64; target=apple_mac_studio_m1_pro_sim; evidence_mode=hybrid |

## Stress phases

| Phase | Iterations | Success rate | P99 latency (ms) | Pressure score | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| launch_storm | 4000 | 98.28% | 87.01 | 60.20 | Exercises preflight, placement, command synthesis, and runtime admission saturation. |
| dirty_page_churn | 2000 | 97.24% | 116.92 | 60.00 | Exercises migration convergence logic, checkpoint tracking, and I/O-heavy memory dirtiness budgets. |
| control_plane_flap | 1000 | 98.92% | 53.49 | 51.40 | Exercises reconciliation, telemetry ingestion, and idempotent action replay under repeated desired-state churn. |

## Engine notes

### UVM

- Result assumes UVM uses prevalidated placement, launch digests, heartbeat telemetry, and migration-budget gating.
- Current native evidence comes from a UVM-owned interpreted guest ISA plus instruction tracing for boot/control flows; it is not yet a full guest-ISA execution engine comparable to QEMU TCG.
- Software-backend or restricted-environment comparison cannot promote superiority claims beyond research_only until direct benchmark evidence exists.
- Apple target remains a simulation path unless the harness runs on macOS with Apple Virtualization.framework access and valid guest artifacts.
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

- Backend: `apple_virtualization`
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
| backend_eligible_for_commercial_vps_like_minimum | missing | direct | backend selection is eligible, but direct evidence mode is not available for this run |

### Isolation blockers

- direct_accelerator_isolation_evidence: direct host evidence does not confirm hardware-backed nested virtualization isolation
- non_container_restricted_execution_envelope: validation run is container-restricted; strong hardware isolation evidence is incomplete
- backend_eligible_for_commercial_vps_like_minimum: backend selection is eligible, but direct evidence mode is not available for this run
- nested virtualization is unavailable, preventing direct in-container hardware-backed VM execution
- container-restricted environment blocks privileged accelerator access such as /dev/kvm and Apple Virtualization.framework

### Isolation next actions

- run validation on a host with direct accelerator evidence (/dev/kvm or equivalent) and nested virtualization access
- rerun on a non-container-restricted host class for isolation attestation closure
- clear environment probe blockers before promoting isolation posture claims

## Fault injection

- Recovery success rate: 97.40%
- Mean recovery time: 133.00 ms
- Injected faults: runtime heartbeat stall, launch artifact corruption, migration convergence failure, backend health degradation, checkpoint digest mismatch
- Notes: Fault injection was executed against the control/runtime planning and recovery model rather than a live nested hypervisor process because nested virtualization is unavailable.; Apple guest recovery remains simulated because Apple virtualization APIs and macOS guest images are unavailable on non-macOS hosts.

