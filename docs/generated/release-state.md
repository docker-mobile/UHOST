# Release State

- Generated at: `2026-04-10T10:27:16Z`
- Generator command: `bash scripts/generate-release-state.sh`
- Git revision: `164892cb063248fcdb3aa8049a60acf98e6b5793`
- Git tree dirty: `true`

## Contracts

| Contract | Path | SHA-256 | Lines |
| --- | --- | --- | ---: |
| OpenAPI | `openapi/control-plane-v1.yaml` | `7eb472dd7e1c518ab8ca68451a46965c0ac6c56ebd38734f44f8d28d49967462` | 9554 |
| Protobuf | `proto/control-plane-v1.proto` | `cb1653d3daf1f49e58661241dd98c4ec95ce6fefa4f1a4144dff6a6c77923d37` | 4394 |

## Evidence

| Artifact | Path | Generated at | SHA-256 |
| --- | --- | --- | --- |
| UVM stack manifest (`wave3-core-generated-benchmark-evidence`) | `docs/benchmarks/generated/uvm-stack-validation-manifest.json` | `2026-04-09 16:07:10 +00:00:00` | `7c539877c6861f3b99a95372074d49741dfd6ff26a6dc68dddcd343de44e8511` |
| Host validation report | `docs/benchmarks/generated/host-validation.md` | `2026-04-09 16:05:49.447659995 +00:00:00` | `1d5710800baa10f7078f716b88156e1af037d60a14d3176ca68bb374f24582de` |

## Operator/Evidence Surfaces

| Surface | Path | Endpoint | Notes | Available |
| --- | --- | --- | --- | --- |
| UVM observe summary | `services/uhost-svc-uvm-observe/src/lib.rs` | `/uvm/observe/summary` | Claim/evidence summary upheld in UVM observe stores | true |
| Secrets summary | `services/uhost-svc-secrets/src/lib.rs` | `/secrets/summary` | Secret/version/ownership totals from encrypted secret records | true |
| Stream summary | `services/uhost-svc-stream/src/lib.rs` | `/stream/summary` | Managed stream, replay-log, and subscriber-lag summary from stream records | true |
| Scheduler summary | `services/uhost-svc-scheduler/src/lib.rs` | `/scheduler/summary` | Inventory and placement totals from scheduler state documents | true |
| UVM control summary | `services/uhost-svc-uvm-control/src/lib.rs` | `/uvm/control/summary` | Template/instance state and claim/backend summary from control-plane records | true |
| Billing owner summaries | `services/uhost-svc-billing/src/lib.rs` | `/billing/owner-summaries` | Tenant-to-account linkage summary from billing records | true |
| Control summary | `services/uhost-svc-control/src/lib.rs` | `/control/summary` | Workload placement overview from control service records | true |
| Observe node-health | `services/uhost-svc-observe/src/lib.rs` | `/observe/node-health` | Node heartbeat + process-report summary from node stores | true |
| Billing summary | `services/uhost-svc-billing/src/lib.rs` | `/billing/summary` | Account/subscription/invoice/provider-sync totals from billing records | true |
| Identity summary | `services/uhost-svc-identity/src/lib.rs` | `/identity/summary` | Principal/session overview from identity stores | true |
| Console status | `services/uhost-svc-console/src/lib.rs` | `/console/status` | Console dashboard snapshot derived from state-root counts | true |
| HA readiness | `services/uhost-svc-ha/src/lib.rs` | `/ha/readiness-summary` | Role/replication/failover assessment recorded in HA stores | true |

## Host Validation Summary

- Measurement mode: `hybrid`
- Execution environment: `container_restricted`
- UVM claim tier: `research_only`
- QEMU claim tier: `compatible`

## Source Of Truth Policy

- Keep mutable verification state in generated artifacts.
- Link human docs to this file instead of maintaining manual command-history blocks.
