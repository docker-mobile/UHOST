# uhost-svc-ha

Purpose:

- Own active/passive role state, leader lease state, and replication health records.
- Coordinate failover, evacuation, drills, reconciliation, and degraded-mode decisions.

Primary endpoints:

- `GET /ha`
- `GET/POST /ha/roles`
- `GET/POST /ha/leader-lease`
- `GET/POST /ha/replication-status`
- `GET/POST /ha/regional-quorum`
- `GET/POST /ha/consensus-log`
- `GET/POST /ha/replication-shipping`
- `GET /ha/reconciliations`
- `POST /ha/reconcile`
- `GET /ha/quorum-summary`
- `GET /ha/failovers`
- `POST /ha/failover`
- `POST /ha/failover-preflight`
- `POST /ha/evacuation`
- `POST /ha/drills`
- `GET/POST /ha/dependency-matrix`
- `GET /ha/degraded-mode`
- `GET /ha/readiness-summary`
- `GET /ha/outbox`

State files:

- `ha/roles.json`
- `ha/leader_lease.json`
- `ha/replication_status.json`
- `ha/failovers.json`
- `ha/failover_workflows.json`
- `ha/repair_workflows.json`
- `ha/regional_quorum.json`
- `ha/consensus_log.json`
- `ha/replication_shipments.json`
- `ha/reconciliations.json`
- `ha/dependencies.json`
- `ha/audit.log`
- `ha/outbox.json`

Operational notes:

- Failover admission stays deny-by-default and depends on replication, quorum, and dependency checks.
- Failover, evacuation, and drill mutations now create a pending HA workflow first and then persist each checkpoint in sequence before projecting the public `ha/failovers.json` view.
- Pending and running entries in `ha/failover_workflows.json` now carry `runner_claim` plus `next_attempt_at` so one fenced HA controller path can heartbeat or take over explicit workflow execution.
- The execution and completion steps in `ha/failover_workflows.json` now persist per-step effect journals with reusable idempotency keys/result digests so started-event emission, role cutover, drill recording, and completion-event emission can replay without duplicating durable side effects.
- Reconciliation, failover, and drill state is durable and outbox-backed for later relay.
- Evacuation workflows persist route-withdrawal, target-readiness, and rollback artifacts at the dedicated evacuation-artifact checkpoint before the cutover step becomes active.
