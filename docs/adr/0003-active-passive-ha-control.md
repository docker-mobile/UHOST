# ADR 0003: Active-Passive HA Control Flows

Status: accepted

Decision:

- Implement active-passive control with explicit node roles, leader leases, and replication status checks in `uhost-svc-ha`.
- Require replication-health and lag gates before failover.
- Support DR drills through the same orchestration path with drill metadata.

Rationale:

- Active-passive is operationally simpler and safer as a default baseline.
- Centralized checks reduce split-brain risk by requiring healthy passive readiness.
- Drill support allows continuous verification without production cutover.

Consequences:

- Failover operations are blocked when replication status is stale or unhealthy.
- Dependency matrix state influences degraded-mode signaling.
