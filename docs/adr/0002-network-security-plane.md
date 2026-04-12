# ADR 0002: Dedicated Network Security Plane

Status: accepted

Decision:

- Add a dedicated `uhost-svc-netsec` service for deny-by-default policy evaluation.
- Persist policies, IP sets, private networks, egress controls, and flow audit records in service-owned stores.
- Expose a policy verification endpoint used by operator and CI tools.

Rationale:

- Keeps security controls isolated from ingress/runtime implementation details.
- Supports incremental migration from all-in-one storage to distributed policy engines.
- Provides explicit audit evidence for each allow/deny decision.

Consequences:

- All egress posture changes now flow through `netsec` API contracts.
- Flow audit volume will grow with traffic and must be included in retention planning.
