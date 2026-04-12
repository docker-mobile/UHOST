# uhost-svc-control

Purpose:

- Own workload and deployment documents for the core hosting control plane.
- Audit mutating operations and emit service-local outbox records.

Primary endpoints:

- `GET /control`
- `GET /control/summary`
- `GET/POST /control/workloads`
- `GET/POST /control/deployments`
- `GET /control/outbox`

State files:

- `control/workloads.json`
- `control/deployments.json`
- `control/audit.log`
- `control/outbox.json`

Operational notes:

- Control mutations remain synchronous and file-backed in beta.
- Outbox records provide a durable handoff for downstream control-plane consumers.
