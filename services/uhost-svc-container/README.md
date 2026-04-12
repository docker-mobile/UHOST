# uhost-svc-container

Purpose:

- Own file-backed node-pool, cluster, and container workload documents for the beta container control surface.
- Provide orchestration endpoints that admit node pools, bind clusters onto them, attach workloads, and summarize declared capacity.

Primary endpoints:

- `GET /container`
- `GET/POST /container/node-pools`
- `GET/DELETE /container/node-pools/{node_pool_id}`
- `GET/POST /container/clusters`
- `GET/DELETE /container/clusters/{cluster_id}`
- `GET/POST /container/workloads`
- `GET/DELETE /container/workloads/{workload_id}`
- `GET /container/reconciliations`
- `POST /container/reconcile`
- `GET /container/outbox`
- `GET /container/summary`

State files:

- `container/audit.log`
- `container/node_pools.json`
- `container/clusters.json`
- `container/workloads.json`
- `container/reconciliations.json`
- `container/outbox.json`

Operational notes:

- Clusters now bind to durable node-pool resources instead of carrying scheduler placement as create-time placeholders.
- Service startup normalizes older cluster-only scheduler placeholders into node-pool records and backfills the cluster binding so reopen remains idempotent across legacy state.
- Node-pool deletes are guarded while any active cluster still references the pool.
- Cluster deletes are guarded while active workloads still reference the cluster.
- Create and read responses include `ETag` and `x-record-version` headers so future integrators can layer optimistic concurrency on top of the persisted records.
- Workload admission and retirement now write durable reconciliation records plus replay-safe audit and outbox events keyed by the reconciliation digest.
- Service startup and `POST /container/reconcile` both replay the reconciler idempotently, backfilling a missing audit or outbox side record without duplicating the other.
