# uhost-svc-scheduler

Purpose:

- Own scheduler node inventory and placement decision documents.
- Provide the durable placement surface used by the beta control plane.

Primary endpoints:

- `GET /scheduler`
- `GET/POST /scheduler/nodes`
- `GET /scheduler/summary`
- `GET/POST /scheduler/placements`

State files:

- `scheduler/nodes.json`
- `scheduler/placements.json`

Operational notes:

- Placement documents are durable records that can be replayed and benchmarked.
- Scheduler state is intentionally compact in beta: node inventory and placement decisions are the durable records.
