# uhost-svc-node

Purpose:

- Own node heartbeat and process-report documents for the runtime-adjacent control path.
- Provide the node-signal surface used by the current beta runtime.

Primary endpoints:

- `GET /node`
- `GET /node/summary`
- `GET/POST /node/heartbeats`
- `GET /node/outbox`
- `GET/POST /node/process-reports`

State files:

- `node/heartbeats.json`
- `node/process_reports.json`
- `node/audit.log`
- `node/outbox.json`

Operational notes:

- Heartbeats and process reports now append events to `node/audit.log` and expose them via `node/outbox.json`.
- The new `GET /node/outbox` route lets observers, lifecycle, and HA consumers pull node-plane events without duplicating state.
- Higher-level observe views can supplement missing direct heartbeat detail with UVM-session-derived state, so node-health summaries may blend direct host records with derived runtime evidence.
