# uhost-svc-observe

Purpose:

- Own alert rules, activity records, OTLP sinks, SLOs, alert routes, slow-path records, and incidents.
- Provide operator-facing read models such as error budgets and exemplars.

Primary endpoints:

- `GET /observe`
- `GET/POST /observe/alert-rules`
- `GET/POST /observe/activity`
- `GET/POST /observe/otlp-exporters`
- `GET/POST /observe/otlp-dispatch`
- `GET/POST /observe/slos`
- `GET /observe/error-budgets`
- `GET /observe/node-health`
- `GET /observe/fleet-ops-rollups`
- `GET/POST /observe/alert-routes`
- `GET/POST /observe/slow-paths`
- `GET /observe/exemplars`
- `GET /observe/incidents`
- `POST /observe/incidents/evaluate`
- `POST /observe/incidents/{incident_id}/resolve`
- `GET /observe/summary`

State files:

- `observe/alert_rules.json`
- `observe/activity.json`
- `observe/otlp_exporters.json`
- `observe/otlp_dispatch.json`
- `observe/slos.json`
- `observe/alert_routes.json`
- `observe/slow_paths.json`
- `observe/incidents.json`

Operational notes:

- Error-budget and exemplar responses are derived views rather than separate persisted collections.
- `GET /observe/node-health` derives a same-host node summary from the sibling `node/` service state files; when direct node heartbeats are absent, those records can include heartbeat rows synthesized from UVM runtime session state.
- `GET /observe/fleet-ops-rollups` derives regional and cell rollups from sibling `runtime/`, `ha/`, `lifecycle/`, and `data/` state files for HA readiness, incident scope, and backlog health.
- Observe keeps durable document collections plus derived read models; it does not emit a separate observe-specific audit/outbox stream in beta.
