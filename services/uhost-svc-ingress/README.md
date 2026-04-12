# uhost-svc-ingress

Purpose:

- Own ingress route definitions, resolution decisions, and flow-audit records.
- Bridge ingress policy with DNS and netsec state in the beta runtime.

Primary endpoints:

- `GET /ingress`
- `GET/POST /ingress/routes`
- `GET /ingress/routes/{route_id}`
- `POST /ingress/routes/{route_id}/health-report`
- `POST /ingress/routes/{route_id}/circuit-event`
- `POST /ingress/resolve`
- `POST /ingress/evaluate`
- `GET /ingress/flow-audit`
- `GET /ingress/flow-audit/summary`
- `GET /ingress/summary`
- `GET /ingress/outbox`

State files:

- `ingress/routes.json`
- `ingress/flow_audit.json`
- `ingress/audit.log`
- `ingress/outbox.json`

Operational notes:

- Route evaluation reads DNS zones plus netsec inspection-profile and private-network state.
- Resolution and evaluation decisions are recorded into the flow-audit collection.
- Steering audits persist explicit `steering_denial_reason`, `selected_locality`, and `selected_canary_pool` fields so locality and canary choices stay visible after the request completes.
