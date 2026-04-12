# uhost-svc-policy

Purpose:

- Own policy documents, approval records, and policy-evaluation entrypoints.
- Provide a file-backed policy plane that other services can call synchronously.

Primary endpoints:

- `GET /policy`
- `GET /policy/summary`
- `GET /policy/outbox`
- `GET/POST /policy/policies`
- `GET/POST /policy/approvals`
- `POST /policy/evaluate`

State files:

- `policy/policies.json`
- `policy/approvals.json`
- `policy/audit.log`
- `policy/outbox.json`

Operational notes:

- Evaluation depends on the stored policy and approval documents rather than transient in-memory state.
- Policy mutations, approval mutations, and evaluations append durable audit/outbox events for downstream explainability and reconciliation.
