# uhost-svc-abuse

Purpose:

- Own abuse signals, reputation state, cases, quarantines, appeals, and operator support/remediation work queues.
- Provide deny-by-default enforcement evaluation used by other control-plane domains.

Primary endpoints:

- `GET /abuse`
- `GET /abuse/summary` (aggregated counts for signals, cases, quarantines, appeals, reputations)
- `GET/POST /abuse/signals`
- `GET/POST /abuse/reputation`
- `GET/POST /abuse/cases`
- `POST /abuse/cases/{case_id}/review`
- `GET/POST /abuse/quarantines`
- `POST /abuse/quarantines/{quarantine_id}/release`
- `GET/POST /abuse/appeals`
- `POST /abuse/appeals/{appeal_id}/review`
- `GET/POST /abuse/support-cases` (operator-only support collection)
- `GET /abuse/support-cases/{id}` (operator-only support detail)
- `POST /abuse/support-cases/{id}/transition` (operator-only status/owner transition)
- `GET/POST /abuse/remediation-cases` (operator-only remediation collection)
- `GET /abuse/remediation-cases/{id}` (operator-only remediation detail)
- `POST /abuse/remediation-cases/{id}/escalate` (operator-only remediation escalation/handoff)
- `POST /abuse/evaluate`
- `GET /abuse/outbox`

State files:

- `abuse/signals.json`
- `abuse/reputation.json`
- `abuse/cases.json`
- `abuse/quarantines.json`
- `abuse/appeals.json`
- `abuse/support_cases.json`
- `abuse/remediation_cases.json`
- `abuse/audit.log`
- `abuse/outbox.json`

Operational notes:

- Quarantine and appeal state feeds other services such as mail and netsec.
- Support cases provide a first-class operator record linked to remediation cases plus governance and notify identifiers.
- Support-case transitions move `status` and `owner` through one audited operator route instead of ad hoc record rewrites.
- Remediation cases link tenant-facing recovery work to abuse cases/quarantines plus governance and notify IDs.
- Remediation cases carry operator owner, SLA target/deadline/state, escalation metadata, and required rollback/verification evidence references for support-style workflows.
- Mutating operations append audit records and durable outbox messages.
