# uhost-svc-governance

Purpose:

- Own legal-hold, retention-policy, change-approval, and audit-checkpoint state.
- Provide tamper-evident governance controls across sensitive control-plane changes.

Primary endpoints:

- `GET /governance`
- `GET /governance/summary`
- `GET/POST /governance/legal-holds`
- `POST /governance/legal-holds/{hold_id}/release`
- `GET/POST /governance/retention-policies`
- `GET/POST /governance/change-requests`
- `POST /governance/change-requests/{change_id}/approve`
- `POST /governance/change-requests/{change_id}/reject`
- `GET /governance/change-requests/{change_id}/approvals`
- `POST /governance/change-requests/{change_id}/apply`
- `GET/POST /governance/audit-checkpoints`
- `GET /governance/audit-integrity`
- `POST /governance/retention-evaluate`
- `GET /governance/outbox`

State files:

- `governance/legal_holds.json`
- `governance/retention_policies.json`
- `governance/change_requests.json`
- `governance/change_approvals.json`
- `governance/audit_checkpoints.json`
- `governance/audit_chain_head.json`
- `governance/audit.log`
- `governance/outbox.json`

Operational notes:

- Audit checkpoints advance a tamper-evident chain head for integrity verification.
- Change requests, approvals, and apply decisions stay durable and separately attributable.
