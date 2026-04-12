# uhost-svc-identity

Purpose:

- Own users, sessions, API keys, and workload identities.
- Enforce password verification, suspension semantics, and durable identity indexes.

Primary endpoints:

- `GET /identity`
- `GET /identity/summary`
- `GET /identity/credential-lifecycle`
- `GET/POST /identity/users`
- `POST /identity/users/bulk`
- `GET /identity/users/{user_id}`
- `POST /identity/users/{user_id}/suspend`
- `POST /identity/users/{user_id}/reactivate`
- `POST /identity/sessions`
- `DELETE /identity/sessions/{session_id}`
- `POST /identity/api-keys`
- `POST /identity/api-keys/{api_key_id}/rotate`
- `POST /identity/api-keys/{api_key_id}/revoke`
- `GET/POST /identity/workload-identities`
- `POST /identity/workload-identities/{workload_identity_id}/rotate`
- `POST /identity/workload-identities/{workload_identity_id}/revoke`
- `GET /identity/outbox`

State files:

- `identity/users.json`
- `identity/users_by_email.json`
- `identity/sessions.json`
- `identity/api_keys.json`
- `identity/api_keys_by_secret_hash.json`
- `identity/workload_identities.json`
- `identity/workload_identities_by_subject.json`
- `identity/journal/`
- `identity/audit.log`
- `identity/outbox.json`

Operational notes:

- Email and workload-subject indexes are reconciled on startup before traffic admission.
- `GET /identity/credential-lifecycle` normalizes sessions, API keys, workload tokens, and secret-version projections into one operator-facing report.
- API key and workload-token rotation keeps superseded secret versions in lifecycle history while immediately cutting authorization over to the new credential material.
- The service implements workload bearer-token authorization for tenant routes in the runtime.
