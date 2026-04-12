# uhost-svc-secrets

Purpose:

- Own encrypted secret-item records for the local control plane.
- Provide explicit create/list and reveal flows instead of raw file access.

Primary endpoints:

- `GET /secrets`
- `GET /secrets/summary`
- `GET/POST /secrets/items`
- `POST /secrets/items/{secret_id}/reveal`
- `POST /secrets/items/{secret_id}/reveal/approvals`
- `POST /secrets/items/{secret_id}/reveal/leases`
- `POST /secrets/items/{secret_id}/reveal/grants/{grant_id}`

State files:

- `secrets/secrets.json`
- `secrets/reveal_grants.json`
- `secrets/audit.log`
- `secrets/outbox.json`

Operational notes:

- Secret payloads are encrypted at rest under the configured master key.
- Direct secret reveals now emit durable audit/outbox events without recording plaintext values.
- Approval and lease routes persist durable reveal grants in `reveal_grants.json`, and the grant-backed reveal route reuses those same authorization records.
- `GET /secrets/summary` is read-only and derived from persisted active records in `secrets/secrets.json`.
