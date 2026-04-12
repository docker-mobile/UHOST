# uhost-svc-dns

Purpose:

- Own DNS zone, record, and provider-task state.
- Track explicit zone verification before downstream services rely on a zone.

Primary endpoints:

- `GET /dns`
- `GET /dns/summary`
- `GET/POST /dns/zones`
- `POST /dns/zones/{zone_id}/verify`
- `GET/POST /dns/records`
- `GET/POST /dns/publication-intents`
- `GET /dns/publication-intents/delivery`
- `GET /dns/provider-tasks`
- `GET /dns/outbox`
- `POST /dns/provider-tasks/{task_id}/deliver`
- `POST /dns/provider-tasks/{task_id}/fail`

State files:

- `dns/zones.json`
- `dns/records.json`
- `dns/publication_intents.json`
- `dns/provider_tasks.json`
- `dns/audit.log`
- `dns/outbox.json`

Operational notes:

- Zone verification is an explicit prerequisite for downstream mail-auth reconciliation.
- Provider-task documents model external DNS delivery and retry work in the beta runtime.
- Zone, record, publication-intent, and provider-task delivery mutations append durable audit/outbox events for downstream reconciliation.
- Publication intents are first-class steerable alias plans: `weighted`, `priority`, `geo`, and `latency` answers are validated before persistence and mirrored into provider-task payloads.
- Alias answers may carry optional health-check hints (`http`, `https`, or `tcp`) so downstream DNS delivery can express failover eligibility without flattening everything into raw records.
- Publication-intent delivery is no longer enqueue-only: provider tasks now surface `pending`, `retry_pending`, `failed`, and `delivered` state with attempt/error metadata, and `/dns/publication-intents/delivery` projects those states back onto the intent surface.
