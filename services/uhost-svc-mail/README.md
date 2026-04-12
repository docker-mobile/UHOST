# uhost-svc-mail

Purpose:

- Own mail domains, relay routes, inbound routes, message events, dead letters, and reputation state.
- Reconcile mail-domain auth records against DNS and abuse state.

Primary endpoints:

- `GET /mail`
- `GET/POST /mail/domains`
- `GET /mail/auth-records`
- `POST /mail/domains/{domain_id}/verify-auth`
- `GET/POST /mail/relay-routes`
- `GET/POST /mail/inbound-routes`
- `GET/POST /mail/message-events`
- `POST /mail/message-events/{message_id}/dispatch`
- `POST /mail/message-events/{message_id}/retry`
- `POST /mail/dispatch`
- `GET /mail/dead-letters`
- `GET /mail/dead-letters/{dead_letter_id}`
- `POST /mail/dead-letters/{dead_letter_id}/replay`
- `GET /mail/reputation`
- `GET /mail/summary`
- `POST /mail/reputation/{domain_id}/adjust`
- `GET /mail/outbox`

State files:

- `mail/domains.json`
- `mail/relay_routes.json`
- `mail/inbound_routes.json`
- `mail/message_events.json`
- `mail/dead_letters.json`
- `mail/reputation.json`
- `mail/audit.log`
- `mail/outbox.json`

Operational notes:

- The service reads DNS zone, record, and provider-task state before reconciling mail DNS records.
- Mail-domain verification now gates on the latest DNS `upsert_record` delivery state for each managed auth/routing record: raw local record presence is insufficient until the DNS provider task is `delivered`, while `failed` deliveries can be re-enqueued without duplicating `pending` or `retry_pending` work.
- Reconciliation covers DKIM/SPF/DMARC plus managed MX, return-path, bounce, and inbound-route evidence records, and it prunes stale managed records when a reconcile run is requested.
- Abuse quarantine state is consulted before dispatch and replay decisions.
