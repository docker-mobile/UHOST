# uhost-svc-notify

Purpose:

- Own webhook endpoints, templates, preferences, alert routes, notification messages, and dead letters.
- Provide delivery, retry, and dispatch-sweep controls for platform notifications.

Primary endpoints:

- `GET /notify`
- `GET /notify/summary`
- `GET/POST /notify/webhook-endpoints`
- `POST /notify/webhook-endpoints/{endpoint_id}/rotate-secret`
- `GET/POST /notify/templates`
- `GET/POST /notify/preferences`
- `GET/POST /notify/alert-routes`
- `POST /notify/alerts/trigger`
- `GET/POST /notify/messages`
- `GET /notify/messages/{notification_id}/history`
- `POST /notify/messages/{notification_id}/acknowledge`
- `POST /notify/messages/{notification_id}/snooze`
- `POST /notify/messages/{notification_id}/escalate`
- `POST /notify/messages/{notification_id}/deliver`
- `POST /notify/messages/{notification_id}/retry`
- `POST /notify/dispatch`
- `GET /notify/dead-letters`
- `POST /notify/dead-letters/{dead_letter_id}/replay`
- `GET /notify/outbox`

State files:

- `notify/webhook_endpoints.json`
- `notify/templates.json`
- `notify/preferences.json`
- `notify/alert_routes.json`
- `notify/notifications.json`
- `notify/dead_letters.json`
- `notify/audit.log`
- `notify/outbox.json`

Operational notes:

- Webhook secrets are rotated through an explicit endpoint instead of in-place mutation.
- Delivery, retry, acknowledgement, snooze, escalation, and dead-letter replay state remain durable and auditable.
- Message history retains optional `case_reference` links so support/remediation lanes can stitch notify evidence back to operator cases.
