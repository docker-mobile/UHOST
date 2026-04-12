# uhost-svc-billing

Purpose:

- Own billing accounts, subscriptions, invoices, budgets, budget burn, budget notifications,
  support entitlements, and provider-sync task records.
- Track external billing-provider reconciliation work in the current beta runtime.
- Enforce soft and hard spend caps with durable burn tracking and threshold notifications.

Primary endpoints:

- `GET /billing`
- `GET /billing/summary`
- `GET/POST /billing/accounts`
- `GET /billing/support-entitlements`
- `GET/POST /billing/budgets`
- `GET /billing/budget-burn`
- `GET /billing/budget-notifications`
- `GET/POST /billing/subscriptions`
- `GET/POST /billing/invoices`
- `GET /billing/provider-sync`
- `POST /billing/provider-sync/{sync_id}/deliver`
- `GET /billing/owner-summaries`

State files:

- `billing/accounts.json`
- `billing/support_entitlements.json`
- `billing/budgets.json`
- `billing/budget_burn.json`
- `billing/budget_notifications.json`
- `billing/subscriptions.json`
- `billing/invoices.json`
- `billing/provider_sync.json`

Operational notes:

- Provider-sync documents act as the file-backed delivery queue for external reconciliation.
- Budget records are first-class resources bound to billing accounts and track threshold
  percentages plus soft or hard cap behavior.
- Account and subscription creation automatically provision durable support-entitlement anchors
  with plan-derived support tier, channels, and initial-response SLA targets.
- Invoice admission updates durable burn records; soft caps admit spend while emitting
  notifications, and hard caps reject spend while persisting a blocked notification.
- Owner summaries aggregate the active billing state per `owner_id` for operator dashboards without claiming additional automation.
- Billing persists provider sync and spend state directly in service-local collections rather than a separate audit/outbox pair.
