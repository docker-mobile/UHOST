# uhost-svc-console

Purpose:

- Serve the HTML console shell for `/` and `/console`.
- Publish a machine-readable same-host dashboard summary for operators.
- Render a styled console-specific not-found page for unmatched `/console/*` routes.

Primary endpoints:

- `GET /`
- `GET /console`
- `GET /console/`
- `GET /console/status`
- `GET /console/summary`
- `GET /console/*`

State files:

- None today. The service owns `console/` as its state root but does not persist collections yet.

Operational notes:

- Responses set `Cache-Control: no-store` and strict browser security headers.
- The rendered console includes the current state root plus read-only counts derived from sibling service state files.
- The operator workbench fans in approvals from `policy/` and `governance/`, grants from `governance/` and `secrets/`, quotas from `billing/`, cases from `abuse/` plus notify-linked workflow state from `notify/notifications.json`, appeals from `abuse/`, and dead letters from `notify/`, `mail/`, and `lifecycle/`.
