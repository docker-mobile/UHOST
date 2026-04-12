# uhost-svc-lifecycle

Purpose:

- Own migrations, rollout plans, maintenance windows, repair jobs, plugins, and background tasks.
- Persist rollout workflow state and workflow-backed dead-letter repair handling for long-running lifecycle operations.

Primary endpoints:

- `GET /lifecycle`
- `GET/POST /lifecycle/migrations`
- `POST /lifecycle/migrations/apply`
- `GET /lifecycle/integrity`
- `GET /lifecycle/summary`
- `GET/POST /lifecycle/rollout-plans`
- `POST /lifecycle/rollout-plans/{rollout_id}/start`
- `POST /lifecycle/rollout-plans/{rollout_id}/advance`
- `POST /lifecycle/rollout-plans/{rollout_id}/pause`
- `POST /lifecycle/rollout-plans/{rollout_id}/resume`
- `POST /lifecycle/rollout-plans/{rollout_id}/rollback`
- `GET/POST /lifecycle/maintenance`
- `GET /lifecycle/repair-jobs`
- `POST /lifecycle/repair-jobs/{repair_job_id}/confirm`
- `GET/POST /lifecycle/plugins`
- `GET/POST /lifecycle/event-subscriptions`
- `GET/POST /lifecycle/background-tasks`
- `GET /lifecycle/compatibility-policy`
- `GET/POST /lifecycle/dead-letters`
- `POST /lifecycle/dead-letter/replay`
- `GET /lifecycle/outbox`

State files:

- `lifecycle/migrations.json`
- `lifecycle/rollouts.json`
- `lifecycle/rollout_workflows.json`
- `lifecycle/maintenance.json`
- `lifecycle/dead_letters.json`
- `lifecycle/repair_jobs.json`
- `lifecycle/repair_job_workflows.json`
- `lifecycle/plugins.json`
- `lifecycle/extension_subscriptions.json`
- `lifecycle/background_tasks.json`
- `lifecycle/audit.log`
- `lifecycle/outbox.json`

Operational notes:

- The service reads `governance/change_requests.json` to keep lifecycle actions aligned with governance approvals.
- Rollout workflow state is persisted separately from rollout-plan documents for crash-safe progression.
- Dead-letter replay queues durable repair workflows and requires explicit downstream confirmation before a repair job becomes `completed`.
