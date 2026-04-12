# uhost-svc-data

Purpose:

- Own managed database, cache, and queue inventory.
- Track backup, restore, failover, and maintenance workflows for data services.

Primary endpoints:

- `GET /data`
- `GET/POST /data/databases`
- `GET /data/databases/{database_id}`
- `POST /data/databases/{database_id}/backups`
- `POST /data/databases/{database_id}/restore`
- `POST /data/databases/{database_id}/failover`
- `POST /data/databases/{database_id}/maintenance`
- `POST /data/databases/{database_id}/migrations`
- `POST /data/databases/{database_id}/exports`
- `POST /data/databases/imports`
- `GET /data/backups`
- `GET /data/backups/{backup_id}/storage-lineage`
- `GET /data/restores`
- `GET /data/restores/{restore_id}/storage-lineage`
- `GET /data/failovers`
- `GET /data/exports`
- `GET /data/imports`
- `GET /data/migrations`
- `GET /data/migrations/{migration_id}`
- `POST /data/migrations/{migration_id}/start`
- `POST /data/migrations/{migration_id}/complete`
- `POST /data/migrations/{migration_id}/fail`
- `GET/POST /data/caches`
- `POST /data/caches/{cache_id}/exports`
- `POST /data/caches/imports`
- `GET/POST /data/queues`
- `POST /data/queues/{queue_id}/exports`
- `POST /data/queues/imports`
- `GET /data/durability-summary`
- `GET /data/outbox`

State files:

- `data/databases.json`
- `data/caches.json`
- `data/queues.json`
- `data/backups.json`
- `data/backup_workflows.json`
- `data/restores.json`
- `data/restore_workflows.json`
- `data/failovers.json`
- `data/failover_workflows.json`
- `data/migrations.json`
- `data/exports.json`
- `data/imports.json`
- `data/audit.log`
- `data/outbox.json`

Operational notes:

- Backup and restore lineage endpoints project durable storage relationships for operators.
- Backup, restore, and failover writes create durable workflow instances first and then sync `backups.json`, `restores.json`, and `failovers.json` as public projections.
- Workflow state keeps replayable per-step evidence and backfills legacy job projections on startup.
- Migration workflows cover major-version upgrades, region moves, replica reseeding, and storage-class changes with pending/running/completed/failed job states.
- Import/export flows persist signed manifests plus checksum catalogs for databases, caches, and queues so verified bundles can be staged before restore-from-import work.
- Mutating operations append audit entries and durable outbox messages.
