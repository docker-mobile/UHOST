# uhost-svc-storage

Purpose:

- Own object-bucket, volume, file-share, archive, upload-session, and blob metadata for the storage control plane.
- Persist snapshot-policy, recovery-point, and restore-workflow records for volumes.
- Track archive rehydrate jobs that move archived inventory back into an operator-usable state.

Primary endpoints:

- `GET /storage`
- `GET /storage/summary`
- `GET/POST /storage/buckets`
- `GET/POST /storage/file-shares`
- `GET/POST /storage/volumes`
- `GET/POST /storage/archives`
- `GET/POST /storage/archive-rehydrate-jobs`
- `POST /storage/uploads`
- `PUT /storage/uploads/{upload_id}/parts/{part_number}`
- `POST /storage/uploads/{upload_id}/complete`
- `GET /storage/objects/{digest}`

State files:

- `storage/buckets.json`
- `storage/file_shares.json`
- `storage/volumes.json`
- `storage/archives.json`
- `storage/archive_rehydrate_jobs.json`
- `storage/volume_snapshot_policies.json`
- `storage/volume_snapshot_workflows.json`
- `storage/volume_recovery_points.json`
- `storage/volume_recovery_point_revisions.json`
- `storage/volume_restore_actions.json`
- `storage/volume_restore_workflows.json`
- `storage/uploads.json`
- `storage/blobs/`

Operational notes:

- Blob bodies live under `storage/blobs/` while metadata remains in JSON and workflow collections.
- Volume snapshot and restore workflow state is reconciled on startup.
