# Storage Drill Evidence

- Generated at: `2026-04-12T17:25:06.224278645Z`
- Generator command: `bash scripts/run-storage-drill-evidence.sh`
- Database id: `dbs_iug6aghxvosrrekmli2hajy2jleva`
- Backing volume id: `vol_snhoeghxvosrrc3b2tg2iciwkjwae`
- Backup id: `aud_owoyigxxvosrrb6nii3mefiznxq6c`
- Restore id: `aud_ifiyqhhxvosrruase4feudk74sbla`
- Restore state: `completed`
- Storage restore action id: `aud_ozlxchpxvosrrdmjb22encvhjsh7i`
- Storage restore workflow id: `aud_ozlxchpxvosrrdmjb22encvhjsh7i`
- Storage restore source mode: `backup_correlated_storage_lineage`
- Active node id: `nod_hbnzmixxvosrq7slliupkugsirgbs`
- Passive node id: `nod_xgazmixxvosrqtl7f2grqqt4es6yo`
- Preflight allowed: `true`
- Replication lag seconds: `2`
- Failover drill id: `fov_n5isojpxvosrqhsxau3yyeoerjwj2`
- Failover state: `completed`
- Failover operation kind: `drill`

## Verification

| Binding | Path | SHA-256 | Notes |
| --- | --- | --- | --- |
| Focused gate | `ci/check-storage-drill-evidence.sh` | `1f9bba8a3068635bfd0120167973fe2ddd820953525f407779c2735946585d91` | Runs `storage_drill_generated_artifact_is_present_and_fresh` |
| Integration test | `cmd/uhostd/tests/storage_drill_evidence.rs` | `6311fbffa54f45b160211c8e74a29beba07a37155a1eca863900cf42705b100b` | Exercises `combined_storage_drill_rehearsal_exercises_restore_replication_and_failover` |

## Outbox Event Types

- Data outbox event types: `data.database.backup.completed.v1`, `data.database.created.v1`, `data.database.restore.completed.v1`
- HA outbox event types: `ha.failover.drill.completed.v1`, `ha.failover.drill.started.v1`, `ha.quorum.updated.v1`, `ha.replication.updated.v1`, `ha.role.updated.v1`
