# Backup and Restore Runbook

This runbook covers the current beta baseline: a same-host `uhostd` deployment
with durable state stored under `state_dir`.

## Purpose

- Preserve service metadata, blobs, and operator evidence before risky work.
- Recover a node onto the same or a replacement host without changing the
  cryptographic root material.
- Prove that backups are restorable instead of assuming they are.

## Scope

Use this runbook for:

- planned upgrades,
- operator-created restore drills,
- emergency recovery after host loss or state corruption.

The current platform truth is still file-backed persistence. A usable backup is
therefore the combination of:

- the full `state_dir`,
- the matching config file,
- the same `secrets.master_key`,
- any release evidence required by your operating policy.

## Prerequisites

1. Identify the active config file passed to `uhostd --config`.
2. Confirm the target host has enough space for both the restored state and
   any temporary verification copies.
3. Decide whether the backup is:
   - a cold backup, taken while `uhostd` is stopped, or
   - a controlled maintenance backup, taken after writes are paused.
4. Record the reason, operator, and timestamp in your incident or change log.

## Backup Procedure

1. Stop `uhostd` or place the node into maintenance mode before copying data.
2. Copy the entire `state_dir`.
3. Copy the active config file.
4. Verify that the copied config still contains the same
   `secrets.master_key`.
5. Record the source host, config path, and backup destination.

## Restore Procedure

1. Restore `state_dir` onto the target host.
2. Restore the matching config file with the same `secrets.master_key`.
3. Start the daemon:

```bash
cargo run -p uhostd -- --config <path>
```

4. Verify the runtime responds on the expected listener.

## Verification

After a restore, confirm:

1. `GET /healthz` returns success.
2. `GET /metrics` returns a current snapshot.
3. Critical service collections load without schema drift.
4. `GET /ha/degraded-mode` matches the expected post-restore state.
5. Any required backups, restore points, or migration manifests are still
   visible through the relevant service routes.

## Restore Drill Cadence

- Run a full restore drill at least monthly in a non-production environment.
- Validate `ha` replication state and `lifecycle` migration compatibility after
  the restored node comes up.
- Export and retain audit evidence such as
  `GET /governance/audit-checkpoints`.

## Known Contract: In-Flight Full-Object Reads

The current verified `uhostd` behavior for full-object downloads is important
when responding to corruption:

- the full-object download path buffers the object into `ApiBody` before the
  client observes response headers,
- if the underlying blob is truncated after `200 OK` headers have been read,
  that in-flight request still completes with the buffered octet body,
- operators should not expect the already-started request to flip into a late
  JSON error envelope or a mid-stream EOF.

Contain first, then validate corruption with a fresh request or with a restore
drill.

## Related Docs

- [Bootstrap Runbook](bootstrap.md)
- [Incident Response Guide](incident-response.md)
- [On-Call Playbook](on-call.md)
- [Configuration Model](../config/overview.md)
