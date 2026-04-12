# Beginner Operator Maintenance Guide

This guide is for first-time operators running the beta all-in-one baseline.
It is intentionally conservative and favors repeatable checks over deep manual
intervention.

## Purpose

- Keep a single-node deployment healthy.
- Catch obvious drift before it becomes recovery work.
- Give new operators a safe default routine.

## Daily Checklist

1. Check daemon health:

```bash
curl -sS http://127.0.0.1:9080/healthz
```

2. Check the current metrics snapshot:

```bash
curl -sS http://127.0.0.1:9080/metrics
```

3. Review recent activity:

```bash
curl -sS http://127.0.0.1:9080/observe/activity
```

4. Confirm there is no unexpected degraded mode or maintenance state.

## Weekly Checklist

1. Back up `state_dir` and the active config file.
2. Review dead letters, repair jobs, and recent failure events.
3. Confirm the host still passes the profiles you rely on:

```bash
bash scripts/host-capability-preflight.sh --profile rust-ci
```

4. Rehearse one bounded recovery path, such as a restore drill or failover
   drill, in a non-production environment.

## Before Risky Changes

1. Open a governance or change record.
2. Confirm rollback input exists:
   - recent backup,
   - known-good config,
   - operator with recovery access.
3. Verify policy-sensitive changes before rollout:

```bash
uhostctl policy verify
```

4. Make sure the relevant runbook is open before starting the change.

## If Something Looks Wrong

1. Do not delete state files manually.
2. Capture current responses from:
   - `/healthz`,
   - `/metrics`,
   - `/ha/degraded-mode`,
   - the affected service endpoints.
3. Record what changed and when.
4. Move to the [Incident Response Guide](incident-response.md).

## Good Beta Hygiene

- Prefer controlled maintenance windows over live repair.
- Do not treat generated evidence as permanent truth; refresh it when the host,
  release, or workload assumptions change.
- Keep the config file and `state_dir` together in your operational inventory.
- Treat secret reveals as audited recovery actions, not as a convenience path.

## Related Docs

- [Bootstrap Runbook](bootstrap.md)
- [Backup and Restore Runbook](backup-restore.md)
- [Failover Drill Runbook](failover-drill.md)
- [Host Readiness](host-readiness.md)
- [Incident Response Guide](incident-response.md)
