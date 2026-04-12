# Failover Drill Runbook

This runbook validates the current active-passive HA flow without waiting for a
real outage.

## Purpose

- Prove that the passive side is promotable.
- Verify operator readiness and evidence capture.
- Detect replication or quorum drift before an incident.

## Scope

Use this for scheduled drills against the current HA baseline. It does not
claim multi-cell or hyperscaler-grade autonomous failover.

## Preconditions

1. Identify the active node and the intended passive target.
2. Confirm you have an operator token with HA privileges.
3. Confirm no higher-priority maintenance or incident is already in progress.

## Pre-Checks

1. Confirm role health:

```text
GET /ha/roles
```

2. Confirm replication lag is within policy:

```text
GET /ha/replication-status
```

3. Confirm quorum is healthy:

```text
GET /ha/quorum-summary
```

4. Confirm degraded mode is not already masking a deeper failure:

```text
GET /ha/degraded-mode
```

5. Run preflight admission:

```text
POST /ha/failover-preflight
```

Verify `allowed=true` before continuing.

## Drill Execution

1. Trigger the drill:

```bash
uhostctl dr drill --from <active_node_id> --to <passive_node_id> --reason "scheduled drill"
```

2. Watch the operation through `GET /ha/failovers`.
3. Inspect `GET /ha/outbox` for emitted drill events matching
   `ha.failover.drill.*.v1`.

## Post-Drill Validation

1. Confirm health and readiness on the promoted side.
2. Confirm no unexpected maintenance flags remain enabled.
3. Confirm quorum is restored if any members were cordoned during the drill.
4. Record the outcome, duration, and any operator confusion or manual steps
   discovered during the drill.

## Evidence To Retain

- preflight result,
- failover record,
- relevant outbox messages,
- operator timeline,
- follow-up actions for any unexpected manual repair.

## Related Docs

- [Backup and Restore Runbook](backup-restore.md)
- [Incident Response Guide](incident-response.md)
- [On-Call Playbook](on-call.md)
- [Threat Model](../threat-model.md)
