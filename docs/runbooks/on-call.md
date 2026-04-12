# On-Call Playbook

This playbook defines the routine operating loop for the beta baseline.

## Purpose

- Catch drift early.
- Keep handoffs crisp.
- Escalate before operator guesswork becomes damage.

## Shift Start

1. Confirm alert routes:

```text
GET /observe/alert-routes
```

2. Review open maintenance windows:

```text
GET /lifecycle/maintenance
```

3. Check HA replication health and degraded mode.

## Hourly Checks

1. Review error budget burn:

```text
GET /observe/error-budgets
```

2. Review denied or suspicious network flows:

```text
GET /netsec/flow-audit
```

3. Review mail reputation changes:

```text
GET /mail/reputation
```

4. Review dead-letter backlog:

```text
GET /lifecycle/dead-letters
```

## What To Record

For any anomaly, capture:

- the endpoint checked,
- the timestamp,
- the before-and-after state,
- whether the issue is new, recurring, or already under mitigation.

## Escalation Triggers

- repeated failover attempts within one hour,
- a critical dependency marked `down` in HA state,
- error budget consumption crossing its target threshold,
- mail reputation crossing the suspension threshold,
- any operator action that would require secret reveal, emergency maintenance,
  or manual state repair.

## Storage Corruption Note

The current `uhostd` full-object download path buffers the full object before
clients observe `200 OK` headers. If a published blob is truncated after those
headers are already on the wire, that in-flight request may still complete with
the buffered octet body. Validate suspected corruption with a fresh request or
with the [Backup and Restore Runbook](backup-restore.md), not by assuming a
late protocol-level failure.

## End-Of-Shift Handoff

1. Summarize active incidents and mitigations.
2. Confirm any temporary controls that are still in effect.
3. Hand off pending migrations, rollouts, or recovery tasks explicitly.
4. Confirm whether any break-glass secret access occurred during the shift.

## Related Docs

- [Incident Response Guide](incident-response.md)
- [Failover Drill Runbook](failover-drill.md)
- [Event Delivery Runbook](event-delivery.md)
- [Routed Secret Reveal Runbook](routed-secret-reveal.md)
