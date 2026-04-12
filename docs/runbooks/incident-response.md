# Incident Response Guide

This guide is the default operator path when the beta platform is unhealthy,
degraded, or suspected to be compromised.

## Purpose

- Establish a disciplined response flow.
- Preserve evidence before manual repair.
- Route operators to the right recovery runbooks quickly.

## Severity Model

- `sev1`
  Global outage, data-loss risk, or security compromise with broad impact.
- `sev2`
  Major customer impact or sustained degradation of core control-plane paths.
- `sev3`
  Localized impact, bounded degradation, or an issue with a clear short-term
  workaround.

## First 15 Minutes

1. Declare the incident and assign an incident commander.
2. Capture current health from:
   - `/healthz`,
   - `/metrics`,
   - `/ha/degraded-mode`.
3. Snapshot relevant state directories and logs before manual mutation.
4. Start an operator activity record:

```text
POST /observe/activity
```

## Containment

1. Enable maintenance mode when continued writes would increase risk:

```text
POST /lifecycle/maintenance
```

2. Apply temporary network controls if abuse or unexpected egress is involved:

```text
POST /netsec/egress-rules
```

3. Suspend compromised mail relay domains when mail reputation is part of the
   blast radius:

```text
POST /mail/reputation/{domain_id}/adjust
```

## Recovery

1. Use controlled failover only when it improves safety, not just because it is
   available:

```bash
uhostctl ha failover
```

2. Use the [Routed Secret Reveal Runbook](routed-secret-reveal.md) if recovery
   needs a stored secret.
3. Replay dead letters only after the downstream dependency is healthy again:

```bash
uhostctl repair replay-dlq
```

4. Confirm governance approvals for any high-risk remediation.

## Storage Corruption Contract

The current verified `uhostd` full-object download behavior matters during
containment:

- an already-started full-object download may still complete with its buffered
  octet body even if the blob is truncated after headers are observed,
- do not assume an in-flight request will self-signal corruption via a late
  JSON error or early EOF,
- contain first, then verify with a fresh request or a restore drill.

## Post-Incident Work

1. Export audit checkpoints:

```text
GET /governance/audit-checkpoints
```

2. Record the timeline, root cause, mitigations, and unresolved questions.
3. Convert each concrete gap into a tracked follow-up.

## Related Docs

- [Backup and Restore Runbook](backup-restore.md)
- [Failover Drill Runbook](failover-drill.md)
- [On-Call Playbook](on-call.md)
- [Routed Secret Reveal Runbook](routed-secret-reveal.md)
- [Threat Model](../threat-model.md)
