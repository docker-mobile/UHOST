# Event Delivery Runbook

This runbook covers the current durable outbox and inbox model used by the
beta same-host platform.

## Purpose

- Inspect event backlog.
- Recover from failed or delayed delivery.
- Replay safely without losing idempotency.

## Current Delivery Model

The current baseline uses a durable outbox and inbox pattern:

- outbox records are persisted per service under
  `<state_dir>/<service>/outbox.json`,
- inbox state is persisted through `DurableInbox` to support deduplication,
- services append events during mutations and operators inspect or replay them
  through service-specific routes.

This is durable, but it is not yet a fully autonomous distributed event fabric.

## Inspect Backlog

Common inspection commands:

```bash
curl -sS http://127.0.0.1:9080/control/outbox
curl -sS http://127.0.0.1:9080/identity/outbox
curl -sS http://127.0.0.1:9080/lifecycle/outbox
```

When inspecting a backlog, record:

- the service,
- the message type,
- the delivery state,
- the first failed timestamp,
- any downstream dependency that is currently unavailable.

## Recovery Flow

1. Pause or protect downstream consumers if replays could compound the failure.
2. Query the relevant outbox routes and isolate messages in `pending` or
   `failed` state.
3. Confirm whether the consumer side already persisted an inbox/dedupe record.
4. Replay messages in timestamp order.
5. Verify that the downstream side completed the intended mutation exactly once.
6. Re-check the outbox and inbox state after replay.

## Verification

A replay is not complete until:

1. the downstream dependency is healthy,
2. the event backlog stops growing for the affected topic,
3. duplicate consumer effects are ruled out,
4. the operator log records what was replayed and why.

## Known Limits

- Outbox dispatch is not yet a general always-on background worker for every
  service.
- Replay remains operator-triggered in several lanes.
- Multi-node replication of outbox storage is part of later HA/DR closure, not
  a completed beta guarantee.

## Related Docs

- [Incident Response Guide](incident-response.md)
- [On-Call Playbook](on-call.md)
- [Failover Drill Runbook](failover-drill.md)
- [Extension and Compatibility Policy](../extensions.md)
