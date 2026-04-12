# Routed Secret Reveal Runbook

Use this runbook when an operator needs a stored secret during recovery,
break-glass work, or controlled validation. The normal path stays within
`uhostctl`; direct file inspection of `state_dir/secrets/` is not an approved
reveal path.

## Purpose

- Reveal secrets through auditable service routes.
- Distinguish normal operator reveals from approval-backed and lease-backed
  reveals.
- Preserve attribution and evidence for every reveal.

## Current Platform Truth

- `uhostd` is the same-host control plane in the current beta baseline.
- Secret and reveal-grant state is persisted under `state_dir/secrets/`.
- These routes require a non-workload operator principal.

## Prerequisites

1. Confirm the daemon is healthy and reachable.
2. Export the endpoint and an operator token:

```bash
export UHOST_ENDPOINT=http://127.0.0.1:9080
export UHOSTCTL_ADMIN_TOKEN='<admin token>'
```

`uhostctl` also accepts `UHOST_ADMIN_TOKEN`.

3. Review the current secret inventory:

```bash
uhostctl secrets items --endpoint "$UHOST_ENDPOINT"
```

4. Use the rollup view if you need the latest version per name or a quick
   count check:

```bash
uhostctl secrets summary --endpoint "$UHOST_ENDPOINT"
```

The summary includes `secret_count`, `unique_secret_name_count`,
`highest_version`, `latest_version_by_name`, and `ownership_scope_totals`.

5. If the secret does not exist yet, create it first and copy the returned `id`
   into `SECRET_ID`:

```bash
uhostctl secrets create \
  --name "incident/db-root" \
  --value "replace-me" \
  --endpoint "$UHOST_ENDPOINT"
```

## Direct Reveal Flow

Use direct reveal when the operator already has standing authority and no
separate approval or lease is required.

```bash
uhostctl secrets reveal \
  --secret-id "$SECRET_ID" \
  --endpoint "$UHOST_ENDPOINT"
```

The reply includes `id`, `name`, `version`, and `value`. Treat `value` as live
plaintext. Do not paste it into tickets, chat, or long-lived notes.

## Grant Type Selection

- `approval-create`
  Single-use. One successful reveal consumes the approval.
- `lease-create`
  Time-bounded. The same grant can be reused until `expires_at`.

Prefer approvals for one-off break-glass access. Prefer short leases only when
the recovery procedure truly needs repeated reveals over a bounded window.

## One-Time Approval Flow

1. Create the approval grant:

```bash
uhostctl secrets approval-create \
  --secret-id "$SECRET_ID" \
  --reason "sev1 incident recovery INC-1234" \
  --endpoint "$UHOST_ENDPOINT"
```

Copy the returned `id` into `GRANT_ID`.

2. Perform the reveal:

```bash
uhostctl secrets grant-reveal \
  --secret-id "$SECRET_ID" \
  --grant-id "$GRANT_ID" \
  --endpoint "$UHOST_ENDPOINT"
```

3. Confirm the approval was consumed and record the reason for the reveal.

## Lease Flow

1. Create a short lease:

```bash
uhostctl secrets lease-create \
  --secret-id "$SECRET_ID" \
  --reason "rotation validation window INC-1234" \
  --lease-seconds 900 \
  --endpoint "$UHOST_ENDPOINT"
```

2. Reuse the same `GRANT_ID` only while the lease remains active:

```bash
uhostctl secrets grant-reveal \
  --secret-id "$SECRET_ID" \
  --grant-id "$GRANT_ID" \
  --endpoint "$UHOST_ENDPOINT"
```

3. Confirm `expires_at` is non-null and keep the lease duration as short as the
   procedure allows.

There is no dedicated `uhostctl` revoke verb for reveal grants yet. The safe
cleanup path today is to let the lease expire and verify no additional reveals
occurred.

## Audit And Evidence

The current persisted evidence surfaces are:

- `state_dir/secrets/secrets.json`
- `state_dir/secrets/reveal_grants.json`
- `state_dir/secrets/audit.log`
- `state_dir/secrets/outbox.json`

Current event types include:

- `secrets.reveal.approved.v1`
- `secrets.reveal.leased.v1`
- `secrets.reveal.executed.v1`

Use `reveal_count`, `last_revealed_at`, and `last_revealed_by` to confirm when
and how a grant was used.

## Guardrails

- `create` requires both `--name` and `--value`.
- `reveal`, `approval-create`, and `lease-create` require `--secret-id`.
- `grant-reveal` requires both `--secret-id` and `--grant-id`.
- `--reason` is required, trimmed, and limited to 256 bytes.
- `--lease-seconds` must be greater than zero.
- Workload identities should not perform break-glass secret reveals.
- Do not bypass the service path by reading plaintext directly from state
  files.

## Related Docs

- [Incident Response Guide](incident-response.md)
- [On-Call Playbook](on-call.md)
- [Threat Model](../threat-model.md)
