# Configuration Model

This document describes how configuration works in the current beta baseline.
The daemon expects one explicit config file, an explicit schema header, and
optional environment overlays.

## Structure

Configuration is split into:

- immutable bootstrap settings,
- runtime policy and operational limits.

At minimum, the config includes:

- `listen`
- `state_dir`
- `[schema]`
- `[secrets]`

Example baseline:

```toml
listen = "127.0.0.1:9080"
state_dir = "./state/dev"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "dev-node"

[secrets]
master_key = "..."
```

## Schema Header

Every config file carries an explicit schema header:

- `schema_version`
  Used for explicit config migration tracking.
- `mode`
  Runtime mode such as `all_in_one`.
- `node_name`
  Immutable bootstrap identity for the node.

## Bootstrap Settings

Bootstrap settings choose things that are not safe to mutate casually at
runtime, including:

- storage paths,
- network listener,
- service mode,
- node identity,
- cryptographic root material.

## Runtime Policy

Reloadable or operationally mutable settings can control things such as:

- limits,
- quotas,
- policy documents,
- routing tables,
- alert rules,
- feature flags.

The exact reload behavior still depends on the owning subsystem; not every
field is hot-reloadable just because it exists in config.

## Environment Overrides

Environment overlays use string-only path assignment with a double-underscore
path separator:

```text
UHOST_SECTION__KEY=value
```

Important rules:

- paths are lowercased during merge,
- values are injected as strings and later deserialized,
- an override fails if it tries to descend into a scalar TOML value,
- the prefix is `UHOST`.

Examples:

- `UHOST_SECRETS__MASTER_KEY=<base64url-encoded key>`
- `UHOST_SCHEMA__MODE=distributed`
- `UHOST_RUNTIME__PROCESS_ROLE=edge`

## Migration And Compatibility

- schema and config migration execution metadata is owned through `lifecycle`
  APIs,
- extension compatibility policy is exposed at
  `/lifecycle/compatibility-policy`,
- collection files and service-owned state also carry schema versions where the
  owning subsystem requires them.

## Operational Guidance

- Keep the config file and `state_dir` paired in backup and recovery workflows.
- Inject secrets at deployment time rather than committing them.
- Do not assume an environment override succeeded silently; verify the daemon
  started with the intended effective config.

## Related Docs

- [Bootstrap Runbook](../runbooks/bootstrap.md)
- [Backup and Restore Runbook](../runbooks/backup-restore.md)
- [Extension and Compatibility Policy](../extensions.md)
- [Threat Model](../threat-model.md)
