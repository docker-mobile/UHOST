# Bootstrap Runbook

This runbook brings up the beta baseline: one `uhostd` process, one local
`state_dir`, and one operator-controlled config file.

## Purpose

- Generate a valid config.
- Start the all-in-one daemon safely.
- Confirm the node is healthy before deeper setup.

## Prerequisites

1. A working Rust toolchain that matches the repository pin.
2. A writable `state_dir`.
3. A base64url-encoded 32-byte `secrets.master_key`.
4. A clear decision about whether this node is local-only or operator-exposed.

## Bootstrap Flow

1. Generate an initial config:

```bash
cargo run -p uhostctl -- init
```

2. Review the baseline example in `configs/dev/all-in-one.toml`.
3. Confirm these values before start:
   - `listen`
   - `state_dir`
   - `schema.schema_version`
   - `schema.mode`
   - `schema.node_name`
   - `secrets.master_key`
4. For anything beyond localhost development, set a bootstrap operator token
   through deployment-time secret delivery, for example:

```bash
export UHOST_SECURITY__BOOTSTRAP_ADMIN_TOKEN='<long unique token>'
```

5. Start the daemon:

```bash
cargo run -p uhostd -- --config configs/dev/all-in-one.toml
```

## Verification

Confirm the process is healthy before moving on:

```bash
curl -sS http://127.0.0.1:9080/healthz
curl -sS http://127.0.0.1:9080/metrics
```

Then verify:

1. the node is listening on the configured address,
2. the expected `state_dir` was created,
3. the daemon did not silently fall back to a different config path,
4. operator access is set up the way you intended.

## Common Mistakes

- Reusing the wrong `secrets.master_key` with an existing `state_dir`.
- Assuming environment overrides are typed; they are string overlays that are
  later deserialized.
- Starting with a config file that was edited for another node name or mode.
- Exposing an operator surface without an explicit bootstrap token or external
  TLS termination plan.

## Related Docs

- [Configuration Model](../config/overview.md)
- [Host Readiness](host-readiness.md)
- [Beginner Operator Maintenance Guide](beginner-maintenance-guide.md)
- [Threat Model](../threat-model.md)
