# Contributing

UHost is a contract-first Rust workspace. Changes should preserve the same-host
beta shape, keep service boundaries explicit, and avoid casual drift between
code, docs, and contracts.

## Development Rules

- keep dependencies deliberate and minimal
- preserve service-owned state boundaries under `services/`
- update checked-in contracts in `openapi/` and `proto/` when public API shape changes
- prefer explicit runtime, auth, and durability behavior over convenience shortcuts

## Local Verification

These are the baseline gates for normal changes:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

When touching evidence, release, or deeper runtime flows, also run the focused
gate that matches the change, for example:

```bash
bash ci/wave3-evidence-gate.sh
bash ci/supply-chain-gate.sh
RUN_LONG=1 bash scripts/run-hyperscale.sh
```

## Pull Requests

- explain the operator-visible change
- list contract or state-file changes explicitly
- include the exact verification commands you ran
- call out follow-up work rather than hiding it in code comments
