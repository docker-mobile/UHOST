# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Verify
- CI uses the pinned toolchain in [rust-toolchain.toml](rust-toolchain.toml) and the exact commands from [.github/workflows/ci.yml](.github/workflows/ci.yml:24):
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace`
- Focused test/bench commands already used in-repo:
  - `cargo test -p uhostd --test all_in_one`
  - `cargo test -p uhostd --test contract_snapshots openapi_snapshot_contains_new_control_domains`
  - `cargo test -p uhostd --test hyperscale hyperscale_load_identity_write_profile -- --ignored --nocapture`
  - `cargo test -p uhost-store --lib`
  - `cargo bench -p uhost-svc-scheduler --bench placement -- --sample-size 10`
  - `cargo bench -p uhost-svc-netsec --bench policy_eval -- --sample-size 10`
- The repo treats these as real gates, not optional extras: `bash ci/perf-gate.sh`, `RUN_LONG=1 bash scripts/run-hyperscale.sh`, and `bash ci/supply-chain-gate.sh`.

## Project-specific rules
- [Cargo.toml](Cargo.toml), [rustfmt.toml](rustfmt.toml), and [clippy.toml](clippy.toml) enforce the main style guardrails: `unsafe_code`, `unwrap()`, `todo!()`, and `dbg!()` are denied, warnings become errors, `missing_docs` warns, Unix newlines are required, field-init shorthand is enabled, and placeholder names `foo`/`bar`/`baz` are disallowed.
- [cmd/uhostd/src/main.rs](cmd/uhostd/src/main.rs:170) accepts only `--config`; unknown flags fail. Default startup config is [configs/dev/all-in-one.toml](configs/dev/all-in-one.toml), and [AllInOneConfig::validate()](cmd/uhostd/src/main.rs:64) only allows a missing bootstrap token in `all_in_one` mode.
- Environment overrides are string-only path overlays in [ConfigLoader::apply_environment_overrides_from_iter()](crates/uhost-core/src/config.rs:72): `UHOST_SECTION__KEY=value`. They fail if they try to descend into a scalar TOML key.
- Request flow is [cmd/uhostd::main()](cmd/uhostd/src/main.rs:119) -> [PlatformRuntime::dispatch()](crates/uhost-runtime/src/lib.rs:153) -> service [HttpService::handle()](crates/uhost-runtime/src/lib.rs:87) -> file-backed state/outbox. `/healthz` and `/metrics` are reserved in [PlatformRuntime::special_response_for_path()](crates/uhost-runtime/src/lib.rs:309).
- HTTP handlers should reuse [parse_json()](crates/uhost-api/src/lib.rs:105), [path_segments()](crates/uhost-api/src/lib.rs:140), [json_response()](crates/uhost-api/src/lib.rs:25), [empty_response()](crates/uhost-api/src/lib.rs:55), and [with_etag()](crates/uhost-api/src/lib.rs:203); [IdentityService::handle()](services/uhost-svc-identity/src/lib.rs:659) is the reference pattern.
- Durable state is per-service under `<state_dir>/<service>/...` as in [IdentityService::open()](services/uhost-svc-identity/src/lib.rs:177). Use [DocumentStore::upsert()](crates/uhost-store/src/document.rs:160) and [DocumentStore::soft_delete()](crates/uhost-store/src/document.rs:210) expected versions, and preserve concurrency headers from [IdentityService::create_user()](services/uhost-svc-identity/src/lib.rs:279).
- Contract work is incomplete until [openapi/control-plane-v1.yaml](openapi/control-plane-v1.yaml) and [proto/control-plane-v1.proto](proto/control-plane-v1.proto) satisfy the literal snapshot checks in [cmd/uhostd/tests/contract_snapshots.rs](cmd/uhostd/tests/contract_snapshots.rs:12).
- New identifiers should extend [define_id!](crates/uhost-types/src/id.rs:126) so IDs keep the repo’s prefixed lowercase-base32 shape.
