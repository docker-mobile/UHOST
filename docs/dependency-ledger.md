# Dependency Ledger

Project UHost is intentionally dependency-starved. This document expands the
short dependency note from the main README into a release-oriented ledger that
explains what is in the workspace, why it is present, and what the replacement
boundary is.

## Policy

- Prefer `std` and existing internal crates first.
- Add a new runtime dependency only when it removes meaningful complexity or
  risk that the current stack cannot reasonably absorb.
- Keep release-critical tooling inspectable and scriptable.
- Treat test-only and benchmark-only dependencies differently from runtime
  dependencies.

## Current Workspace Dependencies

### Core Serialization And Config

- `serde`
  Data structures and API/config serialization.
- `serde_json`
  JSON request, response, and persisted-document encoding.
- `toml`
  Config decoding and environment-overlay merge targets.
- `time`
  Timestamped contracts, evidence metadata, and date handling.

Replacement boundary:
Keep unless the repository removes TOML config or serde-based contracts
entirely. Do not add a second general serialization stack.

### Runtime And HTTP

- `tokio`
  Async runtime, file I/O, networking, timers, and signal handling.
- `bytes`
  Buffer handling where byte ownership matters.
- `http`
  Protocol types.
- `http-body-util`
  Body helpers.
- `hyper`
  HTTP client and server transport.
- `hyper-util`
  Tokio-facing integration helpers.

Replacement boundary:
These form the network/runtime substrate. Replacing them would be a
cross-cutting architectural decision, not an opportunistic library swap.

### Crypto, Identity, And Secret Handling

- `argon2`
  Password hashing.
- `chacha20poly1305`
  Secret encryption at rest.
- `hmac`
  Message authentication and integrity helpers.
- `sha2`
  Digesting, checksums, and verification.
- `getrandom`
  Secure randomness.
- `zeroize`
  Memory cleanup for sensitive material.
- `base64`
  Encoding for operator-facing secret/bootstrap material.

Replacement boundary:
Do not add overlapping crypto libraries casually. Changes here require a clear
migration and re-verification story.

### Test, Fuzz, And Benchmark Support

- `tempfile`
  Temporary directories and files in tests.
- `proptest`
  Property-style testing.
- `criterion`
  Benchmarks.

Replacement boundary:
These are not runtime dependencies. They may evolve separately from the daemon
and CLI runtime stack.

## Internal Workspace Structure

The repository favors internal crates over external expansion:

- `uhost-api`
- `uhost-core`
- `uhost-runtime`
- `uhost-store`
- `uhost-types`
- `uhost-uvm*`
- service crates under `services/`

This keeps platform contracts local, reviewable, and versioned together.

## Supply-Chain Stance

- SBOM, provenance, and signing are produced by repository scripts and existing
  Cargo tooling.
- Vulnerability checks use the repository gate instead of a permanently running
  external dependency service.
- Release verification uses `uhostctl release verify` with manifest and digest
  evidence.

## New Dependency Checklist

Before adding a dependency, answer all of these:

1. What concrete problem does it solve that current code or workspace crates do
   not?
2. Is it runtime, build-only, test-only, or bench-only?
3. Does it overlap with an existing crate already in the workspace?
4. What is the operational or supply-chain cost?
5. How would it be removed later if needed?

## Related Docs

- [Supply-Chain Release Gate](runbooks/supply-chain-release-gate.md)
- [Configuration Model](config/overview.md)
- [Extension and Compatibility Policy](extensions.md)
