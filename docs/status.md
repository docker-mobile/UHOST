# Beta Status

This file describes the current UHost beta in plain terms: what is already solid, what the shipped operating model is, and where the important limits still are.

## Snapshot

UHost `v0.1 beta` is:

- a same-host control-plane runtime centered on [`uhostd`](../cmd/uhostd),
- a Rust workspace with real bounded-context services under [`../services`](../services),
- a contract-first codebase with checked-in REST and protobuf sources,
- a file-backed platform with durable local state, audit trails, and outbox-style records,
- and a software-first UVM stack with control, image, node, observe, and runner surfaces.

## What Is Ready To Evaluate

- Runtime route ownership and surface classification
- Service-local state and optimistic-concurrency patterns
- Operator CLI flows and generated release-state
- Same-host integration flows across control, storage, auth, console, and parts of UVM
- Release and evidence helpers under [`../scripts`](../scripts) and [`../ci`](../ci)

## Current Operating Model

The repo should currently be described as:

- one host,
- one main daemon,
- one local state root,
- one explicit control-plane contract,
- one beta-level operator story.

That is a legitimate beta shape. It is also the limit that should frame the public presentation.

## Important Limits

The current beta does not claim:

- multi-node distributed control-plane operation as the default mode,
- production federation or final operator identity depth,
- global event or workflow substrate maturity,
- public-cloud feature parity,
- or certification-grade VM isolation or performance claims.

Those are roadmap topics, not product-description text for the current beta.

## Release Discipline

For a clean beta tag, the repo should be presented with:

- synchronized top-level docs,
- a cleaned repo surface without scratch planning artifacts,
- generated release-state refreshed from the release candidate tree,
- and verification gates rerun on the exact release snapshot.

## Source Of Truth

Use these docs first:

- [`Repository README`](../README.md)
- [`Documentation Index`](README.md)
- [`architecture.md`](architecture.md)
- [`api/README.md`](api/README.md)
- [`generated/release-state.md`](generated/release-state.md)

This file is intentionally short. It is a presentation layer for the shipped beta, not a backlog dump.
