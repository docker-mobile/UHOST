<div align="center">
  <h1>UHost</h1>
  <p><strong>Dependency-lean hosting control plane and software-first UVM stack.</strong></p>
  <p>
    <a href="https://github.com/docker-mobile/EXPERIMENT-UHOST/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/docker-mobile/EXPERIMENT-UHOST/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/docker-mobile/EXPERIMENT-UHOST/actions/workflows/release.yml"><img alt="Release" src="https://github.com/docker-mobile/EXPERIMENT-UHOST/actions/workflows/release.yml/badge.svg"></a>
  </p>
  <p>
    <code>Rust workspace</code>
    <code>v0.1 beta</code>
    <code>same-host runtime</code>
    <code>contract-first</code>
    <code>bounded-context services</code>
  </p>
</div>

UHost is a real control-plane codebase, not a landing-page shell. It already ships a coherent single-host platform shape with explicit service boundaries, route ownership, checked-in contracts, local durability, an operator CLI, and a serious UVM program.

The right way to read this repository is:

- one deployable beta centered on [`uhostd`](cmd/uhostd),
- many service domains behind one runtime kernel,
- durable file-backed state under `./state`,
- OpenAPI and protobuf contracts that move with the code,
- evidence-backed UVM work without inflated hypervisor claims.

## Why It’s Interesting

| Area | What UHost already does |
| --- | --- |
| Runtime kernel | Central route ownership, surface classification, startup validation, and reserved runtime endpoints. |
| Service model | Real bounded-context services under [`services`](services) instead of one giant handler blob. |
| Data model | Local durable records, optimistic concurrency, audit trails, and outbox-style event handoff. |
| Contracts | Checked-in REST and protobuf definitions under [`openapi`](openapi) and [`proto`](proto). |
| Operator tooling | CLI flows in [`cmd/uhostctl`](cmd/uhostctl) plus generated release and evidence helpers in [`scripts`](scripts). |
| UVM track | Control, image, node, observe, runner, validation, and benchmark surfaces already live in-tree. |

## What Ships In `v0.1 beta`

- [`cmd/uhostd`](cmd/uhostd): the main control-plane daemon
- [`cmd/uhostctl`](cmd/uhostctl): operator CLI and release verification tool
- [`cmd/uhost-uvm-runner`](cmd/uhost-uvm-runner): UVM execution and evidence runner
- [`crates`](crates): shared runtime, store, types, API, core, and UVM libraries
- [`services`](services): control, identity, tenancy, storage, data, billing, DNS, ingress, observe, lifecycle, HA, secrets, UVM services, and more

Current beta operating model:

- one primary deployment shape: same-host `uhostd`
- one default state root: `./state`
- one checked-in dev entry point: [`configs/dev/all-in-one.toml`](configs/dev/all-in-one.toml)
- one public contract family: [`openapi/control-plane-v1.yaml`](openapi/control-plane-v1.yaml) and [`proto/control-plane-v1.proto`](proto/control-plane-v1.proto)

## Architecture At A Glance

```text
client / operator
    -> uhostd
        -> PlatformRuntime
            -> route registry + surface policy
                -> service HttpService
                    -> service-owned state + audit/outbox records
```

Design rules that matter:

- services own their bounded contexts and durable files
- runtime-owned routes cannot be shadowed by services
- public, tenant, operator, and internal surfaces are explicit
- contract changes are checked, not implied
- UVM evidence is published as engineering evidence, not marketing proof

## Quick Start

Run the all-in-one beta:

```bash
cargo run -p uhostd -- --config configs/dev/all-in-one.toml
```

Generate a fresh admin token when you need one:

```bash
cargo run -q -p uhostctl -- token generate
cargo run -q -p uhostctl -- token generate --shell --env UHOSTCTL_ADMIN_TOKEN
```

Bring up one UHost-managed dev UVM session with generated secrets and a reusable
shell env file:

```bash
bash scripts/run-uhost-managed-uvm.sh
source tmp/uhost-managed-uvm/session.env
```

That managed `software_dbt` dev path now exposes control-plane management,
guest-control readiness, guest-owned usernet-style NAT, outbound HTTP/HTTPS
plus generic TCP/UDP egress, a managed HTTP ingress surface that serves the
guest web root from `/var/www`, and managed TCP plus UDP ingress ports for
testing. It still does not expose guest SSH, raw sockets, or a post-start
guest exec API.

Useful verification entry points:

```bash
cargo fmt --all -- --check
cargo test --workspace --no-run
cargo test -p uhostd --test all_in_one
cargo test -p uhostd --test contract_snapshots
bash scripts/generate-release-state.sh
```

If you are working on the UVM path:

```bash
cargo test -p uhost-uvm-softvm
cargo test -p uhost-uvm-runner
bash scripts/run-uvm-stack-validation.sh
```

## Repository Layout

```text
cmd/         binaries and operator entrypoints
crates/      runtime, store, types, API, core, and UVM libraries
services/    bounded-context service implementations
configs/     dev and production-oriented config templates
docs/        architecture, contracts, runbooks, status, and roadmap
openapi/     REST contract source
proto/       protobuf contract source
scripts/     release, evidence, and verification helpers
ci/          repository gates
```

## Read This Next

- [Documentation Index](docs/README.md)
- [Architecture](docs/architecture.md)
- [API And Contract Guide](docs/api/README.md)
- [Beta Status](docs/status.md)
- [Roadmap](docs/roadmap.md)
- [Runbooks](docs/runbooks/README.md)
- [Managed UVM Dev Quickstart](docs/runbooks/managed-uvm-dev-quickstart.md)
- [UVM Virtualization Stack](docs/uvm-virtualization-stack.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Current Scope

UHost is ready to be presented as a normal beta when described as:

- a technically serious same-host control-plane baseline,
- a dependency-lean Rust workspace with real service decomposition,
- a contract-first platform kernel with durable local state,
- and an active UVM engineering program with explicit evidence and limits.

That is the story this repository should tell.

## GitHub Surface

The repository ships with:

- CI in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- release automation in [`.github/workflows/release.yml`](.github/workflows/release.yml)
- issue templates and pull-request templates under [`.github`](.github)
- dependency update automation in [`.github/dependabot.yml`](.github/dependabot.yml)
