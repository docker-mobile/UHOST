# Roadmap

This roadmap starts from the current UHost beta and lays out the next technical phases without turning the repository front door into a manifesto.

## Phase 1: Beta Polish

- Keep the README, docs index, service READMEs, and generated release-state aligned.
- Expand operator-facing docs and runbooks where gaps still make the repo harder to approach.
- Keep CLI and contract UX polished enough for external beta readers.

## Phase 2: Operational Hardening

- Increase daemon-backed integration coverage for the critical control-plane flows.
- Tighten auth, request-surface policy, and runtime admission behavior.
- Improve release discipline around evidence refresh, reproducibility, and packaging.

## Phase 3: Platform Foundations

- Add stronger metadata, queue, lease, watch, and blob primitives behind the local adapter path.
- Build a more general workflow and event-delivery substrate for restore, repair, failover, rollout, and reconciliation.
- Preserve the current file-backed development path while making the substrate less single-host-bound.

## Phase 4: Topology Expansion

- Make split-role deployment shapes routine instead of just represented in manifests.
- Move from one main process toward role-aware same-host and multi-process layouts.
- Add stronger coordination and anti-entropy between roles before broader multi-node claims.

## Phase 5: Domain Maturity

- Deepen identity, policy, tenancy, billing, support, network, storage, and observability workflows.
- Bring newer domains like `container` and `stream` up to the same release and contract discipline as the older services.
- Keep operator workflows cohesive instead of growing disconnected feature islands.

## Phase 6: UVM Maturation

- Keep UVM runner, image, node, observe, and evidence surfaces synchronized.
- Refresh benchmark and validation artifacts whenever UVM claims materially change.
- Improve software-first execution quality without overstating benchmark or isolation conclusions.

## Working Rule

New work should strengthen one of these phases. If it only makes the roadmap look larger without improving the shipped beta or the substrate beneath it, it is probably the wrong next change.
