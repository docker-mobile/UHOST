# Threat Model

This document describes the current beta threat model for Project UHost. It is
written against the actual baseline the repository supports today: a
dependency-starved, file-backed control plane with a strong same-host story and
an incomplete distributed production story.

## Scope

The model covers:

- the `uhostd` API surface,
- persisted service state under `state_dir`,
- operator and workload identities,
- secret storage and reveal paths,
- file-backed event, audit, and migration artifacts,
- UVM orchestration and evidence flows.

It does not claim that every planned distributed, multi-region, or fully
federated control path is already complete.

## Deployment Assumptions

- The default all-in-one node is trusted to hold encrypted secrets and local
  state on one host.
- Network-facing APIs are deny-by-default and should sit behind TLS
  termination before any real exposure.
- Checked-in config stays secret-free; operators inject sensitive material at
  deployment time.
- Workload bearer tokens are valid for workload-safe tenant routes, while some
  operator and runtime routes still depend on bootstrap-era access controls in
  the current baseline.

## Sensitive Assets

- `secrets.master_key`
- password hashes
- API-key secret material at creation time
- persisted service state under `state_dir`
- audit trails and governance evidence
- backup artifacts and restore metadata
- UVM runtime session, checkpoint, and benchmark evidence

## Trust Boundaries

1. External client to `uhostd`
   Network requests cross into the control plane.
2. Runtime/router to service handlers
   Route ownership, surface classification, and principal projection apply.
3. Service handler to file-backed state
   Durable state is persisted per service under `state_dir`.
4. Operator identity to break-glass paths
   Secret reveal, governance, and other sensitive operations require elevated
   attribution.
5. Control plane to node-plane / UVM evidence
   Host capabilities, execution plans, and benchmark claims must remain honest
   about environment limits.

## Primary Threats

- unauthorized operator access,
- workload identity crossing into operator-only surfaces,
- secret exfiltration through direct state inspection or weak reveal controls,
- tampering with persisted state or replaying stale artifacts,
- route shadowing or service collision,
- denial of service through connection or workload pressure,
- false platform claims caused by stale or unsupported evidence,
- incomplete recovery procedures that lose attribution or duplicate effects.

## Existing Controls

- route ownership and route-surface classification prevent services from
  shadowing reserved runtime endpoints,
- runtime connection limits and timeouts bound exposure in the all-in-one
  server,
- password storage uses Argon2id,
- secret payloads are encrypted at rest with ChaCha20Poly1305,
- mutating identity and tenancy actions append audit records,
- typed IDs and validation reduce cross-service ambiguity,
- storage metadata updates use atomic replacement patterns,
- netsec policy is deny-by-default and flow-audited,
- governance approvals enforce separation-of-duties checks,
- HA failover is gated by replication health and lag bounds,
- supply-chain gates emit and verify SBOM, provenance, and release checksums.

## Residual Beta Gaps

- external TLS termination and certificate lifecycle wiring for split-service
  deployments,
- stronger non-bootstrap operator identity and federation,
- broader workload identity rotation, revocation, and service-to-service trust
  policy,
- continuous online advisory-driven vulnerability blocking,
- broader distributed replication and failure-domain closure,
- security certification and hardened-host evidence beyond first-party
  engineering validation.

## Operational Guidance

- Treat secret reveals as audited recovery events, not as a convenience path.
- Treat generated evidence as time-bounded and host-class-specific.
- Use runbooks instead of direct state mutation during incidents.
- Do not upgrade release claims beyond what current evidence and gates can
  support.

## Related Docs

- [Configuration Model](config/overview.md)
- [Dependency Ledger](dependency-ledger.md)
- [Extension and Compatibility Policy](extensions.md)
- [Incident Response Guide](runbooks/incident-response.md)
- [Routed Secret Reveal Runbook](runbooks/routed-secret-reveal.md)
- [UVM Virtualization Stack Architecture](uvm-virtualization-stack.md)
