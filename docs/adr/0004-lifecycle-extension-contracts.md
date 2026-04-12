# ADR 0004: Lifecycle and Extension Contracts

Status: accepted

Decision:

- Extend `uhost-svc-lifecycle` to own migration metadata, dead-letter repair flows, and extension registry contracts.
- Introduce stable plugin compatibility contracts in `uhost-core::extension`.
- Enforce compatibility windows during plugin registration.

Rationale:

- Upgrade and extension behavior must be version-governed from one control point.
- Explicit compatibility policy reduces accidental platform-extension breakage.
- Dead-letter replay and repair metadata improve operational traceability.

Consequences:

- Extension authors must publish min/max API compatibility ranges.
- Migration apply now validates ordering and checksum idempotency.
