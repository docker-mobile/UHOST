# Supply-Chain Release Gate

This runbook describes the release integrity gate for the beta command-line and
daemon artifacts.

## Purpose

- Generate SBOM and provenance evidence.
- run vulnerability and checksum verification,
- sign release artifacts,
- reject release claims that are not backed by current evidence.

## Preconditions

1. The source tree must be clean.
2. The current host must pass the `supply-chain` profile:

```bash
bash scripts/host-capability-preflight.sh --profile supply-chain
```

3. If evidence may be stale, also run:

```bash
bash scripts/host-capability-preflight.sh --profile wave-evidence --deep
```

## Command

```bash
bash ci/supply-chain-gate.sh
```

## Gate Stages

1. `scripts/generate-sbom.sh`
   Produces dependency inventory artifacts.
2. `scripts/generate-provenance.sh`
   Produces release provenance and attestation output.
3. `ci/vuln-check.sh`
   Runs the repository's vulnerability gate.
4. `cargo build --release -p uhostd -p uhostctl -p uhost-uvm-runner`
   Produces the primary release binaries.
5. `scripts/sign-artifacts.sh`
   Signs the built artifacts and manifest.
6. `uhostctl release verify`
   Verifies manifests, checksums, and provenance linkage.

## Expected Artifacts

- `target/sbom/cargo-metadata.json`
- `target/sbom/cargo-tree.txt`
- `target/provenance/attestation.json`
- `target/signatures/artifact-manifest.json`

## Common Failure Modes

- dirty tree blocks provenance generation,
- missing signing prerequisites,
- stale evidence artifacts,
- dependency gate failures,
- release binaries built from a different source tree than the attested one.

## Release Honesty Rules

- Do not reuse stale provenance on a new tree state.
- Do not treat a locally dirty pass as release-quality proof.
- Do not publish release artifacts if `uhostctl release verify` cannot validate
  the final manifest and provenance pair.

## Related Docs

- [Host Readiness](host-readiness.md)
- [Dependency Ledger](../dependency-ledger.md)
- [Threat Model](../threat-model.md)
