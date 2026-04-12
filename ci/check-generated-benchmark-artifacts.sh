#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" && -z "${CARGO_TARGET_DIR:-}" ]]; then
  export UHOST_DISPOSABLE_TARGET_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  benchmark-artifacts
)

echo "[benchmark-artifacts] verifying generated benchmark evidence manifest freshness, cohesion, and exact inventory"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test wave3_evidence wave3_generated_benchmark_artifacts_are_present_and_coherent -- --exact
echo "[benchmark-artifacts] verifying generated validation startup ingest"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test uvm_generated_validation_runtime generated_validation_artifacts_auto_ingest_into_keyed_benchmark_rows_over_http -- --exact
echo "[benchmark-artifacts] passed"
