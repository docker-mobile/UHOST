#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" && -z "${CARGO_TARGET_DIR:-}" ]]; then
  export UHOST_DISPOSABLE_TARGET_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  storage-drill-evidence-check
)

echo "[storage-drill-evidence] verifying generated storage drill evidence freshness and bindings"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test storage_drill_evidence storage_drill_generated_artifact_is_present_and_fresh -- --exact
echo "[storage-drill-evidence] passed"
