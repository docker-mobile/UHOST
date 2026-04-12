#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/docs/generated}"
if [[ -z "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" && -z "${CARGO_TARGET_DIR:-}" ]]; then
  export UHOST_DISPOSABLE_TARGET_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  storage-drill-evidence-refresh
)

mkdir -p "$OUT_DIR"

echo "[storage-drill-evidence] refreshing combined restore/replication/failover drill evidence into $OUT_DIR"
UHOST_STORAGE_DRILL_EVIDENCE_OUT_DIR="$OUT_DIR" \
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test storage_drill_evidence storage_drill_evidence_bundle_can_be_regenerated -- --ignored --exact --nocapture

echo "[storage-drill-evidence] wrote $OUT_DIR/storage-drill-evidence.json"
echo "[storage-drill-evidence] wrote $OUT_DIR/storage-drill-evidence.md"
