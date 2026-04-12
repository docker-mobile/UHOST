#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" perf-gate bash "$0" "$@"
fi
cd "$REPO_ROOT"

echo "[perf-gate] quick hyperscale profiles"
bash scripts/run-hyperscale.sh

echo "[perf-gate] scheduler benchmark smoke"
cargo bench -p uhost-svc-scheduler --bench placement -- --sample-size 10

echo "[perf-gate] netsec benchmark smoke"
cargo bench -p uhost-svc-netsec --bench policy_eval -- --sample-size 10

echo "[perf-gate] passed"
