#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" && -z "${CARGO_TARGET_DIR:-}" ]]; then
  export UHOST_DISPOSABLE_TARGET_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  hyperscale
)

echo "[hyperscale] verifying generated benchmark evidence bundle"
bash "$REPO_ROOT/ci/check-generated-benchmark-artifacts.sh"

echo "[hyperscale] running quick load profile"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test hyperscale hyperscale_load_identity_write_profile -- --ignored --nocapture

echo "[hyperscale] running quick mixed endpoint profile"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test hyperscale hyperscale_mixed_endpoint_profile -- --ignored --nocapture

echo "[hyperscale] running focused wave1 parity profile"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test hyperscale hyperscale_wave1_parity_profile -- --ignored --nocapture

echo "[hyperscale] running optional long profiles when RUN_LONG=1"
if [[ "${RUN_LONG:-0}" == "1" ]]; then
  "${UHOSTD_CARGO[@]}" cargo test -p uhostd --test hyperscale hyperscale_soak_mixed_profile -- --ignored --nocapture
  "${UHOSTD_CARGO[@]}" cargo test -p uhostd --test hyperscale hyperscale_chaos_restart_profile -- --ignored --nocapture
fi

echo "[hyperscale] complete"
