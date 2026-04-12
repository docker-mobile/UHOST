#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" wave3-evidence-gate bash "$0" "$@"
fi
cd "$REPO_ROOT"

UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  wave3-evidence
)

echo "[wave3-evidence] runtime admission and cross-domain rehearsal checks"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test auth_gate runtime_topology_surface_requires_operator_token_and_reports_all_in_one_ownership -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test auth_gate workload_identity_bearer_token_admits_tenant_route_and_keeps_operator_surface_protected -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test wave3_evidence wave3_evidence_refresh_exercises_cross_domain_rehearsal_story -- --exact

echo "[wave3-evidence] toaster adversarial checks"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test toaster

echo "[wave3-evidence] generated benchmark artifact freshness checks"
bash "$REPO_ROOT/ci/check-generated-benchmark-artifacts.sh"

echo "[wave3-evidence] registry and lease substrate checks"
cargo test -p uhost-store lease::tests::local_lease_registration_collection_persists_readiness_and_drain_state -- --exact
cargo test -p uhost-store registry::tests::local_cell_directory_collection_persists_region_membership_and_participants -- --exact

echo "[wave3-evidence] network and storage recovery checks"
cargo test -p uhost-svc-netsec tests::private_network_attachment_is_enforced -- --exact
cargo test -p uhost-svc-ingress tests::create_route_honors_private_exposure_intent -- --exact
cargo test -p uhost-svc-ingress tests::private_route_rejects_missing_private_network_context -- --exact
cargo test -p uhost-svc-storage tests::create_volume_bootstraps_recovery_point_and_completes_snapshot_workflow -- --exact
cargo test -p uhost-svc-storage tests::recovery_point_repair_is_versioned_and_preserves_completed_workflow -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test storage_drill_evidence combined_storage_drill_rehearsal_exercises_restore_replication_and_failover -- --exact
bash ci/check-storage-drill-evidence.sh

echo "[wave3-evidence] uvm portability and restore-lineage checks"
cargo test -p uhost-svc-uvm-node tests::preflight_falls_back_to_software_backend_with_structured_portability_assessment -- --exact
cargo test -p uhost-svc-uvm-node tests::software_runner_restore_updates_lineage_and_health_summary -- --exact

echo "[wave3-evidence] passed"
