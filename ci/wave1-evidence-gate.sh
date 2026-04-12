#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" wave1-evidence-gate bash "$0" "$@"
fi
cd "$REPO_ROOT"

UHOSTD_CARGO=(
  bash
  "$REPO_ROOT/scripts/with-disposable-target-dir.sh"
  wave1-evidence
)

echo "[wave1-evidence] runtime and contract focused checks"
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test auth_gate bootstrap_admin_auth_gate_protects_control_plane_routes -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test route_ownership runtime_preserves_representative_route_ownership -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test contract_snapshots openapi_snapshot_contains_new_control_domains -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test contract_snapshots protobuf_snapshot_contains_new_services -- --exact
"${UHOSTD_CARGO[@]}" cargo test -p uhostd --test wave1_evidence wave1_evidence_refresh_exercises_backend_and_uvm_parity_seams -- --exact

echo "[wave1-evidence] substrate focused checks"
cargo test -p uhost-store metadata::tests::local_metadata_collection_preserves_cross_handle_concurrency_checks -- --exact
cargo test -p uhost-store workflow::tests::local_workflow_collection_preserves_cross_handle_version_checks -- --exact
cargo test -p uhost-store relay::tests::event_relay_persists_replay_and_delivery_metadata -- --exact
cargo test -p uhost-store relay::tests::event_relay_reads_legacy_outbox_records_without_new_metadata -- --exact

echo "[wave1-evidence] service seam focused checks"
cargo test -p uhost-svc-identity tests::issue_workload_identity_persists_sealed_credential_and_principal_metadata -- --exact
cargo test -p uhost-svc-identity tests::issue_workload_identity_enforces_subject_uniqueness_and_ttl_bounds -- --exact
cargo test -p uhost-svc-policy tests::policy_evaluation_returns_structured_explanation_and_principal_context -- --exact
cargo test -p uhost-svc-governance tests::change_approval_persists_authenticated_request_provenance -- --exact
cargo test -p uhost-svc-ingress tests::create_route_accepts_valid_public_dns_and_security_attachments -- --exact
cargo test -p uhost-svc-ingress tests::create_route_rejects_mismatched_zone_binding -- --exact
cargo test -p uhost-svc-uvm-image tests::import_emits_compatibility_requirement_and_evidence -- --exact
cargo test -p uhost-svc-uvm-node tests::preflight_consumes_matching_compatibility_requirement_and_publishes_assessment -- --exact
cargo test -p uhost-svc-uvm-node tests::preflight_reports_mismatched_compatibility_requirement -- --exact

echo "[wave1-evidence] passed"
