use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::{
    CellDirectoryRecord, CellParticipantLeaseState, CellParticipantReconciliationState,
    CellParticipantRecord, CellParticipantState, DocumentCollection, DocumentStore,
    LeaseDrainIntent, LeaseFreshness, LeaseReadiness, LeaseRegistrationRecord,
    ParticipantTombstoneHistoryRecord, RegionDirectoryRecord, StoredDocument, WorkflowPhase,
    WorkflowStepState, stale_participant_cleanup_workflow, stale_participant_cleanup_workflow_id,
};
use uhost_testkit::TempState;
use uhost_types::{
    ChangeRequestId, NodeId, OwnershipScope, ProjectId, ResourceMetadata, UvmImageId,
};

const BOOTSTRAP_TOKEN: &str = "integration-bootstrap-admin-token";
const RUNTIME_TOMBSTONED_EVENT_TYPE: &str = "runtime.participant.tombstoned.v1";
const DATABASE_BACKING_VOLUME_ID_ANNOTATION: &str = "data.storage.backing_volume_id";
const DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION: &str =
    "data.storage.last_restore.source_recovery_point_version";
const DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION: &str =
    "data.storage.last_restore.source_recovery_point_etag";

struct ChildGuard {
    child: Child,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeedGovernanceChangeRequest {
    id: ChangeRequestId,
    title: String,
    change_type: String,
    requested_by: String,
    approved_by: Option<String>,
    reviewer_comment: Option<String>,
    required_approvals: u8,
    state: String,
    metadata: ResourceMetadata,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Harness {
    address: SocketAddr,
    state_dir: PathBuf,
    seeded_change_request_id: Option<String>,
    _temp: TempState,
    _guard: ChildGuard,
    _serial_guard: MutexGuard<'static, ()>,
}

struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

#[test]
fn toaster_cross_domain_token_context_and_preflight_abuse_are_contained() {
    let Some(harness) = launch_harness("toaster-edge-uvm-node", false, Some("approved")) else {
        eprintln!(
            "skipping toaster_cross_domain_token_context_and_preflight_abuse_are_contained: loopback bind not permitted"
        );
        return;
    };

    let edge_token = issue_workload_identity(
        harness.address,
        BOOTSTRAP_TOKEN,
        "svc:toaster-edge",
        &["ingress", "netsec"],
        900,
    );
    let cross_audience = request_json_response(
        harness.address,
        "GET",
        "/uvm/runtime/preflight",
        None,
        Some(edge_token.as_str()),
        None,
    );
    assert_eq!(cross_audience.status, 401);

    let private_network_a = request_json_with_bearer_token(
        harness.address,
        "POST",
        "/netsec/private-networks",
        Some(json!({
            "name": "toaster-private-a",
            "cidr": "10.50.0.0/16",
            "attachments": []
        })),
        edge_token.as_str(),
    );
    let private_network_b = request_json_with_bearer_token(
        harness.address,
        "POST",
        "/netsec/private-networks",
        Some(json!({
            "name": "toaster-private-b",
            "cidr": "10.51.0.0/16",
            "attachments": []
        })),
        edge_token.as_str(),
    );
    let private_network_a_id = private_network_a["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private network a id"))
        .to_owned();
    let private_network_b_id = private_network_b["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private network b id"))
        .to_owned();
    seed_private_network_topology(
        harness.address,
        edge_token.as_str(),
        &private_network_a_id,
        "10.50.1.0/24",
        "10.50.0.0/16",
    );
    let ingress_change_request_id = harness
        .seeded_change_request_id
        .clone()
        .unwrap_or_else(|| panic!("missing seeded governance change request id"));

    let route = request_json_with_bearer_token(
        harness.address,
        "POST",
        "/ingress/routes",
        Some(json!({
            "hostname": "toaster-private.example.com",
            "target": "http://127.0.0.1:18080",
            "backends": [],
            "protocol": "http",
            "sticky_sessions": false,
            "tls_mode": "offload",
            "change_request_id": ingress_change_request_id,
            "publication": {
                "exposure": "private",
                "private_network": {
                    "private_network_id": private_network_a_id.clone()
                }
            }
        })),
        edge_token.as_str(),
    );
    assert_eq!(route["publication"]["exposure"], "private");
    assert_eq!(
        route["publication"]["private_network"]["private_network_id"],
        json!(private_network_a_id.clone())
    );

    let invalid_private_network_context = request_json_response(
        harness.address,
        "POST",
        "/ingress/evaluate",
        Some(json!({
            "hostname": "toaster-private.example.com",
            "protocol": "http",
            "client_ip": "203.0.113.91",
            "private_network_id": "not-a-private-network"
        })),
        Some(edge_token.as_str()),
        None,
    );
    assert_eq!(invalid_private_network_context.status, 400);
    let invalid_private_network_context_body = response_json(&invalid_private_network_context);
    assert_eq!(
        invalid_private_network_context_body["error"]["message"].as_str(),
        Some("invalid private_network_id")
    );

    let mismatched_context = request_json_with_bearer_token(
        harness.address,
        "POST",
        "/ingress/evaluate",
        Some(json!({
            "hostname": "toaster-private.example.com",
            "protocol": "http",
            "client_ip": "203.0.113.92",
            "private_network_id": private_network_b_id.clone()
        })),
        edge_token.as_str(),
    );
    assert_eq!(mismatched_context["admitted"].as_bool(), Some(false));
    assert_eq!(
        mismatched_context["reason"].as_str(),
        Some("private_network_id does not match route private network")
    );

    let matched_context = request_json_with_bearer_token(
        harness.address,
        "POST",
        "/ingress/evaluate",
        Some(json!({
            "hostname": "toaster-private.example.com",
            "protocol": "http",
            "client_ip": "203.0.113.93",
            "private_network_id": private_network_a_id
        })),
        edge_token.as_str(),
    );
    assert_eq!(matched_context["admitted"].as_bool(), Some(true));

    let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt"],
            "max_vcpu": 4,
            "max_memory_mb": 8192,
            "numa_nodes": 1,
            "supports_secure_boot": false,
            "supports_live_migration": false,
            "supports_pci_passthrough": false,
            "software_runner_supported": false,
            "host_evidence_mode": "container_restricted"
        })),
        BOOTSTRAP_TOKEN,
    );
    let capability_id = capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing capability id"));
    let preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/preflight",
        Some(json!({
            "capability_id": capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "vcpu": 2,
            "memory_mb": 2048,
            "migration_policy": "cold_only",
            "require_secure_boot": false,
            "requires_live_migration": false,
            "execution_intent": {
                "preferred_backend": "kvm",
                "fallback_policy": "allow_compatible",
                "required_portability_tier": "portable",
                "evidence_strictness": "require_measured"
            }
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(preflight["legal_allowed"].as_bool(), Some(false));
    assert_eq!(preflight["placement_admitted"].as_bool(), Some(true));
    assert!(preflight["selected_backend"].is_null());
    assert_eq!(
        preflight["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );
    assert_array_contains_substring(
        &preflight["blockers"],
        "requires measured evidence, got simulated",
    );
    assert_array_contains_substring(
        &preflight["blockers"],
        "software_dbt backend requires software_runner_supported capability posture",
    );
    assert_array_contains_substring(
        &preflight["portability_assessment"]["blockers"],
        "requires measured evidence, got simulated",
    );
    assert_array_contains_substring(
        &preflight["portability_assessment"]["blockers"],
        "software_dbt backend requires software_runner_supported capability posture",
    );
}

#[test]
fn toaster_runtime_duplicate_tombstone_and_history_cursor_abuse_are_rejected() {
    let Some(harness) = launch_harness("toaster-runtime-node", true, None) else {
        eprintln!(
            "skipping toaster_runtime_duplicate_tombstone_and_history_cursor_abuse_are_rejected: loopback bind not permitted"
        );
        return;
    };

    let first_tombstone = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/runtime/participants/tombstone",
        Some(json!({
            "registration_id": "controller:stale-peer-node"
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        first_tombstone["participant_registration_id"].as_str(),
        Some("controller:stale-peer-node")
    );
    assert_eq!(
        first_tombstone["removed_from_cell_directory"].as_bool(),
        Some(true)
    );

    let duplicate_tombstone = request_json_response(
        harness.address,
        "POST",
        "/runtime/participants/tombstone",
        Some(json!({
            "registration_id": "controller:stale-peer-node"
        })),
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(duplicate_tombstone.status, 404);

    let history = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history",
        None,
        BOOTSTRAP_TOKEN,
    );
    let history_items = history["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing tombstone history items"));
    assert_eq!(history_items.len(), 1);
    assert_eq!(
        history_items[0]["participant_registration_id"].as_str(),
        Some("controller:stale-peer-node")
    );

    let zero_limit = request_json_response(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history?limit=0",
        None,
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(zero_limit.status, 400);
    let zero_limit_body = response_json(&zero_limit);
    assert_eq!(
        zero_limit_body["error"]["message"].as_str(),
        Some("invalid runtime tombstone history limit")
    );

    let malformed_cursor = request_json_response(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history?cursor=Zm9v",
        None,
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(malformed_cursor.status, 400);
    let malformed_cursor_body = response_json(&malformed_cursor);
    assert_eq!(
        malformed_cursor_body["error"]["message"].as_str(),
        Some("invalid runtime tombstone history cursor")
    );
    assert!(
        malformed_cursor_body["error"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("<unix_timestamp_nanos>:<event_id>"))
    );

    let history_records = read_active_collection_values(
        harness
            .state_dir
            .join("runtime")
            .join("participant-tombstone-history.json")
            .as_path(),
    );
    assert_eq!(history_records.len(), 1);

    let outbox_entries = read_active_collection_values(
        harness
            .state_dir
            .join("runtime")
            .join("outbox.json")
            .as_path(),
    );
    assert_eq!(
        outbox_entries
            .iter()
            .filter(|entry| entry["event_type"] == json!(RUNTIME_TOMBSTONED_EVENT_TYPE))
            .count(),
        1
    );

    let audit_events = read_runtime_audit_events(&harness.state_dir);
    assert_eq!(
        audit_events
            .iter()
            .filter(|event| event["header"]["event_type"] == json!(RUNTIME_TOMBSTONED_EVENT_TYPE))
            .count(),
        1
    );
}

#[test]
fn toaster_restore_lineage_intent_handoff_and_history_pagination_stay_deterministic() {
    let Some(harness) = launch_harness("toaster-wave3-chaos", true, None) else {
        eprintln!(
            "skipping toaster_restore_lineage_intent_handoff_and_history_pagination_stay_deterministic: loopback bind not permitted"
        );
        return;
    };

    let seeded_at = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    seed_runtime_tombstone_history_records(
        harness
            .state_dir
            .join("runtime")
            .join("participant-tombstone-history.json")
            .as_path(),
        vec![
            build_seeded_runtime_tombstone_history_record(
                "history-001",
                "controller:history-node-a",
                "history-node-a",
                seeded_at,
            ),
            build_seeded_runtime_tombstone_history_record(
                "history-002",
                "controller:history-node-b",
                "history-node-b",
                seeded_at + time::Duration::seconds(1),
            ),
            build_seeded_runtime_tombstone_history_record(
                "history-003",
                "controller:history-node-c",
                "history-node-c",
                seeded_at + time::Duration::seconds(2),
            ),
        ],
    );

    let first_history_page = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history?limit=2",
        None,
        BOOTSTRAP_TOKEN,
    );
    let first_history_items = first_history_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing first history page items"));
    assert_eq!(first_history_items.len(), 2);
    assert_eq!(
        first_history_items[0]["participant_registration_id"].as_str(),
        Some("controller:history-node-c")
    );
    assert_eq!(
        first_history_items[1]["participant_registration_id"].as_str(),
        Some("controller:history-node-b")
    );
    let first_page_cursor = first_history_page["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("missing first history page cursor"))
        .to_owned();

    let tombstone = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/runtime/participants/tombstone",
        Some(json!({
            "registration_id": "controller:stale-peer-node"
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        tombstone["participant_registration_id"].as_str(),
        Some("controller:stale-peer-node")
    );
    assert_eq!(
        tombstone["removed_from_cell_directory"].as_bool(),
        Some(true)
    );

    let continued_history_page = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        &format!("/runtime/participants/tombstone-history?limit=2&cursor={first_page_cursor}"),
        None,
        BOOTSTRAP_TOKEN,
    );
    let continued_history_items = continued_history_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing continued history page items"));
    assert_eq!(continued_history_items.len(), 1);
    assert_eq!(
        continued_history_items[0]["participant_registration_id"].as_str(),
        Some("controller:history-node-a")
    );
    assert!(continued_history_page.get("next_cursor").is_none());
    assert_eq!(
        continued_history_page["retention"]["retained_entries"].as_u64(),
        Some(4)
    );

    let refreshed_history_page = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history?limit=2",
        None,
        BOOTSTRAP_TOKEN,
    );
    let refreshed_history_items = refreshed_history_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing refreshed history page items"));
    assert_eq!(refreshed_history_items.len(), 2);
    assert_eq!(
        refreshed_history_items[0]["participant_registration_id"].as_str(),
        Some("controller:stale-peer-node")
    );
    assert_eq!(
        refreshed_history_items[1]["participant_registration_id"].as_str(),
        Some("controller:history-node-c")
    );

    let aggregated_tombstone = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated?participant_registration_id=controller:stale-peer-node",
        None,
        BOOTSTRAP_TOKEN,
    );
    let aggregated_tombstone_items = aggregated_tombstone["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing aggregated tombstone items"));
    assert_eq!(aggregated_tombstone_items.len(), 1);
    assert_eq!(
        aggregated_tombstone_items[0]["history"]["participant_registration_id"].as_str(),
        Some("controller:stale-peer-node")
    );
    assert_eq!(
        aggregated_tombstone_items[0]["relay_evidence"]["event_type"].as_str(),
        Some(RUNTIME_TOMBSTONED_EVENT_TYPE)
    );
    assert_eq!(
        aggregated_tombstone_items[0]["relay_evidence"]["delivery_state"].as_str(),
        Some("pending")
    );
    assert_eq!(
        aggregated_tombstone_items[0]["relay_evidence"]["idempotency_key"],
        aggregated_tombstone_items[0]["history"]["event_id"]
    );

    let seeded_history_without_relay = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated?event_id=history-003",
        None,
        BOOTSTRAP_TOKEN,
    );
    let seeded_history_without_relay_items = seeded_history_without_relay["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing seeded aggregate history items"));
    assert_eq!(seeded_history_without_relay_items.len(), 1);
    assert_eq!(
        seeded_history_without_relay_items[0]["history"]["participant_registration_id"].as_str(),
        Some("controller:history-node-c")
    );
    assert!(seeded_history_without_relay_items[0]["relay_evidence"].is_null());

    let blank_aggregate_filter = request_json_response(
        harness.address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated?participant_registration_id=%20",
        None,
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(blank_aggregate_filter.status, 400);
    let blank_aggregate_filter_body = response_json(&blank_aggregate_filter);
    assert_eq!(
        blank_aggregate_filter_body["error"]["message"].as_str(),
        Some("invalid runtime tombstone aggregate participant_registration_id filter")
    );

    let database = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/data/databases",
        Some(json!({
            "engine": "postgres",
            "version": "16.2",
            "storage_gb": 64,
            "replicas": 2,
            "tls_required": true,
            "primary_region": "us-east-1"
        })),
        BOOTSTRAP_TOKEN,
    );
    let database_id = database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing database id"))
        .to_owned();
    let backup = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/data/databases/{database_id}/backups"),
        Some(json!({
            "kind": "full",
            "reason": "toaster-second-slice-backup"
        })),
        BOOTSTRAP_TOKEN,
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"))
        .to_owned();
    let backing_volume_id = backup["storage_recovery_point"]["volume_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup storage volume id"))
        .to_owned();
    let backup_recovery_point_version = backup["storage_recovery_point"]["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing backup storage recovery point version"));
    let backup_recovery_point_execution_count = backup["storage_recovery_point"]["execution_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing backup storage recovery point execution count"));
    let backup_recovery_point_etag = backup["storage_recovery_point"]["etag"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup storage recovery point etag"))
        .to_owned();

    advance_persisted_volume_recovery_point(&harness.state_dir, backing_volume_id.as_str());
    let drifted_recovery_point = read_collection_record(
        harness
            .state_dir
            .join("storage")
            .join("volume_recovery_points.json")
            .as_path(),
        backing_volume_id.as_str(),
    );
    let drifted_recovery_point_version = drifted_recovery_point["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing drifted recovery point version"));
    let drifted_recovery_point_etag = drifted_recovery_point["value"]["metadata"]["etag"]
        .as_str()
        .unwrap_or_else(|| panic!("missing drifted recovery point etag"))
        .to_owned();
    assert!(drifted_recovery_point_version > backup_recovery_point_version);

    let historical_restore = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/data/databases/{database_id}/restore"),
        Some(json!({
            "backup_id": backup_id,
            "reason": "historical-lineage-drift-check"
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(historical_restore["state"].as_str(), Some("completed"));
    let historical_restore_id = historical_restore["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing historical restore id"));
    let historical_restore_record = read_collection_record(
        harness
            .state_dir
            .join("data")
            .join("restores.json")
            .as_path(),
        historical_restore_id,
    );
    let historical_storage_restore = historical_restore_record["value"]["storage_restore"].clone();
    assert_eq!(
        historical_storage_restore["source_mode"],
        json!("backup_correlated_storage_lineage")
    );
    assert_eq!(
        historical_storage_restore["backup_correlated_recovery_point"]["volume_id"],
        json!(backing_volume_id.clone())
    );
    assert_eq!(
        historical_storage_restore["backup_correlated_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        historical_storage_restore["selected_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        historical_storage_restore["selected_recovery_point"]["execution_count"],
        json!(backup_recovery_point_execution_count)
    );
    assert_eq!(
        historical_storage_restore["selected_recovery_point"]["etag"],
        json!(backup_recovery_point_etag.clone())
    );
    assert_ne!(
        historical_storage_restore["selected_recovery_point"]["version"],
        json!(drifted_recovery_point_version)
    );
    assert_ne!(
        historical_storage_restore["selected_recovery_point"]["etag"],
        json!(drifted_recovery_point_etag.clone())
    );

    let historical_storage_action_id = historical_storage_restore["restore_action_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing historical storage restore action id"));
    let historical_storage_action = read_collection_record(
        harness
            .state_dir
            .join("storage")
            .join("volume_restore_actions.json")
            .as_path(),
        historical_storage_action_id,
    );
    assert_eq!(
        historical_storage_action["value"]["source_recovery_point_version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        historical_storage_action["value"]["source_recovery_point_execution_count"],
        json!(backup_recovery_point_execution_count)
    );
    assert_eq!(
        historical_storage_action["value"]["source_recovery_point_etag"],
        json!(backup_recovery_point_etag.clone())
    );

    let historical_database_record = read_collection_record(
        harness
            .state_dir
            .join("data")
            .join("databases.json")
            .as_path(),
        database_id.as_str(),
    );
    assert_eq!(
        historical_database_record["value"]["metadata"]["annotations"]
            [DATABASE_BACKING_VOLUME_ID_ANNOTATION],
        json!(backing_volume_id.clone())
    );
    assert_eq!(
        historical_database_record["value"]["metadata"]["annotations"]
            [DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION],
        json!(backup_recovery_point_version.to_string())
    );
    assert_eq!(
        historical_database_record["value"]["metadata"]["annotations"]
            [DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION],
        json!(backup_recovery_point_etag.clone())
    );

    advance_persisted_volume_recovery_point(&harness.state_dir, backing_volume_id.as_str());
    let replay_drifted_recovery_point = read_collection_record(
        harness
            .state_dir
            .join("storage")
            .join("volume_recovery_points.json")
            .as_path(),
        backing_volume_id.as_str(),
    );
    let replay_drifted_recovery_point_version = replay_drifted_recovery_point["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing replay drifted recovery point version"));
    let replay_drifted_recovery_point_etag =
        replay_drifted_recovery_point["value"]["metadata"]["etag"]
            .as_str()
            .unwrap_or_else(|| panic!("missing replay drifted recovery point etag"))
            .to_owned();
    assert!(replay_drifted_recovery_point_version > drifted_recovery_point_version);

    let replayed_historical_restore = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/data/databases/{database_id}/restore"),
        Some(json!({
            "backup_id": backup_id,
            "reason": "historical-lineage-replay-check"
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        replayed_historical_restore["state"].as_str(),
        Some("completed")
    );
    let replayed_historical_restore_id = replayed_historical_restore["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing replayed historical restore id"));
    let replayed_historical_restore_record = read_collection_record(
        harness
            .state_dir
            .join("data")
            .join("restores.json")
            .as_path(),
        replayed_historical_restore_id,
    );
    let replayed_storage_restore =
        replayed_historical_restore_record["value"]["storage_restore"].clone();
    assert_eq!(
        replayed_storage_restore["source_mode"],
        json!("backup_correlated_storage_lineage")
    );
    assert_eq!(
        replayed_storage_restore["backup_correlated_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        replayed_storage_restore["selected_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        replayed_storage_restore["selected_recovery_point"]["execution_count"],
        json!(backup_recovery_point_execution_count)
    );
    assert_eq!(
        replayed_storage_restore["selected_recovery_point"]["etag"],
        json!(backup_recovery_point_etag.clone())
    );
    assert_ne!(
        replayed_storage_restore["selected_recovery_point"]["version"],
        json!(replay_drifted_recovery_point_version)
    );
    assert_ne!(
        replayed_storage_restore["selected_recovery_point"]["etag"],
        json!(replay_drifted_recovery_point_etag.clone())
    );

    advance_persisted_volume_recovery_point(&harness.state_dir, backing_volume_id.as_str());
    let fallback_recovery_point = read_collection_record(
        harness
            .state_dir
            .join("storage")
            .join("volume_recovery_points.json")
            .as_path(),
        backing_volume_id.as_str(),
    );
    let fallback_recovery_point_version = fallback_recovery_point["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing fallback recovery point version"));
    let fallback_recovery_point_execution_count =
        fallback_recovery_point["value"]["execution_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing fallback recovery point execution count"));
    let fallback_recovery_point_etag = fallback_recovery_point["value"]["metadata"]["etag"]
        .as_str()
        .unwrap_or_else(|| panic!("missing fallback recovery point etag"))
        .to_owned();
    remove_persisted_volume_recovery_point_revision(
        &harness.state_dir,
        backing_volume_id.as_str(),
        backup_recovery_point_version,
    );
    let harness = restart_harness(harness);

    let fallback_restore = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/data/databases/{database_id}/restore"),
        Some(json!({
            "backup_id": backup_id,
            "reason": "historical-lineage-fallback-check"
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(fallback_restore["state"].as_str(), Some("completed"));
    let fallback_restore_id = fallback_restore["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing fallback restore id"));
    let fallback_restore_record = read_collection_record(
        harness
            .state_dir
            .join("data")
            .join("restores.json")
            .as_path(),
        fallback_restore_id,
    );
    let fallback_storage_restore = fallback_restore_record["value"]["storage_restore"].clone();
    assert_eq!(
        fallback_storage_restore["source_mode"],
        json!("latest_ready_fallback")
    );
    assert_eq!(
        fallback_storage_restore["backup_correlated_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_eq!(
        fallback_storage_restore["selected_recovery_point"]["version"],
        json!(fallback_recovery_point_version)
    );
    assert_eq!(
        fallback_storage_restore["selected_recovery_point"]["execution_count"],
        json!(fallback_recovery_point_execution_count)
    );
    assert_eq!(
        fallback_storage_restore["selected_recovery_point"]["etag"],
        json!(fallback_recovery_point_etag.clone())
    );
    assert_ne!(
        fallback_storage_restore["selected_recovery_point"]["version"],
        json!(backup_recovery_point_version)
    );
    assert_ne!(
        fallback_storage_restore["selected_recovery_point"]["etag"],
        json!(backup_recovery_point_etag.clone())
    );

    let fallback_storage_action_id = fallback_storage_restore["restore_action_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing fallback storage restore action id"));
    let fallback_storage_action = read_collection_record(
        harness
            .state_dir
            .join("storage")
            .join("volume_restore_actions.json")
            .as_path(),
        fallback_storage_action_id,
    );
    assert_eq!(
        fallback_storage_action["value"]["source_recovery_point_version"],
        json!(fallback_recovery_point_version)
    );
    assert_eq!(
        fallback_storage_action["value"]["source_recovery_point_execution_count"],
        json!(fallback_recovery_point_execution_count)
    );
    assert_eq!(
        fallback_storage_action["value"]["source_recovery_point_etag"],
        json!(fallback_recovery_point_etag.clone())
    );

    let fallback_database_record = read_collection_record(
        harness
            .state_dir
            .join("data")
            .join("databases.json")
            .as_path(),
        database_id.as_str(),
    );
    assert_eq!(
        fallback_database_record["value"]["metadata"]["annotations"]
            [DATABASE_BACKING_VOLUME_ID_ANNOTATION],
        json!(backing_volume_id.clone())
    );
    assert_eq!(
        fallback_database_record["value"]["metadata"]["annotations"]
            [DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION],
        json!(fallback_recovery_point_version.to_string())
    );
    assert_eq!(
        fallback_database_record["value"]["metadata"]["annotations"]
            [DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION],
        json!(fallback_recovery_point_etag.clone())
    );

    let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt", "kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let source_capability_id = source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing source capability id"))
        .to_owned();

    let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let target_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": target_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let target_capability_id = target_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing target capability id"))
        .to_owned();

    let explicit_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "require_preferred",
        "required_portability_tier": "accelerator_required",
        "evidence_strictness": "allow_simulated"
    });
    let template = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/templates",
        Some(json!({
            "name": "toaster-intent-template",
            "architecture": "x86_64",
            "vcpu": 4,
            "memory_mb": 4096,
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "firmware_profile": "uefi_secure",
            "device_profile": "cloud-balanced",
            "migration_policy": "best_effort_live",
            "apple_guest_allowed": false,
            "execution_intent": explicit_execution_intent.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(template["execution_intent"], explicit_execution_intent);
    let template_id = template["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing template id"))
        .to_owned();

    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
    let boot_image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
    let instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/instances",
        Some(json!({
            "project_id": project_id.to_string(),
            "name": "toaster-intent-instance",
            "template_id": template_id,
            "boot_image_id": boot_image_id.to_string(),
            "guest_os": "linux",
            "host_node_id": source_node_id.to_string()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(instance["execution_intent"], explicit_execution_intent);
    let instance_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing instance id"))
        .to_owned();

    let started_instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/instances/{instance_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_instance["state"].as_str(), Some("running"));

    let runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": source_node_id.to_string(),
            "capability_id": source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-intent.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_secure",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": true,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "on-failure",
            "max_restarts": 3,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(runtime_session["accelerator_backend"], json!("kvm"));
    let runtime_session_id = runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing runtime session id"))
        .to_owned();
    let runtime_session_intent_record = read_collection_record(
        harness
            .state_dir
            .join("uvm-node")
            .join("runtime_session_intents.json")
            .as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        runtime_session_intent_record["value"]["execution_intent"],
        explicit_execution_intent
    );

    let started_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_runtime_session["state"].as_str(), Some("running"));

    let downgraded_execution_intent = json!({
        "fallback_policy": "allow_compatible",
        "required_portability_tier": "portable",
        "evidence_strictness": "allow_simulated"
    });
    set_control_plane_instance_execution_intent(
        &harness.state_dir,
        instance_id.as_str(),
        downgraded_execution_intent.clone(),
    );
    let downgraded_instance_record = read_collection_record(
        harness
            .state_dir
            .join("uvm-control")
            .join("instances.json")
            .as_path(),
        instance_id.as_str(),
    );
    assert_eq!(
        downgraded_instance_record["value"]["execution_intent"],
        downgraded_execution_intent
    );

    let migration_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": runtime_session_id,
            "to_node_id": target_node_id.to_string(),
            "target_capability_id": target_capability_id,
            "require_secure_boot": true
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(migration_preflight["legal_allowed"].as_bool(), Some(true));
    assert_eq!(
        migration_preflight["selected_backend"].as_str(),
        Some("kvm")
    );
    assert_eq!(
        migration_preflight["portability_assessment"]["intent"],
        json!({
            "preferred_backend": "kvm",
            "fallback_policy": "require_preferred",
            "required_portability_tier": "accelerator_required",
            "evidence_strictness": "allow_simulated"
        })
    );
    assert_eq!(
        migration_preflight["portability_assessment"]["selected_backend"],
        json!("kvm")
    );
    assert_eq!(
        migration_preflight["portability_assessment"]["selected_via_fallback"].as_bool(),
        Some(false)
    );
    assert_ne!(
        migration_preflight["portability_assessment"]["intent"],
        downgraded_execution_intent
    );

    let host_evidence = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/host-evidence",
        Some(json!({
            "evidence_mode": "measured",
            "host_platform": "linux",
            "execution_environment": "bare_metal",
            "hardware_virtualization": true,
            "nested_virtualization": false,
            "qemu_available": true,
            "note": "toaster-intent-handoff"
        })),
        BOOTSTRAP_TOKEN,
    );
    let host_evidence_id = host_evidence["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing host evidence id"))
        .to_owned();
    let migration_preflight_id = migration_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing migration preflight id"))
        .to_owned();
    let claim_decision = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id,
            "runtime_preflight_id": migration_preflight_id
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        claim_decision["runtime_preflight_id"],
        json!(migration_preflight_id.clone())
    );
    assert_eq!(
        claim_decision["portability_assessment"]["intent"],
        json!({
            "preferred_backend": "kvm",
            "fallback_policy": "require_preferred",
            "required_portability_tier": "accelerator_required",
            "evidence_strictness": "allow_simulated"
        })
    );
    assert_eq!(
        claim_decision["portability_assessment"]["selected_backend"],
        json!("kvm")
    );
    assert_eq!(
        claim_decision["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    assert_ne!(
        claim_decision["portability_assessment"]["intent"],
        downgraded_execution_intent
    );
}

#[test]
fn toaster_uvm_checkpoint_migration_replay_weirdness_stays_deterministic_and_lineage_scoped() {
    let Some(harness) = launch_harness("toaster-uvm-replay", false, None) else {
        eprintln!(
            "skipping toaster_uvm_checkpoint_migration_replay_weirdness_stays_deterministic_and_lineage_scoped: loopback bind not permitted"
        );
        return;
    };

    let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let source_capability_id = source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing source capability id"))
        .to_owned();

    let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let target_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": target_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let target_capability_id = target_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing target capability id"))
        .to_owned();

    let runtime_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "require_preferred",
        "required_portability_tier": "accelerator_required",
        "evidence_strictness": "allow_simulated"
    });
    let template = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/templates",
        Some(json!({
            "name": "toaster-replay-template",
            "architecture": "x86_64",
            "vcpu": 4,
            "memory_mb": 4096,
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "firmware_profile": "uefi_secure",
            "device_profile": "cloud-balanced",
            "migration_policy": "best_effort_live",
            "apple_guest_allowed": false,
            "execution_intent": runtime_execution_intent.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    let template_id = template["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing template id"))
        .to_owned();

    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
    let boot_image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
    let instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/instances",
        Some(json!({
            "project_id": project_id.to_string(),
            "name": "toaster-replay-instance",
            "template_id": template_id,
            "boot_image_id": boot_image_id.to_string(),
            "guest_os": "linux",
            "host_node_id": source_node_id.to_string()
        })),
        BOOTSTRAP_TOKEN,
    );
    let instance_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing instance id"))
        .to_owned();

    let started_instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/instances/{instance_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_instance["state"].as_str(), Some("running"));

    let runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": source_node_id.to_string(),
            "capability_id": source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-replay.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_secure",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": true,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "always",
            "max_restarts": 3,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(runtime_session["accelerator_backend"], json!("kvm"));
    let runtime_session_id = runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing runtime session id"))
        .to_owned();
    let runtime_session_intent_path = harness
        .state_dir
        .join("uvm-node")
        .join("runtime_session_intents.json");
    let runtime_session_record_path = harness
        .state_dir
        .join("uvm-node")
        .join("runtime_sessions.json");
    let runtime_intent_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        runtime_intent_record["value"]["execution_intent"],
        runtime_execution_intent
    );
    assert_eq!(
        runtime_intent_record["value"]["first_placement_portability_assessment"]["supported"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        runtime_intent_record["value"]["first_placement_portability_assessment"]["selected_backend"],
        json!("kvm")
    );

    let started_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_runtime_session["state"].as_str(), Some("running"));

    record_uvm_native_claim_perf_attestations(harness.address, instance_id.as_str());
    let host_evidence = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/host-evidence",
        Some(json!({
            "evidence_mode": "measured",
            "host_platform": "linux",
            "execution_environment": "bare_metal",
            "hardware_virtualization": true,
            "nested_virtualization": false,
            "qemu_available": true,
            "note": "toaster-migration-replay"
        })),
        BOOTSTRAP_TOKEN,
    );
    let host_evidence_id = host_evidence["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing host evidence id"))
        .to_owned();
    let initial_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        initial_native_claim["claim_status"].as_str(),
        Some("allowed")
    );
    assert_eq!(
        initial_native_claim["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        initial_native_claim["portability_assessment_source"].as_str(),
        Some("first_placement_lineage")
    );
    assert_eq!(
        initial_native_claim["portability_assessment"]["selected_backend"].as_str(),
        Some("kvm")
    );

    let supported_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": runtime_session_id,
            "to_node_id": target_node_id.to_string(),
            "target_capability_id": target_capability_id,
            "require_secure_boot": true
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(supported_preflight["legal_allowed"].as_bool(), Some(true));
    assert_eq!(
        supported_preflight["selected_backend"].as_str(),
        Some("kvm")
    );
    let supported_preflight_id = supported_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing supported preflight id"))
        .to_owned();
    let intent_after_supported_preflight = read_collection_record(
        runtime_session_intent_path.as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        intent_after_supported_preflight["value"]["last_portability_preflight_id"],
        json!(supported_preflight_id.clone())
    );

    let first_migration_payload = json!({
        "runtime_session_id": runtime_session_id,
        "to_node_id": target_node_id.to_string(),
        "target_capability_id": target_capability_id,
        "kind": "live_precopy",
        "checkpoint_uri": "object://checkpoints/uvm/toaster-replay-rollback",
        "memory_bitmap_hash": "dead0001",
        "disk_generation": 41,
        "reason": "rollback replay drill"
    });
    let started_rollback_migration = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations",
        Some(first_migration_payload.clone()),
        BOOTSTRAP_TOKEN,
    );
    let rollback_migration_id = started_rollback_migration["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rollback migration id"))
        .to_owned();
    let rollback_checkpoint_id = started_rollback_migration["checkpoint_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rollback checkpoint id"))
        .to_owned();
    let replayed_rollback_migration = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations",
        Some(first_migration_payload),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        replayed_rollback_migration["id"],
        json!(rollback_migration_id.clone())
    );
    assert_eq!(
        replayed_rollback_migration["checkpoint_id"],
        json!(rollback_checkpoint_id.clone())
    );

    let rolled_back = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{rollback_migration_id}/rollback"),
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(rolled_back["state"].as_str(), Some("rolled_back"));
    let rolled_back_retry = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{rollback_migration_id}/rollback"),
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(rolled_back_retry["state"].as_str(), Some("rolled_back"));
    assert_eq!(
        rolled_back_retry["id"].as_str(),
        Some(rollback_migration_id.as_str())
    );
    let commit_after_rollback = request_json_response(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{rollback_migration_id}/commit"),
        None,
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(commit_after_rollback.status, 409);
    let commit_after_rollback_body = response_json(&commit_after_rollback);
    assert_eq!(
        commit_after_rollback_body["error"]["message"].as_str(),
        Some("runtime migration is not in progress")
    );
    let runtime_after_rollback = read_collection_record(
        runtime_session_record_path.as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        runtime_after_rollback["value"]["node_id"],
        json!(source_node_id.to_string())
    );
    assert_eq!(
        runtime_after_rollback["value"]["migration_in_progress"].as_bool(),
        Some(false)
    );

    let unsupported_execution_intent = json!({
        "preferred_backend": "apple_virtualization",
        "fallback_policy": "require_preferred",
        "required_portability_tier": "host_specific",
        "evidence_strictness": "require_measured"
    });
    let unsupported_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": runtime_session_id,
            "to_node_id": target_node_id.to_string(),
            "target_capability_id": target_capability_id,
            "require_secure_boot": true,
            "execution_intent": unsupported_execution_intent.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        unsupported_preflight["legal_allowed"].as_bool(),
        Some(false)
    );
    assert!(unsupported_preflight["selected_backend"].is_null());
    assert_eq!(
        unsupported_preflight["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );
    assert_eq!(
        unsupported_preflight["portability_assessment"]["intent"],
        unsupported_execution_intent
    );
    let unsupported_preflight_id = unsupported_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing unsupported preflight id"))
        .to_owned();
    assert_ne!(unsupported_preflight_id, supported_preflight_id);
    let intent_after_unsupported_preflight = read_collection_record(
        runtime_session_intent_path.as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        intent_after_unsupported_preflight["value"]["last_portability_preflight_id"],
        json!(supported_preflight_id.clone())
    );
    assert_ne!(
        intent_after_unsupported_preflight["value"]["last_portability_preflight_id"],
        json!(unsupported_preflight_id.clone())
    );

    let restricted_claim_decision = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id,
            "runtime_preflight_id": unsupported_preflight_id
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        restricted_claim_decision["claim_status"].as_str(),
        Some("restricted")
    );
    assert_eq!(
        restricted_claim_decision["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );

    let second_migration_payload = json!({
        "runtime_session_id": runtime_session_id,
        "to_node_id": target_node_id.to_string(),
        "target_capability_id": target_capability_id,
        "kind": "live_precopy",
        "checkpoint_uri": "object://checkpoints/uvm/toaster-replay-commit",
        "memory_bitmap_hash": "dead0002",
        "disk_generation": 42,
        "reason": "commit replay drill"
    });
    let started_commit_migration = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations",
        Some(second_migration_payload),
        BOOTSTRAP_TOKEN,
    );
    let commit_migration_id = started_commit_migration["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing commit migration id"))
        .to_owned();
    let committed = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{commit_migration_id}/commit"),
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(committed["state"].as_str(), Some("committed"));
    let committed_retry = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{commit_migration_id}/commit"),
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(committed_retry["state"].as_str(), Some("committed"));
    let fail_after_commit = request_json_response(
        harness.address,
        "POST",
        &format!("/uvm/runtime/migrations/{commit_migration_id}/fail"),
        Some(json!({
            "error": "late replay should stay rejected"
        })),
        Some(BOOTSTRAP_TOKEN),
        Some(BOOTSTRAP_TOKEN),
    );
    assert_eq!(fail_after_commit.status, 409);
    let fail_after_commit_body = response_json(&fail_after_commit);
    assert_eq!(
        fail_after_commit_body["error"]["message"].as_str(),
        Some("runtime migration is not in progress")
    );
    let runtime_after_commit = read_collection_record(
        runtime_session_record_path.as_path(),
        runtime_session_id.as_str(),
    );
    assert_eq!(
        runtime_after_commit["value"]["node_id"],
        json!(target_node_id.to_string())
    );
    assert_eq!(
        runtime_after_commit["value"]["migration_in_progress"].as_bool(),
        Some(false)
    );

    let runtime_migrations = read_active_collection_values(
        harness
            .state_dir
            .join("uvm-node")
            .join("runtime_migrations.json")
            .as_path(),
    );
    assert_eq!(runtime_migrations.len(), 2);
    let runtime_checkpoints = read_active_collection_values(
        harness
            .state_dir
            .join("uvm-node")
            .join("runtime_checkpoints.json")
            .as_path(),
    );
    assert_eq!(runtime_checkpoints.len(), 2);

    let final_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(final_native_claim["claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        final_native_claim["native_indistinguishable_status"].as_bool(),
        Some(true)
    );

    let uvm_node_audit_events = read_service_audit_events(&harness.state_dir, "uvm-node");
    assert_eq!(
        uvm_node_audit_events
            .iter()
            .filter(|event| event["header"]["event_type"] == json!("uvm.migration.started.v1"))
            .count(),
        2
    );
    assert_eq!(
        uvm_node_audit_events
            .iter()
            .filter(|event| {
                event["header"]["event_type"] == json!("uvm.node.checkpoint.created.v1")
            })
            .count(),
        2
    );
    assert_eq!(
        uvm_node_audit_events
            .iter()
            .filter(|event| event["header"]["event_type"] == json!("uvm.migration.rolled_back.v1"))
            .count(),
        1
    );
    assert_eq!(
        uvm_node_audit_events
            .iter()
            .filter(|event| event["header"]["event_type"] == json!("uvm.migration.committed.v1"))
            .count(),
        1
    );
}

#[test]
fn toaster_uvm_runtime_session_rollover_stale_lineage_does_not_bleed_into_authoritative_claims() {
    let Some(mut harness) = launch_harness("toaster-uvm-rollover", false, None) else {
        eprintln!(
            "skipping toaster_uvm_runtime_session_rollover_stale_lineage_does_not_bleed_into_authoritative_claims: loopback bind not permitted"
        );
        return;
    };

    let runtime_session_intent_path = runtime_session_store_paths(&harness.state_dir).1;

    let stale_source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let stale_source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": stale_source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let stale_source_capability_id = stale_source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale source capability id"))
        .to_owned();

    let stale_target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let stale_target_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": stale_target_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 1,
            "supports_secure_boot": false,
            "supports_live_migration": false,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "container_restricted"
        })),
        BOOTSTRAP_TOKEN,
    );
    let stale_target_capability_id = stale_target_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale target capability id"))
        .to_owned();

    let stale_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "require_preferred",
        "required_portability_tier": "accelerator_required",
        "evidence_strictness": "allow_simulated"
    });
    let template = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/templates",
        Some(json!({
            "name": "toaster-rollover-template",
            "architecture": "x86_64",
            "vcpu": 4,
            "memory_mb": 4096,
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "firmware_profile": "uefi_standard",
            "device_profile": "cloud-balanced",
            "migration_policy": "best_effort_live",
            "apple_guest_allowed": false,
            "execution_intent": stale_execution_intent.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    let template_id = template["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing template id"))
        .to_owned();

    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
    let boot_image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
    let instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/instances",
        Some(json!({
            "project_id": project_id.to_string(),
            "name": "toaster-rollover-instance",
            "template_id": template_id,
            "boot_image_id": boot_image_id.to_string(),
            "guest_os": "linux",
            "host_node_id": stale_source_node_id.to_string()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(instance["execution_intent"], stale_execution_intent);
    let instance_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing instance id"))
        .to_owned();

    let started_instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/instances/{instance_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_instance["state"].as_str(), Some("running"));

    let stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": stale_source_node_id.to_string(),
            "capability_id": stale_source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-rollover-stale.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_standard",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": false,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "always",
            "max_restarts": 2,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(stale_runtime_session["accelerator_backend"], json!("kvm"));
    let stale_runtime_session_id = stale_runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale runtime session id"))
        .to_owned();
    let stale_runtime_intent_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    assert_eq!(
        stale_runtime_intent_record["value"]["execution_intent"],
        stale_execution_intent
    );
    assert_eq!(
        stale_runtime_intent_record["value"]["first_placement_portability_assessment"]["supported"]
            .as_bool(),
        Some(true)
    );

    let started_stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{stale_runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        started_stale_runtime_session["state"].as_str(),
        Some("running")
    );

    record_uvm_native_claim_perf_attestations(harness.address, instance_id.as_str());
    let host_evidence = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/host-evidence",
        Some(json!({
            "evidence_mode": "measured",
            "host_platform": "linux",
            "execution_environment": "bare_metal",
            "hardware_virtualization": true,
            "nested_virtualization": false,
            "qemu_available": true,
            "note": "toaster-rollover"
        })),
        BOOTSTRAP_TOKEN,
    );
    let host_evidence_id = host_evidence["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing host evidence id"))
        .to_owned();

    let stale_unsupported_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": stale_runtime_session_id,
            "to_node_id": stale_target_node_id.to_string(),
            "target_capability_id": stale_target_capability_id,
            "require_secure_boot": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stale_unsupported_preflight["legal_allowed"].as_bool(),
        Some(false)
    );
    assert!(stale_unsupported_preflight["selected_backend"].is_null());
    assert_eq!(
        stale_unsupported_preflight["portability_assessment"]["intent"],
        stale_execution_intent
    );
    assert_eq!(
        stale_unsupported_preflight["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );
    assert_array_contains_substring(
        &stale_unsupported_preflight["portability_assessment"]["blockers"],
        "selected capability does not support live migration",
    );
    let stale_unsupported_preflight_id = stale_unsupported_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale unsupported preflight id"))
        .to_owned();

    let stale_claim_decision = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id.clone(),
            "runtime_preflight_id": stale_unsupported_preflight_id.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stale_claim_decision["claim_status"].as_str(),
        Some("allowed")
    );
    assert_eq!(
        stale_claim_decision["runtime_preflight_id"],
        json!(stale_unsupported_preflight_id.clone())
    );
    assert_eq!(
        stale_claim_decision["portability_assessment"]["intent"],
        stale_execution_intent
    );
    assert_eq!(
        stale_claim_decision["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        stale_claim_decision["portability_assessment"]["selected_backend"],
        json!("kvm")
    );

    let stale_lineage_created_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
    set_persisted_runtime_session_lineage(
        &harness.state_dir,
        stale_runtime_session_id.as_str(),
        Value::Null,
        Some(stale_unsupported_preflight_id.as_str()),
        Some(stale_lineage_created_at),
    );
    harness = restart_harness(harness);
    let (runtime_session_record_path, runtime_session_intent_path) =
        runtime_session_store_paths(&harness.state_dir);

    let stale_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stale_native_claim["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        stale_native_claim["claim_status"].as_str(),
        Some("restricted")
    );
    assert_eq!(
        stale_native_claim["portability_assessment_source"].as_str(),
        Some("linked_runtime_preflight_lineage")
    );
    assert_eq!(
        stale_native_claim["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );

    let stopped_stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{stale_runtime_session_id}/stop"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stopped_stale_runtime_session["state"].as_str(),
        Some("stopped")
    );
    soft_delete_collection_record(
        runtime_session_record_path.as_path(),
        stale_runtime_session_id.as_str(),
    );

    let stale_runtime_record = find_collection_record(
        runtime_session_record_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    assert!(
        stale_runtime_record
            .as_ref()
            .is_none_or(|record| record["deleted"].as_bool() == Some(true)),
        "expected stale runtime record to be deleted or pruned in {}",
        runtime_session_record_path.display()
    );
    let stale_intent_after_rollover = read_collection_record(
        runtime_session_intent_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    assert_eq!(
        stale_intent_after_rollover["deleted"].as_bool(),
        Some(false)
    );
    assert!(
        stale_intent_after_rollover["value"]["first_placement_portability_assessment"].is_null()
    );
    assert_eq!(
        stale_intent_after_rollover["value"]["last_portability_preflight_id"],
        json!(stale_unsupported_preflight_id.clone())
    );

    let authoritative_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "allow_compatible",
        "required_portability_tier": "portable",
        "evidence_strictness": "allow_simulated"
    });
    set_control_plane_instance_execution_intent(
        &harness.state_dir,
        instance_id.as_str(),
        authoritative_execution_intent.clone(),
    );
    harness = restart_harness(harness);
    let runtime_session_intent_path = runtime_session_store_paths(&harness.state_dir).1;

    let authoritative_source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let authoritative_source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": authoritative_source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt", "kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let authoritative_source_capability_id = authoritative_source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative source capability id"))
        .to_owned();

    let authoritative_target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let authoritative_target_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": authoritative_target_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let authoritative_target_capability_id = authoritative_target_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative target capability id"))
        .to_owned();

    let authoritative_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": authoritative_source_node_id.to_string(),
            "capability_id": authoritative_source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-rollover-authoritative.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_standard",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": false,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "always",
            "max_restarts": 2,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_runtime_session["accelerator_backend"],
        json!("kvm")
    );
    let authoritative_runtime_session_id = authoritative_runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative runtime session id"))
        .to_owned();
    assert_ne!(authoritative_runtime_session_id, stale_runtime_session_id);
    let authoritative_runtime_intent_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        authoritative_runtime_session_id.as_str(),
    );
    assert_eq!(
        authoritative_runtime_intent_record["value"]["execution_intent"],
        authoritative_execution_intent
    );
    assert_eq!(
        authoritative_runtime_intent_record["value"]["first_placement_portability_assessment"]
            ["supported"]
            .as_bool(),
        Some(true)
    );

    let started_authoritative_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{authoritative_runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        started_authoritative_runtime_session["state"].as_str(),
        Some("running")
    );

    let authoritative_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": authoritative_runtime_session_id,
            "to_node_id": authoritative_target_node_id.to_string(),
            "target_capability_id": authoritative_target_capability_id,
            "require_secure_boot": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_preflight["legal_allowed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        authoritative_preflight["selected_backend"].as_str(),
        Some("kvm")
    );
    assert_eq!(
        authoritative_preflight["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        authoritative_preflight["portability_assessment"]["intent"],
        authoritative_execution_intent
    );
    let authoritative_preflight_id = authoritative_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative preflight id"))
        .to_owned();

    set_persisted_runtime_session_lineage(
        &harness.state_dir,
        stale_runtime_session_id.as_str(),
        Value::Null,
        Some(stale_unsupported_preflight_id.as_str()),
        Some(stale_lineage_created_at),
    );
    harness = restart_harness(harness);

    let authoritative_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_native_claim["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        authoritative_native_claim["claim_status"].as_str(),
        Some("allowed")
    );
    assert_eq!(
        authoritative_native_claim["portability_assessment_source"].as_str(),
        Some("first_placement_lineage")
    );
    assert_eq!(
        authoritative_native_claim["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    let authoritative_native_claim_repeat = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_native_claim_repeat,
        authoritative_native_claim
    );

    let authoritative_claim_decision = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id,
            "runtime_preflight_id": authoritative_preflight_id.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_claim_decision["claim_status"].as_str(),
        Some("allowed")
    );
    assert_eq!(
        authoritative_claim_decision["runtime_preflight_id"],
        json!(authoritative_preflight_id)
    );
    assert_eq!(
        authoritative_claim_decision["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        authoritative_claim_decision["portability_assessment"]["intent"],
        authoritative_execution_intent
    );
    assert_ne!(
        authoritative_claim_decision["portability_assessment"]["intent"],
        stale_execution_intent
    );
    assert_eq!(
        authoritative_claim_decision["portability_assessment"]["selected_backend"],
        json!("kvm")
    );
}

#[test]
fn toaster_uvm_runtime_session_missing_authoritative_link_does_not_resurrect_stale_fallback_lineage()
 {
    let Some(mut harness) = launch_harness("toaster-uvm-missing-link", false, None) else {
        eprintln!(
            "skipping toaster_uvm_runtime_session_missing_authoritative_link_does_not_resurrect_stale_fallback_lineage: loopback bind not permitted"
        );
        return;
    };

    let stale_source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let stale_source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": stale_source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let stale_source_capability_id = stale_source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale source capability id"))
        .to_owned();

    let stale_target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let stale_target_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": stale_target_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 1,
            "supports_secure_boot": false,
            "supports_live_migration": false,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "container_restricted"
        })),
        BOOTSTRAP_TOKEN,
    );
    let stale_target_capability_id = stale_target_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale target capability id"))
        .to_owned();

    let stale_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "require_preferred",
        "required_portability_tier": "accelerator_required",
        "evidence_strictness": "allow_simulated"
    });
    let template = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/templates",
        Some(json!({
            "name": "toaster-missing-link-template",
            "architecture": "x86_64",
            "vcpu": 4,
            "memory_mb": 4096,
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "firmware_profile": "uefi_standard",
            "device_profile": "cloud-balanced",
            "migration_policy": "best_effort_live",
            "apple_guest_allowed": false,
            "execution_intent": stale_execution_intent.clone()
        })),
        BOOTSTRAP_TOKEN,
    );
    let template_id = template["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing template id"))
        .to_owned();

    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
    let boot_image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
    let instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/instances",
        Some(json!({
            "project_id": project_id.to_string(),
            "name": "toaster-missing-link-instance",
            "template_id": template_id,
            "boot_image_id": boot_image_id.to_string(),
            "guest_os": "linux",
            "host_node_id": stale_source_node_id.to_string()
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(instance["execution_intent"], stale_execution_intent);
    let instance_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing instance id"))
        .to_owned();

    let started_instance = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/instances/{instance_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(started_instance["state"].as_str(), Some("running"));

    record_uvm_native_claim_perf_attestations(harness.address, instance_id.as_str());
    let host_evidence = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/host-evidence",
        Some(json!({
            "evidence_mode": "measured",
            "host_platform": "linux",
            "execution_environment": "bare_metal",
            "hardware_virtualization": true,
            "nested_virtualization": false,
            "qemu_available": true,
            "note": "toaster-missing-link"
        })),
        BOOTSTRAP_TOKEN,
    );
    let host_evidence_id = host_evidence["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing host evidence id"))
        .to_owned();

    let stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": stale_source_node_id.to_string(),
            "capability_id": stale_source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-missing-link-stale.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_standard",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": false,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "always",
            "max_restarts": 2,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(stale_runtime_session["accelerator_backend"], json!("kvm"));
    let stale_runtime_session_id = stale_runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale runtime session id"))
        .to_owned();

    let started_stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{stale_runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        started_stale_runtime_session["state"].as_str(),
        Some("running")
    );

    let stale_unsupported_preflight = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(json!({
            "runtime_session_id": stale_runtime_session_id,
            "to_node_id": stale_target_node_id.to_string(),
            "target_capability_id": stale_target_capability_id,
            "require_secure_boot": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stale_unsupported_preflight["legal_allowed"].as_bool(),
        Some(false)
    );
    assert!(stale_unsupported_preflight["selected_backend"].is_null());
    assert_eq!(
        stale_unsupported_preflight["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );
    assert_array_contains_substring(
        &stale_unsupported_preflight["portability_assessment"]["blockers"],
        "selected capability does not support live migration",
    );
    let stale_unsupported_preflight_id = stale_unsupported_preflight["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stale unsupported preflight id"))
        .to_owned();

    let stale_lineage_created_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
    set_persisted_runtime_session_lineage(
        &harness.state_dir,
        stale_runtime_session_id.as_str(),
        Value::Null,
        Some(stale_unsupported_preflight_id.as_str()),
        Some(stale_lineage_created_at),
    );
    harness = restart_harness(harness);
    let runtime_session_record_path = runtime_session_store_paths(&harness.state_dir).0;

    let stale_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stale_native_claim["claim_status"].as_str(),
        Some("restricted")
    );
    assert_eq!(
        stale_native_claim["portability_assessment_source"].as_str(),
        Some("linked_runtime_preflight_lineage")
    );
    assert_eq!(
        stale_native_claim["runtime_preflight_id"],
        json!(stale_unsupported_preflight_id.clone())
    );
    assert_eq!(
        stale_native_claim["portability_assessment"]["supported"].as_bool(),
        Some(false)
    );

    let stopped_stale_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{stale_runtime_session_id}/stop"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        stopped_stale_runtime_session["state"].as_str(),
        Some("stopped")
    );
    soft_delete_collection_record(
        runtime_session_record_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    let stale_runtime_record = read_collection_record(
        runtime_session_record_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    assert_eq!(stale_runtime_record["deleted"].as_bool(), Some(true));

    let authoritative_execution_intent = json!({
        "preferred_backend": "kvm",
        "fallback_policy": "allow_compatible",
        "required_portability_tier": "portable",
        "evidence_strictness": "allow_simulated"
    });
    set_control_plane_instance_execution_intent(
        &harness.state_dir,
        instance_id.as_str(),
        authoritative_execution_intent.clone(),
    );
    harness = restart_harness(harness);
    let (runtime_session_record_path, runtime_session_intent_path) =
        runtime_session_store_paths(&harness.state_dir);

    let authoritative_source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let authoritative_source_capability = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": authoritative_source_node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt", "kvm"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 2,
            "supports_secure_boot": true,
            "supports_live_migration": true,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        BOOTSTRAP_TOKEN,
    );
    let authoritative_source_capability_id = authoritative_source_capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative source capability id"))
        .to_owned();

    let authoritative_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/runtime/instances",
        Some(json!({
            "instance_id": instance_id,
            "node_id": authoritative_source_node_id.to_string(),
            "capability_id": authoritative_source_capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "disk_image": "object://images/toaster-missing-link-authoritative.qcow2",
            "vcpu": 4,
            "memory_mb": 4096,
            "firmware_profile": "uefi_standard",
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "migration_policy": "best_effort_live",
            "require_secure_boot": false,
            "requires_live_migration": true,
            "isolation_profile": "cgroup_v2",
            "restart_policy": "always",
            "max_restarts": 2,
            "apple_guest_approved": false
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_runtime_session["accelerator_backend"],
        json!("kvm")
    );
    let authoritative_runtime_session_id = authoritative_runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing authoritative runtime session id"))
        .to_owned();
    assert_ne!(authoritative_runtime_session_id, stale_runtime_session_id);

    let authoritative_runtime_intent_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        authoritative_runtime_session_id.as_str(),
    );
    assert_eq!(
        authoritative_runtime_intent_record["value"]["execution_intent"],
        authoritative_execution_intent
    );
    assert_eq!(
        authoritative_runtime_intent_record["value"]["first_placement_portability_assessment"]
            ["supported"]
            .as_bool(),
        Some(true)
    );

    let started_authoritative_runtime_session = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        &format!("/uvm/runtime/instances/{authoritative_runtime_session_id}/start"),
        Some(json!({})),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        started_authoritative_runtime_session["state"].as_str(),
        Some("running")
    );

    let authoritative_native_claim = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        authoritative_native_claim["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        authoritative_native_claim["claim_status"].as_str(),
        Some("allowed")
    );
    assert_eq!(
        authoritative_native_claim["portability_assessment_source"].as_str(),
        Some("first_placement_lineage")
    );
    assert!(authoritative_native_claim["runtime_preflight_id"].is_null());
    assert_eq!(
        authoritative_native_claim["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );

    soft_delete_collection_record(
        runtime_session_intent_path.as_path(),
        authoritative_runtime_session_id.as_str(),
    );
    let stale_runtime_lineage_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        stale_runtime_session_id.as_str(),
    );
    assert_eq!(
        stale_runtime_lineage_record["deleted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        stale_runtime_lineage_record["value"]["last_portability_preflight_id"],
        json!(stale_unsupported_preflight_id.clone())
    );
    let deleted_authoritative_lineage_record = read_collection_record(
        runtime_session_intent_path.as_path(),
        authoritative_runtime_session_id.as_str(),
    );
    assert_eq!(
        deleted_authoritative_lineage_record["deleted"].as_bool(),
        Some(true)
    );
    let authoritative_runtime_record = read_collection_record(
        runtime_session_record_path.as_path(),
        authoritative_runtime_session_id.as_str(),
    );
    assert_eq!(
        authoritative_runtime_record["deleted"].as_bool(),
        Some(false)
    );
    harness = restart_harness(harness);

    let missing_authoritative_link_status = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        missing_authoritative_link_status["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        missing_authoritative_link_status["claim_status"].as_str(),
        Some("allowed")
    );
    assert!(missing_authoritative_link_status["portability_assessment"].is_null());
    assert!(missing_authoritative_link_status["runtime_preflight_id"].is_null());
    assert_eq!(
        missing_authoritative_link_status["portability_assessment_source"].as_str(),
        Some("unavailable")
    );
    let missing_authoritative_link_status_repeat = request_json_with_bootstrap_token(
        harness.address,
        "GET",
        "/uvm/native-claim-status",
        None,
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        missing_authoritative_link_status_repeat,
        missing_authoritative_link_status
    );

    let missing_authoritative_link_decision = request_json_with_bootstrap_token(
        harness.address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id
        })),
        BOOTSTRAP_TOKEN,
    );
    assert_eq!(
        missing_authoritative_link_decision["host_evidence_id"],
        json!(host_evidence_id)
    );
    assert_eq!(
        missing_authoritative_link_decision["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(
        missing_authoritative_link_decision["claim_status"].as_str(),
        Some("allowed")
    );
    assert!(missing_authoritative_link_decision["runtime_preflight_id"].is_null());
    assert!(missing_authoritative_link_decision["portability_assessment"].is_null());
    assert_eq!(
        missing_authoritative_link_decision["portability_assessment_source"].as_str(),
        Some("unavailable")
    );
}

fn launch_harness(
    node_name: &str,
    seed_tombstone_eligible_stale_peer: bool,
    preseed_change_request_state: Option<&str>,
) -> Option<Harness> {
    let serial_guard = toaster_test_guard();
    let temp = TempState::new().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp
        .create_dir_all("state")
        .unwrap_or_else(|error| panic!("{error}"));
    let seeded_change_request_id =
        preseed_change_request_state.map(|state| seed_governance_change_request(&state_dir, state));
    if seed_tombstone_eligible_stale_peer {
        seed_tombstone_eligible_stale_peer_runtime_records(&temp);
    }
    let address = reserve_loopback_port()?;
    let config_path =
        write_test_config(&temp, address, &state_dir, Some(BOOTSTRAP_TOKEN), node_name);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null());
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        command.stderr(Stdio::inherit());
    } else {
        command.stderr(Stdio::null());
    }
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let guard = ChildGuard { child };

    wait_for_health(address);

    Some(Harness {
        address,
        state_dir,
        seeded_change_request_id,
        _temp: temp,
        _guard: guard,
        _serial_guard: serial_guard,
    })
}

fn restart_harness(harness: Harness) -> Harness {
    let Harness {
        state_dir,
        seeded_change_request_id,
        _temp,
        _guard,
        _serial_guard,
        ..
    } = harness;
    // Stop the live daemon before snapshotting its state so restart tests copy a
    // quiesced on-disk view instead of racing background runtime-session writes.
    drop(_guard);
    let copied_state_dir = _temp
        .create_dir_all(format!(
            "state-restart-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
        .unwrap_or_else(|error| panic!("failed to allocate restart state dir: {error}"));
    copy_dir_recursive(&state_dir, &copied_state_dir);
    repair_runtime_session_snapshot(&copied_state_dir);
    let address =
        reserve_loopback_port().unwrap_or_else(|| panic!("failed to allocate restart port"));
    let config_path = write_test_config(
        &_temp,
        address,
        &copied_state_dir,
        Some(BOOTSTRAP_TOKEN),
        "toaster-restart",
    );

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null());
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        command.stderr(Stdio::inherit());
    } else {
        command.stderr(Stdio::null());
    }
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to respawn uhostd: {error}"));
    let guard = ChildGuard { child };

    wait_for_health(address);

    Harness {
        address,
        state_dir: copied_state_dir,
        seeded_change_request_id,
        _temp,
        _guard: guard,
        _serial_guard,
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("failed to read dir entry: {error}"));
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to read file type: {error}"));
        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path);
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|error| {
                    panic!("failed to create {}: {error}", parent.display())
                });
            }
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "failed to copy {} -> {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
}

fn repair_runtime_session_snapshot(state_dir: &Path) {
    let runtime_sessions_path = state_dir.join("uvm-node").join("runtime_sessions.json");
    let runtime_session_intents_path = state_dir
        .join("uvm-node")
        .join("runtime_session_intents.json");
    let Ok(runtime_sessions_raw) = fs::read(&runtime_sessions_path) else {
        return;
    };
    let Ok(runtime_session_intents_raw) = fs::read(&runtime_session_intents_path) else {
        return;
    };
    let mut runtime_sessions: DocumentCollection<Value> =
        serde_json::from_slice(&runtime_sessions_raw).unwrap_or_else(|error| {
            panic!(
                "invalid runtime session snapshot {}: {error}",
                runtime_sessions_path.display()
            )
        });
    let runtime_session_intents: DocumentCollection<Value> =
        serde_json::from_slice(&runtime_session_intents_raw).unwrap_or_else(|error| {
            panic!(
                "invalid runtime session intent snapshot {}: {error}",
                runtime_session_intents_path.display()
            )
        });

    let mut changed = false;
    for (runtime_session_id, runtime_session_record) in &mut runtime_sessions.records {
        let Some(runtime_session_value) = runtime_session_record.value.as_object_mut() else {
            continue;
        };
        let instance_id_missing = runtime_session_value
            .get("instance_id")
            .is_none_or(|value| value.is_null());
        if !instance_id_missing {
            continue;
        }
        let Some(intent_record) = runtime_session_intents.records.get(runtime_session_id) else {
            continue;
        };
        let Some(intent_instance_id) = intent_record
            .value
            .get("instance_id")
            .cloned()
            .filter(|value| !value.is_null())
        else {
            continue;
        };
        runtime_session_value.insert(String::from("instance_id"), intent_instance_id);
        changed = true;
    }

    if changed {
        fs::write(
            &runtime_sessions_path,
            serde_json::to_vec(&runtime_sessions).unwrap_or_else(|error| {
                panic!(
                    "failed to encode repaired runtime session snapshot {}: {error}",
                    runtime_sessions_path.display()
                )
            }),
        )
        .unwrap_or_else(|error| {
            panic!(
                "failed to write repaired runtime session snapshot {}: {error}",
                runtime_sessions_path.display()
            )
        });
    }
}

fn runtime_session_store_paths(state_dir: &Path) -> (PathBuf, PathBuf) {
    (
        state_dir.join("uvm-node").join("runtime_sessions.json"),
        state_dir
            .join("uvm-node")
            .join("runtime_session_intents.json"),
    )
}

fn toaster_test_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn reserve_loopback_port() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("failed to allocate test port: {error}"),
    };
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("failed to read test port: {error}"));
    drop(listener);
    Some(address)
}

fn seed_governance_change_request(state_dir: &Path, state: &str) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("failed to build tokio runtime: {error}"));
    runtime.block_on(async {
        let store = DocumentStore::open(state_dir.join("governance").join("change_requests.json"))
            .await
            .unwrap_or_else(|error| panic!("failed to open governance change store: {error}"));
        let id = ChangeRequestId::generate()
            .unwrap_or_else(|error| panic!("failed to generate change request id: {error}"));
        let approved_by = match state {
            "approved" | "applied" => Some("operator:toaster-reviewer".to_owned()),
            _ => None,
        };
        store
            .create(
                id.as_str(),
                SeedGovernanceChangeRequest {
                    id: id.clone(),
                    title: "toaster seeded governance change".to_owned(),
                    change_type: "network_policy_change".to_owned(),
                    requested_by: "operator:toaster-requester".to_owned(),
                    approved_by,
                    reviewer_comment: None,
                    required_approvals: 1,
                    state: state.to_owned(),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed governance change request: {error}"));
        id.to_string()
    })
}

fn seed_private_network_topology(
    address: SocketAddr,
    token: &str,
    private_network_id: &str,
    subnet_cidr: &str,
    route_destination: &str,
) {
    let route_table = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/route-tables"),
        Some(json!({
            "name": "private-main"
        })),
        token,
    );
    let route_table_id = route_table["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private route table id"))
        .to_owned();

    let next_hop = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/next-hops"),
        Some(json!({
            "name": "local-ingress",
            "kind": "local"
        })),
        token,
    );
    let next_hop_id = next_hop["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private next hop id"))
        .to_owned();

    let _subnet = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/subnets"),
        Some(json!({
            "name": "private-app-a",
            "cidr": subnet_cidr,
            "route_table_id": route_table_id,
        })),
        token,
    );

    let _route = request_json_with_bearer_token(
        address,
        "POST",
        &format!(
            "/netsec/private-networks/{private_network_id}/route-tables/{route_table_id}/routes"
        ),
        Some(json!({
            "destination": route_destination,
            "next_hop_id": next_hop_id,
        })),
        token,
    );
}

fn write_test_config(
    temp: &TempState,
    address: SocketAddr,
    state_dir: &Path,
    token: Option<&str>,
    node_name: &str,
) -> PathBuf {
    let security = token.map_or_else(String::new, |token| {
        format!(
            r#"

[security]
bootstrap_admin_token = "{token}"
"#
        )
    });
    let config = format!(
        "listen = \"{address}\"\nstate_dir = '{}'\n\n[schema]\nschema_version = 1\nmode = \"all_in_one\"\nnode_name = \"{node_name}\"\n\n[secrets]\nmaster_key = \"{}\"\n{}",
        state_dir.display(),
        base64url_encode(&[0x45; 32]),
        security,
    );
    temp.write("all-in-one.toml", config.as_bytes())
        .unwrap_or_else(|error| panic!("failed to write config: {error}"))
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request_with_auth(address, "GET", "/healthz", None, None, None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

fn request_json_with_bootstrap_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> Value {
    request_json(address, method, path, body, None, Some(token))
}

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> Value {
    request_json(address, method, path, body, Some(token), None)
}

fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> Value {
    let response = request_json_response(address, method, path, body, bearer_token, admin_token);
    assert!(
        (200..=299).contains(&response.status),
        "unexpected status {} for {} {} with body {}",
        response.status,
        method,
        path,
        String::from_utf8_lossy(&response.body)
    );
    response_json(&response)
}

fn request_json_response(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> RawResponse {
    let payload =
        body.map(|value| serde_json::to_vec(&value).unwrap_or_else(|error| panic!("{error}")));
    request(
        address,
        method,
        path,
        payload
            .as_ref()
            .map(|bytes| ("application/json", bytes.as_slice())),
        bearer_token,
        admin_token,
    )
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> RawResponse {
    try_request_with_auth(address, method, path, body, bearer_token, admin_token)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn try_request_with_auth(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (content_type, payload) = body.unwrap_or(("application/json", b""));

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = bearer_token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(token) = admin_token {
        request.push_str(&format!("X-UHost-Admin-Token: {token}\r\n"));
    }
    request.push_str(&format!(
        "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    ));

    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid HTTP response framing"))?;
    let (head, body) = response.split_at(split + 4);
    let status_line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP status line"))?;
    let status_line = std::str::from_utf8(&head[..status_line_end])
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
    let mut status_parts = status_line.split_whitespace();
    let _http_version = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid status code"))?;

    Ok(RawResponse {
        status,
        body: body.to_vec(),
    })
}

fn response_json(response: &RawResponse) -> Value {
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid json response: {error}"))
}

fn issue_workload_identity(
    address: SocketAddr,
    bootstrap_token: &str,
    subject: &str,
    audiences: &[&str],
    ttl_seconds: u64,
) -> String {
    let normalized_subject = subject.to_ascii_lowercase();
    let payload = request_json_with_bootstrap_token(
        address,
        "POST",
        "/identity/workload-identities",
        Some(json!({
            "subject": subject,
            "display_name": format!("{subject} identity"),
            "audiences": audiences,
            "ttl_seconds": ttl_seconds,
        })),
        bootstrap_token,
    );
    let token = payload["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned();
    assert_eq!(
        payload["identity"]["principal"]["subject"].as_str(),
        Some(normalized_subject.as_str())
    );
    token
}

fn record_uvm_native_claim_perf_attestations(address: SocketAddr, instance_id: &str) {
    for workload_class in [
        "general",
        "cpu_intensive",
        "io_intensive",
        "network_intensive",
    ] {
        let perf_attestation = request_json_with_bootstrap_token(
            address,
            "POST",
            "/uvm/perf-attestations",
            Some(json!({
                "instance_id": instance_id,
                "workload_class": workload_class,
                "cpu_overhead_pct": 4,
                "memory_overhead_pct": 4,
                "block_io_latency_overhead_pct": 8,
                "network_latency_overhead_pct": 8,
                "jitter_pct": 8
            })),
            BOOTSTRAP_TOKEN,
        );
        assert_eq!(perf_attestation["workload_class"], json!(workload_class));
    }
}

fn assert_array_contains_substring(value: &Value, needle: &str) {
    let items = value
        .as_array()
        .unwrap_or_else(|| panic!("expected array while searching for `{needle}`"));
    assert!(
        items.iter().any(|item| {
            item.as_str()
                .is_some_and(|candidate| candidate.contains(needle))
        }),
        "expected array {:?} to contain substring `{needle}`",
        items
    );
}

fn seed_tombstone_eligible_stale_peer_runtime_records(temp: &TempState) {
    seed_stale_peer_runtime_records_with_cleanup_state(temp, true);
}

fn seed_stale_peer_runtime_records_with_cleanup_state(temp: &TempState, tombstone_eligible: bool) {
    temp.create_dir_all("state/runtime")
        .unwrap_or_else(|error| panic!("failed to create runtime seed directory: {error}"));

    let now = OffsetDateTime::now_utc();
    let peer_registration_id = "controller:stale-peer-node";
    let mut peer_registration = LeaseRegistrationRecord::new(
        peer_registration_id,
        "runtime_process",
        peer_registration_id,
        "controller",
        Some(String::from("stale-peer-node")),
        15,
    )
    .with_readiness(LeaseReadiness::Ready)
    .with_drain_intent(LeaseDrainIntent::Serving);
    peer_registration.lease_renewed_at = now - time::Duration::seconds(60);
    peer_registration.lease_expires_at = now - time::Duration::seconds(30);

    let mut peer_participant = CellParticipantRecord::new(
        peer_registration_id,
        "runtime_process",
        peer_registration_id,
        "controller",
    )
    .with_node_name("stale-peer-node")
    .with_service_groups(["control"])
    .with_lease_registration_id(peer_registration_id)
    .with_state(CellParticipantState::new(
        LeaseReadiness::Ready,
        LeaseDrainIntent::Serving,
        CellParticipantLeaseState::new(
            now - time::Duration::seconds(5),
            now + time::Duration::seconds(30),
            15,
            LeaseFreshness::Fresh,
        ),
    ));
    peer_participant.registered_at = now - time::Duration::seconds(60);
    peer_participant = peer_participant.with_reconciliation(
        CellParticipantReconciliationState::new(now - time::Duration::seconds(20))
            .with_stale_since(now - time::Duration::seconds(45)),
    );

    let mut registrations = DocumentCollection::default();
    registrations.records.insert(
        peer_registration_id.to_owned(),
        StoredDocument {
            version: 1,
            updated_at: now,
            deleted: false,
            value: peer_registration,
        },
    );
    temp.write(
        "state/runtime/process-registrations.json",
        serde_json::to_vec(&registrations).unwrap_or_else(|error| {
            panic!("failed to encode seeded runtime registration store: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write seeded runtime registration store: {error}"));

    let mut cell_directory = DocumentCollection::default();
    cell_directory.records.insert(
        String::from("local:local-cell"),
        StoredDocument {
            version: 1,
            updated_at: now,
            deleted: false,
            value: CellDirectoryRecord::new(
                "local:local-cell",
                "local-cell",
                RegionDirectoryRecord::new("local", "local"),
            )
            .with_participant(peer_participant.clone()),
        },
    );
    temp.write(
        "state/runtime/cell-directory.json",
        serde_json::to_vec(&cell_directory).unwrap_or_else(|error| {
            panic!("failed to encode seeded runtime cell directory store: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write seeded runtime cell directory store: {error}"));

    let cleanup_workflow_id =
        stale_participant_cleanup_workflow_id("local:local-cell", peer_registration_id);
    let cleanup_observed_at = now - time::Duration::seconds(10);
    let mut cleanup_workflow = stale_participant_cleanup_workflow(
        "local:local-cell",
        &peer_participant,
        now - time::Duration::seconds(45),
        cleanup_observed_at,
    );
    if tombstone_eligible {
        let preflight_confirmed_at = cleanup_observed_at + time::Duration::seconds(5);
        cleanup_workflow
            .state
            .note_stale_observation(preflight_confirmed_at);
        cleanup_workflow
            .state
            .mark_preflight_confirmed(preflight_confirmed_at);
        let tombstone_eligible_at = preflight_confirmed_at + time::Duration::seconds(5);
        cleanup_workflow
            .state
            .note_stale_observation(tombstone_eligible_at);
        cleanup_workflow
            .state
            .mark_tombstone_eligible(tombstone_eligible_at);
        cleanup_workflow.current_step_index = Some(2);
        cleanup_workflow.set_phase(WorkflowPhase::Running);
        cleanup_workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing confirm stale peer workflow step"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "stale peer remained expired across repeated local reconciliation",
                )),
            );
        cleanup_workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing preflight workflow step"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "local preflight confirmed the peer remained expired and draining",
                )),
            );
        cleanup_workflow
            .step_mut(2)
            .unwrap_or_else(|| panic!("missing tombstone workflow step"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from(
                    "peer is locally tombstone-eligible; destructive deletion remains deferred",
                )),
            );
    }

    let mut cleanup_workflows = DocumentCollection::default();
    cleanup_workflows.records.insert(
        cleanup_workflow_id,
        StoredDocument {
            version: 1,
            updated_at: cleanup_workflow.updated_at,
            deleted: false,
            value: cleanup_workflow,
        },
    );
    temp.write(
        "state/runtime/stale-participant-cleanup-workflows.json",
        serde_json::to_vec(&cleanup_workflows).unwrap_or_else(|error| {
            panic!("failed to encode seeded cleanup workflow store: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write seeded cleanup workflow store: {error}"));
}

fn read_active_collection_values(path: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid collection json in {}: {error}", path.display()));
    collection
        .get("records")
        .and_then(Value::as_object)
        .map(|records| {
            records
                .values()
                .filter(|record| !record["deleted"].as_bool().unwrap_or(false))
                .map(|record| {
                    record.get("value").cloned().unwrap_or_else(|| {
                        panic!("record in {} should contain value", path.display())
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn read_runtime_audit_events(state_dir: &Path) -> Vec<Value> {
    read_service_audit_events(state_dir, "runtime")
}

fn read_service_audit_events(state_dir: &Path, service: &str) -> Vec<Value> {
    let raw =
        fs::read_to_string(state_dir.join(service).join("audit.log")).unwrap_or_else(|error| {
            panic!(
                "failed to read {} audit log: {error}",
                state_dir.join(service).display()
            )
        });
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("invalid {service} audit event json: {error}"))
        })
        .collect()
}

fn seed_runtime_tombstone_history_records(
    path: &Path,
    records: Vec<ParticipantTombstoneHistoryRecord>,
) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "failed to create runtime tombstone history seed directory {}: {error}",
                parent.display()
            )
        });
    }
    let mut collection = DocumentCollection::default();
    for record in records {
        collection.records.insert(
            record.event_id.clone(),
            StoredDocument {
                version: 1,
                updated_at: record.tombstoned_at,
                deleted: false,
                value: record,
            },
        );
    }
    fs::write(
        path,
        serde_json::to_vec(&collection).unwrap_or_else(|error| {
            panic!("failed to encode seeded runtime tombstone history: {error}")
        }),
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to write seeded runtime tombstone history {}: {error}",
            path.display()
        )
    });
}

fn build_seeded_runtime_tombstone_history_record(
    event_id: &str,
    registration_id: &str,
    node_name: &str,
    tombstoned_at: OffsetDateTime,
) -> ParticipantTombstoneHistoryRecord {
    let participant = CellParticipantRecord::new(
        registration_id,
        "runtime_process",
        registration_id,
        "controller",
    )
    .with_node_name(node_name)
    .with_service_groups(["control"])
    .with_lease_registration_id(registration_id);
    ParticipantTombstoneHistoryRecord::new(
        event_id,
        &participant,
        format!("cleanup:{registration_id}"),
        tombstoned_at,
        "operator",
        "operator",
        format!("corr:{registration_id}"),
    )
    .with_cell_context(
        "us-west-2:edge-cell",
        "edge-cell",
        &RegionDirectoryRecord::new("us-west-2", "us-west-2"),
    )
    .with_cleanup_review(
        3,
        tombstoned_at - time::Duration::seconds(90),
        Some(tombstoned_at - time::Duration::seconds(60)),
        Some(tombstoned_at - time::Duration::seconds(30)),
    )
    .with_mutation_result(true, true, true)
}

fn read_collection_record(path: &Path, key: &str) -> Value {
    find_collection_record(path, key)
        .unwrap_or_else(|| panic!("missing record `{key}` in {}", path.display()))
}

fn find_collection_record(path: &Path, key: &str) -> Option<Value> {
    let raw =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let collection: Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid collection json in {}: {error}", path.display()));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get(key))
        .cloned()
}

fn advance_persisted_volume_recovery_point(state_dir: &Path, volume_id: &str) {
    let path = state_dir
        .join("storage")
        .join("volume_recovery_points.json");
    let raw = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut collection: DocumentCollection<Value> = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid volume recovery point collection: {error}"));
    let record = collection
        .records
        .get_mut(volume_id)
        .unwrap_or_else(|| panic!("missing persisted recovery point for {volume_id}"));
    record.version += 1;
    let captured_at = OffsetDateTime::now_utc() + time::Duration::minutes(30);
    let interval_minutes = record.value["interval_minutes"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing interval_minutes for {volume_id}"));
    let execution_count = record.value["execution_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing execution_count for {volume_id}"))
        + 1;
    record.updated_at = captured_at;
    record.value["execution_count"] = json!(execution_count);
    record.value["latest_snapshot_at"] = json!(captured_at);
    record.value["next_snapshot_after"] =
        json!(captured_at + time::Duration::minutes(interval_minutes as i64));
    record.value["metadata"]["etag"] = json!(sha256_hex(
        format!("{volume_id}:recovery-point:{}", record.version).as_bytes()
    ));
    record.value["metadata"]["updated_at"] = json!(captured_at);
    fs::write(
        &path,
        serde_json::to_vec(&collection)
            .unwrap_or_else(|error| panic!("failed to encode recovery point collection: {error}")),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn remove_persisted_volume_recovery_point_revision(
    state_dir: &Path,
    volume_id: &str,
    recovery_point_version: u64,
) {
    let path = state_dir
        .join("storage")
        .join("volume_recovery_point_revisions.json");
    let raw = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut collection: DocumentCollection<Value> =
        serde_json::from_slice(&raw).unwrap_or_else(|error| {
            panic!("invalid volume recovery point revision collection: {error}")
        });
    let key = format!("{volume_id}:{recovery_point_version}");
    collection
        .records
        .remove(&key)
        .unwrap_or_else(|| panic!("missing persisted recovery point revision {key}"));
    fs::write(
        &path,
        serde_json::to_vec(&collection).unwrap_or_else(|error| {
            panic!("failed to encode recovery point revision collection: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn set_control_plane_instance_execution_intent(
    state_dir: &Path,
    instance_id: &str,
    execution_intent: Value,
) {
    let path = state_dir.join("uvm-control").join("instances.json");
    let raw = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut collection: DocumentCollection<Value> = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid UVM control instance collection: {error}"));
    let record = collection
        .records
        .get_mut(instance_id)
        .unwrap_or_else(|| panic!("missing control-plane instance {instance_id}"));
    record.version += 1;
    record.updated_at = OffsetDateTime::now_utc();
    record.value["execution_intent"] = execution_intent;
    record.value["metadata"]["etag"] = json!(sha256_hex(
        format!("{instance_id}:execution-intent:{}", record.version).as_bytes()
    ));
    record.value["metadata"]["updated_at"] = json!(record.updated_at);
    fs::write(
        &path,
        serde_json::to_vec(&collection).unwrap_or_else(|error| {
            panic!("failed to encode UVM control instance collection: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn soft_delete_collection_record(path: &Path, key: &str) {
    let raw =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut collection: DocumentCollection<Value> = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid collection json in {}: {error}", path.display()));
    let record = collection
        .records
        .get_mut(key)
        .unwrap_or_else(|| panic!("missing record `{key}` in {}", path.display()));
    record.version += 1;
    record.updated_at = OffsetDateTime::now_utc();
    record.deleted = true;
    fs::write(
        path,
        serde_json::to_vec(&collection).unwrap_or_else(|error| {
            panic!("failed to encode collection {}: {error}", path.display())
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn set_persisted_runtime_session_lineage(
    state_dir: &Path,
    runtime_session_id: &str,
    first_placement_portability_assessment: Value,
    last_portability_preflight_id: Option<&str>,
    created_at: Option<OffsetDateTime>,
) {
    let path = state_dir
        .join("uvm-node")
        .join("runtime_session_intents.json");
    let raw = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let mut collection: DocumentCollection<Value> =
        serde_json::from_slice(&raw).unwrap_or_else(|error| {
            panic!(
                "invalid runtime session intent collection {}: {error}",
                path.display()
            )
        });
    let record = collection
        .records
        .get_mut(runtime_session_id)
        .unwrap_or_else(|| panic!("missing runtime session intent {runtime_session_id}"));
    record.version += 1;
    let now = OffsetDateTime::now_utc();
    record.updated_at = now;
    record.value["first_placement_portability_assessment"] = first_placement_portability_assessment;
    record.value["last_portability_preflight_id"] =
        last_portability_preflight_id.map_or(Value::Null, |value| json!(value));
    if let Some(created_at) = created_at {
        record.value["created_at"] = json!(created_at);
    }
    record.value["metadata"]["etag"] = json!(sha256_hex(
        format!("{runtime_session_id}:lineage:{}", record.version).as_bytes()
    ));
    record.value["metadata"]["updated_at"] = json!(now);
    fs::write(
        &path,
        serde_json::to_vec(&collection).unwrap_or_else(|error| {
            panic!(
                "failed to encode runtime session intent collection {}: {error}",
                path.display()
            )
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}
