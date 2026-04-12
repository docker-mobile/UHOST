use std::collections::BTreeMap;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use time::OffsetDateTime;
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::{
    CellDirectoryRecord, CellParticipantLeaseState, CellParticipantRecord, CellParticipantState,
    DeliveryState, DocumentCollection, EventRelayEnvelope, LeaseDrainIntent, LeaseFreshness,
    LeaseReadiness, LeaseRegistrationRecord, ParticipantTombstoneHistoryRecord,
    RegionDirectoryRecord, RelayStatus, StaleParticipantCleanupStage, StoredDocument,
    WorkflowPhase, WorkflowStepState, stale_participant_cleanup_workflow,
    stale_participant_cleanup_workflow_id,
};
use uhost_types::{AuditActor, AuditId, EventHeader, EventPayload, PlatformEvent, ServiceEvent};

struct ChildGuard {
    child: Child,
    stderr_path: PathBuf,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Run this suite with `cargo test -p uhostd --test auth_gate`.
// It self-serializes here because the cases spawn real `uhostd` children, and
// some intentionally mutate persisted state before restarting the daemon.
fn auth_gate_test_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

const AUTH_GATE_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_GATE_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn spawn_uhostd(config_path: &Path, address: SocketAddr) -> ChildGuard {
    spawn_uhostd_with_envs(config_path, address, &[])
}

fn spawn_uhostd_with_envs(
    config_path: &Path,
    address: SocketAddr,
    envs: &[(&str, &str)],
) -> ChildGuard {
    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let mut command = Command::new(binary);
    let stderr_path = config_path.with_extension("uhostd.stderr.log");
    let stderr = fs::File::create(&stderr_path)
        .unwrap_or_else(|error| panic!("failed to create uhostd stderr log: {error}"));
    command.arg("--config").arg(config_path);
    command.envs(envs.iter().copied());
    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let mut guard = ChildGuard { child, stderr_path };
    wait_for_health(address, &mut guard.child, &guard.stderr_path);
    guard
}

#[test]
fn bootstrap_admin_auth_gate_protects_control_plane_routes() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping bootstrap_admin_auth_gate_protects_control_plane_routes: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let health = request(address, "GET", "/healthz", None, None);
    assert_eq!(health.status, 200);

    let missing_token_metrics = request(address, "GET", "/metrics", None, None);
    assert_eq!(missing_token_metrics.status, 401);

    let missing_token_topology = request(address, "GET", "/runtime/topology", None, None);
    assert_eq!(missing_token_topology.status, 401);

    let missing_token_aggregated_tombstone_history = request(
        address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated",
        None,
        None,
    );
    assert_eq!(missing_token_aggregated_tombstone_history.status, 401);

    let missing_token_identity = request(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"alice@example.com","display_name":"Alice","password":"correct horse battery staple"}"#,
        )),
        None,
    );
    assert_eq!(missing_token_identity.status, 401);

    let created_user = request(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"alice@example.com","display_name":"Alice","password":"correct horse battery staple"}"#,
        )),
        Some(token),
    );
    assert_eq!(created_user.status, 201);

    let outbox = request_json(address, "GET", "/identity/outbox", None, Some(token));
    let first = outbox
        .as_array()
        .and_then(|entries| entries.first())
        .unwrap_or_else(|| panic!("identity outbox should contain at least one event"));
    let actor_subject = first
        .get("payload")
        .and_then(|payload| payload.get("header"))
        .and_then(|header| header.get("actor"))
        .and_then(|actor| actor.get("subject"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing actor subject in outbox event"));
    assert_eq!(actor_subject, "bootstrap_admin");
}

#[test]
fn unsupported_runtime_process_role_fails_startup_with_catalog_backed_error() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping unsupported_runtime_process_role_fails_startup_with_catalog_backed_error: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let output = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .env("UHOST_SCHEMA__MODE", "distributed")
        .env("UHOST_SECRETS__MASTER_KEY", base64url_encode(&[0x84; 32]))
        .env("UHOST_RUNTIME__PROCESS_ROLE", "unsupported")
        .output()
        .unwrap_or_else(|error| panic!("failed to run uhostd: {error}"));

    assert!(
        !output.status.success(),
        "unsupported runtime role should prevent startup"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("runtime.process_role `unsupported` is invalid"),
        "startup error should mention the rejected runtime role: {stderr}"
    );
    assert!(
        stderr.contains("expected one of all_in_one, edge, controller, worker, node_adjacent"),
        "startup error should list supported runtime roles: {stderr}"
    );
}

#[test]
fn split_role_startup_rejects_only_local_manifests() {
    let _serial_guard = auth_gate_test_guard();
    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let token = "integration-bootstrap-admin-token";

    for (index, process_role) in ["edge", "worker", "node_adjacent"].into_iter().enumerate() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
        let config_path = temp.path().join("all-in-one.toml");
        let Some(address) = reserve_loopback_port() else {
            eprintln!(
                "skipping split_role_startup_rejects_only_local_manifests: loopback bind not permitted"
            );
            return;
        };
        write_test_config(&config_path, address, &state_dir, Some(token));

        let output = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .env("UHOST_SCHEMA__MODE", "distributed")
            .env(
                "UHOST_SECRETS__MASTER_KEY",
                base64url_encode(&[(0x90 + index) as u8; 32]),
            )
            .env("UHOST_RUNTIME__PROCESS_ROLE", process_role)
            .output()
            .unwrap_or_else(|error| panic!("failed to run uhostd: {error}"));

        assert!(
            !output.status.success(),
            "{process_role} should fail startup without non-local forward targets"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "runtime.process_role `{process_role}` may not activate with only local manifests"
            )),
            "startup error should explain missing non-local manifests for {process_role}: {stderr}"
        );
        assert!(
            !state_dir
                .join("runtime")
                .join("process-registrations.json")
                .exists(),
            "{process_role} rejection should not persist runtime registrations"
        );
        assert!(
            !state_dir
                .join("runtime")
                .join("cell-directory.json")
                .exists(),
            "{process_role} rejection should not persist runtime cell-directory state"
        );
    }
}

#[test]
fn runtime_topology_surface_requires_operator_token_and_reports_all_in_one_ownership() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_topology_surface_requires_operator_token_and_reports_all_in_one_ownership: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));
    seed_stale_peer_runtime_records(&state_dir);

    let _guard = spawn_uhostd(&config_path, address);

    let missing = request(address, "GET", "/runtime/topology", None, None);
    assert_eq!(missing.status, 401);

    let stored_registration = read_runtime_process_registration(&state_dir);
    let stored_value = stored_registration
        .get("value")
        .unwrap_or_else(|| panic!("missing stored registration value"));
    let stored_cell_directory = read_runtime_cell_directory_record(&state_dir);
    let stored_cell_value = stored_cell_directory
        .get("value")
        .unwrap_or_else(|| panic!("missing stored cell directory value"));
    let stored_participants = stored_cell_value["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored participants array"));
    let stored_participant = stored_participants
        .first()
        .unwrap_or_else(|| panic!("missing stored participant"));
    let stored_participant_state = stored_participant
        .get("state")
        .unwrap_or_else(|| panic!("missing stored participant state"));
    let stale_peer = stored_participants
        .iter()
        .find(|participant| participant["registration_id"] == "controller:stale-peer-node")
        .unwrap_or_else(|| panic!("missing stale peer participant from durable cell directory"));
    let stale_peer_state = stale_peer
        .get("state")
        .unwrap_or_else(|| panic!("missing stale peer participant state"));
    let stored_participant_reconciliation = stored_participant
        .get("reconciliation")
        .unwrap_or_else(|| panic!("missing stored participant reconciliation"));
    let stale_peer_reconciliation = stale_peer
        .get("reconciliation")
        .unwrap_or_else(|| panic!("missing stale peer reconciliation"));
    let cleanup_workflow_id =
        stale_participant_cleanup_workflow_id("local:local-cell", "controller:stale-peer-node");
    let stored_cleanup_workflow =
        read_runtime_stale_cleanup_workflow_record(&state_dir, cleanup_workflow_id.as_str());
    let stored_cleanup_value = stored_cleanup_workflow
        .get("value")
        .unwrap_or_else(|| panic!("missing stored cleanup workflow value"));
    assert_eq!(stored_registration["deleted"], false);
    assert_eq!(stored_value["role"], "all_in_one");
    assert_eq!(stored_value["node_name"], "auth-gate-test-node");
    assert_eq!(stored_value["readiness"], "ready");
    assert_eq!(stored_value["drain_intent"], "serving");
    assert!(!stored_value["lease_renewed_at"].is_null());
    assert!(!stored_value["lease_expires_at"].is_null());
    assert_eq!(stored_cell_directory["deleted"], false);
    assert_eq!(stored_cell_value["cell_id"], "local:local-cell");
    assert_eq!(stored_cell_value["cell_name"], "local-cell");
    assert_eq!(stored_cell_value["region"]["region_id"], "local");
    assert_eq!(stored_cell_value["region"]["region_name"], "local");
    assert_eq!(
        stored_participant["registration_id"],
        "all_in_one:auth-gate-test-node"
    );
    assert_eq!(stored_participant["participant_kind"], "runtime_process");
    assert_eq!(
        stored_participant["subject_id"],
        "all_in_one:auth-gate-test-node"
    );
    assert_eq!(stored_participant["role"], "all_in_one");
    assert_eq!(stored_participant["node_name"], "auth-gate-test-node");
    assert_eq!(
        stored_participant["lease_registration_id"],
        "all_in_one:auth-gate-test-node"
    );
    assert_eq!(stored_participant_state["readiness"], "ready");
    assert_eq!(stored_participant_state["drain_intent"], "serving");
    assert_eq!(
        stored_participant_state["published_drain_intent"],
        "serving"
    );
    assert!(stored_participant_state.get("degraded_reason").is_none());
    assert_eq!(
        stored_participant_state["lease_source"],
        "linked_registration"
    );
    assert_eq!(stored_participant_state["lease"]["duration_seconds"], 15);
    let stored_freshness = stored_participant_state["lease"]["freshness"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stored participant lease freshness"));
    assert!(matches!(stored_freshness, "fresh" | "stale"));
    assert!(!stored_participant_state["lease"]["renewed_at"].is_null());
    assert!(!stored_participant_state["lease"]["expires_at"].is_null());
    assert!(!stored_participant_reconciliation["last_reconciled_at"].is_null());
    assert!(
        stored_participant_reconciliation
            .get("stale_since")
            .is_none()
    );
    assert!(
        stored_participant_reconciliation
            .get("cleanup_workflow_id")
            .is_none()
    );
    assert_eq!(stale_peer["participant_kind"], "runtime_process");
    assert_eq!(stale_peer["subject_id"], "controller:stale-peer-node");
    assert_eq!(stale_peer["role"], "controller");
    assert_eq!(stale_peer["node_name"], "stale-peer-node");
    assert_eq!(
        stale_peer["lease_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(stale_peer_state["readiness"], "ready");
    assert_eq!(stale_peer_state["drain_intent"], "draining");
    assert_eq!(stale_peer_state["published_drain_intent"], "serving");
    assert_eq!(stale_peer_state["degraded_reason"], "lease_expired");
    assert_eq!(stale_peer_state["lease_source"], "linked_registration");
    assert_eq!(stale_peer_state["lease"]["freshness"], "expired");
    assert!(!stale_peer_reconciliation["last_reconciled_at"].is_null());
    assert!(!stale_peer_reconciliation["stale_since"].is_null());
    assert_eq!(
        stale_peer_reconciliation["cleanup_workflow_id"],
        cleanup_workflow_id
    );
    assert_eq!(stored_cleanup_workflow["deleted"], false);
    assert_eq!(
        stored_cleanup_value["workflow_kind"],
        "runtime.participant.cleanup.v1"
    );
    assert_eq!(stored_cleanup_value["subject_kind"], "cell_participant");
    assert_eq!(
        stored_cleanup_value["subject_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(stored_cleanup_value["phase"], "running");
    assert_eq!(stored_cleanup_value["state"]["cell_id"], "local:local-cell");
    assert_eq!(
        stored_cleanup_value["state"]["participant_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(
        stored_cleanup_value["state"]["participant_role"],
        "controller"
    );
    assert_eq!(
        stored_cleanup_value["state"]["action"],
        "evacuate_or_tombstone"
    );
    assert_eq!(
        stored_cleanup_value["state"]["stage"],
        "preflight_confirmed"
    );
    assert_eq!(
        stored_cleanup_value["state"]["review_observations"],
        json!(2)
    );
    assert!(!stored_cleanup_value["state"]["stale_since"].is_null());
    assert!(!stored_cleanup_value["state"]["last_observed_stale_at"].is_null());
    assert!(!stored_cleanup_value["state"]["preflight_confirmed_at"].is_null());
    assert!(
        stored_cleanup_value["state"]
            .get("tombstone_eligible_at")
            .is_none()
    );
    assert_eq!(
        stored_participant["service_groups"],
        json!([
            "control",
            "data_and_messaging",
            "edge",
            "governance_and_operations",
            "identity_and_policy",
            "uvm"
        ])
    );
    assert!(!stored_participant["registered_at"].is_null());

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let process_state = topology
        .get("process_state")
        .unwrap_or_else(|| panic!("missing process_state object"));
    let freshness = process_state["lease"]["freshness"]
        .as_str()
        .unwrap_or_else(|| panic!("missing lease freshness"));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let service_group_directory = topology["service_group_directory"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_group_directory array"));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let edge = groups
        .iter()
        .find(|group| group["group"] == "edge")
        .unwrap_or_else(|| panic!("missing edge runtime topology group"));
    let uvm = groups
        .iter()
        .find(|group| group["group"] == "uvm")
        .unwrap_or_else(|| panic!("missing uvm runtime topology group"));
    let participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "all_in_one:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing runtime participant registration"));
    let edge_directory = service_group_directory
        .iter()
        .find(|entry| entry["group"] == "edge")
        .unwrap_or_else(|| panic!("missing edge service-group directory entry"));
    let control_directory = service_group_directory
        .iter()
        .find(|entry| entry["group"] == "control")
        .unwrap_or_else(|| panic!("missing control service-group directory entry"));
    let participant_state = participant
        .get("state")
        .unwrap_or_else(|| panic!("missing runtime participant state"));
    let stale_peer_participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "controller:stale-peer-node")
        .unwrap_or_else(|| panic!("missing stale runtime participant registration"));
    let stale_peer_participant_state = stale_peer_participant
        .get("state")
        .unwrap_or_else(|| panic!("missing stale runtime participant state"));
    let participant_reconciliation = participant
        .get("reconciliation")
        .unwrap_or_else(|| panic!("missing runtime participant reconciliation"));
    let stale_peer_participant_reconciliation = stale_peer_participant
        .get("reconciliation")
        .unwrap_or_else(|| panic!("missing stale runtime participant reconciliation"));
    let stale_peer_cleanup_workflow = stale_peer_participant_reconciliation
        .get("cleanup_workflow")
        .unwrap_or_else(|| panic!("missing stale runtime cleanup workflow"));

    assert_eq!(topology["process_role"], "all_in_one");
    assert_eq!(topology["deployment_mode"], "all_in_one");
    assert_eq!(topology["node_name"], "auth-gate-test-node");
    assert_eq!(topology["region"]["region_id"], "local");
    assert_eq!(topology["region"]["region_name"], "local");
    assert_eq!(topology["cell"]["cell_id"], "local:local-cell");
    assert_eq!(topology["cell"]["cell_name"], "local-cell");
    assert_eq!(
        process_state["registration_id"],
        "all_in_one:auth-gate-test-node"
    );
    assert_eq!(process_state["readiness"], "ready");
    assert_eq!(process_state["drain_intent"], "serving");
    assert_eq!(process_state["lease"]["duration_seconds"], 15);
    assert!(matches!(freshness, "fresh" | "stale"));
    assert!(!process_state["registered_at"].is_null());
    assert!(!process_state["lease"]["renewed_at"].is_null());
    assert!(!process_state["lease"]["expires_at"].is_null());
    assert_eq!(participant["participant_kind"], "runtime_process");
    assert_eq!(participant["subject_id"], "all_in_one:auth-gate-test-node");
    assert_eq!(participant["role"], "all_in_one");
    assert_eq!(participant["node_name"], "auth-gate-test-node");
    assert_eq!(
        participant["lease_registration_id"],
        "all_in_one:auth-gate-test-node"
    );
    assert_eq!(participant_state["readiness"], "ready");
    assert_eq!(participant_state["drain_intent"], "serving");
    assert_eq!(participant_state["published_drain_intent"], "serving");
    assert!(participant_state.get("degraded_reason").is_none());
    assert_eq!(participant_state["lease_source"], "linked_registration");
    assert_eq!(participant_state["lease"]["duration_seconds"], 15);
    let participant_freshness = participant_state["lease"]["freshness"]
        .as_str()
        .unwrap_or_else(|| panic!("missing runtime participant lease freshness"));
    assert!(matches!(participant_freshness, "fresh" | "stale"));
    assert!(!participant_state["lease"]["renewed_at"].is_null());
    assert!(!participant_state["lease"]["expires_at"].is_null());
    assert!(!participant_reconciliation["last_reconciled_at"].is_null());
    assert!(participant_reconciliation.get("stale_since").is_none());
    assert!(participant_reconciliation.get("cleanup_workflow").is_none());
    assert_eq!(
        stale_peer_participant["participant_kind"],
        "runtime_process"
    );
    assert_eq!(
        stale_peer_participant["subject_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(stale_peer_participant["role"], "controller");
    assert_eq!(stale_peer_participant["node_name"], "stale-peer-node");
    assert_eq!(
        stale_peer_participant["lease_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(stale_peer_participant_state["readiness"], "ready");
    assert_eq!(stale_peer_participant_state["drain_intent"], "draining");
    assert_eq!(
        stale_peer_participant_state["published_drain_intent"],
        "serving"
    );
    assert_eq!(
        stale_peer_participant_state["degraded_reason"],
        "lease_expired"
    );
    assert_eq!(
        stale_peer_participant_state["lease_source"],
        "linked_registration"
    );
    assert_eq!(
        stale_peer_participant_state["lease"]["freshness"],
        "expired"
    );
    assert!(!stale_peer_participant_reconciliation["last_reconciled_at"].is_null());
    assert!(!stale_peer_participant_reconciliation["stale_since"].is_null());
    assert_eq!(stale_peer_cleanup_workflow["id"], cleanup_workflow_id);
    assert_eq!(
        stale_peer_cleanup_workflow["workflow_kind"],
        "runtime.participant.cleanup.v1"
    );
    assert_eq!(stale_peer_cleanup_workflow["phase"], "running");
    assert_eq!(stale_peer_cleanup_workflow["stage"], "preflight_confirmed");
    assert_eq!(stale_peer_cleanup_workflow["review_observations"], json!(2));
    assert!(!stale_peer_cleanup_workflow["last_observed_stale_at"].is_null());
    assert!(!stale_peer_cleanup_workflow["preflight_confirmed_at"].is_null());
    assert!(
        stale_peer_cleanup_workflow
            .get("tombstone_eligible_at")
            .is_none()
    );
    assert!(!stale_peer_cleanup_workflow["created_at"].is_null());
    assert!(!stale_peer_cleanup_workflow["updated_at"].is_null());
    assert_eq!(
        participant["service_groups"],
        json!([
            "control",
            "data_and_messaging",
            "edge",
            "governance_and_operations",
            "identity_and_policy",
            "uvm"
        ])
    );
    assert!(!participant["registered_at"].is_null());
    assert_eq!(
        edge_directory["resolved_registration_ids"],
        json!(["all_in_one:auth-gate-test-node"])
    );
    assert_eq!(edge_directory["conflict_state"], json!("no_conflict"));
    assert_eq!(edge_directory["registrations"][0]["healthy"], json!(true));
    assert_eq!(control_directory["conflict_state"], json!("no_conflict"));
    assert_eq!(
        control_directory["resolved_registration_ids"],
        json!(["all_in_one:auth-gate-test-node"])
    );
    let stale_control_registration = control_directory["registrations"]
        .as_array()
        .unwrap_or_else(|| panic!("missing control service-group registrations"))
        .iter()
        .find(|registration| registration["registration_id"] == "controller:stale-peer-node")
        .unwrap_or_else(|| panic!("missing stale control service-group registration"));
    assert_eq!(stale_control_registration["healthy"], json!(false));
    assert_eq!(
        stale_control_registration["drain_intent"],
        json!("draining")
    );
    assert_eq!(
        stale_control_registration["lease_freshness"],
        json!("expired")
    );
    assert_eq!(edge["owner_role"], "all_in_one");
    assert_eq!(edge["services"], json!(["console", "dns", "ingress"]));
    assert_eq!(uvm["owner_role"], "all_in_one");
    assert_eq!(
        uvm["services"],
        json!(["uvm-control", "uvm-image", "uvm-node", "uvm-observe"])
    );
}

#[test]
fn edge_process_role_requires_operator_token_and_reports_edge_owned_activation() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping edge_process_role_requires_operator_token_and_reports_edge_owned_activation: loopback bind not permitted"
        );
        return;
    };
    let Some(policy_target) = reserve_loopback_port() else {
        eprintln!(
            "skipping edge_process_role_requires_operator_token_and_reports_edge_owned_activation: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config_with_forward_targets(
        &config_path,
        address,
        &state_dir,
        Some(token),
        &BTreeMap::from([(String::from("policy"), policy_target)]),
    );

    let master_key = base64url_encode(&[0x81; 32]);
    let _guard = spawn_uhostd_with_envs(
        &config_path,
        address,
        &[
            ("UHOST_SCHEMA__MODE", "distributed"),
            ("UHOST_SECRETS__MASTER_KEY", master_key.as_str()),
            ("UHOST_RUNTIME__PROCESS_ROLE", "edge"),
        ],
    );

    assert_eq!(request(address, "GET", "/healthz", None, None).status, 200);
    assert_eq!(request(address, "GET", "/metrics", None, None).status, 401);
    assert_eq!(
        request(address, "GET", "/runtime/topology", None, None).status,
        401
    );
    assert_eq!(
        request(
            address,
            "GET",
            "/runtime/participants/tombstone-history",
            None,
            None,
        )
        .status,
        401
    );

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let group_names = groups
        .iter()
        .map(|group| {
            group["group"]
                .as_str()
                .unwrap_or_else(|| panic!("missing runtime service-group name"))
        })
        .collect::<Vec<_>>();
    let edge = groups
        .iter()
        .find(|group| group["group"] == "edge")
        .unwrap_or_else(|| panic!("missing edge runtime topology group"));
    let participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "edge:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing edge runtime participant"));

    assert_eq!(topology["process_role"], "edge");
    assert_eq!(topology["deployment_mode"], "distributed");
    assert_eq!(groups.len(), 1);
    assert_eq!(participants.len(), 1);
    assert_eq!(group_names, vec!["edge"]);
    assert_eq!(edge["owner_role"], "edge");
    assert_eq!(edge["services"], json!(["console", "dns", "ingress"]));
    assert_eq!(participant["role"], "edge");
    assert_eq!(participant["service_groups"], json!(["edge"]));

    assert_eq!(request(address, "GET", "/console", None, None).status, 401);
    assert_eq!(
        request(address, "GET", "/console", None, Some(token)).status,
        200
    );
    assert_eq!(
        request_json(address, "GET", "/ingress", None, Some(token))["service"],
        "ingress"
    );
    assert_eq!(
        request_json(address, "GET", "/dns", None, Some(token))["service"],
        "dns"
    );
    assert_eq!(
        request(address, "GET", "/identity", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/control", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/uvm", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/netsec", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/container", None, Some(token)).status,
        404
    );
}

#[test]
fn edge_process_role_publishes_self_without_reconciling_seeded_peers() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    seed_stale_peer_runtime_records_with_cleanup_state(&state_dir, false);
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping edge_process_role_publishes_self_without_reconciling_seeded_peers: loopback bind not permitted"
        );
        return;
    };
    let Some(policy_target) = reserve_loopback_port() else {
        eprintln!(
            "skipping edge_process_role_publishes_self_without_reconciling_seeded_peers: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config_with_forward_targets(
        &config_path,
        address,
        &state_dir,
        Some(token),
        &BTreeMap::from([(String::from("policy"), policy_target)]),
    );

    let master_key = base64url_encode(&[0x85; 32]);
    let _guard = spawn_uhostd_with_envs(
        &config_path,
        address,
        &[
            ("UHOST_SCHEMA__MODE", "distributed"),
            ("UHOST_SECRETS__MASTER_KEY", master_key.as_str()),
            ("UHOST_RUNTIME__PROCESS_ROLE", "edge"),
        ],
    );

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let stale_peer = participants
        .iter()
        .find(|participant| participant["registration_id"] == "controller:stale-peer-node")
        .unwrap_or_else(|| panic!("missing seeded stale peer participant"));
    let edge_participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "edge:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing edge runtime participant"));

    assert_eq!(participants.len(), 2);
    assert_eq!(edge_participant["role"], "edge");
    assert_eq!(stale_peer["state"]["drain_intent"], "serving");
    assert_eq!(
        stale_peer["state"]["lease_source"],
        "published_state_fallback"
    );
    assert_eq!(stale_peer["state"]["lease"]["freshness"], "fresh");

    let stored_directory = read_runtime_cell_directory_record(&state_dir);
    let stored_stale_peer = stored_directory["value"]["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored runtime participants"))
        .iter()
        .find(|participant| participant["registration_id"] == "controller:stale-peer-node")
        .unwrap_or_else(|| panic!("missing stored seeded stale peer participant"));
    assert_eq!(stored_stale_peer["state"]["drain_intent"], "serving");
    assert_eq!(
        stored_stale_peer["state"]["lease_source"],
        "published_state_fallback"
    );
    assert_eq!(stored_stale_peer["state"]["lease"]["freshness"], "fresh");

    let cleanup_workflow_id =
        stale_participant_cleanup_workflow_id("local:local-cell", "controller:stale-peer-node");
    let stored_cleanup_workflow =
        read_runtime_stale_cleanup_workflow_record(&state_dir, cleanup_workflow_id.as_str());
    assert_eq!(stored_cleanup_workflow["value"]["phase"], "pending");
    assert_eq!(
        stored_cleanup_workflow["value"]["state"]["stage"],
        "pending_review"
    );
}

#[test]
fn controller_process_role_requires_operator_token_and_reports_reduced_activation() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping controller_process_role_requires_operator_token_and_reports_reduced_activation: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let master_key = base64url_encode(&[0x80; 32]);
    let _guard = spawn_uhostd_with_envs(
        &config_path,
        address,
        &[
            ("UHOST_SCHEMA__MODE", "distributed"),
            ("UHOST_SECRETS__MASTER_KEY", master_key.as_str()),
            ("UHOST_RUNTIME__PROCESS_ROLE", "controller"),
        ],
    );

    assert_eq!(request(address, "GET", "/healthz", None, None).status, 200);
    assert_eq!(request(address, "GET", "/metrics", None, None).status, 401);
    assert_eq!(
        request(address, "GET", "/runtime/topology", None, None).status,
        401
    );
    assert_eq!(request(address, "GET", "/identity", None, None).status, 401);

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let group_names = groups
        .iter()
        .map(|group| {
            group["group"]
                .as_str()
                .unwrap_or_else(|| panic!("missing runtime service-group name"))
        })
        .collect::<Vec<_>>();
    let control = groups
        .iter()
        .find(|group| group["group"] == "control")
        .unwrap_or_else(|| panic!("missing control runtime topology group"));
    let participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "controller:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing controller runtime participant"));

    assert_eq!(topology["process_role"], "controller");
    assert_eq!(topology["deployment_mode"], "distributed");
    assert_eq!(participants.len(), 1);
    assert_eq!(
        group_names,
        vec![
            "control",
            "governance_and_operations",
            "identity_and_policy",
            "uvm"
        ]
    );
    assert!(
        groups
            .iter()
            .all(|group| group["owner_role"] == "controller")
    );
    assert_eq!(
        control["services"],
        json!([
            "container",
            "control",
            "ha",
            "lifecycle",
            "node",
            "scheduler"
        ])
    );
    assert_eq!(participant["role"], "controller");
    assert_eq!(
        participant["service_groups"],
        json!([
            "control",
            "governance_and_operations",
            "identity_and_policy",
            "uvm"
        ])
    );

    assert_eq!(
        request_json(address, "GET", "/identity", None, Some(token))["service"],
        "identity"
    );
    assert_eq!(
        request_json(address, "GET", "/control", None, Some(token))["service"],
        "control"
    );
    assert_eq!(
        request_json(address, "GET", "/container", None, Some(token))["service"],
        "container"
    );
    assert_eq!(
        request_json(address, "GET", "/uvm", None, Some(token))["service"],
        "uvm-control"
    );
    assert_eq!(
        request(address, "GET", "/ingress", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/dns", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/netsec", None, Some(token)).status,
        404
    );
}

#[test]
fn worker_process_role_requires_operator_token_and_reports_worker_owned_activation() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping worker_process_role_requires_operator_token_and_reports_worker_owned_activation: loopback bind not permitted"
        );
        return;
    };
    let Some(policy_target) = reserve_loopback_port() else {
        eprintln!(
            "skipping worker_process_role_requires_operator_token_and_reports_worker_owned_activation: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config_with_forward_targets(
        &config_path,
        address,
        &state_dir,
        Some(token),
        &BTreeMap::from([(String::from("policy"), policy_target)]),
    );

    let master_key = base64url_encode(&[0x82; 32]);
    let _guard = spawn_uhostd_with_envs(
        &config_path,
        address,
        &[
            ("UHOST_SCHEMA__MODE", "distributed"),
            ("UHOST_SECRETS__MASTER_KEY", master_key.as_str()),
            ("UHOST_RUNTIME__PROCESS_ROLE", "worker"),
        ],
    );

    assert_eq!(request(address, "GET", "/healthz", None, None).status, 200);
    assert_eq!(request(address, "GET", "/metrics", None, None).status, 401);
    assert_eq!(
        request(address, "GET", "/runtime/topology", None, None).status,
        401
    );
    assert_eq!(
        request(
            address,
            "GET",
            "/runtime/participants/tombstone-history",
            None,
            None,
        )
        .status,
        401
    );
    assert_eq!(request(address, "GET", "/data", None, None).status, 401);

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let group_names = groups
        .iter()
        .map(|group| {
            group["group"]
                .as_str()
                .unwrap_or_else(|| panic!("missing runtime service-group name"))
        })
        .collect::<Vec<_>>();
    let data_and_messaging = groups
        .iter()
        .find(|group| group["group"] == "data_and_messaging")
        .unwrap_or_else(|| panic!("missing data-and-messaging runtime topology group"));
    let participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "worker:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing worker runtime participant"));

    assert_eq!(topology["process_role"], "worker");
    assert_eq!(topology["deployment_mode"], "distributed");
    assert_eq!(groups.len(), 1);
    assert_eq!(participants.len(), 1);
    assert_eq!(group_names, vec!["data_and_messaging"]);
    assert_eq!(data_and_messaging["owner_role"], "worker");
    assert_eq!(
        data_and_messaging["services"],
        json!(["data", "mail", "netsec", "storage", "stream"])
    );
    assert_eq!(participant["role"], "worker");
    assert_eq!(participant["service_groups"], json!(["data_and_messaging"]));

    assert_eq!(
        request_json(address, "GET", "/data", None, Some(token))["service"],
        "data"
    );
    assert_eq!(
        request_json(address, "GET", "/mail", None, Some(token))["service"],
        "mail"
    );
    assert_eq!(
        request_json(address, "GET", "/netsec", None, Some(token))["service"],
        "netsec"
    );
    assert_eq!(
        request_json(address, "GET", "/storage", None, Some(token))["service"],
        "storage"
    );
    assert_eq!(
        request_json(address, "GET", "/stream", None, Some(token))["service"],
        "stream"
    );
    assert_eq!(
        request(address, "GET", "/identity", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/control", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/container", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/ingress", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/uvm", None, Some(token)).status,
        404
    );
}

#[test]
fn node_adjacent_process_role_requires_operator_token_and_reports_node_adjacent_activation() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping node_adjacent_process_role_requires_operator_token_and_reports_node_adjacent_activation: loopback bind not permitted"
        );
        return;
    };
    let Some(policy_target) = reserve_loopback_port() else {
        eprintln!(
            "skipping node_adjacent_process_role_requires_operator_token_and_reports_node_adjacent_activation: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config_with_forward_targets(
        &config_path,
        address,
        &state_dir,
        Some(token),
        &BTreeMap::from([(String::from("policy"), policy_target)]),
    );

    let master_key = base64url_encode(&[0x83; 32]);
    let _guard = spawn_uhostd_with_envs(
        &config_path,
        address,
        &[
            ("UHOST_SCHEMA__MODE", "distributed"),
            ("UHOST_SECRETS__MASTER_KEY", master_key.as_str()),
            ("UHOST_RUNTIME__PROCESS_ROLE", "node_adjacent"),
        ],
    );

    assert_eq!(request(address, "GET", "/healthz", None, None).status, 200);
    assert_eq!(request(address, "GET", "/metrics", None, None).status, 401);
    assert_eq!(
        request(address, "GET", "/runtime/topology", None, None).status,
        401
    );
    assert_eq!(
        request(
            address,
            "GET",
            "/runtime/participants/tombstone-history",
            None,
            None,
        )
        .status,
        401
    );

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing participants array"));
    let group_names = groups
        .iter()
        .map(|group| {
            group["group"]
                .as_str()
                .unwrap_or_else(|| panic!("missing runtime service-group name"))
        })
        .collect::<Vec<_>>();
    let control = groups
        .iter()
        .find(|group| group["group"] == "control")
        .unwrap_or_else(|| panic!("missing control runtime topology group"));
    let uvm = groups
        .iter()
        .find(|group| group["group"] == "uvm")
        .unwrap_or_else(|| panic!("missing uvm runtime topology group"));
    let participant = participants
        .iter()
        .find(|participant| participant["registration_id"] == "node_adjacent:auth-gate-test-node")
        .unwrap_or_else(|| panic!("missing node-adjacent runtime participant"));

    assert_eq!(topology["process_role"], "node_adjacent");
    assert_eq!(topology["deployment_mode"], "distributed");
    assert_eq!(groups.len(), 2);
    assert_eq!(participants.len(), 1);
    assert_eq!(group_names, vec!["control", "uvm"]);
    assert!(
        groups
            .iter()
            .all(|group| group["owner_role"] == "node_adjacent")
    );
    assert_eq!(control["services"], json!(["node"]));
    assert_eq!(uvm["services"], json!(["uvm-node"]));
    assert_eq!(participant["role"], "node_adjacent");
    assert_eq!(participant["service_groups"], json!(["control", "uvm"]));

    assert_eq!(request(address, "GET", "/node", None, None).status, 401);
    assert_eq!(
        request_json(address, "GET", "/node", None, Some(token))["service"],
        "node"
    );
    assert_eq!(
        request_json(address, "GET", "/uvm/node", None, Some(token))["service"],
        "uvm-node"
    );
    assert_eq!(
        request(address, "GET", "/control", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/container", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/uvm", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/uvm/image", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/identity", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/data", None, Some(token)).status,
        404
    );
    assert_eq!(
        request(address, "GET", "/ingress", None, Some(token)).status,
        404
    );
}

#[test]
fn runtime_participant_tombstone_surface_requires_operator_token_and_rejects_non_eligible_targets()
{
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_participant_tombstone_surface_requires_operator_token_and_rejects_non_eligible_targets: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));
    seed_stale_peer_runtime_records(&state_dir);

    let _guard = spawn_uhostd(&config_path, address);

    let missing_token = request(
        address,
        "POST",
        "/runtime/participants/tombstone",
        Some((
            "application/json",
            br#"{"registration_id":"controller:stale-peer-node"}"#,
        )),
        None,
    );
    assert_eq!(missing_token.status, 401);

    let self_target = request(
        address,
        "POST",
        "/runtime/participants/tombstone",
        Some((
            "application/json",
            br#"{"registration_id":"all_in_one:auth-gate-test-node"}"#,
        )),
        Some(token),
    );
    assert_eq!(self_target.status, 403);

    let non_eligible_stale_target = request(
        address,
        "POST",
        "/runtime/participants/tombstone",
        Some((
            "application/json",
            br#"{"registration_id":"controller:stale-peer-node"}"#,
        )),
        Some(token),
    );
    assert_eq!(non_eligible_stale_target.status, 409);

    let cleanup_workflow_id =
        stale_participant_cleanup_workflow_id("local:local-cell", "controller:stale-peer-node");
    let stored_cleanup_workflow =
        read_runtime_stale_cleanup_workflow_record(&state_dir, cleanup_workflow_id.as_str());
    assert_eq!(stored_cleanup_workflow["deleted"], false);
    let stored_cell_directory = read_runtime_cell_directory_record(&state_dir);
    let stored_participants = stored_cell_directory["value"]["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored participants array"));
    assert!(
        stored_participants
            .iter()
            .any(|participant| participant["registration_id"] == "controller:stale-peer-node")
    );
    let tombstone_history = read_runtime_participant_tombstone_history_entries(&state_dir);
    assert!(tombstone_history.is_empty());
    let audit_events = read_runtime_audit_events(&state_dir);
    assert!(
        audit_events
            .iter()
            .all(|event| event["header"]["event_type"] != "runtime.participant.tombstoned.v1")
    );
    let outbox_entries = read_runtime_outbox_entries(&state_dir);
    assert!(
        outbox_entries
            .iter()
            .all(|entry| entry["event_type"] != "runtime.participant.tombstoned.v1")
    );
}

#[test]
fn runtime_participant_tombstone_surface_tombstones_eligible_stale_peer_and_updates_topology() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_participant_tombstone_surface_tombstones_eligible_stale_peer_and_updates_topology: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));
    seed_tombstone_eligible_stale_peer_runtime_records(&state_dir);

    let _guard = spawn_uhostd(&config_path, address);

    let cleanup_workflow_id =
        stale_participant_cleanup_workflow_id("local:local-cell", "controller:stale-peer-node");
    let reply = request_json(
        address,
        "POST",
        "/runtime/participants/tombstone",
        Some((
            "application/json",
            br#"{"registration_id":"controller:stale-peer-node"}"#,
        )),
        Some(token),
    );
    assert_eq!(reply["cell_id"], "local:local-cell");
    assert_eq!(
        reply["participant_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(reply["cleanup_workflow_id"], cleanup_workflow_id);
    assert_eq!(reply["lease_registration_id"], "controller:stale-peer-node");
    assert_eq!(reply["removed_from_cell_directory"], json!(true));
    assert_eq!(reply["lease_registration_soft_deleted"], json!(true));
    assert_eq!(reply["cleanup_workflow_soft_deleted"], json!(true));
    assert!(!reply["tombstoned_at"].is_null());

    let stored_peer_registration =
        read_runtime_process_registration_record(&state_dir, "controller:stale-peer-node");
    assert_eq!(stored_peer_registration["deleted"], true);
    let stored_cleanup_workflow =
        read_runtime_stale_cleanup_workflow_record(&state_dir, cleanup_workflow_id.as_str());
    assert_eq!(stored_cleanup_workflow["deleted"], true);
    let stored_cell_directory = read_runtime_cell_directory_record(&state_dir);
    let stored_participants = stored_cell_directory["value"]["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored participants array"));
    assert!(
        stored_participants
            .iter()
            .all(|participant| participant["registration_id"] != "controller:stale-peer-node")
    );

    let tombstone_history = read_runtime_participant_tombstone_history_entries(&state_dir);
    assert_eq!(tombstone_history.len(), 1);
    let history_entry = tombstone_history
        .first()
        .unwrap_or_else(|| panic!("missing runtime tombstone history entry"));
    assert_eq!(history_entry["cell_id"], "local:local-cell");
    assert_eq!(history_entry["cell_name"], "local-cell");
    assert_eq!(history_entry["region_id"], "local");
    assert_eq!(history_entry["region_name"], "local");
    assert_eq!(
        history_entry["participant_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(history_entry["participant_kind"], "runtime_process");
    assert_eq!(
        history_entry["participant_subject_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(history_entry["participant_role"], "controller");
    assert_eq!(history_entry["cleanup_workflow_id"], cleanup_workflow_id);
    assert_eq!(
        history_entry["review_observations"],
        stored_cleanup_workflow["value"]["state"]["review_observations"]
    );
    assert_eq!(history_entry["actor_subject"], "bootstrap_admin");
    assert_eq!(history_entry["actor_type"], "operator");
    assert_eq!(
        history_entry["lease_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(history_entry["published_drain_intent"], json!("serving"));
    assert_eq!(history_entry["degraded_reason"], json!("lease_expired"));
    assert_eq!(history_entry["lease_source"], json!("linked_registration"));
    assert_eq!(history_entry["removed_from_cell_directory"], json!(true));
    assert_eq!(
        history_entry["lease_registration_soft_deleted"],
        json!(true)
    );
    assert_eq!(history_entry["cleanup_workflow_soft_deleted"], json!(true));
    assert!(!history_entry["event_id"].is_null());
    assert!(!history_entry["stale_since"].is_null());
    assert!(!history_entry["preflight_confirmed_at"].is_null());
    assert!(!history_entry["tombstone_eligible_at"].is_null());
    assert!(!history_entry["tombstoned_at"].is_null());
    assert!(!history_entry["correlation_id"].is_null());

    let audit_events = read_runtime_audit_events(&state_dir);
    let tombstone_audit = audit_events
        .iter()
        .find(|event| event["header"]["event_type"] == "runtime.participant.tombstoned.v1")
        .unwrap_or_else(|| panic!("runtime audit log should contain tombstone event"));
    assert_eq!(tombstone_audit["header"]["source_service"], "runtime");
    assert_eq!(
        tombstone_audit["header"]["actor"]["subject"],
        "bootstrap_admin"
    );
    assert_eq!(tombstone_audit["header"]["actor"]["actor_type"], "operator");
    assert_eq!(tombstone_audit["payload"]["kind"], "service");
    assert_eq!(
        tombstone_audit["payload"]["data"]["resource_kind"],
        "cell_participant"
    );
    assert_eq!(
        tombstone_audit["payload"]["data"]["resource_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(tombstone_audit["payload"]["data"]["action"], "tombstoned");
    assert_eq!(
        tombstone_audit["payload"]["data"]["details"]["event_id"],
        history_entry["event_id"]
    );

    let outbox_entries = read_runtime_outbox_entries(&state_dir);
    let tombstone_outbox = outbox_entries
        .iter()
        .find(|entry| entry["event_type"] == "runtime.participant.tombstoned.v1")
        .unwrap_or_else(|| panic!("runtime outbox should contain tombstone event"));
    assert_eq!(tombstone_outbox["topic"], "runtime.events.v1");
    assert_eq!(tombstone_outbox["source_service"], "runtime");
    assert_eq!(
        tombstone_outbox["idempotency_key"],
        history_entry["event_id"]
    );
    assert_eq!(
        tombstone_outbox["payload"]["header"]["event_type"],
        "runtime.participant.tombstoned.v1"
    );
    assert_eq!(
        tombstone_outbox["payload"]["header"]["source_service"],
        "runtime"
    );
    assert_eq!(
        tombstone_outbox["payload"]["header"]["actor"]["subject"],
        "bootstrap_admin"
    );
    assert_eq!(
        tombstone_outbox["payload"]["payload"]["data"]["details"]["event_id"],
        history_entry["event_id"]
    );

    let topology = request_json(address, "GET", "/runtime/topology", None, Some(token));
    let participants = topology["participants"]
        .as_array()
        .unwrap_or_else(|| panic!("missing topology participants array"));
    assert!(
        participants
            .iter()
            .all(|participant| participant["registration_id"] != "controller:stale-peer-node")
    );
    assert!(
        participants
            .iter()
            .any(|participant| participant["registration_id"] == "all_in_one:auth-gate-test-node")
    );
    let topology_history = topology["tombstone_history"]
        .as_array()
        .unwrap_or_else(|| panic!("missing topology tombstone history array"));
    assert_eq!(topology_history.len(), 1);
    assert_eq!(
        topology_history[0]["participant_registration_id"],
        "controller:stale-peer-node"
    );
    assert_eq!(topology_history[0]["event_id"], history_entry["event_id"]);
    assert_eq!(topology_history[0]["actor_subject"], "bootstrap_admin");
    assert_eq!(
        topology_history[0]["published_drain_intent"],
        json!("serving")
    );
    assert_eq!(
        topology_history[0]["degraded_reason"],
        json!("lease_expired")
    );
    assert_eq!(
        topology_history[0]["lease_source"],
        json!("linked_registration")
    );

    let aggregated = request_json(
        address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated",
        None,
        Some(token),
    );
    let aggregated_items = aggregated["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing aggregated tombstone history items"));
    assert_eq!(aggregated_items.len(), 1);
    assert_eq!(
        aggregated_items[0]["history"]["event_id"],
        history_entry["event_id"]
    );
    assert_eq!(
        aggregated_items[0]["history"]["cleanup_workflow_id"],
        history_entry["cleanup_workflow_id"]
    );
    assert_eq!(
        aggregated_items[0]["history"]["published_drain_intent"],
        json!("serving")
    );
    assert_eq!(
        aggregated_items[0]["history"]["degraded_reason"],
        json!("lease_expired")
    );
    assert_eq!(
        aggregated_items[0]["history"]["lease_source"],
        json!("linked_registration")
    );
    assert_eq!(
        aggregated_items[0]["relay_evidence"]["idempotency_key"],
        history_entry["event_id"]
    );
    assert_eq!(
        aggregated_items[0]["relay_evidence"]["source_service"],
        json!("runtime")
    );
    assert_eq!(
        aggregated_items[0]["relay_evidence"]["event_type"],
        json!("runtime.participant.tombstoned.v1")
    );
    assert_eq!(
        aggregated_items[0]["relay_evidence"]["delivery_state"],
        json!("pending")
    );
    assert_eq!(
        aggregated_items[0]["relay_evidence"]["replay_count"],
        json!(0)
    );
}

#[test]
fn runtime_participant_tombstone_history_surface_requires_operator_token_and_projects_multi_cell_pages()
 {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_participant_tombstone_history_surface_requires_operator_token_and_projects_multi_cell_pages: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let seeded_at = OffsetDateTime::now_utc();
    seed_runtime_tombstone_history_records(
        &state_dir,
        &[
            runtime_tombstone_history_record(
                "history-local",
                "local:local-cell",
                "local-cell",
                "local",
                "local",
                "controller:local-peer-node",
                "controller",
                Some("local-peer-node"),
                &["control"],
                seeded_at - time::Duration::seconds(1),
            ),
            runtime_tombstone_history_record(
                "history-east",
                "us-east-1:control-a",
                "control-a",
                "us-east-1",
                "us-east-1",
                "worker:east-peer-node",
                "worker",
                Some("east-peer-node"),
                &["control", "edge"],
                seeded_at - time::Duration::seconds(2),
            ),
            runtime_tombstone_history_record(
                "history-west",
                "us-west-2:control-b",
                "control-b",
                "us-west-2",
                "us-west-2",
                "node_adjacent:west-peer-node",
                "node_adjacent",
                Some("west-peer-node"),
                &["uvm"],
                seeded_at - time::Duration::seconds(3),
            ),
        ],
    );

    let _guard = spawn_uhostd(&config_path, address);

    let missing = request(
        address,
        "GET",
        "/runtime/participants/tombstone-history",
        None,
        None,
    );
    assert_eq!(missing.status, 401);

    let first_page = request_json(
        address,
        "GET",
        "/runtime/participants/tombstone-history?limit=2",
        None,
        Some(token),
    );
    let first_items = first_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing first tombstone history page items"));
    assert_eq!(first_items.len(), 2);
    assert_eq!(first_items[0]["event_id"], "history-local");
    assert_eq!(first_items[0]["cell_id"], "local:local-cell");
    assert_eq!(first_items[0]["region_id"], "local");
    assert_eq!(
        first_items[0]["cleanup_workflow_id"],
        stale_participant_cleanup_workflow_id("local:local-cell", "controller:local-peer-node")
    );
    assert_eq!(first_items[0]["correlation_id"], "corr-history-local");
    assert!(first_items[0].get("published_drain_intent").is_none());
    assert!(first_items[0].get("degraded_reason").is_none());
    assert!(first_items[0].get("lease_source").is_none());
    assert_eq!(first_items[1]["event_id"], "history-east");
    assert_eq!(first_items[1]["cell_name"], "control-a");
    assert_eq!(first_items[1]["region_name"], "us-east-1");
    assert_eq!(first_page["retention"]["max_entries"], json!(128));
    assert_eq!(first_page["retention"]["retained_entries"], json!(3));
    assert_eq!(first_page["retention"]["pruned_entries"], json!(0));
    assert_eq!(
        first_page["retention"]["oldest_retained_event_id"],
        "history-west"
    );

    let next_cursor = first_page
        .get("next_cursor")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing next tombstone history cursor"));
    let second_page = request_json(
        address,
        "GET",
        format!("/runtime/participants/tombstone-history?limit=2&cursor={next_cursor}").as_str(),
        None,
        Some(token),
    );
    let second_items = second_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing second tombstone history page items"));
    assert_eq!(second_items.len(), 1);
    assert_eq!(second_items[0]["event_id"], "history-west");
    assert_eq!(second_items[0]["cell_id"], "us-west-2:control-b");
    assert_eq!(second_items[0]["region_id"], "us-west-2");
    assert!(second_page.get("next_cursor").is_none());
}

#[test]
fn runtime_participant_tombstone_history_surface_applies_retention_to_seeded_history() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_participant_tombstone_history_surface_applies_retention_to_seeded_history: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let seeded_at = OffsetDateTime::now_utc();
    let records = (0..130)
        .map(|index| {
            let (cell_id, cell_name, region_id, region_name, participant_role, service_groups) =
                if index % 2 == 0 {
                    (
                        "local:local-cell",
                        "local-cell",
                        "local",
                        "local",
                        "controller",
                        &["control"][..],
                    )
                } else {
                    (
                        "us-east-1:edge-a",
                        "edge-a",
                        "us-east-1",
                        "us-east-1",
                        "worker",
                        &["edge"][..],
                    )
                };
            let event_id = format!("history-{index:03}");
            let participant_registration_id = format!("runtime:stale-peer-{index:03}");
            let node_name = format!("stale-peer-{index:03}");
            runtime_tombstone_history_record(
                event_id.as_str(),
                cell_id,
                cell_name,
                region_id,
                region_name,
                participant_registration_id.as_str(),
                participant_role,
                Some(node_name.as_str()),
                service_groups,
                seeded_at - time::Duration::seconds(index.into()),
            )
        })
        .collect::<Vec<_>>();
    seed_runtime_tombstone_history_records(&state_dir, &records);

    let _guard = spawn_uhostd(&config_path, address);

    let projection = request_json(
        address,
        "GET",
        "/runtime/participants/tombstone-history",
        None,
        Some(token),
    );
    let items = projection["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing retained tombstone history page items"));
    assert_eq!(items.len(), 25);
    assert_eq!(items[0]["event_id"], "history-000");
    assert_eq!(projection["retention"]["max_entries"], json!(128));
    assert_eq!(projection["retention"]["retained_entries"], json!(128));
    assert_eq!(projection["retention"]["pruned_entries"], json!(2));
    assert_eq!(
        projection["retention"]["oldest_retained_event_id"],
        "history-127"
    );

    let active_history = read_runtime_participant_tombstone_history_entries(&state_dir);
    assert_eq!(active_history.len(), 128);
    assert!(
        active_history
            .iter()
            .all(|entry| entry["event_id"] != "history-128")
    );
    assert!(
        active_history
            .iter()
            .all(|entry| entry["event_id"] != "history-129")
    );

    let stored_history_records = read_runtime_participant_tombstone_history_records(&state_dir);
    assert_eq!(
        stored_history_records
            .iter()
            .filter(|record| record["deleted"].as_bool().unwrap_or(false))
            .count(),
        2
    );
    assert!(stored_history_records.iter().any(|record| {
        record["deleted"] == json!(true) && record["value"]["event_id"] == "history-128"
    }));
    assert!(stored_history_records.iter().any(|record| {
        record["deleted"] == json!(true) && record["value"]["event_id"] == "history-129"
    }));
}

#[test]
fn runtime_participant_tombstone_aggregated_history_surface_requires_operator_token_and_applies_stable_filters()
 {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_participant_tombstone_aggregated_history_surface_requires_operator_token_and_applies_stable_filters: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let seeded_at = OffsetDateTime::now_utc();
    let local_history = runtime_tombstone_history_record(
        "aud_abcdefghijklmnopqrstu",
        "local:local-cell",
        "local-cell",
        "local",
        "local",
        "controller:local-peer-node",
        "controller",
        Some("local-peer-node"),
        &["control"],
        seeded_at - time::Duration::seconds(1),
    );
    let east_newer_history = runtime_tombstone_history_record(
        "aud_bcdefghijklmnopqrstuv",
        "us-east-1:control-a",
        "control-a",
        "us-east-1",
        "us-east-1",
        "worker:east-peer-b",
        "worker",
        Some("east-peer-b"),
        &["control", "edge"],
        seeded_at - time::Duration::seconds(2),
    );
    let east_older_history = runtime_tombstone_history_record(
        "aud_cdefghijklmnopqrstuvw",
        "us-east-1:control-a",
        "control-a",
        "us-east-1",
        "us-east-1",
        "worker:east-peer-a",
        "worker",
        Some("east-peer-a"),
        &["control"],
        seeded_at - time::Duration::seconds(3),
    );
    let west_history = runtime_tombstone_history_record(
        "aud_defghijklmnopqrstuvwx",
        "us-west-2:control-b",
        "control-b",
        "us-west-2",
        "us-west-2",
        "node_adjacent:west-peer-node",
        "node_adjacent",
        Some("west-peer-node"),
        &["uvm"],
        seeded_at - time::Duration::seconds(4),
    );
    seed_runtime_tombstone_history_records(
        &state_dir,
        &[
            local_history.clone(),
            east_newer_history.clone(),
            east_older_history.clone(),
            west_history.clone(),
        ],
    );
    seed_runtime_outbox_entries(
        &state_dir,
        &[
            runtime_tombstone_outbox_envelope(
                &local_history,
                "relay-local",
                DeliveryState::Delivered {
                    delivered_at: local_history.tombstoned_at + time::Duration::seconds(1),
                },
                RelayStatus {
                    backend: String::from("local_file"),
                    attempts: 1,
                    last_attempt_at: Some(local_history.tombstoned_at + time::Duration::seconds(1)),
                    delivered_at: Some(local_history.tombstoned_at + time::Duration::seconds(1)),
                    last_error: None,
                    next_retry_at: None,
                    replay_count: 0,
                    last_replayed_at: None,
                    last_replay_reason: None,
                },
                local_history.tombstoned_at + time::Duration::seconds(1),
            ),
            runtime_tombstone_outbox_envelope(
                &east_newer_history,
                "relay-east-newer",
                DeliveryState::Pending,
                RelayStatus {
                    backend: String::from("local_file"),
                    attempts: 2,
                    last_attempt_at: Some(
                        east_newer_history.tombstoned_at + time::Duration::seconds(2),
                    ),
                    delivered_at: None,
                    last_error: None,
                    next_retry_at: None,
                    replay_count: 2,
                    last_replayed_at: Some(
                        east_newer_history.tombstoned_at + time::Duration::seconds(3),
                    ),
                    last_replay_reason: Some(String::from("operator replay")),
                },
                east_newer_history.tombstoned_at + time::Duration::seconds(3),
            ),
            runtime_tombstone_outbox_envelope(
                &east_older_history,
                "relay-east-older",
                DeliveryState::Delivered {
                    delivered_at: east_older_history.tombstoned_at + time::Duration::seconds(1),
                },
                RelayStatus {
                    backend: String::from("local_file"),
                    attempts: 1,
                    last_attempt_at: Some(
                        east_older_history.tombstoned_at + time::Duration::seconds(1),
                    ),
                    delivered_at: Some(
                        east_older_history.tombstoned_at + time::Duration::seconds(1),
                    ),
                    last_error: None,
                    next_retry_at: None,
                    replay_count: 0,
                    last_replayed_at: None,
                    last_replay_reason: None,
                },
                east_older_history.tombstoned_at + time::Duration::seconds(1),
            ),
            runtime_tombstone_outbox_envelope(
                &west_history,
                "relay-west",
                DeliveryState::Failed {
                    attempts: 3,
                    last_error: String::from("transport outage"),
                    next_retry_at: west_history.tombstoned_at + time::Duration::seconds(60),
                },
                RelayStatus {
                    backend: String::from("local_file"),
                    attempts: 3,
                    last_attempt_at: Some(west_history.tombstoned_at + time::Duration::seconds(5)),
                    delivered_at: None,
                    last_error: Some(String::from("transport outage")),
                    next_retry_at: Some(west_history.tombstoned_at + time::Duration::seconds(60)),
                    replay_count: 1,
                    last_replayed_at: Some(west_history.tombstoned_at + time::Duration::seconds(4)),
                    last_replay_reason: Some(String::from("regional replay")),
                },
                west_history.tombstoned_at + time::Duration::seconds(5),
            ),
        ],
    );

    let _guard = spawn_uhostd(&config_path, address);

    let missing = request(
        address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated",
        None,
        None,
    );
    assert_eq!(missing.status, 401);

    let first_page = request_json(
        address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated?limit=2",
        None,
        Some(token),
    );
    let first_items = first_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing first aggregated tombstone history page items"));
    assert_eq!(first_items.len(), 2);
    assert_eq!(
        first_items[0]["history"]["event_id"],
        json!(local_history.event_id.clone())
    );
    assert_eq!(
        first_items[0]["relay_evidence"]["message_id"],
        json!("relay-local")
    );
    assert_eq!(
        first_items[0]["relay_evidence"]["delivery_state"],
        json!("delivered")
    );
    assert_eq!(
        first_items[1]["history"]["event_id"],
        json!(east_newer_history.event_id.clone())
    );
    assert_eq!(first_items[1]["history"]["region_id"], json!("us-east-1"));
    assert_eq!(first_items[1]["relay_evidence"]["replay_count"], json!(2));
    assert_eq!(
        first_items[1]["relay_evidence"]["last_replay_reason"],
        json!("operator replay")
    );
    assert_eq!(
        first_items[1]["relay_evidence"]["idempotency_key"],
        json!(east_newer_history.event_id.clone())
    );
    assert_eq!(first_page["retention"]["retained_entries"], json!(4));

    let next_cursor = first_page
        .get("next_cursor")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing aggregated tombstone history cursor"));
    let second_page = request_json(
        address,
        "GET",
        format!("/runtime/participants/tombstone-history/aggregated?limit=2&cursor={next_cursor}")
            .as_str(),
        None,
        Some(token),
    );
    let second_items = second_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing second aggregated tombstone history page items"));
    assert_eq!(second_items.len(), 2);
    assert_eq!(
        second_items[0]["history"]["event_id"],
        json!(east_older_history.event_id.clone())
    );
    assert_eq!(
        second_items[1]["history"]["event_id"],
        json!(west_history.event_id.clone())
    );
    assert_eq!(
        second_items[1]["relay_evidence"]["delivery_state"],
        json!("failed")
    );
    assert_eq!(
        second_items[1]["relay_evidence"]["last_error"],
        json!("transport outage")
    );
    assert!(second_page.get("next_cursor").is_none());

    let east_first = request_json(
        address,
        "GET",
        "/runtime/participants/tombstone-history/aggregated?region_id=us-east-1&limit=1",
        None,
        Some(token),
    );
    let east_first_items = east_first["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing filtered aggregated history page items"));
    assert_eq!(east_first_items.len(), 1);
    assert_eq!(
        east_first_items[0]["history"]["event_id"],
        json!(east_newer_history.event_id.clone())
    );
    let east_next_cursor = east_first
        .get("next_cursor")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing filtered aggregated tombstone history cursor"));
    let east_second = request_json(
        address,
        "GET",
        format!(
            "/runtime/participants/tombstone-history/aggregated?region_id=us-east-1&limit=1&cursor={east_next_cursor}"
        )
        .as_str(),
        None,
        Some(token),
    );
    let east_second_items = east_second["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing second filtered aggregated history page items"));
    assert_eq!(east_second_items.len(), 1);
    assert_eq!(
        east_second_items[0]["history"]["event_id"],
        json!(east_older_history.event_id.clone())
    );
    assert!(east_second.get("next_cursor").is_none());

    let cleanup_filtered = request_json(
        address,
        "GET",
        format!(
            "/runtime/participants/tombstone-history/aggregated?cleanup_workflow_id={}",
            east_older_history.cleanup_workflow_id
        )
        .as_str(),
        None,
        Some(token),
    );
    let cleanup_items = cleanup_filtered["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing cleanup filtered aggregated items"));
    assert_eq!(cleanup_items.len(), 1);
    assert_eq!(
        cleanup_items[0]["history"]["participant_registration_id"],
        json!(east_older_history.participant_registration_id.clone())
    );
}

#[test]
fn workload_identity_bearer_token_admits_workload_safe_tenant_route_and_keeps_operator_surface_protected()
 {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping workload_identity_bearer_token_admits_workload_safe_tenant_route_and_keeps_operator_surface_protected: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let workload_token =
        issue_workload_identity(address, token, "svc:build-runner", &["identity"], 900);
    let identity_root =
        request_json_with_bearer_token(address, "GET", "/identity", None, &workload_token);
    assert_eq!(identity_root["service"], "identity");

    let metrics = request_with_bearer_token(address, "GET", "/metrics", None, &workload_token);
    assert_eq!(metrics.status, 401);
}

#[test]
fn abuse_remediation_routes_require_operator_principal_in_runtime_catalog() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_remediation_routes_require_operator_principal_in_runtime_catalog: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let abuse_token = issue_workload_identity(address, token, "svc:abuse-runner", &["abuse"], 900);
    let abuse_root = request_json_with_bearer_token(address, "GET", "/abuse", None, &abuse_token);
    assert_eq!(abuse_root["service"], "abuse");

    let create_case_body = serde_json::to_vec(&json!({
        "subject_kind": "service_identity",
        "subject": "svc:abuse-runtime-auth",
        "reason": "runtime remediation auth regression",
        "priority": "high",
        "signal_ids": [],
        "evidence_refs": [],
    }))
    .unwrap_or_else(|error| panic!("failed to serialize abuse case request: {error}"));
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(("application/json", create_case_body.as_slice())),
        Some(token),
    );
    let abuse_case_id = abuse_case["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing abuse case id"))
        .to_owned();

    let denied_list = request_with_bearer_token(
        address,
        "GET",
        "/abuse/remediation-cases",
        None,
        &abuse_token,
    );
    assert_eq!(denied_list.status, 403);
    let denied_list_payload: Value = serde_json::from_slice(&denied_list.body)
        .unwrap_or_else(|error| panic!("invalid denied remediation list response: {error}"));
    assert_eq!(
        denied_list_payload["error"]["message"],
        json!("route request class `operator_read` requires operator principal")
    );

    let remediation_case_body = serde_json::to_vec(&json!({
        "tenant_subject": "tenant.runtime-auth",
        "reason": "manual remediation required",
        "rollback_evidence_refs": ["runbook:runtime-auth-rollback"],
        "verification_evidence_refs": ["checklist:runtime-auth-verify"],
        "abuse_case_ids": [abuse_case_id.clone()],
        "quarantine_ids": [],
        "change_request_ids": [],
        "notify_message_ids": [],
    }))
    .unwrap_or_else(|error| panic!("failed to serialize remediation case request: {error}"));
    let denied_create = request_with_bearer_token(
        address,
        "POST",
        "/abuse/remediation-cases",
        Some(("application/json", remediation_case_body.as_slice())),
        &abuse_token,
    );
    assert_eq!(denied_create.status, 403);
    let denied_create_payload: Value = serde_json::from_slice(&denied_create.body)
        .unwrap_or_else(|error| panic!("invalid denied remediation create response: {error}"));
    assert_eq!(
        denied_create_payload["error"]["message"],
        json!("route request class `operator_mutate` requires operator principal")
    );

    let remediation_case = request_json(
        address,
        "POST",
        "/abuse/remediation-cases",
        Some(("application/json", remediation_case_body.as_slice())),
        Some(token),
    );
    let remediation_case_id = remediation_case["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing remediation case id"))
        .to_owned();

    let detail_path = format!("/abuse/remediation-cases/{remediation_case_id}");
    let denied_detail =
        request_with_bearer_token(address, "GET", detail_path.as_str(), None, &abuse_token);
    assert_eq!(denied_detail.status, 403);
    let denied_detail_payload: Value = serde_json::from_slice(&denied_detail.body)
        .unwrap_or_else(|error| panic!("invalid denied remediation detail response: {error}"));
    assert_eq!(
        denied_detail_payload["error"]["message"],
        json!("route request class `operator_read` requires operator principal")
    );

    let listed = request_json(
        address,
        "GET",
        "/abuse/remediation-cases",
        None,
        Some(token),
    );
    let listed_items = listed
        .as_array()
        .unwrap_or_else(|| panic!("missing remediation case list"));
    assert_eq!(listed_items.len(), 1);
    assert_eq!(listed_items[0]["id"], json!(remediation_case_id.clone()));

    let detail = request_json(address, "GET", detail_path.as_str(), None, Some(token));
    assert_eq!(detail["id"], json!(remediation_case_id));
    assert_eq!(detail["tenant_subject"], json!("tenant.runtime-auth"));
    assert_eq!(detail["abuse_case_ids"], json!([abuse_case_id]));
}

#[test]
fn api_key_bearer_token_admits_non_workload_control_plane_paths_but_not_identity_admin_or_operator_routes()
 {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping api_key_bearer_token_admits_non_workload_control_plane_paths_but_not_identity_admin_or_operator_routes: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let created_user = request_json(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"human@example.com","display_name":"Human","password":"correct horse battery staple"}"#,
        )),
        Some(token),
    );
    let user_id = created_user["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created user id"))
        .to_owned();
    let create_api_key_body = format!(r#"{{"user_id":"{user_id}","name":"human-cli"}}"#);

    let created_api_key = request_json(
        address,
        "POST",
        "/identity/api-keys",
        Some(("application/json", create_api_key_body.as_bytes())),
        Some(token),
    );
    let api_key_secret = created_api_key["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing api key secret"))
        .to_owned();

    let governance_root =
        request_json_with_bearer_token(address, "GET", "/governance", None, &api_key_secret);
    assert_eq!(governance_root["service"], "governance");

    let secrets_root =
        request_json_with_bearer_token(address, "GET", "/secrets", None, &api_key_secret);
    assert_eq!(secrets_root["service"], "secrets");

    let created_policy = request_with_bearer_token(
        address,
        "POST",
        "/policy/policies",
        Some((
            "application/json",
            br#"{"resource_kind":"service","action":"deploy","effect":"allow","selector":{"env":"prod"}}"#,
        )),
        &api_key_secret,
    );
    assert_eq!(created_policy.status, 201);

    let identity_admin = request_with_bearer_token(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"forbidden@example.com","display_name":"Forbidden","password":"correct horse battery staple"}"#,
        )),
        &api_key_secret,
    );
    assert_eq!(identity_admin.status, 403);

    let metrics = request_with_bearer_token(address, "GET", "/metrics", None, &api_key_secret);
    assert_eq!(metrics.status, 401);
}

#[test]
fn api_key_rotate_and_revoke_cutover_updates_real_runtime_authorization() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping api_key_rotate_and_revoke_cutover_updates_real_runtime_authorization: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let created_user = request_json(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"rotate-human@example.com","display_name":"Rotate Human","password":"correct horse battery staple"}"#,
        )),
        Some(token),
    );
    let user_id = created_user["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created user id"))
        .to_owned();
    let create_api_key_body = format!(r#"{{"user_id":"{user_id}","name":"rotating-cli"}}"#);

    let created_api_key = request_json(
        address,
        "POST",
        "/identity/api-keys",
        Some(("application/json", create_api_key_body.as_bytes())),
        Some(token),
    );
    let api_key_id = created_api_key["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created api key id"))
        .to_owned();
    let issued_secret = created_api_key["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued api key secret"))
        .to_owned();

    let initial_governance =
        request_json_with_bearer_token(address, "GET", "/governance", None, &issued_secret);
    assert_eq!(initial_governance["service"], "governance");

    let rotated_api_key = request_json(
        address,
        "POST",
        format!("/identity/api-keys/{api_key_id}/rotate").as_str(),
        None,
        Some(token),
    );
    assert_eq!(rotated_api_key["version"], json!(2));
    assert_eq!(rotated_api_key["active"], json!(true));
    let rotated_secret = rotated_api_key["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rotated api key secret"))
        .to_owned();
    assert_ne!(rotated_secret, issued_secret);

    let stale_governance =
        request_with_bearer_token(address, "GET", "/governance", None, &issued_secret);
    assert_eq!(stale_governance.status, 401);

    let fresh_governance =
        request_json_with_bearer_token(address, "GET", "/governance", None, &rotated_secret);
    assert_eq!(fresh_governance["service"], "governance");

    let lifecycle_after_rotate = request_json(
        address,
        "GET",
        "/identity/credential-lifecycle",
        None,
        Some(token),
    );
    let api_key_secret_entries = lifecycle_after_rotate["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
        .iter()
        .filter(|entry| {
            entry["kind"] == json!("secret_version")
                && entry["source_id"] == json!(api_key_id.clone())
                && entry["source_kind"] == json!("api_key")
        })
        .collect::<Vec<_>>();
    assert_eq!(api_key_secret_entries.len(), 2);
    assert!(api_key_secret_entries.iter().any(|entry| {
        entry["version"] == json!(1)
            && entry["state"] == json!("revoked")
            && entry["principal_subject"] == json!(format!("user:{user_id}"))
    }));
    assert!(api_key_secret_entries.iter().any(|entry| {
        entry["version"] == json!(2)
            && entry["state"] == json!("active")
            && entry["principal_subject"] == json!(format!("user:{user_id}"))
    }));

    let revoked_api_key = request_json(
        address,
        "POST",
        format!("/identity/api-keys/{api_key_id}/revoke").as_str(),
        None,
        Some(token),
    );
    assert_eq!(revoked_api_key["active"], json!(false));
    assert_eq!(revoked_api_key["metadata"]["lifecycle"], json!("deleted"));

    let revoked_governance =
        request_with_bearer_token(address, "GET", "/governance", None, &rotated_secret);
    assert_eq!(revoked_governance.status, 401);

    let lifecycle_after_revoke = request_json(
        address,
        "GET",
        "/identity/credential-lifecycle",
        None,
        Some(token),
    );
    let api_key_entry = lifecycle_after_revoke["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
        .iter()
        .find(|entry| entry["kind"] == json!("api_key") && entry["id"] == json!(api_key_id.clone()))
        .unwrap_or_else(|| panic!("missing api key lifecycle entry"));
    assert_eq!(api_key_entry["state"], json!("revoked"));
    assert!(
        lifecycle_after_revoke["entries"]
            .as_array()
            .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
            .iter()
            .filter(|entry| entry["source_id"] == json!(api_key_id.clone()))
            .all(|entry| entry["state"] == json!("revoked"))
    );
}

#[test]
fn backup_storage_lineage_surface_requires_operator_principal_and_preserves_backup_restore_flows() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping backup_storage_lineage_surface_requires_operator_principal_and_preserves_backup_restore_flows: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let workload_token = issue_workload_identity(address, token, "svc:data-runner", &["data"], 900);
    let create_database_body = serde_json::to_vec(&json!({
        "engine": "postgres",
        "version": "16.4",
        "storage_gb": 64,
        "replicas": 2,
        "tls_required": true,
        "tags": {},
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create database request: {error}"));
    let created_database = request_json_with_bearer_token(
        address,
        "POST",
        "/data/databases",
        Some(("application/json", create_database_body.as_slice())),
        &workload_token,
    );
    let database_id = created_database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created database id"))
        .to_owned();

    let create_backup_body = serde_json::to_vec(&json!({
        "kind": "full",
        "reason": "backup lineage auth regression",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create backup request: {error}"));
    let backup = request_json_with_bearer_token(
        address,
        "POST",
        format!("/data/databases/{database_id}/backups").as_str(),
        Some(("application/json", create_backup_body.as_slice())),
        &workload_token,
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"))
        .to_owned();
    assert_eq!(
        backup["storage_recovery_point_selection_reason"],
        json!(
            "backup recorded the ready storage recovery point that was current when the backup completed"
        )
    );
    assert_eq!(
        backup["storage_recovery_point_state_reason"],
        json!(
            "persisted backup storage recovery point still matches the current ready storage recovery point"
        )
    );
    let lineage_path = format!("/data/backups/{backup_id}/storage-lineage");

    let denied =
        request_with_bearer_token(address, "GET", lineage_path.as_str(), None, &workload_token);
    assert_eq!(denied.status, 403);
    let denied_payload: Value = serde_json::from_slice(&denied.body)
        .unwrap_or_else(|error| panic!("invalid denied backup-lineage response: {error}"));
    assert_eq!(
        denied_payload["error"]["message"],
        json!("route request class `operator_read` requires operator principal")
    );

    let lineage = request_json(address, "GET", lineage_path.as_str(), None, Some(token));
    assert_eq!(lineage["backup_id"], json!(backup_id));
    assert_eq!(
        lineage["storage_volume_id"],
        backup["storage_recovery_point"]["volume_id"]
    );
    assert_eq!(lineage["recovery_point"], backup["storage_recovery_point"]);
    assert_eq!(
        lineage["selection_reason"],
        backup["storage_recovery_point_selection_reason"]
    );
    assert_eq!(
        lineage["recovery_point_state_reason"],
        json!(
            "persisted backup storage recovery point still matches the current ready storage recovery point"
        )
    );

    let restore_body = serde_json::to_vec(&json!({
        "backup_id": backup_id,
        "reason": "backup lineage auth regression",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize restore request: {error}"));
    let restored = request_json_with_bearer_token(
        address,
        "POST",
        format!("/data/databases/{database_id}/restore").as_str(),
        Some(("application/json", restore_body.as_slice())),
        &workload_token,
    );
    assert_eq!(restored["state"], json!("completed"));
    assert_eq!(
        restored["storage_restore_selected_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        restored["storage_restore_backup_correlated_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        restored["storage_restore_source_mode"],
        json!("backup_correlated_storage_lineage")
    );
    assert_eq!(
        restored["storage_restore_selection_reason"],
        json!(
            "selected backup-correlated storage recovery point recorded by the originating backup"
        )
    );
    assert_eq!(
        restored["storage_restore_selected_recovery_point_state_reason"],
        json!(
            "persisted restore-selected storage recovery point still matches the current ready storage recovery point"
        )
    );
    assert!(
        restored.get("storage_restore").is_none(),
        "restore response should not expose internal storage lineage"
    );
}

#[test]
fn restore_storage_lineage_surface_requires_operator_principal_and_preserves_tenant_restore_flow() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping restore_storage_lineage_surface_requires_operator_principal_and_preserves_tenant_restore_flow: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let workload_token = issue_workload_identity(address, token, "svc:data-runner", &["data"], 900);
    let create_database_body = serde_json::to_vec(&json!({
        "engine": "postgres",
        "version": "16.4",
        "storage_gb": 64,
        "replicas": 2,
        "tls_required": true,
        "tags": {},
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create database request: {error}"));
    let created_database = request_json_with_bearer_token(
        address,
        "POST",
        "/data/databases",
        Some(("application/json", create_database_body.as_slice())),
        &workload_token,
    );
    let database_id = created_database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created database id"))
        .to_owned();

    let create_backup_body = serde_json::to_vec(&json!({
        "kind": "full",
        "reason": "tenant restore auth regression",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create backup request: {error}"));
    let backup = request_json_with_bearer_token(
        address,
        "POST",
        format!("/data/databases/{database_id}/backups").as_str(),
        Some(("application/json", create_backup_body.as_slice())),
        &workload_token,
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"))
        .to_owned();

    let restore_body = serde_json::to_vec(&json!({
        "backup_id": backup_id,
        "reason": "tenant restore auth regression",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize restore request: {error}"));
    let restored = request_json_with_bearer_token(
        address,
        "POST",
        format!("/data/databases/{database_id}/restore").as_str(),
        Some(("application/json", restore_body.as_slice())),
        &workload_token,
    );
    assert_eq!(restored["state"], json!("completed"));
    assert_eq!(
        restored["storage_restore_selected_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        restored["storage_restore_backup_correlated_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        restored["storage_restore_source_mode"],
        json!("backup_correlated_storage_lineage")
    );
    assert_eq!(
        restored["storage_restore_selection_reason"],
        json!(
            "selected backup-correlated storage recovery point recorded by the originating backup"
        )
    );
    assert_eq!(
        restored["storage_restore_selected_recovery_point_state_reason"],
        json!(
            "persisted restore-selected storage recovery point still matches the current ready storage recovery point"
        )
    );
    assert!(
        restored.get("storage_restore").is_none(),
        "restore response should not expose internal storage lineage"
    );
    let restore_id = restored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore id"))
        .to_owned();
    let lineage_path = format!("/data/restores/{restore_id}/storage-lineage");

    let denied =
        request_with_bearer_token(address, "GET", lineage_path.as_str(), None, &workload_token);
    assert_eq!(denied.status, 403);
    let denied_payload: Value = serde_json::from_slice(&denied.body)
        .unwrap_or_else(|error| panic!("invalid denied restore-lineage response: {error}"));
    assert_eq!(
        denied_payload["error"]["message"],
        json!("route request class `operator_read` requires operator principal")
    );

    let lineage = request_json(address, "GET", lineage_path.as_str(), None, Some(token));
    assert_eq!(lineage["restore_id"], json!(restore_id));
    assert_eq!(
        lineage["source_mode"],
        json!("backup_correlated_storage_lineage")
    );
    assert_eq!(
        lineage["storage_volume_id"],
        backup["storage_recovery_point"]["volume_id"]
    );
    assert_eq!(
        lineage["selected_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        lineage["backup_correlated_recovery_point"],
        backup["storage_recovery_point"]
    );
    assert_eq!(
        lineage["selection_reason"],
        json!(
            "selected backup-correlated storage recovery point recorded by the originating backup"
        )
    );
    assert_eq!(
        lineage["selected_recovery_point_state_reason"],
        json!(
            "persisted restore-selected storage recovery point still matches the current ready storage recovery point"
        )
    );
    assert!(
        !lineage["restore_action_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "restore lineage should project the linked storage restore action id"
    );
    assert!(
        !lineage["restore_workflow_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "restore lineage should project the linked storage restore workflow id"
    );
}

#[test]
fn operator_restore_storage_lineage_surface_projects_latest_ready_fallback_restores() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping operator_restore_storage_lineage_surface_projects_latest_ready_fallback_restores: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let guard = spawn_uhostd(&config_path, address);

    let create_database_body = serde_json::to_vec(&json!({
        "engine": "postgres",
        "version": "16.3",
        "storage_gb": 72,
        "replicas": 2,
        "tls_required": true,
        "tags": {},
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create database request: {error}"));
    let created_database = request_json(
        address,
        "POST",
        "/data/databases",
        Some(("application/json", create_database_body.as_slice())),
        Some(token),
    );
    let database_id = created_database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created database id"))
        .to_owned();

    let create_backup_body = serde_json::to_vec(&json!({
        "kind": "full",
        "reason": "fallback restore lineage check",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize create backup request: {error}"));
    let backup = request_json(
        address,
        "POST",
        format!("/data/databases/{database_id}/backups").as_str(),
        Some(("application/json", create_backup_body.as_slice())),
        Some(token),
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"))
        .to_owned();
    let backup_storage_recovery_point = backup["storage_recovery_point"].clone();
    let volume_id = backup_storage_recovery_point["volume_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup storage recovery point volume id"))
        .to_owned();
    let initial_version = backup_storage_recovery_point["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing backup storage recovery point version"));

    drop(guard);
    advance_persisted_volume_recovery_point(&state_dir, &volume_id);
    let latest_recovery_point = read_storage_recovery_point(&state_dir, &volume_id);
    remove_persisted_volume_recovery_point_revision(&state_dir, &volume_id, initial_version);
    let _guard = spawn_uhostd(&config_path, address);

    let restore_body = serde_json::to_vec(&json!({
        "backup_id": backup_id,
        "reason": "fallback restore lineage check",
    }))
    .unwrap_or_else(|error| panic!("failed to serialize restore request: {error}"));
    let restored = request_json(
        address,
        "POST",
        format!("/data/databases/{database_id}/restore").as_str(),
        Some(("application/json", restore_body.as_slice())),
        Some(token),
    );
    assert_eq!(restored["state"], json!("completed"));
    assert_eq!(
        restored["storage_restore_selected_recovery_point"],
        latest_recovery_point.clone()
    );
    assert_eq!(
        restored["storage_restore_backup_correlated_recovery_point"],
        backup_storage_recovery_point.clone()
    );
    assert_eq!(
        restored["storage_restore_source_mode"],
        json!("latest_ready_fallback")
    );
    assert_eq!(
        restored["storage_restore_selection_reason"],
        json!(
            "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point"
        )
    );
    assert_eq!(
        restored["storage_restore_selected_recovery_point_state_reason"],
        json!(
            "persisted restore-selected storage recovery point still matches the current ready storage recovery point"
        )
    );
    assert!(
        restored.get("storage_restore").is_none(),
        "restore response should not expose internal storage lineage"
    );
    let restore_id = restored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore id"))
        .to_owned();
    let lineage = request_json(
        address,
        "GET",
        format!("/data/restores/{restore_id}/storage-lineage").as_str(),
        None,
        Some(token),
    );

    assert_eq!(lineage["restore_id"], json!(restore_id));
    assert_eq!(lineage["source_mode"], json!("latest_ready_fallback"));
    assert_eq!(lineage["storage_volume_id"], json!(volume_id));
    assert_eq!(
        lineage["backup_correlated_recovery_point"],
        backup_storage_recovery_point
    );
    assert_eq!(
        lineage["selected_recovery_point"]["version"],
        latest_recovery_point["version"]
    );
    assert_eq!(
        lineage["selected_recovery_point"]["execution_count"],
        latest_recovery_point["execution_count"]
    );
    assert_eq!(
        lineage["selected_recovery_point"]["etag"],
        latest_recovery_point["etag"]
    );
    assert_eq!(
        lineage["selected_recovery_point"]["captured_at"],
        latest_recovery_point["captured_at"]
    );
    assert_eq!(
        lineage["selection_reason"],
        json!(
            "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point"
        )
    );
    assert_eq!(
        lineage["selected_recovery_point_state_reason"],
        json!(
            "persisted restore-selected storage recovery point still matches the current ready storage recovery point"
        )
    );
    assert_ne!(
        lineage["selected_recovery_point"]["version"],
        lineage["backup_correlated_recovery_point"]["version"]
    );
    assert_ne!(
        lineage["selected_recovery_point"]["etag"],
        lineage["backup_correlated_recovery_point"]["etag"]
    );
}

#[test]
fn uvm_preflight_evidence_artifacts_surface_requires_operator_token() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping uvm_preflight_evidence_artifacts_surface_requires_operator_token: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let missing = request(
        address,
        "GET",
        "/uvm/preflight-evidence-artifacts",
        None,
        None,
    );
    assert_eq!(missing.status, 401);

    let uvm_token = issue_workload_identity(
        address,
        token,
        "svc:uvm-observe-runner",
        &["uvm-observe"],
        900,
    );
    let denied = request_with_bearer_token(
        address,
        "GET",
        "/uvm/preflight-evidence-artifacts",
        None,
        &uvm_token,
    );
    assert_eq!(denied.status, 401);

    let artifacts = request_json(
        address,
        "GET",
        "/uvm/preflight-evidence-artifacts",
        None,
        Some(token),
    );
    assert!(
        artifacts.is_array(),
        "operator token should receive a preflight evidence artifact list"
    );
}

#[test]
fn workload_identity_bearer_token_rejects_malformed_and_audience_mismatched_requests() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping workload_identity_bearer_token_rejects_malformed_and_audience_mismatched_requests: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let secrets_only_token =
        issue_workload_identity(address, token, "svc:secrets-runner", &["secrets"], 900);
    let mismatched =
        request_with_bearer_token(address, "GET", "/identity", None, &secrets_only_token);
    assert_eq!(mismatched.status, 401);

    let malformed = request_with_bearer_token(
        address,
        "GET",
        "/identity",
        None,
        "not-a-real-workload-token",
    );
    assert_eq!(malformed.status, 401);
}

#[test]
fn workload_identity_rotate_and_revoke_cutover_updates_real_runtime_authorization() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping workload_identity_rotate_and_revoke_cutover_updates_real_runtime_authorization: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let issued_identity =
        issue_workload_identity_payload(address, token, "svc:build-rotate", &["identity"], 900);
    let workload_identity_id = issued_identity["identity"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload identity id"))
        .to_owned();
    let issued_token = issued_identity["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned();

    let initial_identity_root =
        request_json_with_bearer_token(address, "GET", "/identity", None, &issued_token);
    assert_eq!(initial_identity_root["service"], "identity");

    let rotated_identity = request_json(
        address,
        "POST",
        format!("/identity/workload-identities/{workload_identity_id}/rotate").as_str(),
        None,
        Some(token),
    );
    assert_eq!(
        rotated_identity["identity"]["credential"]["version"],
        json!(2)
    );
    let rotated_token = rotated_identity["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rotated workload token"))
        .to_owned();
    assert_ne!(rotated_token, issued_token);

    let stale_identity_root =
        request_with_bearer_token(address, "GET", "/identity", None, &issued_token);
    assert_eq!(stale_identity_root.status, 401);

    let fresh_identity_root =
        request_json_with_bearer_token(address, "GET", "/identity", None, &rotated_token);
    assert_eq!(fresh_identity_root["service"], "identity");

    let lifecycle_after_rotate = request_json(
        address,
        "GET",
        "/identity/credential-lifecycle",
        None,
        Some(token),
    );
    let workload_secret_entries = lifecycle_after_rotate["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
        .iter()
        .filter(|entry| {
            entry["kind"] == json!("secret_version")
                && entry["source_id"] == json!(workload_identity_id.clone())
                && entry["source_kind"] == json!("workload_token")
        })
        .collect::<Vec<_>>();
    assert_eq!(workload_secret_entries.len(), 2);
    assert!(workload_secret_entries.iter().any(|entry| {
        entry["version"] == json!(1)
            && entry["state"] == json!("revoked")
            && entry["principal_subject"] == json!("svc:build-rotate")
    }));
    assert!(workload_secret_entries.iter().any(|entry| {
        entry["version"] == json!(2)
            && entry["state"] == json!("active")
            && entry["principal_subject"] == json!("svc:build-rotate")
    }));

    let revoked_identity = request_json(
        address,
        "POST",
        format!("/identity/workload-identities/{workload_identity_id}/revoke").as_str(),
        None,
        Some(token),
    );
    assert_eq!(revoked_identity["active"], json!(false));
    assert_eq!(revoked_identity["metadata"]["lifecycle"], json!("deleted"));

    let revoked_identity_root =
        request_with_bearer_token(address, "GET", "/identity", None, &rotated_token);
    assert_eq!(revoked_identity_root.status, 401);

    let lifecycle_after_revoke = request_json(
        address,
        "GET",
        "/identity/credential-lifecycle",
        None,
        Some(token),
    );
    let workload_entry = lifecycle_after_revoke["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
        .iter()
        .find(|entry| {
            entry["kind"] == json!("workload_token")
                && entry["id"] == json!(workload_identity_id.clone())
        })
        .unwrap_or_else(|| panic!("missing workload lifecycle entry"));
    assert_eq!(workload_entry["state"], json!("revoked"));
    assert!(
        lifecycle_after_revoke["entries"]
            .as_array()
            .unwrap_or_else(|| panic!("missing credential lifecycle entries"))
            .iter()
            .filter(|entry| entry["source_id"] == json!(workload_identity_id.clone()))
            .all(|entry| entry["state"] == json!("revoked"))
    );
}

#[test]
fn internal_runtime_routes_require_runtime_audience_service_identity() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping internal_runtime_routes_require_runtime_audience_service_identity: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let missing = request(address, "GET", "/internal/runtime/routes", None, None);
    assert_eq!(missing.status, 401);

    let bootstrap = request(
        address,
        "GET",
        "/internal/runtime/routes",
        None,
        Some(token),
    );
    assert_eq!(bootstrap.status, 401);

    let wrong_audience =
        issue_workload_identity(address, token, "svc:identity-peer", &["identity"], 900);
    let wrong_audience_response = request_with_bearer_token(
        address,
        "GET",
        "/internal/runtime/routes",
        None,
        &wrong_audience,
    );
    assert_eq!(wrong_audience_response.status, 401);

    let runtime_token =
        issue_workload_identity(address, token, "svc:runtime-peer", &["runtime"], 900);
    let routes = request_json_with_bearer_token(
        address,
        "GET",
        "/internal/runtime/routes",
        None,
        &runtime_token,
    );
    assert_eq!(routes["service"], "runtime-internal");
    let bindings = routes["bindings"]
        .as_array()
        .unwrap_or_else(|| panic!("missing internal runtime route bindings"));
    assert!(
        bindings.iter().any(|binding| {
            binding["claim"] == "/internal/runtime/routes"
                && binding["match_kind"] == "exact"
                && binding["method_match"] == "any"
                && binding["request_class"] == "read"
                && binding["audience"] == "runtime"
        }),
        "internal runtime route catalog should advertise the routes endpoint"
    );
    assert!(
        bindings.iter().any(|binding| {
            binding["claim"] == "/internal/runtime/topology"
                && binding["match_kind"] == "exact"
                && binding["method_match"] == "any"
                && binding["request_class"] == "read"
                && binding["audience"] == "runtime"
        }),
        "internal runtime route catalog should advertise the topology endpoint"
    );

    let topology = request_json_with_bearer_token(
        address,
        "GET",
        "/internal/runtime/topology",
        None,
        &runtime_token,
    );
    assert_eq!(topology["process_role"], "all_in_one");
    assert_eq!(topology["node_name"], "auth-gate-test-node");
}

#[test]
fn workload_identity_bearer_token_cannot_use_operator_bound_service_paths() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping workload_identity_bearer_token_cannot_use_operator_bound_service_paths: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let operatorish_token = issue_workload_identity(
        address,
        token,
        "svc:ops-bot",
        &["policy", "governance", "secrets"],
        900,
    );

    let policy_mutation = request_with_bearer_token(
        address,
        "POST",
        "/policy/policies",
        Some((
            "application/json",
            br#"{"resource_kind":"service","action":"deploy","effect":"allow","selector":{"env":"prod"}}"#,
        )),
        &operatorish_token,
    );
    assert_eq!(policy_mutation.status, 403);

    let governance_root =
        request_with_bearer_token(address, "GET", "/governance", None, &operatorish_token);
    assert_eq!(governance_root.status, 403);

    let secrets_root =
        request_with_bearer_token(address, "GET", "/secrets", None, &operatorish_token);
    assert_eq!(secrets_root.status, 403);

    let policy_evaluation = request_json_with_bearer_token(
        address,
        "POST",
        "/policy/evaluate",
        Some((
            "application/json",
            br#"{"resource_kind":"service","action":"deploy","selector":{"env":"prod"}}"#,
        )),
        &operatorish_token,
    );
    assert_eq!(policy_evaluation["decision"], "deny");
}

#[test]
fn workload_identity_bearer_token_cannot_use_operator_bound_summary_paths() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping workload_identity_bearer_token_cannot_use_operator_bound_summary_paths: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

    let _guard = spawn_uhostd(&config_path, address);

    let operatorish_token = issue_workload_identity(
        address,
        token,
        "svc:ops-bot",
        &["policy", "governance", "secrets"],
        900,
    );

    let mut checked_routes = 0_u8;
    for path in ["/governance/summary", "/policy/summary", "/secrets/summary"] {
        let operator_allowed = request(address, "GET", path, None, Some(token));
        if operator_allowed.status == 404 {
            continue;
        }
        assert_eq!(
            operator_allowed.status, 200,
            "operator token should reach {path} when implemented"
        );
        let denied = request_with_bearer_token(address, "GET", path, None, &operatorish_token);
        assert_eq!(
            denied.status, 403,
            "workload identity token should be rejected for {path}"
        );
        checked_routes = checked_routes.saturating_add(1);
    }
    assert!(
        checked_routes > 0,
        "expected at least one implemented control-plane summary route"
    );
}

#[test]
fn loopback_all_in_one_without_bootstrap_token_uses_explicit_local_dev_service_access_only() {
    let _serial_guard = auth_gate_test_guard();
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping loopback_all_in_one_without_bootstrap_token_uses_explicit_local_dev_service_access_only: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir, None);

    let _guard = spawn_uhostd(&config_path, address);

    let health = request(address, "GET", "/healthz", None, None);
    assert_eq!(health.status, 200);

    let metrics = request(address, "GET", "/metrics", None, None);
    assert_eq!(metrics.status, 401);

    let identity = request_json(address, "GET", "/identity", None, None);
    assert_eq!(identity["service"], "identity");

    let created_user = request(
        address,
        "POST",
        "/identity/users",
        Some((
            "application/json",
            br#"{"email":"bob@example.com","display_name":"Bob","password":"correct horse battery staple"}"#,
        )),
        None,
    );
    assert_eq!(created_user.status, 201);
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path, token: Option<&str>) {
    write_test_config_with_forward_targets(path, address, state_dir, token, &BTreeMap::new());
}

fn write_test_config_with_forward_targets(
    path: &Path,
    address: SocketAddr,
    state_dir: &Path,
    token: Option<&str>,
    forward_targets: &BTreeMap<String, SocketAddr>,
) {
    let security = token.map_or_else(String::new, |token| {
        format!(
            r#"

[security]
bootstrap_admin_token = "{token}"
"#
        )
    });
    let runtime = if forward_targets.is_empty() {
        String::new()
    } else {
        let mut section = String::from("\n[runtime.forward_targets]\n");
        for (service_name, target) in forward_targets {
            section.push_str(format!("{service_name} = \"{target}\"\n").as_str());
        }
        section
    };
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "auth-gate-test-node"

[secrets]
master_key = "{}"
{}{}"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
        security,
        runtime,
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn seed_stale_peer_runtime_records(state_dir: &Path) {
    seed_stale_peer_runtime_records_with_cleanup_state(state_dir, false);
}

fn seed_tombstone_eligible_stale_peer_runtime_records(state_dir: &Path) {
    seed_stale_peer_runtime_records_with_cleanup_state(state_dir, true);
}

fn seed_runtime_tombstone_history_records(
    state_dir: &Path,
    records: &[ParticipantTombstoneHistoryRecord],
) {
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir)
        .unwrap_or_else(|error| panic!("failed to create runtime seed directory: {error}"));
    let mut history = DocumentCollection::default();
    for record in records.iter().cloned() {
        history.records.insert(
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
        runtime_dir.join("participant-tombstone-history.json"),
        serde_json::to_vec(&history).unwrap_or_else(|error| {
            panic!("failed to encode seeded runtime tombstone history store: {error}")
        }),
    )
    .unwrap_or_else(|error| {
        panic!("failed to write seeded runtime tombstone history store: {error}")
    });
}

fn seed_runtime_outbox_entries(state_dir: &Path, entries: &[EventRelayEnvelope<PlatformEvent>]) {
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir)
        .unwrap_or_else(|error| panic!("failed to create runtime outbox seed directory: {error}"));
    let mut outbox = DocumentCollection::default();
    for entry in entries.iter().cloned() {
        outbox.records.insert(
            entry.id.clone(),
            StoredDocument {
                version: 1,
                updated_at: entry.updated_at,
                deleted: false,
                value: entry,
            },
        );
    }
    fs::write(
        runtime_dir.join("outbox.json"),
        serde_json::to_vec(&outbox).unwrap_or_else(|error| {
            panic!("failed to encode seeded runtime outbox store: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write seeded runtime outbox store: {error}"));
}

fn runtime_tombstone_history_record(
    event_id: &str,
    cell_id: &str,
    cell_name: &str,
    region_id: &str,
    region_name: &str,
    participant_registration_id: &str,
    participant_role: &str,
    node_name: Option<&str>,
    service_groups: &[&str],
    tombstoned_at: OffsetDateTime,
) -> ParticipantTombstoneHistoryRecord {
    let mut participant = CellParticipantRecord::new(
        participant_registration_id,
        "runtime_process",
        participant_registration_id,
        participant_role,
    )
    .with_service_groups(service_groups.iter().copied())
    .with_lease_registration_id(participant_registration_id);
    if let Some(node_name) = node_name {
        participant = participant.with_node_name(node_name);
    }
    ParticipantTombstoneHistoryRecord::new(
        event_id,
        &participant,
        stale_participant_cleanup_workflow_id(cell_id, participant_registration_id),
        tombstoned_at,
        "bootstrap_admin",
        "operator",
        format!("corr-{event_id}"),
    )
    .with_cell_context(
        cell_id,
        cell_name,
        &RegionDirectoryRecord::new(region_id, region_name),
    )
    .with_cleanup_review(
        3,
        tombstoned_at - time::Duration::seconds(30),
        Some(tombstoned_at - time::Duration::seconds(20)),
        Some(tombstoned_at - time::Duration::seconds(10)),
    )
    .with_mutation_result(true, true, true)
}

fn runtime_tombstone_outbox_envelope(
    history: &ParticipantTombstoneHistoryRecord,
    message_id: &str,
    state: DeliveryState,
    relay: RelayStatus,
    updated_at: OffsetDateTime,
) -> EventRelayEnvelope<PlatformEvent> {
    EventRelayEnvelope {
        id: String::from(message_id),
        topic: String::from("runtime.events.v1"),
        idempotency_key: Some(history.event_id.clone()),
        source_service: Some(String::from("runtime")),
        event_type: Some(String::from("runtime.participant.tombstoned.v1")),
        payload: PlatformEvent {
            header: EventHeader {
                event_id: AuditId::parse(history.event_id.clone()).unwrap_or_else(|error| {
                    panic!("invalid seeded runtime tombstone event id: {error}")
                }),
                event_type: String::from("runtime.participant.tombstoned.v1"),
                schema_version: 1,
                source_service: String::from("runtime"),
                emitted_at: history.tombstoned_at,
                actor: AuditActor {
                    subject: history.actor_subject.clone(),
                    actor_type: history.actor_type.clone(),
                    source_ip: None,
                    correlation_id: history.correlation_id.clone(),
                },
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: String::from("cell_participant"),
                resource_id: history.participant_registration_id.clone(),
                action: String::from("tombstoned"),
                details: serde_json::to_value(history).unwrap_or_else(|error| {
                    panic!("failed to encode seeded runtime tombstone event details: {error}")
                }),
            }),
        },
        created_at: history.tombstoned_at,
        updated_at,
        state,
        relay,
    }
}

fn seed_stale_peer_runtime_records_with_cleanup_state(state_dir: &Path, tombstone_eligible: bool) {
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir)
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
    fs::write(
        runtime_dir.join("process-registrations.json"),
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
    fs::write(
        runtime_dir.join("cell-directory.json"),
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
        assert_eq!(
            cleanup_workflow.state.stage,
            StaleParticipantCleanupStage::TombstoneEligible
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
    fs::write(
        runtime_dir.join("stale-participant-cleanup-workflows.json"),
        serde_json::to_vec(&cleanup_workflows).unwrap_or_else(|error| {
            panic!("failed to encode seeded cleanup workflow store: {error}")
        }),
    )
    .unwrap_or_else(|error| panic!("failed to write seeded cleanup workflow store: {error}"));
}

fn wait_for_health(address: SocketAddr, child: &mut Child, stderr_path: &Path) {
    let deadline = Instant::now() + AUTH_GATE_STARTUP_TIMEOUT;
    let mut last_probe_result = String::from("connection not attempted");
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to inspect child process health: {error}"))
        {
            let stderr = read_uhostd_stderr(stderr_path);
            panic!(
                "uhostd exited before becoming healthy on {address} with status {status}; last probe result: {last_probe_result}; stderr: {stderr}"
            );
        }
        match try_request(address, "GET", "/healthz", None, None) {
            Ok(response) if response.status == 200 => return,
            Ok(response) => {
                last_probe_result = format!("received status {}", response.status);
            }
            Err(error) => {
                last_probe_result = error.to_string();
            }
        }
        thread::sleep(AUTH_GATE_STARTUP_POLL_INTERVAL);
    }
    let stderr = read_uhostd_stderr(stderr_path);
    panic!(
        "uhostd did not become healthy within {:?} on {address}; last probe result: {last_probe_result}; stderr: {stderr}",
        AUTH_GATE_STARTUP_TIMEOUT,
    );
}

fn read_uhostd_stderr(path: &Path) -> String {
    let stderr = fs::read_to_string(path)
        .unwrap_or_else(|error| format!("failed to read stderr log {}: {error}", path.display()));
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        String::from("<empty>")
    } else {
        trimmed.to_owned()
    }
}

fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: Option<&str>,
) -> Value {
    let response = request(address, method, path, body, token);
    assert!(
        (200..=299).contains(&response.status),
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid json response: {error}"))
}

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> Value {
    let response = request_with_bearer_token(address, method, path, body, token);
    assert!(
        (200..=299).contains(&response.status),
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid json response: {error}"))
}

fn advance_persisted_volume_recovery_point(state_dir: &Path, volume_id: &str) {
    let path = state_dir
        .join("storage")
        .join("volume_recovery_points.json");
    let raw = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read storage recovery point store: {error}"));
    let mut collection: DocumentCollection<Value> = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid storage recovery point store json: {error}"));
    let record = collection
        .records
        .get_mut(volume_id)
        .unwrap_or_else(|| panic!("missing persisted recovery point {volume_id}"));
    record.version += 1;
    let captured_at = OffsetDateTime::now_utc() + time::Duration::minutes(30);
    let interval_minutes = record.value["interval_minutes"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing interval_minutes"));
    let execution_count = record.value["execution_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing execution_count"))
        + 1;
    record.updated_at = captured_at;
    record.value["execution_count"] = json!(execution_count);
    record.value["latest_snapshot_at"] = json!(captured_at);
    record.value["next_snapshot_after"] =
        json!(captured_at + time::Duration::minutes(interval_minutes as i64));
    record.value["metadata"]["etag"] = json!(sha256_hex(
        format!("{volume_id}:recovery-point:{}", record.version).as_bytes(),
    ));
    record.value["metadata"]["updated_at"] = json!(captured_at);
    let payload = serde_json::to_vec(&collection)
        .unwrap_or_else(|error| panic!("failed to encode storage recovery point store: {error}"));
    fs::write(path, payload)
        .unwrap_or_else(|error| panic!("failed to write storage recovery point store: {error}"));
}

fn remove_persisted_volume_recovery_point_revision(
    state_dir: &Path,
    volume_id: &str,
    recovery_point_version: u64,
) {
    let path = state_dir
        .join("storage")
        .join("volume_recovery_point_revisions.json");
    let raw = fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read storage recovery point revision store: {error}")
    });
    let mut collection: DocumentCollection<Value> =
        serde_json::from_slice(&raw).unwrap_or_else(|error| {
            panic!("invalid storage recovery point revision store json: {error}")
        });
    let key = format!("{volume_id}:{recovery_point_version}");
    collection
        .records
        .remove(&key)
        .unwrap_or_else(|| panic!("missing persisted recovery point revision {key}"));
    let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| {
        panic!("failed to encode storage recovery point revision store: {error}")
    });
    fs::write(path, payload).unwrap_or_else(|error| {
        panic!("failed to write storage recovery point revision store: {error}")
    });
}

fn read_storage_recovery_point(state_dir: &Path, volume_id: &str) -> Value {
    let raw = fs::read(
        state_dir
            .join("storage")
            .join("volume_recovery_points.json"),
    )
    .unwrap_or_else(|error| panic!("failed to read storage recovery point store: {error}"));
    let collection: DocumentCollection<Value> = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid storage recovery point store json: {error}"));
    let record = collection
        .records
        .get(volume_id)
        .cloned()
        .unwrap_or_else(|| panic!("missing persisted recovery point {volume_id}"));
    json!({
        "volume_id": volume_id,
        "version": record.version,
        "execution_count": record.value["execution_count"].clone(),
        "etag": record.value["metadata"]["etag"].clone(),
        "captured_at": record.value["latest_snapshot_at"].clone(),
    })
}

fn read_runtime_process_registration(state_dir: &Path) -> Value {
    read_runtime_process_registration_record(state_dir, "all_in_one:auth-gate-test-node")
}

fn read_runtime_process_registration_record(state_dir: &Path, registration_id: &str) -> Value {
    let raw = fs::read_to_string(state_dir.join("runtime").join("process-registrations.json"))
        .unwrap_or_else(|error| panic!("failed to read runtime registration store: {error}"));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid runtime registration store json: {error}"));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get(registration_id))
        .cloned()
        .unwrap_or_else(|| panic!("runtime registration store should contain {registration_id}"))
}

fn read_runtime_cell_directory_record(state_dir: &Path) -> Value {
    let raw = fs::read_to_string(state_dir.join("runtime").join("cell-directory.json"))
        .unwrap_or_else(|error| panic!("failed to read runtime cell directory store: {error}"));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid runtime cell directory store json: {error}"));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get("local:local-cell"))
        .cloned()
        .unwrap_or_else(|| panic!("runtime cell directory store should contain local cell record"))
}

fn read_runtime_stale_cleanup_workflow_record(state_dir: &Path, workflow_id: &str) -> Value {
    let raw = fs::read_to_string(
        state_dir
            .join("runtime")
            .join("stale-participant-cleanup-workflows.json"),
    )
    .unwrap_or_else(|error| panic!("failed to read cleanup workflow store: {error}"));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid cleanup workflow store json: {error}"));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get(workflow_id))
        .cloned()
        .unwrap_or_else(|| panic!("cleanup workflow store should contain {workflow_id}"))
}

fn read_runtime_participant_tombstone_history_entries(state_dir: &Path) -> Vec<Value> {
    read_active_collection_values(
        state_dir
            .join("runtime")
            .join("participant-tombstone-history.json")
            .as_path(),
    )
}

fn read_runtime_participant_tombstone_history_records(state_dir: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(
        state_dir
            .join("runtime")
            .join("participant-tombstone-history.json"),
    )
    .unwrap_or_else(|error| panic!("failed to read runtime tombstone history store: {error}"));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid runtime tombstone history store json: {error}"));
    collection
        .get("records")
        .and_then(Value::as_object)
        .map(|records| records.values().cloned().collect())
        .unwrap_or_default()
}

fn read_runtime_outbox_entries(state_dir: &Path) -> Vec<Value> {
    read_active_collection_values(state_dir.join("runtime").join("outbox.json").as_path())
}

fn read_runtime_audit_events(state_dir: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(state_dir.join("runtime").join("audit.log"))
        .unwrap_or_else(|error| panic!("failed to read runtime audit log: {error}"));
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("invalid runtime audit event json: {error}"))
        })
        .collect()
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

struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: Option<&str>,
) -> RawResponse {
    try_request(address, method, path, body, token)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn request_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> RawResponse {
    try_request_with_auth(address, method, path, body, Some(token), None)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: Option<&str>,
) -> Result<RawResponse, Error> {
    try_request_with_auth(address, method, path, body, token, token)
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

fn issue_workload_identity_payload(
    address: SocketAddr,
    bootstrap_token: &str,
    subject: &str,
    audiences: &[&str],
    ttl_seconds: u64,
) -> Value {
    let body = serde_json::to_vec(&json!({
        "subject": subject,
        "display_name": format!("{subject} identity"),
        "audiences": audiences,
        "ttl_seconds": ttl_seconds,
    }))
    .unwrap_or_else(|error| panic!("failed to serialize workload identity request: {error}"));
    let payload = request_json(
        address,
        "POST",
        "/identity/workload-identities",
        Some(("application/json", body.as_slice())),
        Some(bootstrap_token),
    );
    let issued_token = payload["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned();
    let issued_hash = payload["identity"]["credential"]["secret_preview"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(
        payload["identity"]["principal"]["subject"],
        subject.to_ascii_lowercase()
    );
    assert_eq!(
        payload["identity"]["credential"]["secret_preview"],
        json!(issued_token.chars().take(10).collect::<String>())
    );
    assert_eq!(sha256_hex(issued_token.as_bytes()).len(), 64);
    assert!(!issued_hash.is_empty());
    payload
}

fn issue_workload_identity(
    address: SocketAddr,
    bootstrap_token: &str,
    subject: &str,
    audiences: &[&str],
    ttl_seconds: u64,
) -> String {
    issue_workload_identity_payload(address, bootstrap_token, subject, audiences, ttl_seconds)
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned()
}
