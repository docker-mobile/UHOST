use std::collections::BTreeSet;
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
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use uhost_core::{base64url_encode, sha256_hex};
use uhost_types::NodeId;

const GENERATED_JSON_PATH: &str = "docs/generated/storage-drill-evidence.json";
const GENERATED_MD_PATH: &str = "docs/generated/storage-drill-evidence.md";
const GENERATED_BUNDLE_NAME: &str = "storage-restore-replication-failover-drill-evidence";
const GENERATOR_SCRIPT_PATH: &str = "scripts/run-storage-drill-evidence.sh";
const FOCUSED_GATE_PATH: &str = "ci/check-storage-drill-evidence.sh";
const WAVE3_GATE_PATH: &str = "ci/wave3-evidence-gate.sh";
const TEST_FILE_PATH: &str = "cmd/uhostd/tests/storage_drill_evidence.rs";
const REHEARSAL_TEST_NAME: &str =
    "combined_storage_drill_rehearsal_exercises_restore_replication_and_failover";
const GENERATED_ARTIFACT_TEST_NAME: &str = "storage_drill_generated_artifact_is_present_and_fresh";
const GENERATED_EVIDENCE_MAX_AGE_DAYS: i64 = 30;
const DRILL_REASON: &str = "scheduled restore-replication-failover drill";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Clone)]
struct CombinedDrillSnapshot {
    database_id: String,
    backing_volume_id: String,
    backup_id: String,
    backup_snapshot_uri: String,
    backup_recovery_point_version: u64,
    backup_recovery_point_etag: String,
    restore_id: String,
    restore_state: String,
    storage_restore_action_id: String,
    storage_restore_workflow_id: String,
    storage_restore_source_mode: String,
    storage_restore_selection_reason: String,
    storage_restore_recovery_point_version: u64,
    storage_restore_recovery_point_etag: String,
    storage_restore_recovery_point_captured_at: String,
    active_node_id: String,
    passive_node_id: String,
    replication_lag_seconds: u64,
    preflight_allowed: bool,
    preflight_observed_replication_lag_seconds: u64,
    failover_drill_id: String,
    failover_state: String,
    failover_operation_kind: String,
    data_outbox_event_types: Vec<String>,
    ha_outbox_event_types: Vec<String>,
}

#[test]
fn combined_storage_drill_rehearsal_exercises_restore_replication_and_failover() {
    let _guard = storage_drill_test_guard();
    let Some(snapshot) = run_combined_storage_drill(true) else {
        eprintln!(
            "skipping {REHEARSAL_TEST_NAME}: loopback bind not permitted in this environment"
        );
        return;
    };

    assert_eq!(snapshot.restore_state, "completed");
    assert_eq!(
        snapshot.storage_restore_source_mode,
        "backup_correlated_storage_lineage"
    );
    assert_eq!(
        snapshot.storage_restore_selection_reason,
        "selected backup-correlated storage recovery point recorded by the originating backup"
    );
    assert_eq!(
        snapshot.backup_recovery_point_version,
        snapshot.storage_restore_recovery_point_version
    );
    assert_eq!(
        snapshot.backup_recovery_point_etag,
        snapshot.storage_restore_recovery_point_etag
    );
    assert!(snapshot.preflight_allowed);
    assert_eq!(snapshot.preflight_observed_replication_lag_seconds, 2);
    assert_eq!(snapshot.failover_state, "completed");
    assert_eq!(snapshot.failover_operation_kind, "drill");
    assert!(
        snapshot
            .data_outbox_event_types
            .iter()
            .any(|event_type| event_type == "data.database.backup.completed.v1")
    );
    assert!(
        snapshot
            .data_outbox_event_types
            .iter()
            .any(|event_type| event_type == "data.database.restore.completed.v1")
    );
    assert!(
        snapshot
            .ha_outbox_event_types
            .iter()
            .any(|event_type| event_type == "ha.failover.drill.started.v1")
    );
    assert!(
        snapshot
            .ha_outbox_event_types
            .iter()
            .any(|event_type| event_type == "ha.failover.drill.completed.v1")
    );
}

#[test]
fn storage_drill_generated_artifact_is_present_and_fresh() {
    let generator_script = read_text_file(GENERATOR_SCRIPT_PATH);
    assert!(
        generator_script.contains(
            "cargo test -p uhostd --test storage_drill_evidence storage_drill_evidence_bundle_can_be_regenerated -- --ignored --exact --nocapture"
        ),
        "{GENERATOR_SCRIPT_PATH} must run the exact ignored regeneration test"
    );
    assert!(
        generator_script.contains("UHOST_STORAGE_DRILL_EVIDENCE_OUT_DIR"),
        "{GENERATOR_SCRIPT_PATH} must forward the output directory environment override"
    );

    let focused_gate = read_text_file(FOCUSED_GATE_PATH);
    assert!(
        focused_gate.contains(
            "cargo test -p uhostd --test storage_drill_evidence storage_drill_generated_artifact_is_present_and_fresh -- --exact"
        ),
        "{FOCUSED_GATE_PATH} must run the exact generated artifact verification test"
    );

    let wave3_gate = read_text_file(WAVE3_GATE_PATH);
    assert!(
        wave3_gate.contains(
            "cargo test -p uhostd --test storage_drill_evidence combined_storage_drill_rehearsal_exercises_restore_replication_and_failover -- --exact"
        ),
        "{WAVE3_GATE_PATH} must run the live combined storage drill rehearsal test"
    );
    assert!(
        wave3_gate.contains("bash ci/check-storage-drill-evidence.sh"),
        "{WAVE3_GATE_PATH} must run the generated storage drill evidence freshness gate"
    );

    let manifest = read_json_file(GENERATED_JSON_PATH);
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["bundle"].as_str(), Some(GENERATED_BUNDLE_NAME));
    let generated_at = manifest["generated_at"]
        .as_str()
        .unwrap_or_else(|| panic!("{GENERATED_JSON_PATH} is missing generated_at"));
    let generated_at = OffsetDateTime::parse(generated_at, &Rfc3339)
        .unwrap_or_else(|error| panic!("invalid generated_at in {GENERATED_JSON_PATH}: {error}"));
    let manifest_age = OffsetDateTime::now_utc() - generated_at;
    assert!(
        manifest_age <= TimeDuration::days(GENERATED_EVIDENCE_MAX_AGE_DAYS),
        "generated storage drill evidence is stale: age is {} days, which exceeds the {} day freshness budget; rerun `bash {GENERATOR_SCRIPT_PATH}`",
        manifest_age.whole_days(),
        GENERATED_EVIDENCE_MAX_AGE_DAYS
    );

    assert_eq!(
        manifest["generator"]["script"].as_str(),
        Some(GENERATOR_SCRIPT_PATH)
    );
    let generator_script_sha = manifest["generator"]["script_sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("{GENERATED_JSON_PATH} is missing generator.script_sha256"));
    assert_sha256_hex(
        generator_script_sha,
        &format!("{GENERATED_JSON_PATH} generator.script_sha256"),
    );
    assert_eq!(
        generator_script_sha,
        file_sha256(GENERATOR_SCRIPT_PATH),
        "generator script digest mismatch in {GENERATED_JSON_PATH} for {GENERATOR_SCRIPT_PATH}"
    );
    assert_eq!(
        manifest["generator"]["command"].as_str(),
        Some("bash scripts/run-storage-drill-evidence.sh")
    );
    assert_eq!(
        manifest["generator"]["generated_directory"].as_str(),
        Some("docs/generated")
    );

    let focused_gate_binding = manifest["verification"]["focused_gate"]
        .as_object()
        .unwrap_or_else(|| panic!("{GENERATED_JSON_PATH} is missing verification.focused_gate"));
    assert_eq!(
        focused_gate_binding.get("path").and_then(Value::as_str),
        Some(FOCUSED_GATE_PATH)
    );
    let focused_gate_sha = focused_gate_binding
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("{GENERATED_JSON_PATH} is missing verification.focused_gate.sha256")
        });
    assert_sha256_hex(
        focused_gate_sha,
        &format!("{GENERATED_JSON_PATH} verification.focused_gate.sha256"),
    );
    assert_eq!(
        focused_gate_sha,
        file_sha256(FOCUSED_GATE_PATH),
        "focused gate digest mismatch in {GENERATED_JSON_PATH} for {FOCUSED_GATE_PATH}"
    );

    let integration_test_binding = manifest["verification"]["integration_test"]
        .as_object()
        .unwrap_or_else(|| {
            panic!("{GENERATED_JSON_PATH} is missing verification.integration_test")
        });
    assert_eq!(
        integration_test_binding.get("path").and_then(Value::as_str),
        Some(TEST_FILE_PATH)
    );
    assert_eq!(
        integration_test_binding
            .get("test_name")
            .and_then(Value::as_str),
        Some(REHEARSAL_TEST_NAME)
    );
    let integration_test_sha = integration_test_binding
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("{GENERATED_JSON_PATH} is missing verification.integration_test.sha256")
        });
    assert_sha256_hex(
        integration_test_sha,
        &format!("{GENERATED_JSON_PATH} verification.integration_test.sha256"),
    );
    assert_eq!(
        integration_test_sha,
        file_sha256(TEST_FILE_PATH),
        "integration test digest mismatch in {GENERATED_JSON_PATH} for {TEST_FILE_PATH}"
    );

    let drill = manifest["drill"]
        .as_object()
        .unwrap_or_else(|| panic!("{GENERATED_JSON_PATH} is missing drill"));
    assert_eq!(
        drill.get("restore_state").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        drill
            .get("storage_restore_source_mode")
            .and_then(Value::as_str),
        Some("backup_correlated_storage_lineage")
    );
    assert_eq!(
        drill.get("failover_state").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        drill.get("failover_operation_kind").and_then(Value::as_str),
        Some("drill")
    );
    assert_eq!(
        drill.get("preflight_allowed").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        drill
            .get("preflight_observed_replication_lag_seconds")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert!(
        drill
            .get("database_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "{GENERATED_JSON_PATH} is missing drill.database_id"
    );
    assert!(
        drill
            .get("backing_volume_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "{GENERATED_JSON_PATH} is missing drill.backing_volume_id"
    );
    assert!(
        drill
            .get("storage_restore_action_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "{GENERATED_JSON_PATH} is missing drill.storage_restore_action_id"
    );
    let data_outbox_event_types = json_string_array(
        drill.get("data_outbox_event_types").unwrap_or_else(|| {
            panic!("{GENERATED_JSON_PATH} is missing drill.data_outbox_event_types")
        }),
        &format!("{GENERATED_JSON_PATH} drill.data_outbox_event_types"),
    );
    assert!(
        data_outbox_event_types
            .iter()
            .any(|event_type| event_type == "data.database.backup.completed.v1"),
        "{GENERATED_JSON_PATH} is missing data.database.backup.completed.v1 from drill.data_outbox_event_types"
    );
    assert!(
        data_outbox_event_types
            .iter()
            .any(|event_type| event_type == "data.database.restore.completed.v1"),
        "{GENERATED_JSON_PATH} is missing data.database.restore.completed.v1 from drill.data_outbox_event_types"
    );
    let ha_outbox_event_types = json_string_array(
        drill.get("ha_outbox_event_types").unwrap_or_else(|| {
            panic!("{GENERATED_JSON_PATH} is missing drill.ha_outbox_event_types")
        }),
        &format!("{GENERATED_JSON_PATH} drill.ha_outbox_event_types"),
    );
    assert!(
        ha_outbox_event_types
            .iter()
            .any(|event_type| event_type == "ha.failover.drill.started.v1"),
        "{GENERATED_JSON_PATH} is missing ha.failover.drill.started.v1 from drill.ha_outbox_event_types"
    );
    assert!(
        ha_outbox_event_types
            .iter()
            .any(|event_type| event_type == "ha.failover.drill.completed.v1"),
        "{GENERATED_JSON_PATH} is missing ha.failover.drill.completed.v1 from drill.ha_outbox_event_types"
    );

    let markdown = read_text_file(GENERATED_MD_PATH);
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Generator command:",
        "`bash scripts/run-storage-drill-evidence.sh`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Restore state:",
        "`completed`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Storage restore source mode:",
        "`backup_correlated_storage_lineage`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Failover state:",
        "`completed`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Failover operation kind:",
        "`drill`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Preflight allowed:",
        "`true`",
    );
    assert_markdown_field_equals(
        &markdown,
        GENERATED_MD_PATH,
        "- Replication lag seconds:",
        "`2`",
    );

    let markdown_database_id =
        extract_markdown_field(&markdown, GENERATED_MD_PATH, "- Database id:");
    assert_eq!(
        markdown_database_id,
        &format!(
            "`{}`",
            drill
                .get("database_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{GENERATED_JSON_PATH} is missing drill.database_id"))
        )
    );
    let markdown_failover_drill_id =
        extract_markdown_field(&markdown, GENERATED_MD_PATH, "- Failover drill id:");
    assert_eq!(
        markdown_failover_drill_id,
        &format!(
            "`{}`",
            drill
                .get("failover_drill_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!(
                    "{GENERATED_JSON_PATH} is missing drill.failover_drill_id"
                ))
        )
    );
}

#[test]
#[ignore]
fn storage_drill_evidence_bundle_can_be_regenerated() {
    let _guard = storage_drill_test_guard();
    let snapshot = run_combined_storage_drill(false).unwrap_or_else(|| {
        panic!(
            "loopback bind not permitted while regenerating storage drill evidence; rerun on a host that allows local TCP listeners"
        )
    });
    write_generated_bundle(&output_dir_from_env(), &snapshot);
}

fn storage_drill_test_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn run_combined_storage_drill(skip_on_bind_denied: bool) -> Option<CombinedDrillSnapshot> {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let address = match reserve_loopback_port() {
        Some(address) => address,
        None if skip_on_bind_denied => return None,
        None => panic!("loopback bind not permitted"),
    };
    let config_path = temp.path().join("all-in-one.toml");
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let _guard = ChildGuard { child };

    wait_for_health(address);

    let database = request_json(
        address,
        "POST",
        "/data/databases",
        Some(json!({
            "engine": "postgres",
            "version": "16.2",
            "storage_gb": 50,
            "replicas": 2,
            "tls_required": true,
            "primary_region": "us-east-1"
        })),
    );
    let database_id = database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing database id"))
        .to_owned();
    let backing_volume_id = database["metadata"]["annotations"]["data.storage.backing_volume_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backing volume annotation"))
        .to_owned();

    let backup = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/backups"),
        Some(json!({
            "kind": "full",
            "reason": DRILL_REASON,
        })),
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"))
        .to_owned();
    let backup_snapshot_uri = backup["snapshot_uri"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup snapshot uri"))
        .to_owned();
    let backup_recovery_point_version = backup["storage_recovery_point"]["version"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing backup storage recovery point version"));
    let backup_recovery_point_etag = backup["storage_recovery_point"]["etag"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup storage recovery point etag"))
        .to_owned();

    let restore = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/restore"),
        Some(json!({
            "backup_id": &backup_id,
            "reason": DRILL_REASON,
        })),
    );
    let restore_id = restore["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore id"))
        .to_owned();
    let restore_state = restore["state"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore state"))
        .to_owned();
    let storage_restore_source_mode = restore["storage_restore_source_mode"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore source mode"))
        .to_owned();
    let storage_restore_selection_reason = restore["storage_restore_selection_reason"]
        .as_str()
        .unwrap_or_else(|| panic!("missing restore selection reason"))
        .to_owned();

    let restore_record = read_collection_record(
        &state_dir.join("data").join("restores.json"),
        restore_id.as_str(),
    );
    let storage_restore_action_id = restore_record["value"]["storage_restore"]["restore_action_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing storage restore action id"))
        .to_owned();
    let storage_restore_workflow_id =
        restore_record["value"]["storage_restore"]["restore_workflow_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing storage restore workflow id"))
            .to_owned();
    let storage_restore_recovery_point_version =
        restore_record["value"]["storage_restore"]["selected_recovery_point"]["version"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing selected recovery point version"));
    let storage_restore_recovery_point_etag =
        restore_record["value"]["storage_restore"]["selected_recovery_point"]["etag"]
            .as_str()
            .unwrap_or_else(|| panic!("missing selected recovery point etag"))
            .to_owned();
    let storage_restore_recovery_point_captured_at = json_rfc3339_timestamp(
        &restore_record["value"]["storage_restore"]["selected_recovery_point"]["captured_at"],
        "selected recovery point captured_at",
    );

    let storage_restore_action = read_collection_record(
        &state_dir
            .join("storage")
            .join("volume_restore_actions.json"),
        storage_restore_action_id.as_str(),
    );
    assert_eq!(
        storage_restore_action["value"]["state"].as_str(),
        Some("completed")
    );
    assert_eq!(
        storage_restore_action["value"]["source_recovery_point_version"].as_u64(),
        Some(storage_restore_recovery_point_version)
    );

    let persisted_database = read_collection_record(
        &state_dir.join("data").join("databases.json"),
        database_id.as_str(),
    );
    assert_eq!(
        persisted_database["value"]["metadata"]["annotations"]["data.storage.backing_volume_id"]
            .as_str(),
        Some(backing_volume_id.as_str())
    );
    assert_eq!(
        persisted_database["value"]["metadata"]["annotations"]["data.storage.last_restore_action_id"]
            .as_str(),
        Some(storage_restore_action_id.as_str())
    );
    assert_eq!(
        persisted_database["value"]["metadata"]["annotations"]["data.storage.last_restore_backup_id"]
            .as_str(),
        Some(backup_id.as_str())
    );

    let active_node_id = NodeId::generate()
        .unwrap_or_else(|error| panic!("{error}"))
        .to_string();
    let passive_node_id = NodeId::generate()
        .unwrap_or_else(|error| panic!("{error}"))
        .to_string();

    let _ = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(json!({
            "node_id": &active_node_id,
            "role": "active",
            "healthy": true,
        })),
    );
    let _ = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(json!({
            "node_id": &passive_node_id,
            "role": "passive",
            "healthy": true,
        })),
    );
    let _ = request_json(
        address,
        "POST",
        "/ha/replication-status",
        Some(json!({
            "source_node_id": &active_node_id,
            "target_node_id": &passive_node_id,
            "lag_seconds": 2,
            "healthy": true,
        })),
    );
    let _ = request_json(
        address,
        "POST",
        "/ha/regional-quorum",
        Some(json!({
            "region": "us-east-1",
            "node_id": &active_node_id,
            "role": "leader",
            "term": 5,
            "vote_weight": 1,
            "healthy": true,
            "replicated_log_index": 1200,
            "applied_log_index": 1200,
            "lease_seconds": 90,
        })),
    );
    let _ = request_json(
        address,
        "POST",
        "/ha/regional-quorum",
        Some(json!({
            "region": "us-east-1",
            "node_id": &passive_node_id,
            "role": "follower",
            "term": 5,
            "vote_weight": 1,
            "healthy": true,
            "replicated_log_index": 1200,
            "applied_log_index": 1200,
            "lease_seconds": 90,
        })),
    );

    let preflight = request_json(
        address,
        "POST",
        "/ha/failover-preflight",
        Some(json!({
            "from_node_id": &active_node_id,
            "to_node_id": &passive_node_id,
            "max_replication_lag_seconds": 30,
        })),
    );
    let preflight_allowed = preflight["allowed"]
        .as_bool()
        .unwrap_or_else(|| panic!("missing preflight allowed"));
    let preflight_observed_replication_lag_seconds = preflight["observed_replication_lag_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing preflight observed replication lag"));
    assert!(preflight_allowed);
    assert_eq!(preflight_observed_replication_lag_seconds, 2);

    let failover_drill = request_json(
        address,
        "POST",
        "/ha/drills",
        Some(json!({
            "from_node_id": &active_node_id,
            "to_node_id": &passive_node_id,
            "reason": DRILL_REASON,
            "max_replication_lag_seconds": 30,
        })),
    );
    let failover_drill_id = failover_drill["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing failover drill id"))
        .to_owned();
    let failover_state = failover_drill["state"]
        .as_str()
        .unwrap_or_else(|| panic!("missing failover drill state"))
        .to_owned();
    let failover_operation_kind = failover_drill["operation_kind"]
        .as_str()
        .unwrap_or_else(|| panic!("missing failover drill operation kind"))
        .to_owned();
    assert_eq!(failover_state, "completed");
    assert_eq!(failover_operation_kind, "drill");
    assert_eq!(failover_drill["drill"].as_bool(), Some(true));

    let stored_failover = read_collection_record(
        &state_dir.join("ha").join("failovers.json"),
        failover_drill_id.as_str(),
    );
    assert_eq!(
        stored_failover["value"]["state"].as_str(),
        Some("completed")
    );
    assert_eq!(stored_failover["value"]["drill"].as_bool(), Some(true));
    assert_eq!(
        stored_failover["value"]["operation_kind"].as_str(),
        Some("drill")
    );

    let replication_key = format!("{active_node_id}:{passive_node_id}");
    let stored_replication = read_collection_record(
        &state_dir.join("ha").join("replication_status.json"),
        replication_key.as_str(),
    );
    let replication_lag_seconds = stored_replication["value"]["lag_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing stored replication lag"));
    assert_eq!(replication_lag_seconds, 2);
    assert_eq!(stored_replication["value"]["healthy"].as_bool(), Some(true));

    let data_outbox_event_types =
        read_outbox_event_types(&state_dir.join("data").join("outbox.json"));
    let ha_outbox_event_types = read_outbox_event_types(&state_dir.join("ha").join("outbox.json"));

    Some(CombinedDrillSnapshot {
        database_id,
        backing_volume_id,
        backup_id,
        backup_snapshot_uri,
        backup_recovery_point_version,
        backup_recovery_point_etag,
        restore_id,
        restore_state,
        storage_restore_action_id,
        storage_restore_workflow_id,
        storage_restore_source_mode,
        storage_restore_selection_reason,
        storage_restore_recovery_point_version,
        storage_restore_recovery_point_etag,
        storage_restore_recovery_point_captured_at,
        active_node_id,
        passive_node_id,
        replication_lag_seconds,
        preflight_allowed,
        preflight_observed_replication_lag_seconds,
        failover_drill_id,
        failover_state,
        failover_operation_kind,
        data_outbox_event_types,
        ha_outbox_event_types,
    })
}

fn read_outbox_event_types(path: &Path) -> Vec<String> {
    read_active_collection_values(path)
        .into_iter()
        .filter_map(|record| {
            record
                .get("event_type")
                .and_then(Value::as_str)
                .or_else(|| {
                    record
                        .get("payload")
                        .and_then(|payload| payload.get("header"))
                        .and_then(|header| header.get("event_type"))
                        .and_then(Value::as_str)
                })
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn write_generated_bundle(output_dir: &Path, snapshot: &CombinedDrillSnapshot) {
    fs::create_dir_all(output_dir)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", output_dir.display()));
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|error| panic!("failed to format generated_at: {error}"));
    let generated_directory = workspace_relative_path(output_dir);
    let manifest = json!({
        "schema_version": 1,
        "bundle": GENERATED_BUNDLE_NAME,
        "generated_at": generated_at,
        "generator": {
            "script": GENERATOR_SCRIPT_PATH,
            "script_sha256": file_sha256(GENERATOR_SCRIPT_PATH),
            "command": "bash scripts/run-storage-drill-evidence.sh",
            "generated_directory": generated_directory,
        },
        "verification": {
            "focused_gate": {
                "path": FOCUSED_GATE_PATH,
                "sha256": file_sha256(FOCUSED_GATE_PATH),
            },
            "integration_test": {
                "path": TEST_FILE_PATH,
                "test_name": REHEARSAL_TEST_NAME,
                "sha256": file_sha256(TEST_FILE_PATH),
            }
        },
        "drill": {
            "database_id": &snapshot.database_id,
            "backing_volume_id": &snapshot.backing_volume_id,
            "backup_id": &snapshot.backup_id,
            "backup_snapshot_uri": &snapshot.backup_snapshot_uri,
            "backup_recovery_point_version": snapshot.backup_recovery_point_version,
            "backup_recovery_point_etag": &snapshot.backup_recovery_point_etag,
            "restore_id": &snapshot.restore_id,
            "restore_state": &snapshot.restore_state,
            "storage_restore_action_id": &snapshot.storage_restore_action_id,
            "storage_restore_workflow_id": &snapshot.storage_restore_workflow_id,
            "storage_restore_source_mode": &snapshot.storage_restore_source_mode,
            "storage_restore_selection_reason": &snapshot.storage_restore_selection_reason,
            "storage_restore_recovery_point_version": snapshot.storage_restore_recovery_point_version,
            "storage_restore_recovery_point_etag": &snapshot.storage_restore_recovery_point_etag,
            "storage_restore_recovery_point_captured_at": &snapshot.storage_restore_recovery_point_captured_at,
            "active_node_id": &snapshot.active_node_id,
            "passive_node_id": &snapshot.passive_node_id,
            "replication_lag_seconds": snapshot.replication_lag_seconds,
            "preflight_allowed": snapshot.preflight_allowed,
            "preflight_observed_replication_lag_seconds": snapshot.preflight_observed_replication_lag_seconds,
            "failover_drill_id": &snapshot.failover_drill_id,
            "failover_state": &snapshot.failover_state,
            "failover_operation_kind": &snapshot.failover_operation_kind,
            "data_outbox_event_types": &snapshot.data_outbox_event_types,
            "ha_outbox_event_types": &snapshot.ha_outbox_event_types,
        },
        "notes": [
            "This artifact is generated from a live all-in-one rehearsal that spans data restore and HA drill flows.",
            "Refresh the bundle after the rehearsal path, generator script, or focused gate changes.",
        ],
    });
    let json_path = output_dir.join("storage-drill-evidence.json");
    let json_bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_else(|error| {
        panic!("failed to encode generated storage drill evidence: {error}")
    });
    fs::write(
        &json_path,
        format!("{}\n", String::from_utf8_lossy(&json_bytes)),
    )
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", json_path.display()));

    let markdown = format!(
        "# Storage Drill Evidence\n\n- Generated at: `{generated_at}`\n- Generator command: `bash scripts/run-storage-drill-evidence.sh`\n- Database id: `{}`\n- Backing volume id: `{}`\n- Backup id: `{}`\n- Restore id: `{}`\n- Restore state: `{}`\n- Storage restore action id: `{}`\n- Storage restore workflow id: `{}`\n- Storage restore source mode: `{}`\n- Active node id: `{}`\n- Passive node id: `{}`\n- Preflight allowed: `{}`\n- Replication lag seconds: `{}`\n- Failover drill id: `{}`\n- Failover state: `{}`\n- Failover operation kind: `{}`\n\n## Verification\n\n| Binding | Path | SHA-256 | Notes |\n| --- | --- | --- | --- |\n| Focused gate | `{}` | `{}` | Runs `{}` |\n| Integration test | `{}` | `{}` | Exercises `{}` |\n\n## Outbox Event Types\n\n- Data outbox event types: {}\n- HA outbox event types: {}\n",
        snapshot.database_id,
        snapshot.backing_volume_id,
        snapshot.backup_id,
        snapshot.restore_id,
        snapshot.restore_state,
        snapshot.storage_restore_action_id,
        snapshot.storage_restore_workflow_id,
        snapshot.storage_restore_source_mode,
        snapshot.active_node_id,
        snapshot.passive_node_id,
        snapshot.preflight_allowed,
        snapshot.replication_lag_seconds,
        snapshot.failover_drill_id,
        snapshot.failover_state,
        snapshot.failover_operation_kind,
        FOCUSED_GATE_PATH,
        file_sha256(FOCUSED_GATE_PATH),
        GENERATED_ARTIFACT_TEST_NAME,
        TEST_FILE_PATH,
        file_sha256(TEST_FILE_PATH),
        REHEARSAL_TEST_NAME,
        format_event_type_list(&snapshot.data_outbox_event_types),
        format_event_type_list(&snapshot.ha_outbox_event_types),
    );
    let md_path = output_dir.join("storage-drill-evidence.md");
    fs::write(&md_path, markdown)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", md_path.display()));
}

fn output_dir_from_env() -> PathBuf {
    match std::env::var("UHOST_STORAGE_DRILL_EVIDENCE_OUT_DIR") {
        Ok(raw) => {
            let path = PathBuf::from(raw);
            if path.is_absolute() {
                path
            } else {
                workspace_root().join(path)
            }
        }
        Err(_) => workspace_path("docs/generated"),
    }
}

fn format_event_type_list(event_types: &[String]) -> String {
    event_types
        .iter()
        .map(|event_type| format!("`{event_type}`"))
        .collect::<Vec<_>>()
        .join(", ")
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "storage-drill-test-node"

[secrets]
master_key = "{}"
"#,
        state_dir.display(),
        base64url_encode(&[0x51; 32]),
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request(address, "GET", "/healthz", None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<Value>) -> Value {
    let payload =
        body.map(|value| serde_json::to_vec(&value).unwrap_or_else(|error| panic!("{error}")));
    let response = request(
        address,
        method,
        path,
        payload
            .as_ref()
            .map(|bytes| ("application/json", bytes.as_slice())),
    );
    assert!(
        (200..=299).contains(&response.status),
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid json response: {error}"))
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
) -> RawResponse {
    try_request(address, method, path, body)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        payload.len(),
    );
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

fn read_collection_record(path: &Path, key: &str) -> Value {
    let raw =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let collection: Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid collection json in {}: {error}", path.display()));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get(key))
        .cloned()
        .unwrap_or_else(|| panic!("missing record `{key}` in {}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("failed to canonicalize workspace root: {error}"))
}

fn workspace_path(path: &str) -> PathBuf {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }
    workspace_root().join(candidate)
}

fn workspace_relative_path(path: &Path) -> String {
    let root = workspace_root();
    let lexical_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .components()
        .collect::<PathBuf>();
    let absolute = if path.is_absolute() {
        canonicalize_loosely(path)
    } else {
        canonicalize_loosely(&root.join(path))
    };
    absolute
        .strip_prefix(&root)
        .or_else(|_| absolute.strip_prefix(&lexical_root))
        .unwrap_or(&absolute)
        .to_string_lossy()
        .replace('\\', "/")
}

fn canonicalize_loosely(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let Some(parent) = path.parent() else {
        return path.to_path_buf();
    };
    let Ok(canonical_parent) = parent.canonicalize() else {
        return path.to_path_buf();
    };
    match path.file_name() {
        Some(file_name) => canonical_parent.join(file_name),
        None => canonical_parent,
    }
}

fn read_text_file(path: &str) -> String {
    let resolved = workspace_path(path);
    fs::read_to_string(&resolved)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", resolved.display()))
}

fn read_json_file(path: &str) -> Value {
    let raw = read_text_file(path);
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("invalid json in {path}: {error}"))
}

fn json_rfc3339_timestamp(value: &Value, context: &str) -> String {
    serde_json::from_value::<OffsetDateTime>(value.clone())
        .unwrap_or_else(|error| panic!("invalid {context}: {error}"))
        .format(&Rfc3339)
        .unwrap_or_else(|error| panic!("failed to format {context}: {error}"))
}

fn extract_markdown_field<'a>(contents: &'a str, path: &str, prefix: &str) -> &'a str {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .unwrap_or_else(|| panic!("missing `{prefix}` in {path}"))
}

fn assert_markdown_field_equals(contents: &str, path: &str, prefix: &str, expected: &str) {
    let actual = extract_markdown_field(contents, path, prefix);
    assert_eq!(
        actual, expected,
        "unexpected value for `{prefix}` in {path}"
    );
}

fn json_string_array(value: &Value, context: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{context} must contain only string entries"))
                .to_owned()
        })
        .collect()
}

fn file_sha256(path: &str) -> String {
    let resolved = workspace_path(path);
    let bytes = fs::read(&resolved)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", resolved.display()));
    sha256_hex(&bytes)
}

fn assert_sha256_hex(value: &str, context: &str) {
    assert_eq!(
        value.len(),
        64,
        "{context} must be a 64-character SHA-256 hex digest"
    );
    assert!(
        value.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{context} must contain only hexadecimal characters"
    );
}
