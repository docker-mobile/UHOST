use std::fs;
use std::future::Future;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use time::{Duration as TimeDuration, OffsetDateTime};
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::{
    CellDirectoryCollection, CellDirectoryRecord, CellParticipantLeaseState, CellParticipantRecord,
    CellParticipantState, DocumentStore, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
    RegionDirectoryRecord, WorkflowInstance, WorkflowPhase,
};
use uhost_svc_observe::ObserveIncident;
use uhost_types::{AuditId, OwnershipScope, ResourceMetadata};

const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn test_child_stderr() -> Stdio {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

#[test]
fn fleet_ops_rollups_are_operational_from_all_in_one_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    seed_incidents_before_start(&state_dir);
    seed_runtime_cell_directory_before_start(&state_dir);

    let config_path = temp.path().join("fleet-ops-rollups.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping fleet_ops_rollups_are_operational_from_all_in_one_runtime: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(test_child_stderr())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let _guard = ChildGuard { child };

    wait_for_health(address);
    seed_cross_service_rollup_state_after_start(&state_dir);

    let rollups = wait_for_fleet_ops_rollups(address);
    let expected_state_root = state_dir.display().to_string();
    assert_eq!(
        rollups["state_root"].as_str(),
        Some(expected_state_root.as_str())
    );
    assert_eq!(rollups["ha_readiness"]["total_regions"].as_u64(), Some(2));
    assert_eq!(rollups["ha_readiness"]["ready_regions"].as_u64(), Some(1));
    assert_eq!(
        rollups["ha_readiness"]["degraded_regions"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["ha_readiness"]["regions_missing_reconciliation"].as_u64(),
        Some(0)
    );
    assert_eq!(
        rollups["ha_readiness"]["unreconciled_regions"].as_u64(),
        Some(1)
    );
    assert_eq!(rollups["ha_readiness"]["total_cells"].as_u64(), Some(3));
    assert_eq!(rollups["ha_readiness"]["ready_cells"].as_u64(), Some(2));
    assert_eq!(rollups["ha_readiness"]["degraded_cells"].as_u64(), Some(1));
    assert_eq!(
        rollups["ha_readiness"]["critical_dependencies_down"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["ha_readiness"]["critical_dependencies_degraded"].as_u64(),
        Some(1)
    );

    assert_eq!(
        rollups["incident_state"]["total_incidents"].as_u64(),
        Some(3)
    );
    assert_eq!(
        rollups["incident_state"]["open_incidents"].as_u64(),
        Some(2)
    );
    assert_eq!(
        rollups["incident_state"]["resolved_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["incident_state"]["attributed_region_incidents"].as_u64(),
        Some(2)
    );
    assert_eq!(
        rollups["incident_state"]["attributed_cell_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["incident_state"]["unattributed_incidents"].as_u64(),
        Some(1)
    );

    assert_eq!(
        rollups["backlog_health"]["attention_items"].as_u64(),
        Some(6)
    );
    assert_eq!(
        rollups["backlog_health"]["critical_items"].as_u64(),
        Some(5)
    );
    assert_eq!(
        rollups["backlog_health"]["ha_failovers_in_progress"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["ha_failovers_failed"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["ha_repair_workflows_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["ha_repair_workflows_failed"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["lifecycle_dead_letters_pending"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["lifecycle_repair_jobs_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["lifecycle_repair_jobs_failed"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["data_failovers_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["data_failovers_failed"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["data_migrations_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        rollups["backlog_health"]["data_migrations_failed"].as_u64(),
        Some(1)
    );

    let east_region = find_object_by_field(&rollups["regions"], "region_id", "region-east");
    assert_eq!(east_region["ha_readiness"]["ready"].as_bool(), Some(false));
    assert_eq!(east_region["ha_readiness"]["total_cells"].as_u64(), Some(2));
    assert_eq!(
        east_region["ha_readiness"]["degraded_cells"].as_u64(),
        Some(1)
    );
    assert_eq!(
        east_region["ha_readiness"]["uncommitted_entries"].as_u64(),
        Some(2)
    );
    assert_eq!(
        east_region["ha_readiness"]["lagging_nodes"].as_u64(),
        Some(1)
    );
    assert_eq!(
        east_region["incident_state"]["open_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        east_region["backlog_health"]["data_migrations_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        east_region["backlog_health"]["data_migrations_failed"].as_u64(),
        Some(1)
    );

    let west_region = find_object_by_field(&rollups["regions"], "region_id", "region-west");
    assert_eq!(west_region["ha_readiness"]["ready"].as_bool(), Some(true));
    assert_eq!(
        west_region["incident_state"]["open_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        west_region["backlog_health"]["data_failovers_active"].as_u64(),
        Some(1)
    );
    assert_eq!(
        west_region["backlog_health"]["data_migrations_active"].as_u64(),
        Some(1)
    );

    let cell_a = find_object_by_field(&rollups["cells"], "cell_id", "region-east:cell-a");
    assert_eq!(cell_a["ha_readiness"]["ready"].as_bool(), Some(true));
    assert_eq!(cell_a["incident_state"]["open_incidents"].as_u64(), Some(1));

    let cell_b = find_object_by_field(&rollups["cells"], "cell_id", "region-east:cell-b");
    assert_eq!(cell_b["ha_readiness"]["ready"].as_bool(), Some(false));
    assert_eq!(
        cell_b["ha_readiness"]["draining_participants"].as_u64(),
        Some(1)
    );
    assert_eq!(
        cell_b["ha_readiness"]["stale_participants"].as_u64(),
        Some(1)
    );
    assert_eq!(
        cell_b["backlog_health"]["takeover_pending"].as_u64(),
        Some(1)
    );
    assert_eq!(
        cell_b["backlog_health"]["attention_items"].as_u64(),
        Some(2)
    );
}

fn seed_incidents_before_start(state_dir: &Path) {
    block_on(async {
        let incidents =
            DocumentStore::<ObserveIncident>::open(state_dir.join("observe/incidents.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let now = parse_timestamp("2026-04-08T12:00:00Z");
        let open_cell_incident = ObserveIncident {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            source_kind: String::from("alert_rule"),
            source_id: String::from("region-east-cell-a"),
            severity: String::from("critical"),
            summary: String::from("cell a unavailable"),
            route_id: None,
            destination: None,
            status: String::from("open"),
            correlation_id: None,
            created_at: now,
            resolved_at: None,
            metadata: scoped_metadata(Some("region-east"), Some("region-east:cell-a")),
        };
        incidents
            .create(open_cell_incident.id.as_str(), open_cell_incident.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let open_region_incident = ObserveIncident {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            source_kind: String::from("slo"),
            source_id: String::from("region-west"),
            severity: String::from("high"),
            summary: String::from("region west latency"),
            route_id: None,
            destination: None,
            status: String::from("open"),
            correlation_id: None,
            created_at: now,
            resolved_at: None,
            metadata: scoped_metadata(Some("region-west"), None),
        };
        incidents
            .create(
                open_region_incident.id.as_str(),
                open_region_incident.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let resolved_global_incident = ObserveIncident {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            source_kind: String::from("alert_rule"),
            source_id: String::from("global"),
            severity: String::from("medium"),
            summary: String::from("global incident"),
            route_id: None,
            destination: None,
            status: String::from("resolved"),
            correlation_id: None,
            created_at: now,
            resolved_at: Some(now),
            metadata: scoped_metadata(None, None),
        };
        let resolved_global_incident_id = resolved_global_incident.id.to_string();
        incidents
            .create(
                resolved_global_incident_id.as_str(),
                resolved_global_incident,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    });
}

fn seed_runtime_cell_directory_before_start(state_dir: &Path) {
    block_on(async {
        let cells =
            CellDirectoryCollection::open_local(state_dir.join("runtime/cell-directory.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let now = parse_timestamp("2026-04-08T12:00:00Z");
        let east = RegionDirectoryRecord::new("region-east", "region-east");
        let fresh_lease = CellParticipantLeaseState::new(
            now,
            now + TimeDuration::minutes(5),
            300,
            LeaseFreshness::Fresh,
        );
        let stale_lease = CellParticipantLeaseState::new(
            now,
            now + TimeDuration::seconds(30),
            300,
            LeaseFreshness::Stale,
        );

        let cell_a = CellDirectoryRecord::new("region-east:cell-a", "cell-a", east.clone())
            .with_participant(
                CellParticipantRecord::new(
                    "reg-east-a",
                    "runtime_process",
                    "subject-east-a",
                    "control",
                )
                .with_state(CellParticipantState::new(
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Serving,
                    fresh_lease,
                )),
            );
        let cell_a_id = cell_a.cell_id.to_string();
        cells
            .create(cell_a_id.as_str(), cell_a)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let cell_b = CellDirectoryRecord::new("region-east:cell-b", "cell-b", east)
            .with_participant(
                CellParticipantRecord::new(
                    "reg-east-b",
                    "runtime_process",
                    "subject-east-b",
                    "control",
                )
                .with_state(CellParticipantState::new(
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Draining,
                    stale_lease,
                )),
            );
        let cell_b_id = cell_b.cell_id.to_string();
        cells
            .create(cell_b_id.as_str(), cell_b)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    });
}

fn seed_cross_service_rollup_state_after_start(state_dir: &Path) {
    block_on(async {
        let reconciliations =
            DocumentStore::<Value>::open(state_dir.join("ha/reconciliations.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        reconciliations
            .create(
                "region-east",
                json!({
                    "region": "region-east",
                    "latest_log_index": 12,
                    "committed_log_index": 10,
                    "majority_threshold": 2,
                    "healthy_votes": 1,
                    "uncommitted_entries": 2,
                    "lagging_nodes": ["nod-east-2"],
                    "fully_reconciled": false
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reconciliations
            .create(
                "region-west",
                json!({
                    "region": "region-west",
                    "latest_log_index": 8,
                    "committed_log_index": 8,
                    "majority_threshold": 2,
                    "healthy_votes": 2,
                    "uncommitted_entries": 0,
                    "lagging_nodes": [],
                    "fully_reconciled": true
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dependencies = DocumentStore::<Value>::open(state_dir.join("ha/dependencies.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        dependencies
            .create(
                "dns",
                json!({
                    "dependency": "dns",
                    "status": "down",
                    "critical": true
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        dependencies
            .create(
                "storage",
                json!({
                    "dependency": "storage",
                    "status": "degraded",
                    "critical": true
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ha_failovers = DocumentStore::<Value>::open(state_dir.join("ha/failovers.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        ha_failovers
            .create("failover-running", json!({ "state": "in_progress" }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        ha_failovers
            .create("failover-failed", json!({ "state": "failed" }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ha_repair_workflows = DocumentStore::<WorkflowInstance<Value>>::open(
            state_dir.join("ha/repair_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        ha_repair_workflows
            .create(
                "repair-running",
                workflow_instance("repair-running", WorkflowPhase::Running, Value::Null),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        ha_repair_workflows
            .create(
                "repair-failed",
                workflow_instance("repair-failed", WorkflowPhase::Failed, Value::Null),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letters =
            DocumentStore::<Value>::open(state_dir.join("lifecycle/dead_letters.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        dead_letters
            .create("dlq-pending", json!({ "replayed": false }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        dead_letters
            .create("dlq-replayed", json!({ "replayed": true }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair_job_workflows = DocumentStore::<WorkflowInstance<Value>>::open(
            state_dir.join("lifecycle/repair_job_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        repair_job_workflows
            .create(
                "repair-active",
                workflow_instance(
                    "repair-active",
                    WorkflowPhase::Running,
                    json!({
                        "status": "pending_confirmation"
                    }),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        repair_job_workflows
            .create(
                "repair-failed",
                workflow_instance(
                    "repair-failed",
                    WorkflowPhase::Failed,
                    json!({
                        "status": "failed"
                    }),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair_jobs =
            DocumentStore::<Value>::open(state_dir.join("lifecycle/repair_jobs.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        repair_jobs
            .create(
                "repair-projection-completed",
                json!({
                    "status": "completed"
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let data_failovers = DocumentStore::<Value>::open(state_dir.join("data/failovers.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        data_failovers
            .create("data-failover-running", json!({ "state": "running" }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        data_failovers
            .create("data-failover-failed", json!({ "state": "failed" }))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let data_failover_workflows = DocumentStore::<WorkflowInstance<Value>>::open(
            state_dir.join("data/failover_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        data_failover_workflows
            .create(
                "data-failover-workflow",
                workflow_instance(
                    "data-failover-workflow",
                    WorkflowPhase::Running,
                    json!({ "target_region": "region-west" }),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migrations = DocumentStore::<Value>::open(state_dir.join("data/migrations.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        migrations
            .create(
                "migration-running",
                json!({
                    "state": "running",
                    "source_region": "region-east",
                    "target_region": "region-west"
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        migrations
            .create(
                "migration-failed",
                json!({
                    "state": "failed",
                    "source_region": "region-east",
                    "target_region": null
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    });
}

fn workflow_instance(id: &str, phase: WorkflowPhase, state: Value) -> WorkflowInstance<Value> {
    let created_at = parse_timestamp("2026-04-08T12:00:00Z");
    WorkflowInstance {
        id: String::from(id),
        workflow_kind: String::from("test.workflow"),
        subject_kind: String::from("test_subject"),
        subject_id: String::from(id),
        phase,
        current_step_index: None,
        steps: Vec::new(),
        created_at,
        updated_at: created_at,
        completed_at: None,
        next_attempt_at: None,
        runner_claim: None,
        state,
    }
}

fn scoped_metadata(region: Option<&str>, cell_id: Option<&str>) -> ResourceMetadata {
    let seed = format!("{}:{}", region.unwrap_or("none"), cell_id.unwrap_or("none"));
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Platform,
        Some(seed.clone()),
        sha256_hex(seed.as_bytes()),
    );
    if let Some(region) = region {
        metadata
            .annotations
            .insert(String::from("region"), String::from(region));
    }
    if let Some(cell_id) = cell_id {
        metadata
            .annotations
            .insert(String::from("cell_id"), String::from(cell_id));
    }
    metadata
}

fn parse_timestamp(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|error| panic!("{error}"))
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("{error}"))
        .block_on(future)
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
node_name = "test-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{DEFAULT_BOOTSTRAP_ADMIN_TOKEN}"

[placement]
region_name = "region-west"
cell_name = "cell-c"
"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
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

fn wait_for_fleet_ops_rollups(address: SocketAddr) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        last = request_json(address, "GET", "/observe/fleet-ops-rollups", None);
        if last["ha_readiness"]["total_regions"].as_u64() == Some(2)
            && last["ha_readiness"]["total_cells"].as_u64() == Some(3)
            && last["incident_state"]["total_incidents"].as_u64() == Some(3)
        {
            return last;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("fleet ops rollups did not stabilize in time: {last}");
}

fn find_object_by_field<'a>(items: &'a Value, field: &str, expected: &str) -> &'a Value {
    items
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value[field].as_str() == Some(expected))
        })
        .unwrap_or_else(|| panic!("missing object where {field}={expected}"))
}

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Value {
    let response = request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
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
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = is_idempotent_method(method);
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request(address, method, path, body) {
            Ok(response) => return response,
            Err(error) if allow_retry && is_transient_request_error(&error) => {
                last_error = Some(error);
                let exponent = attempt.min(5);
                let backoff_ms = 50_u64.saturating_mul(1_u64 << exponent).min(1_200);
                thread::sleep(Duration::from_millis(backoff_ms));
            }
            Err(error) => panic!("request {method} {path} failed: {error}"),
        }
    }
    let error = last_error.unwrap_or_else(|| Error::other("request failed after retries"));
    panic!("request {method} {path} failed after retries: {error}");
}

fn is_idempotent_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

fn is_transient_request_error(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::TimedOut
    ) || matches!(error.raw_os_error(), Some(11))
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
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAuthorization: Bearer {DEFAULT_BOOTSTRAP_ADMIN_TOKEN}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
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
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid http response framing"))?;
    let (head, body) = response.split_at(split + 4);
    let status_line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing http status line"))?;
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
