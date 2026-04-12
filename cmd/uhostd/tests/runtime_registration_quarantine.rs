use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use uhost_core::base64url_encode;
use uhost_store::{
    CellDirectoryCollection, CellDirectoryRecord, CellParticipantLeaseState, CellParticipantRecord,
    CellParticipantState, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
    LeaseRegistrationCollection, LeaseRegistrationRecord, RegionDirectoryRecord,
};

const ALL_IN_ONE_SERVICE_GROUPS: &[&str] = &[
    "control",
    "data_and_messaging",
    "edge",
    "governance_and_operations",
    "identity_and_policy",
    "uvm",
];
const RUNTIME_QUARANTINE_TOKEN: &str = "integration-bootstrap-admin-token-runtime-quarantine";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn runtime_quarantines_conflicting_registrations_from_service_group_resolution() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap_or_else(|error| panic!("{error}"));
    seed_conflicting_all_in_one_peer(&state_dir).await;

    let Some((address, _guard)) = spawn_runtime_quarantine_daemon(
        &temp,
        &state_dir,
        "runtime_quarantines_conflicting_registrations_from_service_group_resolution",
    ) else {
        return;
    };

    wait_for_health(address);

    let topology = request_json_with_admin_token(
        address,
        "GET",
        "/runtime/topology",
        None,
        RUNTIME_QUARANTINE_TOKEN,
    );
    let service_group_directory = topology["service_group_directory"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_group_directory array"));
    let edge = service_group_directory
        .iter()
        .find(|entry| entry["group"] == "edge")
        .unwrap_or_else(|| panic!("missing edge service-group directory entry"));

    assert_eq!(
        edge["conflict_state"],
        json!("multiple_healthy_registrations")
    );
    assert_eq!(edge["resolved_registration_ids"], json!([]));
    assert_eq!(
        edge["quarantine_summaries"],
        json!([{
            "reason": "healthy_conflict",
            "registration_count": 2
        }])
    );
    let edge_registrations = edge["registrations"]
        .as_array()
        .unwrap_or_else(|| panic!("missing edge registrations"));
    assert_eq!(edge_registrations.len(), 2);
    assert!(
        edge_registrations
            .iter()
            .all(|registration| registration["healthy"] == json!(false)),
        "conflicting edge registrations should be quarantined from healthy resolution"
    );

    let stored_directory = read_runtime_service_group_directory_record(&state_dir);
    let stored_edge = stored_directory["value"]["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored service-group entries"))
        .iter()
        .find(|entry| entry["group"] == "edge")
        .unwrap_or_else(|| panic!("missing stored edge service-group directory entry"));
    assert_eq!(
        stored_edge["conflict_state"],
        json!("multiple_healthy_registrations")
    );
    assert_eq!(stored_edge["resolved_registration_ids"], json!([]));
    let stored_edge_registrations = stored_edge["registrations"]
        .as_array()
        .unwrap_or_else(|| panic!("missing stored edge registrations"));
    assert_eq!(stored_edge_registrations.len(), 2);
    assert!(
        stored_edge_registrations
            .iter()
            .all(|registration| registration["healthy"] == json!(false)),
        "persisted conflicting edge registrations should remain quarantined"
    );
}

#[tokio::test]
async fn runtime_topology_reports_invalid_link_quarantine_summaries() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap_or_else(|error| panic!("{error}"));
    seed_impossible_runtime_link_peer(&state_dir).await;

    let Some((address, _guard)) = spawn_runtime_quarantine_daemon(
        &temp,
        &state_dir,
        "runtime_topology_reports_invalid_link_quarantine_summaries",
    ) else {
        return;
    };

    wait_for_health(address);

    let topology = request_json_with_admin_token(
        address,
        "GET",
        "/runtime/topology",
        None,
        RUNTIME_QUARANTINE_TOKEN,
    );
    let service_group_directory = topology["service_group_directory"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_group_directory array"));
    let data = service_group_directory
        .iter()
        .find(|entry| entry["group"] == "data_and_messaging")
        .unwrap_or_else(|| panic!("missing data_and_messaging service-group directory entry"));

    assert_eq!(data["conflict_state"], json!("no_conflict"));
    assert_eq!(
        data["resolved_registration_ids"],
        json!(["all_in_one:runtime-quarantine-node"])
    );
    assert_eq!(
        data["quarantine_summaries"],
        json!([{
            "reason": "invalid_runtime_registration_link",
            "registration_count": 1
        }])
    );
    let data_registrations = data["registrations"]
        .as_array()
        .unwrap_or_else(|| panic!("missing data_and_messaging registrations"));
    let quarantined_registration = data_registrations
        .iter()
        .find(|registration| registration["registration_id"] == "controller:node-b")
        .unwrap_or_else(|| panic!("missing quarantined invalid-link registration"));
    assert_eq!(
        quarantined_registration["subject_id"],
        json!("controller:node-b")
    );
    assert_eq!(
        quarantined_registration["lease_registration_id"],
        json!("worker:node-b")
    );
    assert_eq!(quarantined_registration["healthy"], json!(false));
    assert_eq!(quarantined_registration["drain_intent"], json!("draining"));
    assert_eq!(
        quarantined_registration["lease_freshness"],
        json!("expired")
    );
}

#[tokio::test]
async fn runtime_topology_omits_quarantine_summaries_for_healthy_groups() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    let runtime_dir = state_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap_or_else(|error| panic!("{error}"));

    let Some((address, _guard)) = spawn_runtime_quarantine_daemon(
        &temp,
        &state_dir,
        "runtime_topology_omits_quarantine_summaries_for_healthy_groups",
    ) else {
        return;
    };

    wait_for_health(address);

    let topology = request_json_with_admin_token(
        address,
        "GET",
        "/runtime/topology",
        None,
        RUNTIME_QUARANTINE_TOKEN,
    );
    let service_group_directory = topology["service_group_directory"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_group_directory array"));
    assert!(
        !service_group_directory.is_empty(),
        "healthy runtime topology should still publish service-group entries"
    );
    assert!(
        service_group_directory.iter().all(|entry| {
            entry
                .get("quarantine_summaries")
                .is_none_or(|value| value == &json!([]))
        }),
        "healthy runtime topology should keep quarantine_summaries absent or empty outside the dedicated quarantine path"
    );
}

async fn seed_conflicting_all_in_one_peer(state_dir: &Path) {
    let registration_store = LeaseRegistrationCollection::open_local(
        state_dir.join("runtime").join("process-registrations.json"),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let cell_directory_store =
        CellDirectoryCollection::open_local(state_dir.join("runtime").join("cell-directory.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

    let peer_registration = LeaseRegistrationRecord::new(
        "all_in_one:peer-node",
        "runtime_process",
        "all_in_one:peer-node",
        "all_in_one",
        Some(String::from("peer-node")),
        15,
    )
    .with_readiness(LeaseReadiness::Ready)
    .with_drain_intent(LeaseDrainIntent::Serving);
    registration_store
        .upsert(
            peer_registration.registration_id.as_str(),
            peer_registration.clone(),
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let peer_participant = CellParticipantRecord::new(
        peer_registration.registration_id.clone(),
        "runtime_process",
        peer_registration.subject_id.clone(),
        peer_registration.role.clone(),
    )
    .with_node_name("peer-node")
    .with_service_groups(ALL_IN_ONE_SERVICE_GROUPS.iter().copied())
    .with_lease_registration_id(peer_registration.registration_id.clone())
    .with_state(CellParticipantState::new(
        LeaseReadiness::Ready,
        LeaseDrainIntent::Serving,
        CellParticipantLeaseState::new(
            peer_registration.lease_renewed_at,
            peer_registration.lease_expires_at,
            peer_registration.lease_duration_seconds,
            LeaseFreshness::Fresh,
        ),
    ));
    cell_directory_store
        .upsert(
            "local:local-cell",
            CellDirectoryRecord::new(
                "local:local-cell",
                "local-cell",
                RegionDirectoryRecord::new("local", "local"),
            )
            .with_participant(peer_participant),
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
}

async fn seed_impossible_runtime_link_peer(state_dir: &Path) {
    let registration_store = LeaseRegistrationCollection::open_local(
        state_dir.join("runtime").join("process-registrations.json"),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let cell_directory_store =
        CellDirectoryCollection::open_local(state_dir.join("runtime").join("cell-directory.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

    let peer_registration = LeaseRegistrationRecord::new(
        "worker:node-b",
        "runtime_process",
        "worker:node-b",
        "worker",
        Some(String::from("node-b")),
        15,
    )
    .with_readiness(LeaseReadiness::Ready)
    .with_drain_intent(LeaseDrainIntent::Serving);
    let peer_registration_id = peer_registration.registration_id.clone();
    registration_store
        .upsert(peer_registration_id.as_str(), peer_registration, None)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let now = time::OffsetDateTime::now_utc();
    let stale_peer = CellParticipantRecord::new(
        "controller:node-b",
        "runtime_process",
        "controller:node-b",
        "controller",
    )
    .with_node_name("node-b")
    .with_service_groups(["data_and_messaging"])
    .with_lease_registration_id("worker:node-b")
    .with_state(CellParticipantState::new(
        LeaseReadiness::Ready,
        LeaseDrainIntent::Serving,
        CellParticipantLeaseState::new(
            now,
            now + time::Duration::seconds(15),
            15,
            LeaseFreshness::Fresh,
        ),
    ));
    cell_directory_store
        .upsert(
            "local:local-cell",
            CellDirectoryRecord::new(
                "local:local-cell",
                "local-cell",
                RegionDirectoryRecord::new("local", "local"),
            )
            .with_participant(stale_peer),
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
}

fn spawn_runtime_quarantine_daemon(
    temp: &TempDir,
    state_dir: &Path,
    skip_name: &str,
) -> Option<(SocketAddr, ChildGuard)> {
    let config_path = temp.path().join("runtime-registration-quarantine.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!("skipping {skip_name}: loopback bind not permitted");
        return None;
    };
    write_test_config(&config_path, address, state_dir, RUNTIME_QUARANTINE_TOKEN);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    Some((address, ChildGuard { child }))
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path, token: &str) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "runtime-quarantine-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{token}"
"#,
        state_dir.display(),
        base64url_encode(&[0x52; 32]),
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request_with_admin_token(address, "GET", "/healthz", None, None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

fn request_json_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: &str,
) -> Value {
    let response = try_request_with_admin_token(address, method, path, body, Some(admin_token))
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"));
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

fn try_request_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: Option<&str>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let payload = body.unwrap_or("").as_bytes();

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        payload.len()
    );
    if let Some(admin_token) = admin_token {
        request.push_str(format!("Authorization: Bearer {admin_token}\r\n").as_str());
    }
    request.push_str("\r\n");
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

fn read_runtime_service_group_directory_record(state_dir: &Path) -> Value {
    let raw = fs::read_to_string(
        state_dir
            .join("runtime")
            .join("service-group-directory.json"),
    )
    .unwrap_or_else(|error| {
        panic!("failed to read runtime service-group directory store: {error}")
    });
    let collection: Value = serde_json::from_str(&raw).unwrap_or_else(|error| {
        panic!("invalid runtime service-group directory store json: {error}")
    });
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get("local:local-cell"))
        .cloned()
        .unwrap_or_else(|| {
            panic!("runtime service-group directory store should contain local cell record")
        })
}
