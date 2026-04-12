use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::tempdir;
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::DocumentStore;
use uhost_types::{ChangeRequestId, OwnershipScope, ResourceMetadata};

const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";

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

fn test_child_stderr() -> Stdio {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

#[test]
fn ingress_flow_audit_preserves_steering_evidence_after_restart() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let allow_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let deny_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let config_path = temp.path().join("ingress-flow-audit.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping ingress_flow_audit_preserves_steering_evidence_after_restart: loopback bind not permitted"
        );
        return;
    };
    let Some(policy_target) = reserve_loopback_port() else {
        eprintln!(
            "skipping ingress_flow_audit_preserves_steering_evidence_after_restart: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir, policy_target);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));

    let first_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let allow_route_payload = json!({
        "hostname": "restart-allow.example.com",
        "protocol": "https",
        "tls_mode": "strict_https",
        "sticky_sessions": false,
        "backends": [
            {
                "target": "http://10.0.0.91:8080",
                "weight": 1,
                "region": "us-east-1",
                "cell": "use1-edge-a",
                "canary": false
            },
            {
                "target": "http://10.0.0.92:8080",
                "weight": 1,
                "region": "us-east-1",
                "cell": "use1-edge-a",
                "canary": true
            }
        ],
        "steering_policy": {
            "locality_mode": "cell",
            "fallback_to_any_healthy": true,
            "canary": {
                "traffic_percent": 100
            }
        },
        "change_request_id": allow_change_request_id
    })
    .to_string();
    let allow_route = request_json(
        address,
        "POST",
        "/ingress/routes",
        Some(&allow_route_payload),
    );
    assert!(
        allow_route["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing allow route id"))
            .starts_with("rte_")
    );

    let allow_evaluation = request_json(
        address,
        "POST",
        "/ingress/evaluate",
        Some(
            r#"{"hostname":"restart-allow.example.com","protocol":"https","client_ip":"198.51.100.177","session_key":"tenant-persist","preferred_region":"us-east-1","preferred_cell":"use1-edge-a"}"#,
        ),
    );
    assert!(allow_evaluation["admitted"].as_bool().unwrap_or(false));
    assert_eq!(
        allow_evaluation["selected_backend_id"].as_str(),
        Some("backend-2")
    );

    let deny_route_payload = json!({
        "hostname": "restart-deny.example.com",
        "protocol": "https",
        "tls_mode": "strict_https",
        "sticky_sessions": false,
        "backends": [
            {
                "target": "http://10.0.0.93:8080",
                "weight": 1,
                "region": "us-east-1",
                "cell": "use1-edge-a",
                "canary": false
            }
        ],
        "steering_policy": {
            "locality_mode": "region",
            "fallback_to_any_healthy": false,
            "canary": {
                "traffic_percent": 0
            }
        },
        "change_request_id": deny_change_request_id
    })
    .to_string();
    let deny_route = request_json(
        address,
        "POST",
        "/ingress/routes",
        Some(&deny_route_payload),
    );
    assert!(
        deny_route["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing deny route id"))
            .starts_with("rte_")
    );

    let deny_evaluation = request_json(
        address,
        "POST",
        "/ingress/evaluate",
        Some(
            r#"{"hostname":"restart-deny.example.com","protocol":"https","client_ip":"198.51.100.178","preferred_region":"eu-central-1"}"#,
        ),
    );
    assert!(!deny_evaluation["admitted"].as_bool().unwrap_or(true));
    assert_eq!(
        deny_evaluation["reason"].as_str(),
        Some("route steering policy found no backend candidates for preferred locality")
    );

    drop(first_guard);

    let _second_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let flow_audit = request_json(address, "GET", "/ingress/flow-audit", None);
    let flow_audit_entries = flow_audit
        .as_array()
        .unwrap_or_else(|| panic!("missing ingress flow audit array"));
    assert_eq!(flow_audit_entries.len(), 2);

    let allow_audit = find_audit_by_hostname(flow_audit_entries, "restart-allow.example.com");
    assert_allow_steering_audit_entry(allow_audit);

    let deny_audit = find_audit_by_hostname(flow_audit_entries, "restart-deny.example.com");
    assert_deny_steering_audit_entry(deny_audit);

    let filtered_allow_audit = request_json(
        address,
        "GET",
        "/ingress/flow-audit?hostname=restart-allow.example.com&verdict=allow",
        None,
    );
    let filtered_allow_entries = filtered_allow_audit
        .as_array()
        .unwrap_or_else(|| panic!("missing filtered allow ingress flow audit array"));
    assert_eq!(filtered_allow_entries.len(), 1);
    let filtered_allow_entry =
        find_audit_by_hostname(filtered_allow_entries, "restart-allow.example.com");
    assert_allow_steering_audit_entry(filtered_allow_entry);

    let filtered_deny_audit = request_json(
        address,
        "GET",
        "/ingress/flow-audit?hostname=restart-deny.example.com&verdict=deny",
        None,
    );
    let filtered_deny_entries = filtered_deny_audit
        .as_array()
        .unwrap_or_else(|| panic!("missing filtered deny ingress flow audit array"));
    assert_eq!(filtered_deny_entries.len(), 1);
    let filtered_deny_entry =
        find_audit_by_hostname(filtered_deny_entries, "restart-deny.example.com");
    assert_deny_steering_audit_entry(filtered_deny_entry);
}

fn spawn_uhostd(binary: &str, config_path: &Path) -> ChildGuard {
    let child = Command::new(binary)
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(test_child_stderr())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    ChildGuard { child }
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
        let normalized_state = state.trim().to_ascii_lowercase();
        let approved_by = matches!(normalized_state.as_str(), "approved" | "applied")
            .then(|| String::from("bootstrap-reviewer"));
        store
            .create(
                id.as_str(),
                SeedGovernanceChangeRequest {
                    id: id.clone(),
                    title: String::from("seeded ingress restart integration change request"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("bootstrap-admin"),
                    approved_by,
                    reviewer_comment: None,
                    required_approvals: 1,
                    state: normalized_state,
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

fn write_test_config(
    path: &Path,
    address: SocketAddr,
    state_dir: &Path,
    policy_target: SocketAddr,
) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "distributed"
node_name = "ingress-flow-audit-test-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{DEFAULT_BOOTSTRAP_ADMIN_TOKEN}"

[runtime]
process_role = "edge"

[runtime.forward_targets]
policy = "{policy_target}"
"#,
        state_dir.display(),
        base64url_encode(&[0x81; 32]),
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
    serde_json::from_slice(&response.body).unwrap_or_else(|error| {
        panic!(
            "invalid json response: {error}; body={}",
            String::from_utf8_lossy(&response.body)
        )
    })
}

fn find_audit_by_hostname<'a>(entries: &'a [Value], hostname: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| entry["hostname"].as_str() == Some(hostname))
        .unwrap_or_else(|| panic!("missing flow-audit entry for hostname {hostname}"))
}

fn assert_allow_steering_audit_entry(entry: &Value) {
    assert_eq!(entry["verdict"].as_str(), Some("allow"));
    assert_eq!(
        entry["selected_locality"].as_str(),
        Some("cell:use1-edge-a")
    );
    assert_eq!(entry["selected_canary_pool"].as_str(), Some("canary"));
    assert!(entry["steering_denial_reason"].is_null());
}

fn assert_deny_steering_audit_entry(entry: &Value) {
    assert_eq!(entry["verdict"].as_str(), Some("deny"));
    assert_eq!(
        entry["reason"].as_str(),
        Some("route steering policy found no backend candidates for preferred locality")
    );
    assert_eq!(
        entry["steering_denial_reason"].as_str(),
        Some("route steering policy found no backend candidates for preferred locality")
    );
    assert_eq!(
        entry["selected_locality"].as_str(),
        Some("region:eu-central-1")
    );
    assert_eq!(
        entry["selected_canary_pool"].as_str(),
        Some("not_evaluated")
    );
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
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing http version"))?;
    let status = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing http status"))?
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;

    Ok(RawResponse {
        status,
        body: body.to_vec(),
    })
}
