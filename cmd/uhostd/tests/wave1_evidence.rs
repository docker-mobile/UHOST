use std::collections::BTreeMap;
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
use uhost_types::{ChangeRequestId, NodeId, OwnershipScope, ResourceMetadata};

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

#[test]
fn wave1_evidence_refresh_exercises_backend_and_uvm_parity_seams() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let ingress_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping wave1_evidence_refresh_exercises_backend_and_uvm_parity_seams: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token";
    write_test_config(&config_path, address, &state_dir, Some(token));

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

    let create_identity_body = serde_json::to_vec(&json!({
        "subject": "  svc:Build-Runner  ",
        "display_name": "  Build Runner  ",
        "audiences": ["secrets", "IDENTITY", "secrets"],
        "ttl_seconds": 900,
    }))
    .unwrap_or_else(|error| panic!("{error}"));
    let created_identity = request(
        address,
        "POST",
        "/identity/workload-identities",
        Some(("application/json", create_identity_body.as_slice())),
        Some(token),
    );
    assert_eq!(created_identity.status, 201);
    assert!(created_identity.headers.contains_key("etag"));
    assert_eq!(
        created_identity
            .headers
            .get("x-record-version")
            .map(String::as_str),
        Some("1")
    );
    let created_identity_payload: Value = serde_json::from_slice(&created_identity.body)
        .unwrap_or_else(|error| panic!("invalid workload identity response: {error}"));
    let created_identity_id = created_identity_payload["identity"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload identity id"));
    assert_eq!(
        created_identity_payload["identity"]["principal"]["kind"],
        "workload"
    );
    assert_eq!(
        created_identity_payload["identity"]["principal"]["subject"],
        "svc:build-runner"
    );
    assert_eq!(
        created_identity_payload["identity"]["audiences"],
        json!(["secrets", "identity"])
    );

    let identities = request_json(
        address,
        "GET",
        "/identity/workload-identities",
        None,
        Some(token),
    );
    assert!(
        identities
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .any(|item| item.get("id").and_then(Value::as_str) == Some(created_identity_id))
            })
            .unwrap_or(false)
    );

    let allow_policy = request_json(
        address,
        "POST",
        "/policy/policies",
        Some(json!({
            "resource_kind": "service",
            "action": "deploy",
            "effect": "allow",
            "selector": {
                "env": "prod",
                "team": "payments"
            }
        })),
        Some(token),
    );
    let deny_policy = request_json(
        address,
        "POST",
        "/policy/policies",
        Some(json!({
            "resource_kind": "service",
            "action": "deploy",
            "effect": "deny",
            "selector": {
                "env": "prod",
                "compliance": "blocked"
            }
        })),
        Some(token),
    );
    let evaluation = request_json(
        address,
        "POST",
        "/policy/evaluate",
        Some(json!({
            "resource_kind": "service",
            "action": "deploy",
            "selector": {
                "env": "prod",
                "team": "payments",
                "compliance": "blocked"
            }
        })),
        Some(token),
    );
    assert_eq!(evaluation["decision"], "deny");
    assert_eq!(evaluation["explanation"]["actor"], "bootstrap_admin");
    assert_eq!(evaluation["explanation"]["principal"]["kind"], "operator");
    assert_eq!(
        evaluation["explanation"]["principal"]["subject"],
        "bootstrap_admin"
    );
    assert_eq!(
        evaluation["explanation"]["principal"]["credential_id"],
        "bootstrap_admin_token"
    );
    assert_array_contains_string(
        &evaluation["explanation"]["matched_policy_ids"],
        allow_policy["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing allow policy id")),
    );
    assert_array_contains_string(
        &evaluation["explanation"]["matched_policy_ids"],
        deny_policy["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing deny policy id")),
    );
    assert_array_contains_string(
        &evaluation["explanation"]["decisive_policy_ids"],
        deny_policy["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing deny policy id")),
    );
    assert!(
        evaluation["explanation"]["rule_evaluations"]
            .as_array()
            .map(|items| items.len() >= 2)
            .unwrap_or(false)
    );

    let zone = request_json(
        address,
        "POST",
        "/dns/zones",
        Some(json!({ "domain": "example.com" })),
        Some(token),
    );
    let inspection_profile = request_json(
        address,
        "POST",
        "/netsec/inspection-profiles",
        Some(json!({
            "name": "edge-prod",
            "blocked_countries": ["RU"],
            "min_waf_score": 600,
            "max_bot_score": 350,
            "ddos_mode": "mitigate"
        })),
        Some(token),
    );
    let ingress_route = request_json(
        address,
        "POST",
        "/ingress/routes",
        Some(json!({
            "hostname": "api.example.com",
            "protocol": "https",
            "tls_mode": "strict_https",
            "backends": [
                { "target": "http://10.0.0.10:8080", "weight": 1 },
                { "target": "http://10.0.0.11:8080", "weight": 1 }
            ],
            "change_request_id": ingress_change_request_id,
            "publication": {
                "exposure": "public",
                "dns_binding": {
                    "zone_id": zone["id"].as_str().unwrap_or_else(|| panic!("missing zone id"))
                },
                "security_policy": {
                    "inspection_profile_id": inspection_profile["id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("missing inspection profile id"))
                }
            }
        })),
        Some(token),
    );
    assert_eq!(ingress_route["publication"]["exposure"], "public");
    assert_eq!(
        ingress_route["publication"]["dns_binding"]["zone_id"],
        zone["id"]
    );
    assert_eq!(
        ingress_route["publication"]["security_policy"]["inspection_profile_id"],
        inspection_profile["id"]
    );

    let ingress_evaluation = request_json(
        address,
        "POST",
        "/ingress/evaluate",
        Some(json!({
            "hostname": "api.example.com",
            "protocol": "https",
            "client_ip": "203.0.113.10",
            "session_key": "wave1-evidence-session"
        })),
        Some(token),
    );
    assert!(ingress_evaluation["admitted"].as_bool().unwrap_or(false));
    let ingress_flow_summary = request_json(
        address,
        "GET",
        "/ingress/flow-audit/summary",
        None,
        Some(token),
    );
    assert!(ingress_flow_summary["total"].as_u64().unwrap_or_default() >= 1);

    let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let capability = request_json(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": node_id.to_string(),
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 1,
            "supports_secure_boot": false,
            "supports_live_migration": false,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        Some(token),
    );
    let preflight = request_json(
        address,
        "POST",
        "/uvm/runtime/preflight",
        Some(json!({
            "capability_id": capability["id"].as_str().unwrap_or_else(|| panic!("missing capability id")),
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "vcpu": 2,
            "memory_mb": 2048,
            "migration_policy": "cold_only",
            "require_secure_boot": false,
            "requires_live_migration": false,
            "compatibility_requirement": {
                "guest_architecture": "x86_64",
                "machine_family": "general_purpose_pci",
                "guest_profile": "linux_standard",
                "boot_device": "disk",
                "claim_tier": "compatible"
            }
        })),
        Some(token),
    );
    assert!(preflight["legal_allowed"].as_bool().unwrap_or(false));
    assert!(preflight["placement_admitted"].as_bool().unwrap_or(false));
    assert!(
        preflight["compatibility_assessment"]["supported"]
            .as_bool()
            .unwrap_or(false)
    );
    assert_array_contains_string(
        &preflight["compatibility_assessment"]["matched_backends"],
        "software_dbt",
    );
    assert!(
        preflight["compatibility_assessment"]["evidence"]
            .as_array()
            .map(|rows| {
                rows.iter().any(|row| {
                    row.get("source").and_then(Value::as_str) == Some("image_contract")
                        && row
                            .get("summary")
                            .and_then(Value::as_str)
                            .is_some_and(|summary| {
                                summary.contains("matched the requested runtime shape")
                            })
                })
            })
            .unwrap_or(false)
    );
}

fn assert_array_contains_string(value: &Value, expected: &str) {
    assert!(
        value
            .as_array()
            .map(|items| items.iter().any(|item| item.as_str() == Some(expected)))
            .unwrap_or(false),
        "expected array to contain `{expected}`, got {value}`"
    );
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
                    title: String::from("seeded integration change request"),
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path, token: Option<&str>) {
    let security = token.map_or_else(String::new, |token| {
        format!(
            r#"

[security]
bootstrap_admin_token = "{token}"
"#
        )
    });
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "wave1-evidence-test-node"

[secrets]
master_key = "{}"
{}"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
        security,
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request(address, "GET", "/healthz", None, None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> Value {
    let payload =
        body.map(|value| serde_json::to_vec(&value).unwrap_or_else(|error| panic!("{error}")));
    let response = request(
        address,
        method,
        path,
        payload
            .as_ref()
            .map(|bytes| ("application/json", bytes.as_slice())),
        token,
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
    headers: BTreeMap<String, String>,
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

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: Option<&str>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (content_type, payload) = body.unwrap_or(("application/json", b""));

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
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
    let head_text = std::str::from_utf8(head)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
    let mut lines = head_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let _http_version = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid status code"))?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    Ok(RawResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}
