use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use uhost_core::base64url_encode;
use uhost_types::NodeId;

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
fn anti_entropy_reconcile_route_is_idempotent_in_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("ha-anti-entropy-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping anti_entropy_reconcile_route_is_idempotent_in_runtime: loopback bind not permitted"
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

    let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let seeded_node_ids = vec![first.clone(), second.clone()];

    let _ = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(json!({
            "node_id": first.to_string(),
            "role": "active",
            "healthy": true,
        })),
    );
    let _ = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(json!({
            "node_id": second.to_string(),
            "role": "active",
            "healthy": true,
        })),
    );

    let workflows_after_role_updates = request_json(address, "GET", "/ha/repair-workflows", None);
    let initial_workflow_items = workflows_after_role_updates
        .as_array()
        .unwrap_or_else(|| panic!("repair workflows route should return an array"));
    assert_eq!(initial_workflow_items.len(), 1);
    assert_eq!(
        initial_workflow_items[0]["phase"].as_str(),
        Some("completed")
    );
    assert_eq!(
        initial_workflow_items[0]["state"]["drift_kind"].as_str(),
        Some("dual_active")
    );
    let workflow_id = initial_workflow_items[0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing repair workflow id"))
        .to_owned();

    let first_reconcile = request_json(address, "POST", "/ha/anti-entropy/reconcile", None);
    assert!(first_reconcile.is_null());

    let second_reconcile = request_json(address, "POST", "/ha/anti-entropy/reconcile", None);
    assert!(second_reconcile.is_null());

    let workflows_after = request_json(address, "GET", "/ha/repair-workflows", None);
    let workflow_items = workflows_after
        .as_array()
        .unwrap_or_else(|| panic!("repair workflows route should return an array"));
    assert_eq!(workflow_items.len(), 1);
    assert_eq!(workflow_items[0]["id"].as_str(), Some(workflow_id.as_str()));
    assert_eq!(workflow_items[0]["phase"].as_str(), Some("completed"));

    let roles = request_json(address, "GET", "/ha/roles", None);
    let role_items = roles
        .as_array()
        .unwrap_or_else(|| panic!("roles route should return an array"));
    assert_eq!(role_items.len(), 2);
    assert_eq!(
        role_items
            .iter()
            .filter(|record| record["role"].as_str() == Some("active"))
            .count(),
        1
    );
    for node_id in &seeded_node_ids {
        assert!(
            role_items
                .iter()
                .any(|record| record["node_id"].as_str() == Some(node_id.as_str())),
            "missing seeded node {node_id} after runtime repair execution"
        );
    }

    let outbox = request_json(address, "GET", "/ha/outbox", None);
    let outbox_items = outbox
        .as_array()
        .unwrap_or_else(|| panic!("ha outbox route should return an array"));
    assert_eq!(
        count_outbox_event_type(outbox_items, "ha.anti_entropy.repair.enqueued.v1"),
        1
    );
    assert_eq!(
        count_outbox_event_type(outbox_items, "ha.anti_entropy.repair.completed.v1"),
        1
    );
    assert_eq!(
        count_outbox_event_type(outbox_items, "ha.anti_entropy.repair.resolved.v1"),
        0
    );
}

fn count_outbox_event_type(records: &[Value], event_type: &str) -> usize {
    records
        .iter()
        .filter(|record| record["payload"]["header"]["event_type"].as_str() == Some(event_type))
        .count()
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
node_name = "anti-entropy-test-node"

[secrets]
master_key = "{}"
"#,
        state_dir.display(),
        base64url_encode(&[0x5a; 32]),
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
