use std::collections::BTreeMap;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;
use uhost_core::base64url_encode;

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn runtime_preserves_representative_route_ownership() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let token = "integration-bootstrap-admin-token";
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_preserves_representative_route_ownership: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir, token);

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

    assert_eq!(request(address, "GET", "/healthz", None).status, 200);
    assert_eq!(request(address, "GET", "/readyz", None).status, 200);
    assert_eq!(request(address, "GET", "/metrics", None).status, 401);
    assert_eq!(
        request(address, "GET", "/runtime/topology", None).status,
        401
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/runtime/participants/tombstone",
            Some(r#"{"registration_id":"all_in_one:route-ownership-test-node"}"#),
        )
        .status,
        401
    );
    assert_eq!(
        request(
            address,
            "GET",
            "/runtime/participants/tombstone-history",
            None,
        )
        .status,
        401
    );
    assert_eq!(
        request(
            address,
            "GET",
            "/runtime/participants/tombstone-history/aggregated",
            None,
        )
        .status,
        401
    );
    assert_eq!(
        request(address, "GET", "/uvm/control/summary", None).status,
        401
    );
    assert_eq!(request(address, "GET", "/uvm/runtime", None).status, 401);
    assert_eq!(request(address, "GET", "/uvm/node", None).status, 401);
    assert_eq!(request(address, "GET", "/uvm/observe", None).status, 401);
    assert_eq!(request(address, "GET", "/uvm/outbox", None).status, 401);

    assert_eq!(
        request_json_with_admin_token(address, "GET", "/identity", None, token)["service"],
        "identity"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/control", None, token)["service"],
        "control"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/container", None, token)["service"],
        "container"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/uvm", None, token)["service"],
        "uvm-control"
    );
    assert_eq!(
        request_with_admin_token(address, "GET", "/uvm/control/summary", None, token).status,
        200
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/uvm/image", None, token)["service"],
        "uvm-image"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/uvm/runtime", None, token)["service"],
        "uvm-node"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/uvm/node", None, token)["service"],
        "uvm-node"
    );
    assert_eq!(
        request_json_with_admin_token(address, "GET", "/uvm/observe", None, token)["service"],
        "uvm-observe"
    );
    assert_eq!(
        request_with_admin_token(address, "GET", "/uvm/outbox", None, token).status,
        200
    );
}

#[test]
fn split_role_runtime_forwards_configured_non_local_route_families() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let controller_state_dir = temp.path().join("controller-state");
    let edge_state_dir = temp.path().join("edge-state");
    let worker_state_dir = temp.path().join("worker-state");
    fs::create_dir_all(&controller_state_dir).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(&edge_state_dir).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(&worker_state_dir).unwrap_or_else(|error| panic!("{error}"));
    let controller_config_path = temp.path().join("controller.toml");
    let edge_config_path = temp.path().join("edge.toml");
    let worker_config_path = temp.path().join("worker.toml");
    let Some(controller_address) = reserve_loopback_port() else {
        eprintln!(
            "skipping split_role_runtime_forwards_configured_non_local_route_families: loopback bind not permitted"
        );
        return;
    };
    let Some(edge_address) = reserve_loopback_port() else {
        eprintln!(
            "skipping split_role_runtime_forwards_configured_non_local_route_families: loopback bind not permitted"
        );
        return;
    };
    let Some(worker_address) = reserve_loopback_port() else {
        eprintln!(
            "skipping split_role_runtime_forwards_configured_non_local_route_families: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token-00000001";
    write_split_role_test_config(
        &controller_config_path,
        controller_address,
        &controller_state_dir,
        "route-forward-controller",
        "controller",
        token,
        &BTreeMap::from([
            (String::from("data"), worker_address),
            (String::from("dns"), edge_address),
            (String::from("ingress"), edge_address),
            (String::from("mail"), worker_address),
            (String::from("netsec"), worker_address),
            (String::from("storage"), worker_address),
        ]),
    );
    write_split_role_test_config(
        &edge_config_path,
        edge_address,
        &edge_state_dir,
        "route-forward-edge",
        "edge",
        token,
        &BTreeMap::from([
            (String::from("control"), controller_address),
            (String::from("container"), controller_address),
            (String::from("governance"), controller_address),
            (String::from("identity"), controller_address),
            (String::from("policy"), controller_address),
            (String::from("scheduler"), controller_address),
            (String::from("secrets"), controller_address),
            (String::from("tenancy"), controller_address),
            (String::from("uvm-control"), controller_address),
            (String::from("uvm-image"), controller_address),
            (String::from("uvm-observe"), controller_address),
        ]),
    );
    write_split_role_test_config(
        &worker_config_path,
        worker_address,
        &worker_state_dir,
        "route-forward-worker",
        "worker",
        token,
        &BTreeMap::from([
            (String::from("identity"), controller_address),
            (String::from("ingress"), edge_address),
        ]),
    );

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let controller_child = Command::new(&binary)
        .arg("--config")
        .arg(&controller_config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn controller uhostd: {error}"));
    let _controller_guard = ChildGuard {
        child: controller_child,
    };
    wait_for_health(controller_address);

    let edge_child = Command::new(&binary)
        .arg("--config")
        .arg(&edge_config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn edge uhostd: {error}"));
    let _edge_guard = ChildGuard { child: edge_child };
    wait_for_health(edge_address);

    let worker_child = Command::new(&binary)
        .arg("--config")
        .arg(&worker_config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn worker uhostd: {error}"));
    let _worker_guard = ChildGuard {
        child: worker_child,
    };
    wait_for_health(worker_address);

    for (path, service_name) in [
        ("/identity", "identity"),
        ("/tenancy", "tenancy"),
        ("/control", "control"),
        ("/container", "container"),
        ("/scheduler", "scheduler"),
        ("/policy", "policy"),
        ("/governance", "governance"),
        ("/secrets", "secrets"),
        ("/uvm", "uvm-control"),
        ("/uvm/image", "uvm-image"),
        ("/uvm/observe", "uvm-observe"),
    ] {
        assert_eq!(
            request_json_with_admin_token(edge_address, "GET", path, None, token)["service"],
            service_name
        );
    }

    for (path, service_name) in [
        ("/dns", "dns"),
        ("/ingress", "ingress"),
        ("/data", "data"),
        ("/mail", "mail"),
        ("/netsec", "netsec"),
        ("/storage", "storage"),
    ] {
        assert_eq!(
            request_json_with_admin_token(controller_address, "GET", path, None, token)["service"],
            service_name
        );
    }

    for (path, service_name) in [("/identity", "identity"), ("/ingress", "ingress")] {
        assert_eq!(
            request_json_with_admin_token(worker_address, "GET", path, None, token)["service"],
            service_name
        );
    }
}

#[test]
fn node_adjacent_runtime_forwards_shared_group_non_local_route_families() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let controller_state_dir = temp.path().join("controller-state");
    let node_adjacent_state_dir = temp.path().join("node-adjacent-state");
    fs::create_dir_all(&controller_state_dir).unwrap_or_else(|error| panic!("{error}"));
    fs::create_dir_all(&node_adjacent_state_dir).unwrap_or_else(|error| panic!("{error}"));
    let controller_config_path = temp.path().join("controller.toml");
    let node_adjacent_config_path = temp.path().join("node-adjacent.toml");
    let Some(controller_address) = reserve_loopback_port() else {
        eprintln!(
            "skipping node_adjacent_runtime_forwards_shared_group_non_local_route_families: loopback bind not permitted"
        );
        return;
    };
    let Some(node_adjacent_address) = reserve_loopback_port() else {
        eprintln!(
            "skipping node_adjacent_runtime_forwards_shared_group_non_local_route_families: loopback bind not permitted"
        );
        return;
    };
    let token = "integration-bootstrap-admin-token-00000002";
    write_split_role_test_config(
        &controller_config_path,
        controller_address,
        &controller_state_dir,
        "route-forward-controller",
        "controller",
        token,
        &BTreeMap::new(),
    );
    write_split_role_test_config(
        &node_adjacent_config_path,
        node_adjacent_address,
        &node_adjacent_state_dir,
        "route-forward-node-adjacent",
        "node_adjacent",
        token,
        &BTreeMap::from([
            (String::from("control"), controller_address),
            (String::from("ha"), controller_address),
            (String::from("lifecycle"), controller_address),
            (String::from("scheduler"), controller_address),
            (String::from("uvm-control"), controller_address),
            (String::from("uvm-image"), controller_address),
            (String::from("uvm-observe"), controller_address),
        ]),
    );

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let controller_child = Command::new(&binary)
        .arg("--config")
        .arg(&controller_config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn controller uhostd: {error}"));
    let _controller_guard = ChildGuard {
        child: controller_child,
    };
    wait_for_health(controller_address);

    let node_adjacent_child = Command::new(binary)
        .arg("--config")
        .arg(&node_adjacent_config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn node-adjacent uhostd: {error}"));
    let _node_adjacent_guard = ChildGuard {
        child: node_adjacent_child,
    };
    wait_for_health(node_adjacent_address);

    for (path, service_name) in [
        ("/node", "node"),
        ("/uvm/node", "uvm-node"),
        ("/control", "control"),
        ("/scheduler", "scheduler"),
        ("/ha", "ha"),
        ("/lifecycle", "lifecycle"),
        ("/uvm", "uvm-control"),
        ("/uvm/image", "uvm-image"),
        ("/uvm/observe", "uvm-observe"),
    ] {
        assert_eq!(
            request_json_with_admin_token(node_adjacent_address, "GET", path, None, token)["service"],
            service_name
        );
    }
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
node_name = "route-ownership-test-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{token}"
"#,
        state_dir.display(),
        base64url_encode(&[0x24; 32]),
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn write_split_role_test_config(
    path: &Path,
    address: SocketAddr,
    state_dir: &Path,
    node_name: &str,
    process_role: &str,
    token: &str,
    forward_targets: &BTreeMap<String, SocketAddr>,
) {
    let forward_targets = if forward_targets.is_empty() {
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
mode = "distributed"
node_name = "{node_name}"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{token}"

[runtime]
process_role = "{process_role}"{forward_targets}
"#,
        state_dir.display(),
        base64url_encode(&[0x91; 32]),
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

fn request_json_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: &str,
) -> Value {
    let response = request_with_admin_token(address, method, path, body, admin_token);
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

fn request(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> RawResponse {
    try_request_with_admin_token(address, method, path, body, None)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn request_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: &str,
) -> RawResponse {
    try_request_with_admin_token(address, method, path, body, Some(admin_token))
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<RawResponse, Error> {
    try_request_with_admin_token(address, method, path, body, None)
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
