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
fn runtime_idempotency_journal_replays_response_after_restart() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("idempotency-config.toml");
    let token = "integration-bootstrap-admin-token";
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping runtime_idempotency_journal_replays_response_after_restart: loopback bind not permitted"
        );
        return;
    };
    write_test_config_with_token(&config_path, address, &state_dir, token);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));

    let first_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let idempotency_key = "user-create-1";
    let request_body = r#"{"email":"idem@example.com","display_name":"Idem","password":"correct horse battery staple"}"#;
    let created = request_json_with_bearer_and_idempotency_key(
        address,
        "POST",
        "/identity/users",
        Some(request_body),
        token,
        idempotency_key,
    );
    let created_id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created user id"))
        .to_owned();

    drop(first_guard);

    let _second_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let replayed = request_json_with_bearer_and_idempotency_key(
        address,
        "POST",
        "/identity/users",
        Some(request_body),
        token,
        idempotency_key,
    );
    assert_eq!(
        replayed["id"].as_str(),
        Some(created_id.as_str()),
        "replayed response should return the original created user",
    );

    let users = request_json_with_bearer_token(address, "GET", "/identity/users", None, token);
    let user_ids = users
        .as_array()
        .unwrap_or_else(|| panic!("missing user list"))
        .iter()
        .filter_map(|user| user.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(user_ids, vec![created_id.as_str()]);
}

fn spawn_uhostd(binary: &str, config_path: &Path) -> ChildGuard {
    let child = Command::new(binary)
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
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

fn write_test_config_with_token(path: &Path, address: SocketAddr, state_dir: &Path, token: &str) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "idempotency-test-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{token}"
"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request(address, "GET", "/healthz", None, &[])
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
) -> Value {
    request_json_with_headers(
        address,
        method,
        path,
        body,
        &[("Authorization", format!("Bearer {token}"))],
    )
}

fn request_json_with_bearer_and_idempotency_key(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
    idempotency_key: &str,
) -> Value {
    request_json_with_headers(
        address,
        method,
        path,
        body,
        &[
            ("Authorization", format!("Bearer {token}")),
            ("Idempotency-Key", idempotency_key.to_owned()),
        ],
    )
}

fn request_json_with_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &[(&str, String)],
) -> Value {
    let response = try_request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        headers,
    )
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

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    headers: &[(&str, String)],
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let extra_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n{extra_headers}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
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
