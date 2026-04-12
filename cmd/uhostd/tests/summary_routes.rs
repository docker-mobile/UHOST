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
fn summary_routes_are_operational_from_all_in_one() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one-summary.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping summary_routes_are_operational_from_all_in_one: loopback bind not permitted"
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
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let _guard = ChildGuard { child };

    wait_for_health(address);

    let _ = request_json(
        address,
        "POST",
        "/mail/domains",
        Some(r#"{"domain":"summary.example","zone_id":null}"#),
    );
    let _ = request_json(
        address,
        "POST",
        "/observe/activity",
        Some(r#"{"category":"request","summary":"summary smoke","correlation_id":null}"#),
    );
    let _ = request_json(
        address,
        "POST",
        "/observe/alert-rules",
        Some(r#"{"name":"summary-latency","expression":"latency_ms>200","severity":"high"}"#),
    );

    let data_summary = request_json(address, "GET", "/data/durability-summary", None);
    assert!(
        data_summary
            .get("database_count")
            .and_then(Value::as_u64)
            .is_some(),
        "durability summary missing database_count"
    );

    let mail_summary = request_json(address, "GET", "/mail/summary", None);
    assert_eq!(
        mail_summary["domain_count"].as_u64().unwrap_or_default(),
        1,
        "mail summary should count the created domain"
    );

    let observe_summary = request_json(address, "GET", "/observe/summary", None);
    assert_eq!(
        observe_summary["activity_count"]
            .as_u64()
            .unwrap_or_default(),
        1,
        "observe summary should count the recorded activity"
    );
    assert!(
        observe_summary
            .get("activity_category_counts")
            .and_then(Value::as_object)
            .and_then(|obj| obj.get("request"))
            .and_then(Value::as_u64)
            == Some(1),
        "request activity bucket should have one entry"
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
