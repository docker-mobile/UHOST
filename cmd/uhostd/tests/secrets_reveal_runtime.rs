use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use uhost_core::base64url_encode;

const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";

struct ChildGuard {
    child: Child,
}

struct ChildStderr {
    sink: Stdio,
    path: Option<PathBuf>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn test_child_stderr(temp_dir: &Path) -> ChildStderr {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        ChildStderr {
            sink: Stdio::inherit(),
            path: None,
        }
    } else {
        let path = temp_dir.join("uhostd.stderr.log");
        let file = fs::File::create(&path)
            .unwrap_or_else(|error| panic!("failed to create stderr capture file: {error}"));
        ChildStderr {
            sink: Stdio::from(file),
            path: Some(path),
        }
    }
}

#[test]
fn routed_secret_reveal_grant_flows_work_through_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping routed_secret_reveal_grant_flows_work_through_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child_stderr = test_child_stderr(temp.path());
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(child_stderr.sink)
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let mut guard = ChildGuard { child };

    wait_for_health(address, &mut guard.child, child_stderr.path.as_deref());

    let ready = request_json(address, "GET", "/readyz", None);
    assert_eq!(
        ready["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing readyz status")),
        "ready"
    );

    let approval_secret = request_json(
        address,
        "POST",
        "/secrets/items",
        Some(
            &json!({
                "name": "approval-secret",
                "value": "approval-runtime-value"
            })
            .to_string(),
        ),
    );
    let approval_secret_id = required_string(&approval_secret, "id").to_owned();
    let (approval_status, approval_grant) = request_json_with_status(
        address,
        "POST",
        &format!("/secrets/items/{approval_secret_id}/reveal/approvals"),
        Some(
            &json!({
                "reason": "runtime approval verification"
            })
            .to_string(),
        ),
    );
    assert_eq!(
        approval_status, 201,
        "unexpected approval grant: {approval_grant}"
    );
    let approval_grant_id = required_string(&approval_grant, "id").to_owned();
    assert_eq!(
        approval_grant["secret_id"].as_str(),
        Some(approval_secret_id.as_str())
    );
    assert_eq!(approval_grant["grant_kind"].as_str(), Some("approval"));
    assert_eq!(
        approval_grant["reason"].as_str(),
        Some("runtime approval verification")
    );
    assert_eq!(approval_grant["reveal_count"].as_u64(), Some(0));
    assert!(approval_grant["expires_at"].is_null());

    let (approval_reveal_status, approval_reveal) = request_json_with_status(
        address,
        "POST",
        &format!("/secrets/items/{approval_secret_id}/reveal/grants/{approval_grant_id}"),
        None,
    );
    assert_eq!(
        approval_reveal_status, 200,
        "unexpected approval reveal: {approval_reveal}"
    );
    assert_eq!(
        approval_reveal["value"].as_str(),
        Some("approval-runtime-value")
    );

    let approval_reuse = request(
        address,
        "POST",
        &format!("/secrets/items/{approval_secret_id}/reveal/grants/{approval_grant_id}"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(approval_reuse.status, 409);
    let approval_reuse_body = json_from_bytes(&approval_reuse.body);
    assert_eq!(
        approval_reuse_body["error"]["message"].as_str(),
        Some("secret reveal approval has already been used")
    );

    let lease_secret = request_json(
        address,
        "POST",
        "/secrets/items",
        Some(
            &json!({
                "name": "lease-secret",
                "value": "lease-runtime-value"
            })
            .to_string(),
        ),
    );
    let lease_secret_id = required_string(&lease_secret, "id").to_owned();
    let (lease_status, lease_grant) = request_json_with_status(
        address,
        "POST",
        &format!("/secrets/items/{lease_secret_id}/reveal/leases"),
        Some(
            &json!({
                "reason": "runtime lease verification",
                "lease_seconds": 45
            })
            .to_string(),
        ),
    );
    assert_eq!(lease_status, 201, "unexpected lease grant: {lease_grant}");
    let lease_grant_id = required_string(&lease_grant, "id").to_owned();
    assert_eq!(
        lease_grant["secret_id"].as_str(),
        Some(lease_secret_id.as_str())
    );
    assert_eq!(lease_grant["grant_kind"].as_str(), Some("lease"));
    assert_eq!(
        lease_grant["reason"].as_str(),
        Some("runtime lease verification")
    );
    assert_eq!(lease_grant["reveal_count"].as_u64(), Some(0));
    assert!(!lease_grant["expires_at"].is_null());

    for attempt in 1..=2 {
        let (lease_reveal_status, lease_reveal) = request_json_with_status(
            address,
            "POST",
            &format!("/secrets/items/{lease_secret_id}/reveal/grants/{lease_grant_id}"),
            None,
        );
        assert_eq!(
            lease_reveal_status, 200,
            "unexpected lease reveal {attempt}: {lease_reveal}"
        );
        assert_eq!(lease_reveal["value"].as_str(), Some("lease-runtime-value"));
    }

    let secrets_root = state_dir.join("secrets");
    let reveal_grants = read_json_file(&secrets_root.join("reveal_grants.json"));
    let stored_approval_grant = stored_record_value(&reveal_grants, &approval_grant_id);
    assert_eq!(
        stored_approval_grant["secret_id"].as_str(),
        Some(approval_secret_id.as_str())
    );
    assert_eq!(
        stored_approval_grant["grant_kind"].as_str(),
        Some("approval")
    );
    assert_eq!(stored_approval_grant["reveal_count"].as_u64(), Some(1));
    assert_eq!(
        stored_approval_grant["last_revealed_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert!(!stored_approval_grant["last_revealed_at"].is_null());

    let stored_lease_grant = stored_record_value(&reveal_grants, &lease_grant_id);
    assert_eq!(
        stored_lease_grant["secret_id"].as_str(),
        Some(lease_secret_id.as_str())
    );
    assert_eq!(stored_lease_grant["grant_kind"].as_str(), Some("lease"));
    assert_eq!(stored_lease_grant["reveal_count"].as_u64(), Some(2));
    assert_eq!(
        stored_lease_grant["last_revealed_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert!(!stored_lease_grant["last_revealed_at"].is_null());
    assert_eq!(stored_lease_grant["expires_at"], lease_grant["expires_at"]);

    let outbox = read_json_file(&secrets_root.join("outbox.json"));
    let outbox_records = outbox["records"]
        .as_object()
        .unwrap_or_else(|| panic!("outbox records should be an object: {outbox}"));
    assert_eq!(outbox_records.len(), 5);
    assert_eq!(
        count_outbox_event_type(outbox_records, "secrets.reveal.approved.v1"),
        1
    );
    assert_eq!(
        count_outbox_event_type(outbox_records, "secrets.reveal.leased.v1"),
        1
    );
    assert_eq!(
        count_outbox_event_type(outbox_records, "secrets.reveal.executed.v1"),
        3
    );

    let (approval_reveal_events, lease_reveal_events) =
        authorization_kind_counts(outbox_records, "secrets.reveal.executed.v1");
    assert_eq!(approval_reveal_events, 1);
    assert_eq!(lease_reveal_events, 2);

    let audit_entries = read_json_lines(&secrets_root.join("audit.log"));
    assert_eq!(audit_entries.len(), 5);
    assert_eq!(
        count_audit_event_type(&audit_entries, "secrets.reveal.approved.v1"),
        1
    );
    assert_eq!(
        count_audit_event_type(&audit_entries, "secrets.reveal.leased.v1"),
        1
    );
    assert_eq!(
        count_audit_event_type(&audit_entries, "secrets.reveal.executed.v1"),
        3
    );
    assert!(
        audit_entries.iter().all(|entry| {
            entry["header"]["actor"]["subject"].as_str() == Some("bootstrap_admin")
        })
    );

    let audit_log = fs::read_to_string(secrets_root.join("audit.log"))
        .unwrap_or_else(|error| panic!("failed to read secrets audit log: {error}"));
    assert!(!audit_log.contains("approval-runtime-value"));
    assert!(!audit_log.contains("lease-runtime-value"));
    let outbox_text = fs::read_to_string(secrets_root.join("outbox.json"))
        .unwrap_or_else(|error| panic!("failed to read secrets outbox: {error}"));
    assert!(!outbox_text.contains("approval-runtime-value"));
    assert!(!outbox_text.contains("lease-runtime-value"));
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
bootstrap_admin_token = "{}"
"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn wait_for_health(address: SocketAddr, child: &mut Child, stderr_path: Option<&Path>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request(
            address,
            "GET",
            "/healthz",
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ) && response.status == 200
        {
            return;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to query child status: {error}"))
        {
            let stderr = read_child_stderr(stderr_path);
            panic!("uhostd exited before becoming healthy with {status}: {stderr}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    let stderr = read_child_stderr(stderr_path);
    panic!("uhostd did not become healthy in time: {stderr}");
}

fn read_child_stderr(stderr_path: Option<&Path>) -> String {
    let Some(stderr_path) = stderr_path else {
        return String::from("stderr not captured");
    };
    match fs::read_to_string(stderr_path) {
        Ok(stderr) => {
            let trimmed = stderr.trim();
            if trimmed.is_empty() {
                String::from("stderr empty")
            } else {
                trimmed.to_owned()
            }
        }
        Err(error) => format!("failed to read stderr capture: {error}"),
    }
}

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Value {
    request_json_with_status(address, method, path, body).1
}

fn request_json_with_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, Value) {
    let response = request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert!(
        (200..=299).contains(&response.status),
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    (response.status, json_from_bytes(&response.body))
}

fn read_json_file(path: &Path) -> Value {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("invalid json in {}: {error}", path.display()))
}

fn read_json_lines(path: &Path) -> Vec<Value> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("invalid json line in {}: {error}", path.display()))
        })
        .collect()
}

fn stored_record_value<'a>(collection: &'a Value, key: &str) -> &'a Value {
    collection["records"][key]["value"]
        .as_object()
        .map(|_| &collection["records"][key]["value"])
        .unwrap_or_else(|| panic!("missing stored record value for {key}: {collection}"))
}

fn count_outbox_event_type(records: &serde_json::Map<String, Value>, event_type: &str) -> usize {
    records
        .values()
        .filter(|record| {
            record["value"]["payload"]["header"]["event_type"].as_str() == Some(event_type)
        })
        .count()
}

fn authorization_kind_counts(
    records: &serde_json::Map<String, Value>,
    event_type: &str,
) -> (usize, usize) {
    let approval = records
        .values()
        .filter(|record| {
            record["value"]["payload"]["header"]["event_type"].as_str() == Some(event_type)
                && record["value"]["payload"]["payload"]["kind"].as_str() == Some("service")
                && record["value"]["payload"]["payload"]["data"]["details"]["authorization_kind"]
                    .as_str()
                    == Some("approval")
        })
        .count();
    let lease = records
        .values()
        .filter(|record| {
            record["value"]["payload"]["header"]["event_type"].as_str() == Some(event_type)
                && record["value"]["payload"]["payload"]["kind"].as_str() == Some("service")
                && record["value"]["payload"]["payload"]["data"]["details"]["authorization_kind"]
                    .as_str()
                    == Some("lease")
        })
        .count();
    (approval, lease)
}

fn count_audit_event_type(entries: &[Value], event_type: &str) -> usize {
    entries
        .iter()
        .filter(|entry| entry["header"]["event_type"].as_str() == Some(event_type))
        .count()
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

fn json_from_bytes(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or_else(|error| panic!("invalid json response: {error}"))
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
    token: &str,
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = matches!(method, "GET" | "HEAD" | "OPTIONS");
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request(address, method, path, body, token) {
            Ok(response) => return response,
            Err(error)
                if allow_retry
                    && matches!(
                        error.kind(),
                        ErrorKind::WouldBlock
                            | ErrorKind::Interrupted
                            | ErrorKind::ConnectionRefused
                            | ErrorKind::ConnectionReset
                            | ErrorKind::TimedOut
                    ) =>
            {
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

fn try_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
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
