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

#[test]
fn notify_workflows_are_operational_from_all_in_one() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("notify-workflows.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping notify_workflows_are_operational_from_all_in_one: loopback bind not permitted"
        );
        return;
    };
    write_test_config_with_token(
        &config_path,
        address,
        &state_dir,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let _guard = spawn_uhostd(&binary, &config_path);

    wait_for_health(address);

    let create_payload = json!({
        "channel": "incident",
        "destination": "ops://incident-room",
        "subject": "Case review",
        "body": "review pending",
        "subject_key": "tenant:alpha",
        "case_reference": "support:case-123",
        "locale": "en-us"
    })
    .to_string();
    let created = request_json_with_bearer_token_and_status(
        address,
        "POST",
        "/notify/messages",
        Some(&create_payload),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        201,
    );
    let notification_id = required_string(&created, "id").to_owned();
    assert_eq!(created["state"].as_str(), Some("queued"));
    assert_eq!(created["case_reference"].as_str(), Some("support:case-123"));

    let delivered = request_json_with_bearer_token_and_status(
        address,
        "POST",
        &format!("/notify/messages/{notification_id}/deliver"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(delivered["state"].as_str(), Some("delivered"));

    let snooze_payload = json!({
        "snooze_seconds": 900,
        "reason": "waiting on operator handoff"
    })
    .to_string();
    let snoozed = request_json_with_bearer_token_and_status(
        address,
        "POST",
        &format!("/notify/messages/{notification_id}/snooze"),
        Some(&snooze_payload),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(snoozed["case_reference"].as_str(), Some("support:case-123"));
    assert_eq!(snoozed["snoozed_by"].as_str(), Some("bootstrap_admin"));
    assert!(!snoozed["snoozed_until"].is_null());

    let acknowledge_payload = json!({
        "note": "operator accepted case"
    })
    .to_string();
    let acknowledged = request_json_with_bearer_token_and_status(
        address,
        "POST",
        &format!("/notify/messages/{notification_id}/acknowledge"),
        Some(&acknowledge_payload),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(
        acknowledged["case_reference"].as_str(),
        Some("support:case-123")
    );
    assert_eq!(
        acknowledged["acknowledged_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(
        acknowledged["acknowledgement_note"].as_str(),
        Some("operator accepted case")
    );
    assert!(!acknowledged["acknowledged_at"].is_null());
    assert!(acknowledged["snoozed_until"].is_null());
    assert!(acknowledged["snoozed_by"].is_null());
    assert!(acknowledged["snooze_reason"].is_null());

    let history = request_json_with_bearer_token_and_status(
        address,
        "GET",
        &format!("/notify/messages/{notification_id}/history"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(
        history["notification_id"].as_str(),
        Some(notification_id.as_str())
    );
    assert_eq!(history["case_reference"].as_str(), Some("support:case-123"));
    assert_eq!(history["acknowledged_by"].as_str(), Some("bootstrap_admin"));
    assert_eq!(history["escalation_count"].as_u64(), Some(0));
    let history_events = history["history"]
        .as_array()
        .unwrap_or_else(|| panic!("history should be an array: {history}"));
    assert_eq!(history_events.len(), 4);
    assert_eq!(history_events[0]["event"].as_str(), Some("queued"));
    assert_eq!(history_events[1]["event"].as_str(), Some("delivered"));
    assert_eq!(history_events[2]["event"].as_str(), Some("snoozed"));
    assert_eq!(history_events[3]["event"].as_str(), Some("acknowledged"));
    for entry in history_events {
        assert_eq!(entry["actor"].as_str(), Some("bootstrap_admin"));
        assert_eq!(entry["case_reference"].as_str(), Some("support:case-123"));
    }

    let original_payload = json!({
        "channel": "operator_alert",
        "destination": "ops://primary",
        "subject": "approval pending",
        "body": "change request requires review",
        "subject_key": "tenant:alpha",
        "case_reference": "support:case-42",
        "locale": "en-us"
    })
    .to_string();
    let original = request_json_with_bearer_token_and_status(
        address,
        "POST",
        "/notify/messages",
        Some(&original_payload),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        201,
    );
    let original_id = required_string(&original, "id").to_owned();

    let original_delivered = request_json_with_bearer_token_and_status(
        address,
        "POST",
        &format!("/notify/messages/{original_id}/deliver"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(original_delivered["state"].as_str(), Some("delivered"));

    let escalate_payload = json!({
        "channel": "incident",
        "destination": "ops://pager",
        "reason": "SLA breach risk"
    })
    .to_string();
    let escalated = request_json_with_bearer_token_and_status(
        address,
        "POST",
        &format!("/notify/messages/{original_id}/escalate"),
        Some(&escalate_payload),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        201,
    );
    let escalated_id = required_string(&escalated, "id").to_owned();
    assert_eq!(escalated["state"].as_str(), Some("queued"));
    assert_eq!(escalated["channel"].as_str(), Some("incident"));
    assert_eq!(
        escalated["case_reference"].as_str(),
        Some("support:case-42")
    );
    assert!(
        required_string(&escalated, "subject").starts_with("[ESCALATED] "),
        "expected escalated subject prefix in {escalated}"
    );

    let original_history = request_json_with_bearer_token_and_status(
        address,
        "GET",
        &format!("/notify/messages/{original_id}/history"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(
        original_history["case_reference"].as_str(),
        Some("support:case-42")
    );
    assert_eq!(original_history["escalation_count"].as_u64(), Some(1));
    assert_eq!(
        original_history["last_escalated_notification_id"].as_str(),
        Some(escalated_id.as_str())
    );
    let original_events = original_history["history"]
        .as_array()
        .unwrap_or_else(|| panic!("history should be an array: {original_history}"));
    assert_eq!(original_events.len(), 3);
    assert_eq!(original_events[0]["event"].as_str(), Some("queued"));
    assert_eq!(original_events[1]["event"].as_str(), Some("delivered"));
    assert_eq!(original_events[2]["event"].as_str(), Some("escalated"));
    assert_eq!(
        original_events[2]["actor"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(
        original_events[2]["related_notification_id"].as_str(),
        Some(escalated_id.as_str())
    );
    assert_eq!(
        original_events[2]["case_reference"].as_str(),
        Some("support:case-42")
    );

    let escalated_history = request_json_with_bearer_token_and_status(
        address,
        "GET",
        &format!("/notify/messages/{escalated_id}/history"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        200,
    );
    assert_eq!(
        escalated_history["notification_id"].as_str(),
        Some(escalated_id.as_str())
    );
    assert_eq!(
        escalated_history["case_reference"].as_str(),
        Some("support:case-42")
    );
    let escalated_events = escalated_history["history"]
        .as_array()
        .unwrap_or_else(|| panic!("history should be an array: {escalated_history}"));
    assert_eq!(escalated_events.len(), 1);
    assert_eq!(escalated_events[0]["event"].as_str(), Some("queued"));
    assert_eq!(
        escalated_events[0]["actor"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(
        escalated_events[0]["case_reference"].as_str(),
        Some("support:case-42")
    );
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
node_name = "notify-test-node"

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

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

fn request_json_with_bearer_token_and_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
    expected_status: u16,
) -> Value {
    let response = try_request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        &[("Authorization", format!("Bearer {token}"))],
    )
    .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"));
    assert_eq!(
        response.status,
        expected_status,
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid json response for {method} {path}: {error}"))
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
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing status line terminator"))?;
    let status_line = std::str::from_utf8(&head[..status_line_end])
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing status code"))?
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;

    Ok(RawResponse {
        status,
        body: body.to_vec(),
    })
}
