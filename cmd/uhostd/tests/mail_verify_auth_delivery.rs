use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;
use uhost_core::base64url_encode;

const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";
const GOVERNANCE_CHANGE_REQUEST_HEADER: &str = "x-uhost-change-request-id";

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
fn mail_verify_auth_after_dns_delivery_with_governed_resources() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping mail_verify_auth_after_dns_delivery_with_governed_resources: loopback bind not permitted in this environment"
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

    let created_user = request_json(
        address,
        "POST",
        "/identity/users",
        Some(
            r#"{"email":"alice@example.com","display_name":"Alice","password":"correct horse battery staple"}"#,
        ),
    );
    let bulk_users = request_json(
        address,
        "POST",
        "/identity/users/bulk",
        Some(
            r#"{"users":[{"email":"bulk-1@example.com","display_name":"Bulk One","password":"pw-1"},{"email":"bulk-2@example.com","display_name":"Bulk Two","password":"pw-2"}],"fail_fast":false}"#,
        ),
    );
    assert_eq!(bulk_users["created_count"].as_u64().unwrap_or_default(), 2);

    let users = request_json(address, "GET", "/identity/users", None);
    let alice_id = created_user["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing alice user id"))
        .to_owned();
    let approver_id = find_user_id_by_email(&users, "bulk-1@example.com");
    let alice_api_key = create_api_key_secret(address, &alice_id, "alice-governance-cli");
    let approver_api_key = create_api_key_secret(address, &approver_id, "bulk-one-governance-cli");

    let change_request = request_json_with_bearer_token(
        address,
        "POST",
        "/governance/change-requests",
        Some(&format!(
            r#"{{"title":"Publish mail auth DNS","change_type":"deploy","requested_by":"user:{alice_id}"}}"#
        )),
        &alice_api_key,
    );
    let change_request_id = change_request["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing governance change_request_id"))
        .to_owned();
    let _approved = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/governance/change-requests/{change_request_id}/approve"),
        Some(&format!(
            r#"{{"approver":"user:{approver_id}","comment":"approved"}}"#
        )),
        &approver_api_key,
    );
    let _applied = request_json(
        address,
        "POST",
        &format!("/governance/change-requests/{change_request_id}/apply"),
        Some(r#"{"executor":"bootstrap_admin","note":"window approved"}"#),
    );

    let zone = request_json_with_extra_headers(
        address,
        "POST",
        "/dns/zones",
        Some(r#"{"domain":"example.com"}"#),
        &[(GOVERNANCE_CHANGE_REQUEST_HEADER, change_request_id.as_str())],
    );
    assert_eq!(
        zone["change_authorization"]["change_request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing dns zone change_request_id")),
        change_request_id
    );
    assert_eq!(
        zone["metadata"]["annotations"]["governance.change_request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing dns zone governance annotation")),
        change_request_id
    );
    let zone_id = zone["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing zone id"))
        .to_owned();

    let verified_zone = request_json(
        address,
        "POST",
        &format!("/dns/zones/{zone_id}/verify"),
        None,
    );
    assert!(
        verified_zone["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing zone verification state"))
    );

    let mail_domain = request_json_with_extra_headers(
        address,
        "POST",
        "/mail/domains",
        Some(&format!(
            r#"{{"domain":"example.com","zone_id":"{zone_id}"}}"#
        )),
        &[(GOVERNANCE_CHANGE_REQUEST_HEADER, change_request_id.as_str())],
    );
    assert_eq!(
        mail_domain["change_authorization"]["change_request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing mail domain change_request_id")),
        change_request_id
    );
    assert_eq!(
        mail_domain["metadata"]["annotations"]["governance.change_request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing mail domain governance annotation")),
        change_request_id
    );
    let domain_id = mail_domain["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing mail domain id"))
        .to_owned();

    let pending_auth_check = request_json(
        address,
        "POST",
        &format!("/mail/domains/{domain_id}/verify-auth"),
        Some(r#"{"reconcile_missing":true,"ttl":120}"#),
    );
    assert!(
        !pending_auth_check["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing initial auth verification status"))
    );
    assert_eq!(
        pending_auth_check["reconciled_records"]
            .as_u64()
            .unwrap_or_default(),
        3
    );
    assert_eq!(
        pending_auth_check["missing_records"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing initial missing_records")),
        3
    );

    let dns_provider_tasks = request_json(address, "GET", "/dns/provider-tasks", None);
    let deliverable_task_ids = dns_provider_tasks
        .as_array()
        .unwrap_or_else(|| panic!("provider tasks response should be an array"))
        .iter()
        .filter(|task| {
            task["action"].as_str().unwrap_or_default() == "upsert_record"
                && task["resource_id"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with(&format!("{zone_id}:"))
                && task["status"].as_str().unwrap_or_default() == "pending"
        })
        .filter_map(|task| task["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(deliverable_task_ids.len(), 3);
    for task_id in &deliverable_task_ids {
        let delivered = request_json(
            address,
            "POST",
            &format!("/dns/provider-tasks/{task_id}/deliver"),
            None,
        );
        assert_eq!(
            delivered["status"]
                .as_str()
                .unwrap_or_else(|| panic!("missing delivered task status")),
            "delivered"
        );
    }

    let verified_auth_check = request_json(
        address,
        "POST",
        &format!("/mail/domains/{domain_id}/verify-auth"),
        Some(r#"{"reconcile_missing":false}"#),
    );
    assert!(
        verified_auth_check["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing delivered auth verification status"))
    );
    assert_eq!(
        verified_auth_check["reconciled_records"]
            .as_u64()
            .unwrap_or_default(),
        0
    );
    assert_eq!(
        verified_auth_check["missing_records"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing verified missing_records")),
        0
    );

    let filtered_auth_records = request_json(
        address,
        "GET",
        &format!("/mail/auth-records?domain_id={domain_id}"),
        None,
    );
    let auth_views = filtered_auth_records
        .as_array()
        .unwrap_or_else(|| panic!("auth records response should be an array"));
    assert_eq!(auth_views.len(), 1);
    assert!(
        auth_views[0]["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing auth-record view verification state"))
    );
    let required_records = auth_views[0]["required_records"]
        .as_array()
        .unwrap_or_else(|| panic!("missing required_records array"));
    assert_eq!(required_records.len(), 3);
    assert!(required_records.iter().all(|record| {
        record["present"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing present flag"))
    }));
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
            &[],
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
    request_json_with_extra_headers(address, method, path, body, &[])
}

fn request_json_with_extra_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Value {
    request_json_with_bearer_token_and_extra_headers(
        address,
        method,
        path,
        body,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        extra_headers,
    )
}

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
) -> Value {
    request_json_with_bearer_token_and_extra_headers(address, method, path, body, token, &[])
}

fn request_json_with_bearer_token_and_extra_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Value {
    let response = request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        token,
        extra_headers,
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

fn find_user_id_by_email(users: &Value, email: &str) -> String {
    users
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|item| {
                (item["email"].as_str() == Some(email))
                    .then(|| item["id"].as_str().map(str::to_owned))
                    .flatten()
            })
        })
        .unwrap_or_else(|| panic!("missing user id for {email}"))
}

fn create_api_key_secret(address: SocketAddr, user_id: &str, name: &str) -> String {
    let payload = format!(r#"{{"user_id":"{user_id}","name":"{name}"}}"#);
    request_json(address, "POST", "/identity/api-keys", Some(&payload))["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing api key secret for {user_id}"))
        .to_owned()
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
    extra_headers: &[(&str, &str)],
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = matches!(method, "GET" | "HEAD" | "OPTIONS");
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request(address, method, path, body, token, extra_headers) {
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
    extra_headers: &[(&str, &str)],
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let extra_headers = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n{extra_headers}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
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
