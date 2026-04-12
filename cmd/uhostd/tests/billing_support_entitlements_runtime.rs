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

fn test_child_stderr() -> Stdio {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

#[test]
fn billing_support_entitlements_are_operational_from_all_in_one_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("billing-support-entitlements.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping billing_support_entitlements_are_operational_from_all_in_one_runtime: loopback bind not permitted"
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

    let account = request_json(
        address,
        "POST",
        "/billing/accounts",
        Some(r#"{"owner_id":"tenant-support-runtime","plan":"pro","credits_cents":5000}"#),
    );
    let account_id = account["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing billing account id"));

    let subscription = request_json(
        address,
        "POST",
        "/billing/subscriptions",
        Some(&format!(
            r#"{{"billing_account_id":"{account_id}","plan":"enterprise"}}"#
        )),
    );
    let subscription_id = subscription["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing subscription id"));

    let entitlements = request_json(address, "GET", "/billing/support-entitlements", None);
    assert_eq!(
        entitlements
            .as_array()
            .unwrap_or_else(|| panic!("support entitlements response should be an array"))
            .len(),
        2
    );
    let account_entitlement = find_object_by_field(&entitlements, "source_kind", "billing_account");
    assert_eq!(
        account_entitlement["billing_account_id"].as_str(),
        Some(account_id)
    );
    assert!(
        account_entitlement["subscription_id"].is_null(),
        "account entitlement should not carry a subscription id"
    );
    assert_eq!(account_entitlement["source_plan"].as_str(), Some("pro"));
    assert_eq!(
        account_entitlement["support_tier"].as_str(),
        Some("business")
    );
    assert_eq!(
        string_array(&account_entitlement["channels"]),
        vec!["portal", "email", "phone"]
    );
    assert_eq!(
        account_entitlement["initial_response_sla_minutes"].as_u64(),
        Some(240)
    );
    assert_eq!(account_entitlement["active"].as_bool(), Some(true));
    assert!(
        account_entitlement["metadata"].is_object(),
        "account entitlement metadata should be present"
    );

    let subscription_entitlement =
        find_object_by_field(&entitlements, "subscription_id", subscription_id);
    assert_eq!(
        subscription_entitlement["billing_account_id"].as_str(),
        Some(account_id)
    );
    assert_eq!(
        subscription_entitlement["source_kind"].as_str(),
        Some("subscription")
    );
    assert_eq!(
        subscription_entitlement["subscription_id"].as_str(),
        Some(subscription_id)
    );
    assert_eq!(
        subscription_entitlement["source_plan"].as_str(),
        Some("enterprise")
    );
    assert_eq!(
        subscription_entitlement["support_tier"].as_str(),
        Some("enterprise")
    );
    assert_eq!(
        string_array(&subscription_entitlement["channels"]),
        vec!["portal", "email", "phone", "slack"]
    );
    assert_eq!(
        subscription_entitlement["initial_response_sla_minutes"].as_u64(),
        Some(60)
    );
    assert_eq!(subscription_entitlement["active"].as_bool(), Some(true));
    assert!(
        subscription_entitlement["metadata"].is_object(),
        "subscription entitlement metadata should be present"
    );

    let summary = request_json(address, "GET", "/billing/summary", None);
    assert_eq!(summary["support_entitlement_count"].as_u64(), Some(2));
    assert_eq!(
        summary["active_support_entitlement_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        summary["support_entitlements_linked_to_active_accounts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        summary["support_entitlements_linked_to_active_subscriptions"].as_u64(),
        Some(1)
    );
    assert_eq!(
        summary["support_entitlement_source_totals"]["billing_account"].as_u64(),
        Some(1)
    );
    assert_eq!(
        summary["support_entitlement_source_totals"]["subscription"].as_u64(),
        Some(1)
    );
    assert_eq!(
        summary["support_entitlement_source_totals"]
            .as_object()
            .unwrap_or_else(|| panic!("support_entitlement_source_totals should be an object"))
            .len(),
        2
    );
    assert_eq!(summary["support_tier_totals"]["business"].as_u64(), Some(1));
    assert_eq!(
        summary["support_tier_totals"]["enterprise"].as_u64(),
        Some(1)
    );
    assert_eq!(
        summary["support_tier_totals"]
            .as_object()
            .unwrap_or_else(|| panic!("support_tier_totals should be an object"))
            .len(),
        2
    );

    let owner_summaries = request_json(address, "GET", "/billing/owner-summaries", None);
    assert_eq!(
        owner_summaries["owners"]
            .as_array()
            .unwrap_or_else(|| panic!("owner summaries response should contain an owners array"))
            .len(),
        1
    );
    let owner_summary = find_object_by_field(
        &owner_summaries["owners"],
        "owner_id",
        "tenant-support-runtime",
    );
    assert_eq!(owner_summary["support_entitlement_count"].as_u64(), Some(2));
}

fn find_object_by_field<'a>(items: &'a Value, field: &str, expected: &str) -> &'a Value {
    items
        .as_array()
        .unwrap_or_else(|| panic!("expected array for field search"))
        .iter()
        .find(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing object with {field}={expected}"))
}

fn string_array(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected string array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("expected string array item"))
        })
        .collect()
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
node_name = "billing-support-runtime-node"

[secrets]
master_key = "{}"
"#,
        state_dir.display(),
        base64url_encode(&[0x24; 32]),
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
