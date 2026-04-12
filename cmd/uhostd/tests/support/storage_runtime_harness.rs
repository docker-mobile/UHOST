#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use uhost_core::base64url_encode;

pub const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";

pub struct RunningUhostd {
    pub address: SocketAddr,
    pub state_dir: PathBuf,
    _temp: TempDir,
    _child: ChildGuard,
}

pub struct RawResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub struct ResponseHead {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    body_prefix: Vec<u8>,
}

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

pub fn spawn_test_runtime(fixture_name: &str, node_name: &str) -> Option<RunningUhostd> {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join(format!("{fixture_name}.toml"));
    let address = reserve_loopback_port()?;
    write_test_config_with_token(
        &config_path,
        address,
        &state_dir,
        node_name,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

    let binary = std::env::var("UHOSTD_TEST_BINARY")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_uhostd"))
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(test_child_stderr())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let child = ChildGuard { child };
    wait_for_health(address);

    Some(RunningUhostd {
        address,
        state_dir,
        _temp: temp,
        _child: child,
    })
}

fn write_test_config_with_token(
    path: &Path,
    address: SocketAddr,
    state_dir: &Path,
    node_name: &str,
    token: &str,
) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "{node_name}"

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
        if let Ok(response) =
            try_request_with_token_and_headers(address, "GET", "/healthz", None, &[], None)
            && response.status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("uhostd did not become healthy in time");
}

pub fn blob_path(state_dir: &Path, digest: &str) -> PathBuf {
    state_dir
        .join("storage")
        .join("blobs")
        .join(&digest[..2])
        .join(digest)
}

pub fn blob_sidecar_path(state_dir: &Path, digest: &str) -> PathBuf {
    blob_path(state_dir, digest).with_extension("integrity.json")
}

pub fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

#[allow(dead_code)]
pub fn request_json_with_admin_token_and_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: &str,
    expected_status: u16,
) -> Value {
    request_json_with_token_and_status(
        address,
        method,
        path,
        body.map(|body| ("application/json", body.as_bytes().to_vec())),
        &[],
        Some(admin_token),
        expected_status,
    )
}

pub fn request_json_with_token_and_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, Vec<u8>)>,
    headers: &[(&str, String)],
    token: Option<&str>,
    expected_status: u16,
) -> Value {
    let response = request_with_token_and_headers(address, method, path, body, headers, token);
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

#[allow(dead_code)]
pub fn request_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    admin_token: &str,
) -> RawResponse {
    request_with_token_and_headers(
        address,
        method,
        path,
        body.map(|body| ("application/json", body.as_bytes().to_vec())),
        &[],
        Some(admin_token),
    )
}

#[allow(dead_code)]
pub fn request_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
) -> RawResponse {
    request_with_token_and_headers(
        address,
        method,
        path,
        body.map(|body| ("application/json", body.as_bytes().to_vec())),
        &[],
        Some(token),
    )
}

pub fn request_with_token_and_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, Vec<u8>)>,
    headers: &[(&str, String)],
    token: Option<&str>,
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = is_idempotent_method(method);
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        let borrowed_body = body
            .as_ref()
            .map(|(content_type, body)| (*content_type, body.as_slice()));
        match try_request_with_token_and_headers(
            address,
            method,
            path,
            borrowed_body,
            headers,
            token,
        ) {
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

pub fn open_request_with_token_and_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    headers: &[(&str, String)],
    token: Option<&str>,
) -> Result<TcpStream, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let extra_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n{authorization}{extra_headers}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        payload.len(),
    );
    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    Ok(stream)
}

pub fn read_response_head(stream: &mut TcpStream) -> Result<ResponseHead, Error> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before response headers completed",
            ));
        }
        response.extend_from_slice(&chunk[..bytes_read]);
        if let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_prefix = response.split_off(split + 4);
            response.truncate(split + 4);
            let (status, headers) = parse_http_head(&response)?;
            return Ok(ResponseHead {
                status,
                headers,
                body_prefix,
            });
        }
    }
}

pub fn finish_response(mut stream: TcpStream, head: ResponseHead) -> Result<RawResponse, Error> {
    let mut body = head.body_prefix;
    stream.read_to_end(&mut body)?;
    Ok(RawResponse {
        status: head.status,
        headers: head.headers,
        body,
    })
}

#[allow(dead_code)]
pub fn issue_workload_identity(
    address: SocketAddr,
    bootstrap_token: &str,
    subject: &str,
    audiences: &[&str],
    ttl_seconds: u64,
) -> String {
    let body = json!({
        "subject": subject,
        "display_name": format!("{subject} identity"),
        "audiences": audiences,
        "ttl_seconds": ttl_seconds,
    })
    .to_string();
    let payload = request_json_with_admin_token_and_status(
        address,
        "POST",
        "/identity/workload-identities",
        Some(body.as_str()),
        bootstrap_token,
        201,
    );
    payload
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned()
}

pub fn assert_error_envelope(
    response: RawResponse,
    expected_status: u16,
    expected_code: &str,
    expected_message: &str,
    expected_detail_fragments: Option<&[&str]>,
) {
    assert_eq!(
        response.status,
        expected_status,
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    let payload: Value = serde_json::from_slice(&response.body)
        .unwrap_or_else(|error| panic!("invalid error response json: {error}"));
    let error = &payload["error"];
    assert_eq!(error["code"], json!(expected_code));
    assert_eq!(error["message"], json!(expected_message));
    match expected_detail_fragments {
        Some(fragments) => {
            let detail = error["detail"]
                .as_str()
                .unwrap_or_else(|| panic!("expected detail string in {payload}"));
            for fragment in fragments {
                assert!(
                    detail.contains(fragment),
                    "expected detail containing `{fragment}`, got `{detail}`"
                );
            }
        }
        None => assert!(
            error["detail"].is_null(),
            "expected null detail in {payload}"
        ),
    }
}

fn try_request_with_token_and_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    headers: &[(&str, String)],
    token: Option<&str>,
) -> Result<RawResponse, Error> {
    let mut stream =
        open_request_with_token_and_headers(address, method, path, body, headers, token)?;
    let head = read_response_head(&mut stream)?;
    finish_response(stream, head)
}

fn parse_http_head(head: &[u8]) -> Result<(u16, BTreeMap<String, String>), Error> {
    let head_text = std::str::from_utf8(head)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
    let mut lines = head_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing http status line"))?;
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
    Ok((status, headers))
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
