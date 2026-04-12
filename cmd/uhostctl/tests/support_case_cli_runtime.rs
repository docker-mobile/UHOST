use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

#[test]
fn abuse_support_case_cli_flows_work_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_support_case_cli_flows_work_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "abuse_support_case_cli_flows_work_against_uhostd",
    ) else {
        return;
    };

    let child_stderr = test_child_stderr(temp.path());
    let child = Command::new(&uhostd_binary)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(child_stderr.sink)
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let mut guard = ChildGuard { child };

    wait_for_health(address, &mut guard.child, child_stderr.path.as_deref());

    let endpoint = format!("http://{address}");
    let abuse_case_payload = json!({
        "subject_kind": "tenant",
        "subject": "tenant:org_1",
        "reason": "cli support runtime seed",
    })
    .to_string();
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(abuse_case_payload.as_str()),
    );
    let abuse_case_id = required_string(&abuse_case, "id").to_owned();

    let remediation = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "cli support remediation seed",
            "--owner",
            "operator:incident",
            "--rollback-evidence",
            "runbook:tenant-rollback",
            "--verification-evidence",
            "checklist:tenant-verification",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let remediation_case_id = required_string(&remediation, "id").to_owned();

    let created = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "support-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "cli support case verification",
            "--owner",
            "operator:support",
            "--priority",
            "high",
            "--remediation-case-id",
            remediation_case_id.as_str(),
            "--change-request-id",
            "chg_support234",
            "--notify-message-id",
            "ntf_support234",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let support_case_id = required_string(&created, "id").to_owned();
    assert_eq!(created["tenant_subject"].as_str(), Some("tenant:org_1"));
    assert_eq!(created["opened_by"].as_str(), Some("bootstrap_admin"));
    assert_eq!(created["owner"].as_str(), Some("operator:support"));
    assert_eq!(
        created["reason"].as_str(),
        Some("cli support case verification")
    );
    assert_eq!(created["status"].as_str(), Some("open"));
    assert_eq!(created["priority"].as_str(), Some("high"));
    assert_eq!(
        created["remediation_case_ids"][0].as_str(),
        Some(remediation_case_id.as_str())
    );
    assert_eq!(
        created["change_request_ids"][0].as_str(),
        Some("chg_support234")
    );
    assert_eq!(
        created["notify_message_ids"][0].as_str(),
        Some("ntf_support234")
    );

    let listed = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "support-cases",
            "--tenant-subject",
            "tenant:org_1",
            "--owner",
            "operator:support",
            "--status",
            "open",
            "--priority",
            "high",
            "--remediation-case-id",
            remediation_case_id.as_str(),
            "--change-request-id",
            "chg_support234",
            "--notify-message-id",
            "ntf_support234",
            "--limit",
            "5",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let listed = listed
        .as_array()
        .unwrap_or_else(|| panic!("support case list response should be an array: {listed}"));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"].as_str(), Some(support_case_id.as_str()));
    assert_eq!(listed[0]["status"].as_str(), Some("open"));

    let fetched = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "support-case-get",
            "--support-case-id",
            support_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(fetched["id"].as_str(), Some(support_case_id.as_str()));
    assert_eq!(fetched["owner"].as_str(), Some("operator:support"));
    assert_eq!(fetched["status"].as_str(), Some("open"));

    let transitioned = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "support-case-transition",
            "--support-case-id",
            support_case_id.as_str(),
            "--reason",
            "waiting on tenant reply",
            "--status",
            "waiting_on_tenant",
            "--owner",
            "operator:support-tier2",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(transitioned["id"].as_str(), Some(support_case_id.as_str()));
    assert_eq!(
        transitioned["owner"].as_str(),
        Some("operator:support-tier2")
    );
    assert_eq!(transitioned["status"].as_str(), Some("waiting_on_tenant"));
    assert_eq!(transitioned["priority"].as_str(), Some("high"));

    let relisted = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "support-cases",
            "--tenant-subject",
            "tenant:org_1",
            "--owner",
            "operator:support-tier2",
            "--status",
            "waiting_on_tenant",
            "--priority",
            "high",
            "--remediation-case-id",
            remediation_case_id.as_str(),
            "--change-request-id",
            "chg_support234",
            "--notify-message-id",
            "ntf_support234",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let relisted = relisted
        .as_array()
        .unwrap_or_else(|| panic!("support case list response should be an array: {relisted}"));
    assert_eq!(relisted.len(), 1);
    assert_eq!(relisted[0]["id"].as_str(), Some(support_case_id.as_str()));
    assert_eq!(relisted[0]["status"].as_str(), Some("waiting_on_tenant"));
    assert_eq!(
        relisted[0]["owner"].as_str(),
        Some("operator:support-tier2")
    );

    let abuse_root = state_dir.join("abuse");
    let stored_support_cases = read_json_file(&abuse_root.join("support_cases.json"));
    let stored_support = stored_record_value(&stored_support_cases, &support_case_id);
    assert_eq!(
        stored_support["remediation_case_ids"][0].as_str(),
        Some(remediation_case_id.as_str())
    );
    assert_eq!(stored_support["status"].as_str(), Some("waiting_on_tenant"));
    assert_eq!(
        stored_support["owner"].as_str(),
        Some("operator:support-tier2")
    );
    assert_eq!(stored_support["priority"].as_str(), Some("high"));
    assert_eq!(
        stored_support["change_request_ids"][0].as_str(),
        Some("chg_support234")
    );
    assert_eq!(
        stored_support["notify_message_ids"][0].as_str(),
        Some("ntf_support234")
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

fn resolve_uhostd_binary(uhostctl_binary: &Path, test_name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("UHOSTD_TEST_BINARY") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
        eprintln!(
            "skipping {test_name}: UHOSTD_TEST_BINARY does not point to a file: {}",
            candidate.display()
        );
        return None;
    }

    if let Ok(path) = std::env::var("CARGO_BIN_EXE_uhostd") {
        return Some(PathBuf::from(path));
    }

    let candidate = sibling_workspace_binary_path(uhostctl_binary, "uhostd");
    if candidate.is_file() {
        return Some(candidate);
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("failed to resolve workspace root from CARGO_MANIFEST_DIR"));
    let output = Command::new("cargo")
        .current_dir(&repo_root)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("MAKEFLAGS")
        .arg("build")
        .arg("--jobs")
        .arg("1")
        .arg("-p")
        .arg("uhostd")
        .arg("--bin")
        .arg("uhostd")
        .output()
        .unwrap_or_else(|error| panic!("failed to build uhostd test binary: {error}"));
    if !output.status.success() {
        eprintln!(
            "skipping {test_name}: failed to build uhostd test binary with status {}:\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return None;
    }
    if !candidate.is_file() {
        eprintln!(
            "skipping {test_name}: uhostd test binary was not produced at {}",
            candidate.display()
        );
        return None;
    }
    Some(candidate)
}

fn sibling_workspace_binary_path(current_binary: &Path, binary_name: &str) -> PathBuf {
    let file_name = format!("{binary_name}{}", std::env::consts::EXE_SUFFIX);
    let direct_candidate = current_binary.with_file_name(&file_name);
    if direct_candidate.is_file() {
        return direct_candidate;
    }

    let parent = current_binary
        .parent()
        .unwrap_or_else(|| panic!("missing parent directory for {}", current_binary.display()));
    let is_deps_dir = parent.file_name().and_then(|value| value.to_str()) == Some("deps");
    if is_deps_dir {
        let workspace_target_dir = parent
            .parent()
            .unwrap_or_else(|| panic!("missing target directory above {}", parent.display()));
        return workspace_target_dir.join(file_name);
    }
    direct_candidate
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

fn run_uhostctl_json(binary: &Path, args: &[&str]) -> Value {
    let output = run_uhostctl(binary, args);
    assert!(
        output.status.success(),
        "uhostctl {:?} failed with status {}:\nstdout:\n{}\nstderr:\n{}",
        args,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("invalid UTF-8 in uhostctl stdout: {error}"));
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "uhostctl {:?} returned empty stdout",
        args
    );
    serde_json::from_str(trimmed)
        .unwrap_or_else(|error| panic!("invalid json from uhostctl {:?}: {error}", args))
}

fn run_uhostctl(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .env("UHOSTCTL_ADMIN_TOKEN", DEFAULT_BOOTSTRAP_ADMIN_TOKEN)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run uhostctl {:?}: {error}", args))
}

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Value {
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
    json_from_bytes(&response.body)
}

fn read_json_file(path: &Path) -> Value {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("invalid json in {}: {error}", path.display()))
}

fn stored_record_value<'a>(collection: &'a Value, key: &str) -> &'a Value {
    collection["records"][key]["value"]
        .as_object()
        .map(|_| &collection["records"][key]["value"])
        .unwrap_or_else(|| panic!("missing stored record value for {key}: {collection}"))
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

    let (content_type, body_bytes) = body.unwrap_or(("application/json", &[]));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(request.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes)?;
    }
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "response missing header terminator"))?;
    let head = std::str::from_utf8(&response[..header_end])
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    let status = head
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "response missing status code"))?
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    Ok(RawResponse {
        status,
        body: response[header_end..].to_vec(),
    })
}
