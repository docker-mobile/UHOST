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
use uhost_types::UvmInstanceId;

const BOOTSTRAP_TOKEN: &str = "integration-bootstrap-admin-token";
const REQUIRED_WORKLOAD_CLASSES: &[&str] = &[
    "general",
    "cpu_intensive",
    "io_intensive",
    "network_intensive",
];

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

#[test]
fn uvm_claim_tier_runtime_demotes_without_direct_proof_and_preserves_with_it() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("uvm-claim-tier-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping uvm_claim_tier_runtime_demotes_without_direct_proof_and_preserves_with_it: loopback bind not permitted"
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

    let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
    seed_competitive_perf_attestations(address, &instance_id);
    let host_evidence = create_measured_host_evidence(address);
    let host_evidence_id = required_string(&host_evidence, "id");
    let host_class_evidence_key = required_string(&host_evidence, "host_class_evidence_key");

    let demoted_status =
        request_json_with_bootstrap_token(address, "GET", "/uvm/native-claim-status", None);
    assert_eq!(
        demoted_status["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(demoted_status["claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        demoted_status["host_evidence_id"].as_str(),
        Some(host_evidence_id)
    );
    assert_eq!(
        demoted_status["host_class_evidence_key"].as_str(),
        Some(host_class_evidence_key)
    );
    assert_eq!(
        demoted_status["observed_highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        demoted_status["highest_claim_tier"].as_str(),
        Some("compatible")
    );
    assert_eq!(
        demoted_status["benchmark_claim_tier_ceiling"].as_str(),
        Some("compatible")
    );
    assert_eq!(
        demoted_status["benchmark_ready_scenarios"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let demoted_decision = request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id
        })),
    );
    assert_eq!(demoted_decision["claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        demoted_decision["highest_claim_tier"].as_str(),
        Some("compatible")
    );
    assert_eq!(
        demoted_decision["observed_highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        demoted_decision["benchmark_claim_tier_ceiling"].as_str(),
        Some("compatible")
    );
    let demoted_annotations = demoted_decision["metadata"]["annotations"]
        .as_object()
        .unwrap_or_else(|| panic!("missing claim decision annotations"));
    assert_eq!(
        demoted_annotations
            .get("observed_highest_claim_tier")
            .and_then(Value::as_str),
        Some("competitive")
    );
    assert_eq!(
        demoted_annotations
            .get("benchmark_claim_tier_ceiling")
            .and_then(Value::as_str),
        Some("compatible")
    );
    assert_eq!(
        demoted_annotations
            .get("claim_tier_demoted_from")
            .and_then(Value::as_str),
        Some("competitive")
    );
    assert_eq!(
        demoted_annotations
            .get("benchmark_host_class_evidence_key")
            .and_then(Value::as_str),
        Some(host_class_evidence_key)
    );
    assert!(!demoted_annotations.contains_key("benchmark_ready_scenarios"));

    for &workload_class in REQUIRED_WORKLOAD_CLASSES {
        seed_direct_benchmark_claim_proof(address, host_evidence_id, workload_class);
    }

    let preserved_status =
        request_json_with_bootstrap_token(address, "GET", "/uvm/native-claim-status", None);
    assert_eq!(
        preserved_status["native_indistinguishable_status"].as_bool(),
        Some(true)
    );
    assert_eq!(preserved_status["claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        preserved_status["host_evidence_id"].as_str(),
        Some(host_evidence_id)
    );
    assert_eq!(
        preserved_status["host_class_evidence_key"].as_str(),
        Some(host_class_evidence_key)
    );
    assert_eq!(
        preserved_status["observed_highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        preserved_status["highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        preserved_status["benchmark_claim_tier_ceiling"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        preserved_status["benchmark_ready_scenarios"].as_array(),
        Some(&vec![json!("steady_state")])
    );

    let preserved_decision = request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/claim-decisions",
        Some(json!({
            "host_evidence_id": host_evidence_id
        })),
    );
    assert_eq!(preserved_decision["claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        preserved_decision["highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        preserved_decision["observed_highest_claim_tier"].as_str(),
        Some("competitive")
    );
    assert_eq!(
        preserved_decision["benchmark_claim_tier_ceiling"].as_str(),
        Some("competitive")
    );
    let preserved_annotations = preserved_decision["metadata"]["annotations"]
        .as_object()
        .unwrap_or_else(|| panic!("missing claim decision annotations"));
    assert_eq!(
        preserved_annotations
            .get("observed_highest_claim_tier")
            .and_then(Value::as_str),
        Some("competitive")
    );
    assert_eq!(
        preserved_annotations
            .get("benchmark_claim_tier_ceiling")
            .and_then(Value::as_str),
        Some("competitive")
    );
    assert_eq!(
        preserved_annotations
            .get("benchmark_host_class_evidence_key")
            .and_then(Value::as_str),
        Some(host_class_evidence_key)
    );
    assert_eq!(
        preserved_annotations
            .get("benchmark_ready_scenarios")
            .and_then(Value::as_str),
        Some("steady_state")
    );
    assert!(!preserved_annotations.contains_key("claim_tier_demoted_from"));
}

fn seed_competitive_perf_attestations(address: SocketAddr, instance_id: &UvmInstanceId) {
    for &workload_class in REQUIRED_WORKLOAD_CLASSES {
        let attestation = request_json_with_bootstrap_token(
            address,
            "POST",
            "/uvm/perf-attestations",
            Some(json!({
                "instance_id": instance_id.to_string(),
                "workload_class": workload_class,
                "claim_tier": "competitive",
                "claim_evidence_mode": "measured",
                "cpu_overhead_pct": 4,
                "memory_overhead_pct": 4,
                "block_io_latency_overhead_pct": 8,
                "network_latency_overhead_pct": 8,
                "jitter_pct": 7
            })),
        );
        assert_eq!(attestation["workload_class"].as_str(), Some(workload_class));
        assert_eq!(attestation["claim_tier"].as_str(), Some("competitive"));
    }
}

fn create_measured_host_evidence(address: SocketAddr) -> Value {
    request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/host-evidence",
        Some(json!({
            "evidence_mode": "measured",
            "host_platform": host_platform_key(),
            "execution_environment": "bare_metal",
            "hardware_virtualization": true,
            "nested_virtualization": true,
            "qemu_available": true,
            "note": "uvm-claim-tier-runtime"
        })),
    )
}

fn seed_direct_benchmark_claim_proof(
    address: SocketAddr,
    host_evidence_id: &str,
    workload_class: &str,
) {
    let campaign = request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/benchmark-campaigns",
        Some(json!({
            "name": format!("runtime-claim-proof-{workload_class}"),
            "target": "host",
            "workload_class": workload_class,
            "require_qemu_baseline": true,
            "require_container_baseline": false
        })),
    );
    let campaign_id = required_string(&campaign, "id").to_owned();

    for (engine, boot_time_ms, steady_state_score, control_plane_p99_ms) in [
        ("software_dbt", 100_u32, 900_u32, 10_u32),
        ("qemu", 180_u32, 780_u32, 18_u32),
    ] {
        let baseline = request_json_with_bootstrap_token(
            address,
            "POST",
            "/uvm/benchmark-baselines",
            Some(json!({
                "campaign_id": campaign_id.clone(),
                "engine": engine,
                "scenario": "steady_state",
                "measurement_mode": "direct",
                "evidence_mode": "measured",
                "measured": true,
                "boot_time_ms": boot_time_ms,
                "steady_state_score": steady_state_score,
                "control_plane_p99_ms": control_plane_p99_ms,
                "host_evidence_id": host_evidence_id,
                "note": format!("runtime baseline {engine} {workload_class}")
            })),
        );
        assert_eq!(baseline["engine"].as_str(), Some(engine));
        assert_eq!(baseline["workload_class"].as_str(), Some(workload_class));
        assert_eq!(baseline["scenario"].as_str(), Some("steady_state"));
        assert_eq!(baseline["measurement_mode"].as_str(), Some("direct"));

        let result = request_json_with_bootstrap_token(
            address,
            "POST",
            "/uvm/benchmark-results",
            Some(json!({
                "campaign_id": campaign_id.clone(),
                "engine": engine,
                "scenario": "steady_state",
                "measurement_mode": "direct",
                "evidence_mode": "measured",
                "measured": true,
                "boot_time_ms": boot_time_ms.saturating_sub(3),
                "steady_state_score": steady_state_score + 5,
                "control_plane_p99_ms": control_plane_p99_ms.saturating_sub(1),
                "host_evidence_id": host_evidence_id,
                "note": format!("runtime result {engine} {workload_class}")
            })),
        );
        assert_eq!(result["engine"].as_str(), Some(engine));
        assert_eq!(result["workload_class"].as_str(), Some(workload_class));
        assert_eq!(result["scenario"].as_str(), Some("steady_state"));
        assert_eq!(result["measurement_mode"].as_str(), Some("direct"));
    }
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

fn host_platform_key() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "dragonfly") {
        "dragonflybsd"
    } else {
        "linux"
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "uvm-claim-tier-runtime-test-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{BOOTSTRAP_TOKEN}"
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

fn request_json_with_bootstrap_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Value {
    let response = request_with_headers(
        address,
        method,
        path,
        body.as_ref(),
        &[("Authorization", format!("Bearer {BOOTSTRAP_TOKEN}"))],
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

fn request_with_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&Value>,
    headers: &[(&str, String)],
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = matches!(method, "GET" | "HEAD" | "OPTIONS");
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request(address, method, path, body, headers) {
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
    body: Option<&Value>,
    headers: &[(&str, String)],
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let body_text = body.map(Value::to_string).unwrap_or_default();
    let payload = body_text.as_bytes();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        payload.len(),
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
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
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid http response framing"))?;
    let (head, body_bytes) = response.split_at(split + 4);
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
        body: body_bytes.to_vec(),
    })
}
