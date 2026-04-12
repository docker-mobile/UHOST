use std::collections::BTreeMap;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use uhost_core::{base64url_encode, sha256_hex};

const BOOTSTRAP_TOKEN: &str = "integration-bootstrap-admin-token";
const GENERATED_TARGET: &str = "ubuntu_22_04_vm";
const GENERATED_WORKLOAD_CLASS: &str = "generated_validation_ubuntu_22_04_vm";
const GENERATED_HOST_CLASS_EVIDENCE_KEY: &str = "linux_container_restricted";
const GENERATED_GUEST_RUN_LINEAGE: &str = "wave3-core-generated-benchmark-evidence_ubuntu_22_04_vm";
const GENERATED_HOST_TARGET: &str = "host";
const GENERATED_HOST_WORKLOAD_CLASS: &str = "generated_validation_host";
const GENERATED_HOST_HOST_CLASS_EVIDENCE_KEY: &str = "linux_bare_metal";

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
fn generated_validation_artifacts_auto_ingest_into_keyed_benchmark_rows_over_http() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    write_generated_validation_bundle(temp.path());

    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("uvm-generated-validation-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping generated_validation_artifacts_auto_ingest_into_keyed_benchmark_rows_over_http: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));

    let first_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let first_campaigns =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-campaigns");
    assert_eq!(first_campaigns.as_array().map(Vec::len), Some(1));
    let first_campaign = find_campaign(&first_campaigns, GENERATED_TARGET);
    let campaign_id = required_string(first_campaign, "id").to_owned();
    assert_eq!(
        first_campaign["name"].as_str(),
        Some("generated-validation-ubuntu_22_04_vm")
    );
    assert_eq!(first_campaign["target"].as_str(), Some(GENERATED_TARGET));
    assert_eq!(
        first_campaign["workload_class"].as_str(),
        Some(GENERATED_WORKLOAD_CLASS)
    );
    assert_eq!(first_campaign["state"].as_str(), Some("ready"));
    assert_eq!(
        first_campaign["require_qemu_baseline"].as_bool(),
        Some(true)
    );
    assert_eq!(
        first_campaign["require_container_baseline"].as_bool(),
        Some(false)
    );

    let first_baselines =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-baselines");
    assert_eq!(first_baselines.as_array().map(Vec::len), Some(8));
    assert_eq!(
        rows_for_campaign(&first_baselines, &campaign_id).len(),
        8,
        "expected one keyed baseline row per generated scenario-engine tuple",
    );
    let first_baseline = find_row(
        &first_baselines,
        &campaign_id,
        "software_dbt",
        "steady_state",
    );
    let first_baseline_id = required_string(first_baseline, "id").to_owned();
    assert_eq!(
        first_baseline["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(
        first_baseline["workload_class"].as_str(),
        Some(GENERATED_WORKLOAD_CLASS)
    );
    assert_eq!(
        first_baseline["guest_run_lineage"].as_str(),
        Some(GENERATED_GUEST_RUN_LINEAGE)
    );
    assert_eq!(first_baseline["measurement_mode"].as_str(), Some("hybrid"));
    assert_eq!(first_baseline["evidence_mode"].as_str(), Some("prohibited"));
    assert_eq!(first_baseline["boot_time_ms"].as_u64(), Some(154));
    assert_eq!(first_baseline["steady_state_score"].as_u64(), Some(13606));
    assert_eq!(first_baseline["control_plane_p99_ms"].as_u64(), Some(20));
    assert!(
        first_baseline["note"]
            .as_str()
            .unwrap_or_default()
            .contains("auto-ingested from docs/benchmarks/generated/ubuntu-validation.md")
    );

    let first_results = request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-results");
    assert_eq!(first_results.as_array().map(Vec::len), Some(8));
    assert_eq!(
        rows_for_campaign(&first_results, &campaign_id).len(),
        8,
        "expected one keyed result row per generated scenario-engine tuple",
    );
    let first_result = find_row(&first_results, &campaign_id, "qemu", "migration_pressure");
    let first_result_id = required_string(first_result, "id").to_owned();
    assert_eq!(
        first_result["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(
        first_result["workload_class"].as_str(),
        Some(GENERATED_WORKLOAD_CLASS)
    );
    assert_eq!(
        first_result["guest_run_lineage"].as_str(),
        Some(GENERATED_GUEST_RUN_LINEAGE)
    );
    assert_eq!(first_result["measurement_mode"].as_str(), Some("hybrid"));
    assert_eq!(first_result["evidence_mode"].as_str(), Some("simulated"));
    assert_eq!(first_result["boot_time_ms"].as_u64(), Some(748));
    assert_eq!(first_result["steady_state_score"].as_u64(), Some(8412));
    assert_eq!(first_result["control_plane_p99_ms"].as_u64(), Some(51));
    assert_eq!(first_result["host_evidence_id"], Value::Null);

    let first_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!("/uvm/benchmark-campaigns/{campaign_id}/summary").as_str(),
    );
    assert_eq!(first_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        first_summary["missing_baselines"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        first_summary["missing_results"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        first_summary["comparisons"].as_array().map(Vec::len),
        Some(8)
    );

    drop(first_guard);

    let _second_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let reopened_campaigns =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-campaigns");
    assert_eq!(reopened_campaigns.as_array().map(Vec::len), Some(1));
    let reopened_campaign = find_campaign(&reopened_campaigns, GENERATED_TARGET);
    assert_eq!(
        required_string(reopened_campaign, "id"),
        campaign_id.as_str()
    );

    let reopened_baselines =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-baselines");
    assert_eq!(reopened_baselines.as_array().map(Vec::len), Some(8));
    assert_eq!(
        rows_for_campaign(&reopened_baselines, &campaign_id).len(),
        8
    );
    let reopened_baseline = find_row(
        &reopened_baselines,
        &campaign_id,
        "software_dbt",
        "steady_state",
    );
    assert_eq!(
        required_string(reopened_baseline, "id"),
        first_baseline_id.as_str()
    );

    let reopened_results =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-results");
    assert_eq!(reopened_results.as_array().map(Vec::len), Some(8));
    assert_eq!(rows_for_campaign(&reopened_results, &campaign_id).len(), 8);
    let reopened_result = find_row(
        &reopened_results,
        &campaign_id,
        "qemu",
        "migration_pressure",
    );
    assert_eq!(
        required_string(reopened_result, "id"),
        first_result_id.as_str()
    );

    let reopened_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!("/uvm/benchmark-campaigns/{campaign_id}/summary").as_str(),
    );
    assert_eq!(reopened_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        reopened_summary["missing_baselines"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        reopened_summary["missing_results"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        reopened_summary["comparisons"].as_array().map(Vec::len),
        Some(8)
    );
}

#[test]
fn generated_validation_host_and_guest_artifacts_surface_distinct_benchmark_campaigns_over_http() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    write_generated_validation_bundle_with_host_and_guest_reports(temp.path());

    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp
        .path()
        .join("uvm-generated-validation-multi-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping generated_validation_host_and_guest_artifacts_surface_distinct_benchmark_campaigns_over_http: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let _guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let campaigns = request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-campaigns");
    assert_eq!(campaigns.as_array().map(Vec::len), Some(2));

    let host_campaign = find_campaign(&campaigns, GENERATED_HOST_TARGET);
    let host_campaign_id = required_string(host_campaign, "id").to_owned();
    assert_eq!(
        host_campaign["name"].as_str(),
        Some("generated-validation-host")
    );
    assert_eq!(
        host_campaign["workload_class"].as_str(),
        Some(GENERATED_HOST_WORKLOAD_CLASS)
    );
    assert_eq!(host_campaign["state"].as_str(), Some("ready"));
    assert_eq!(host_campaign["require_qemu_baseline"].as_bool(), Some(true));
    assert_eq!(
        host_campaign["require_container_baseline"].as_bool(),
        Some(false)
    );

    let guest_campaign = find_campaign(&campaigns, GENERATED_TARGET);
    let guest_campaign_id = required_string(guest_campaign, "id").to_owned();
    assert_eq!(
        guest_campaign["name"].as_str(),
        Some("generated-validation-ubuntu_22_04_vm")
    );
    assert_eq!(
        guest_campaign["workload_class"].as_str(),
        Some(GENERATED_WORKLOAD_CLASS)
    );
    assert_ne!(host_campaign_id, guest_campaign_id);

    let baselines = request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-baselines");
    assert_eq!(baselines.as_array().map(Vec::len), Some(10));
    assert_eq!(rows_for_campaign(&baselines, &host_campaign_id).len(), 2);
    assert_eq!(rows_for_campaign(&baselines, &guest_campaign_id).len(), 8);

    let host_baseline = find_row(&baselines, &host_campaign_id, "software_dbt", "cold_boot");
    assert_eq!(
        host_baseline["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(
        host_baseline["workload_class"].as_str(),
        Some(GENERATED_HOST_WORKLOAD_CLASS)
    );
    assert_eq!(host_baseline["guest_run_lineage"], Value::Null);
    assert_eq!(host_baseline["measurement_mode"].as_str(), Some("direct"));
    assert_eq!(host_baseline["evidence_mode"].as_str(), Some("measured"));

    let guest_baseline = find_row(
        &baselines,
        &guest_campaign_id,
        "software_dbt",
        "steady_state",
    );
    assert_eq!(
        guest_baseline["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(
        guest_baseline["workload_class"].as_str(),
        Some(GENERATED_WORKLOAD_CLASS)
    );
    assert_eq!(
        guest_baseline["guest_run_lineage"].as_str(),
        Some(GENERATED_GUEST_RUN_LINEAGE)
    );
    assert_eq!(guest_baseline["measurement_mode"].as_str(), Some("hybrid"));
    assert_eq!(guest_baseline["evidence_mode"].as_str(), Some("prohibited"));

    let results = request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-results");
    assert_eq!(results.as_array().map(Vec::len), Some(10));
    assert_eq!(rows_for_campaign(&results, &host_campaign_id).len(), 2);
    assert_eq!(rows_for_campaign(&results, &guest_campaign_id).len(), 8);

    let host_result = find_row(&results, &host_campaign_id, "qemu", "service_readiness");
    assert_eq!(
        host_result["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(host_result["guest_run_lineage"], Value::Null);
    assert_eq!(host_result["measurement_mode"].as_str(), Some("direct"));
    assert_eq!(host_result["evidence_mode"].as_str(), Some("simulated"));

    let guest_result = find_row(&results, &guest_campaign_id, "qemu", "migration_pressure");
    assert_eq!(
        guest_result["host_class_evidence_key"].as_str(),
        Some(GENERATED_HOST_CLASS_EVIDENCE_KEY)
    );
    assert_eq!(
        guest_result["guest_run_lineage"].as_str(),
        Some(GENERATED_GUEST_RUN_LINEAGE)
    );
    assert_eq!(guest_result["measurement_mode"].as_str(), Some("hybrid"));
    assert_eq!(guest_result["evidence_mode"].as_str(), Some("simulated"));

    let host_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!("/uvm/benchmark-campaigns/{host_campaign_id}/summary").as_str(),
    );
    assert_eq!(host_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        host_summary["missing_baselines"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        host_summary["missing_results"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        host_summary["comparisons"].as_array().map(Vec::len),
        Some(2)
    );

    let guest_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!("/uvm/benchmark-campaigns/{guest_campaign_id}/summary").as_str(),
    );
    assert_eq!(guest_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        guest_summary["missing_baselines"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        guest_summary["missing_results"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        guest_summary["comparisons"].as_array().map(Vec::len),
        Some(8)
    );
}

#[test]
fn generated_validation_host_and_guest_campaign_ids_remain_stable_across_restart() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    write_generated_validation_bundle_with_host_and_guest_reports(temp.path());

    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp
        .path()
        .join("uvm-generated-validation-multi-restart-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping generated_validation_host_and_guest_campaign_ids_remain_stable_across_restart: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));

    let first_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let first_campaigns =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-campaigns");
    assert_eq!(first_campaigns.as_array().map(Vec::len), Some(2));
    let first_host_campaign = find_campaign(&first_campaigns, GENERATED_HOST_TARGET);
    let first_host_campaign_id = required_string(first_host_campaign, "id").to_owned();
    let first_guest_campaign = find_campaign(&first_campaigns, GENERATED_TARGET);
    let first_guest_campaign_id = required_string(first_guest_campaign, "id").to_owned();
    assert_ne!(first_host_campaign_id, first_guest_campaign_id);

    let first_baselines =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-baselines");
    assert_eq!(first_baselines.as_array().map(Vec::len), Some(10));
    assert_eq!(
        rows_for_campaign(&first_baselines, &first_host_campaign_id).len(),
        2
    );
    assert_eq!(
        rows_for_campaign(&first_baselines, &first_guest_campaign_id).len(),
        8
    );
    let first_host_baseline_ids = row_id_map(&first_baselines, &first_host_campaign_id);
    let first_guest_baseline_ids = row_id_map(&first_baselines, &first_guest_campaign_id);

    let first_results = request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-results");
    assert_eq!(first_results.as_array().map(Vec::len), Some(10));
    assert_eq!(
        rows_for_campaign(&first_results, &first_host_campaign_id).len(),
        2
    );
    assert_eq!(
        rows_for_campaign(&first_results, &first_guest_campaign_id).len(),
        8
    );
    let first_host_result_ids = row_id_map(&first_results, &first_host_campaign_id);
    let first_guest_result_ids = row_id_map(&first_results, &first_guest_campaign_id);

    let first_host_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!(
            "/uvm/benchmark-campaigns/{}/summary",
            first_host_campaign_id
        )
        .as_str(),
    );
    assert_eq!(first_host_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        first_host_summary["comparisons"].as_array().map(Vec::len),
        Some(2)
    );

    let first_guest_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!(
            "/uvm/benchmark-campaigns/{}/summary",
            first_guest_campaign_id
        )
        .as_str(),
    );
    assert_eq!(first_guest_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        first_guest_summary["comparisons"].as_array().map(Vec::len),
        Some(8)
    );

    drop(first_guard);

    let _second_guard = spawn_uhostd(&binary, &config_path);
    wait_for_health(address);

    let reopened_campaigns =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-campaigns");
    assert_eq!(reopened_campaigns.as_array().map(Vec::len), Some(2));
    let reopened_host_campaign = find_campaign(&reopened_campaigns, GENERATED_HOST_TARGET);
    assert_eq!(
        required_string(reopened_host_campaign, "id"),
        first_host_campaign_id.as_str()
    );
    let reopened_guest_campaign = find_campaign(&reopened_campaigns, GENERATED_TARGET);
    assert_eq!(
        required_string(reopened_guest_campaign, "id"),
        first_guest_campaign_id.as_str()
    );

    let reopened_baselines =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-baselines");
    assert_eq!(reopened_baselines.as_array().map(Vec::len), Some(10));
    assert_eq!(
        rows_for_campaign(&reopened_baselines, &first_host_campaign_id).len(),
        2
    );
    assert_eq!(
        rows_for_campaign(&reopened_baselines, &first_guest_campaign_id).len(),
        8
    );
    let reopened_host_baseline_ids = row_id_map(&reopened_baselines, &first_host_campaign_id);
    let reopened_guest_baseline_ids = row_id_map(&reopened_baselines, &first_guest_campaign_id);
    assert_eq!(reopened_host_baseline_ids, first_host_baseline_ids);
    assert_eq!(reopened_guest_baseline_ids, first_guest_baseline_ids);

    let reopened_results =
        request_json_with_bootstrap_token(address, "GET", "/uvm/benchmark-results");
    assert_eq!(reopened_results.as_array().map(Vec::len), Some(10));
    assert_eq!(
        rows_for_campaign(&reopened_results, &first_host_campaign_id).len(),
        2
    );
    assert_eq!(
        rows_for_campaign(&reopened_results, &first_guest_campaign_id).len(),
        8
    );
    let reopened_host_result_ids = row_id_map(&reopened_results, &first_host_campaign_id);
    let reopened_guest_result_ids = row_id_map(&reopened_results, &first_guest_campaign_id);
    assert_eq!(reopened_host_result_ids, first_host_result_ids);
    assert_eq!(reopened_guest_result_ids, first_guest_result_ids);

    let reopened_host_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!(
            "/uvm/benchmark-campaigns/{}/summary",
            first_host_campaign_id
        )
        .as_str(),
    );
    assert_eq!(reopened_host_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        reopened_host_summary["comparisons"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let reopened_guest_summary = request_json_with_bootstrap_token(
        address,
        "GET",
        format!(
            "/uvm/benchmark-campaigns/{}/summary",
            first_guest_campaign_id
        )
        .as_str(),
    );
    assert_eq!(reopened_guest_summary["status"].as_str(), Some("ready"));
    assert_eq!(
        reopened_guest_summary["comparisons"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
}

fn find_campaign<'a>(campaigns: &'a Value, target: &str) -> &'a Value {
    array_items(campaigns)
        .iter()
        .find(|value| value["target"].as_str() == Some(target))
        .unwrap_or_else(|| panic!("missing benchmark campaign for target `{target}`"))
}

fn rows_for_campaign<'a>(rows: &'a Value, campaign_id: &str) -> Vec<&'a Value> {
    array_items(rows)
        .iter()
        .filter(|value| value["campaign_id"].as_str() == Some(campaign_id))
        .collect::<Vec<_>>()
}

fn row_id_map(rows: &Value, campaign_id: &str) -> BTreeMap<String, String> {
    rows_for_campaign(rows, campaign_id)
        .into_iter()
        .map(|value| {
            let engine = required_string(value, "engine");
            let scenario = required_string(value, "scenario");
            let id = required_string(value, "id");
            (format!("{engine}:{scenario}"), id.to_owned())
        })
        .collect::<BTreeMap<_, _>>()
}

fn find_row<'a>(rows: &'a Value, campaign_id: &str, engine: &str, scenario: &str) -> &'a Value {
    let matching = rows_for_campaign(rows, campaign_id)
        .into_iter()
        .filter(|value| value["engine"].as_str() == Some(engine))
        .filter(|value| value["scenario"].as_str() == Some(scenario))
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one row for campaign `{campaign_id}`, engine `{engine}`, scenario `{scenario}`",
    );
    matching[0]
}

fn array_items(value: &Value) -> &[Value] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected array response but found {value}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

fn spawn_uhostd(binary: &str, config_path: &Path) -> ChildGuard {
    let child = Command::new(binary)
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(test_child_stderr())
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "uvm-generated-validation-runtime-test-node"

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

fn test_child_stderr() -> Stdio {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
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

fn request_json_with_bootstrap_token(address: SocketAddr, method: &str, path: &str) -> Value {
    let response = request_with_headers(
        address,
        method,
        path,
        None,
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

fn generated_validation_ubuntu_report_markdown() -> String {
    String::from(
        r#"# UVM Validation Report

- Generated at: 2026-04-09 16:05:49.619701749 +00:00:00
- Target: `ubuntu_22_04_vm`
- Guest architecture: `x86_64`
- Host platform: `linux`
- Execution environment: `container_restricted`
- Measurement mode: `hybrid`
- QEMU available: `true`
- Nested virtualization available: `false`

## Comparison

- UVM claim tier: `research_only` (prohibited)
- QEMU claim tier: `compatible` (simulated)

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | hybrid | 175.44 | 12517.45 | 18.74 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| steady_state | uvm | hybrid | 154.38 | 13605.92 | 19.73 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| migration_pressure | uvm | hybrid | 196.49 | 11428.98 | 24.46 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| fault_recovery | uvm | hybrid | 207.01 | 10340.50 | 25.65 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| cold_boot | qemu | hybrid | 667.58 | 9213.14 | 39.38 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| steady_state | qemu | hybrid | 587.47 | 10014.28 | 41.45 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| migration_pressure | qemu | hybrid | 747.69 | 8411.99 | 51.40 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| fault_recovery | qemu | hybrid | 787.74 | 7610.85 | 53.89 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |

## Stress phases
"#,
    )
}

fn generated_validation_host_report_markdown() -> String {
    String::from(
        r#"# UVM Validation Report

- Generated at: 2026-04-09 16:01:12.000000000 +00:00:00
- Target: `host`
- Guest architecture: `x86_64`
- Host platform: `linux`
- Execution environment: `bare_metal`
- Measurement mode: `direct`
- QEMU available: `true`
- Nested virtualization available: `true`

## Comparison

- UVM claim tier: `competitive` (measured)
- QEMU claim tier: `compatible` (simulated)

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | direct | 89.11 | 14120.44 | 11.42 | backend=software_dbt; target=host; evidence_mode=direct |
| service_readiness | qemu | direct | 312.87 | 10015.12 | 23.68 | backend=qemu-kvm-x86_64; target=host; evidence_mode=direct |

## Stress phases
"#,
    )
}

fn write_generated_validation_bundle(workspace_root: &Path) {
    let generated_dir = workspace_root.join("docs/benchmarks/generated");
    fs::create_dir_all(&generated_dir).unwrap_or_else(|error| panic!("{error}"));

    let report = generated_validation_ubuntu_report_markdown();
    fs::write(generated_dir.join("ubuntu-validation.md"), &report)
        .unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        generated_dir.join("ubuntu-26.04-installer-boot-witness.json"),
        "{\"boot\":\"installer\"}\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        generated_dir.join("ubuntu-26.04-disk-boot-witness.json"),
        "{\"boot\":\"disk\"}\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let manifest = json!({
        "bundle": "wave3-core-generated-benchmark-evidence",
        "artifacts": [
            {
                "path": "docs/benchmarks/generated/ubuntu-validation.md",
                "kind": "validation_report",
                "target": GENERATED_TARGET,
                "generated_at": "2026-04-09 16:05:49.619701749 +00:00:00",
                "sha256": sha256_hex(report.as_bytes()),
                "references": [
                    "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
                    "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json"
                ]
            }
        ]
    });
    fs::write(
        generated_dir.join("uvm-stack-validation-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

fn write_generated_validation_bundle_with_host_and_guest_reports(workspace_root: &Path) {
    let generated_dir = workspace_root.join("docs/benchmarks/generated");
    fs::create_dir_all(&generated_dir).unwrap_or_else(|error| panic!("{error}"));

    let host_report = generated_validation_host_report_markdown();
    fs::write(generated_dir.join("host-validation.md"), &host_report)
        .unwrap_or_else(|error| panic!("{error}"));

    let guest_report = generated_validation_ubuntu_report_markdown();
    fs::write(generated_dir.join("ubuntu-validation.md"), &guest_report)
        .unwrap_or_else(|error| panic!("{error}"));

    fs::write(
        generated_dir.join("ubuntu-26.04-installer-boot-witness.json"),
        "{\"boot\":\"installer\"}\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    fs::write(
        generated_dir.join("ubuntu-26.04-disk-boot-witness.json"),
        "{\"boot\":\"disk\"}\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let manifest = json!({
        "bundle": "wave3-core-generated-benchmark-evidence",
        "artifacts": [
            {
                "path": "docs/benchmarks/generated/host-validation.md",
                "kind": "validation_report",
                "target": GENERATED_HOST_TARGET,
                "generated_at": "2026-04-09 16:01:12.000000000 +00:00:00",
                "sha256": sha256_hex(host_report.as_bytes()),
                "references": []
            },
            {
                "path": "docs/benchmarks/generated/ubuntu-validation.md",
                "kind": "validation_report",
                "target": GENERATED_TARGET,
                "generated_at": "2026-04-09 16:05:49.619701749 +00:00:00",
                "sha256": sha256_hex(guest_report.as_bytes()),
                "references": [
                    "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
                    "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json"
                ]
            }
        ]
    });
    fs::write(
        generated_dir.join("uvm-stack-validation-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}
