use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{
    Date, Duration as TimeDuration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset,
};
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::DocumentStore;
use uhost_testkit::TempState;
use uhost_types::{ChangeRequestId, NodeId, OwnershipScope, ResourceMetadata};

struct ChildGuard {
    child: Child,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeedGovernanceChangeRequest {
    id: ChangeRequestId,
    title: String,
    change_type: String,
    requested_by: String,
    approved_by: Option<String>,
    reviewer_comment: Option<String>,
    required_approvals: u8,
    state: SeedGovernanceChangeRequestState,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeedGovernanceChangeRequestState {
    Pending,
    Approved,
    Rejected,
    Applied,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn wave3_evidence_refresh_exercises_cross_domain_rehearsal_story() {
    let temp = TempState::new().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp
        .create_dir_all("state")
        .unwrap_or_else(|error| panic!("{error}"));
    let ingress_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping wave3_evidence_refresh_exercises_cross_domain_rehearsal_story: loopback bind not permitted"
        );
        return;
    };
    let bootstrap_token = "integration-bootstrap-admin-token";
    let config_path = write_test_config(
        &temp,
        "all-in-one.toml",
        address,
        &state_dir,
        Some(bootstrap_token),
    );

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

    let topology = request_json_with_bootstrap_token(
        address,
        "GET",
        "/runtime/topology",
        None,
        bootstrap_token,
    );
    assert_eq!(topology["process_role"].as_str(), Some("all_in_one"));
    assert_eq!(topology["deployment_mode"].as_str(), Some("all_in_one"));
    let groups = topology["service_groups"]
        .as_array()
        .unwrap_or_else(|| panic!("missing service_groups array"));
    let edge_group = find_named_object(groups, "group", "edge");
    let data_group = find_named_object(groups, "group", "data_and_messaging");
    let uvm_group = find_named_object(groups, "group", "uvm");
    assert_eq!(edge_group["owner_role"].as_str(), Some("all_in_one"));
    assert_eq!(data_group["owner_role"].as_str(), Some("all_in_one"));
    assert_eq!(uvm_group["owner_role"].as_str(), Some("all_in_one"));
    assert_array_contains_string(&edge_group["services"], "ingress");
    assert_array_contains_string(&data_group["services"], "netsec");
    assert_array_contains_string(&data_group["services"], "storage");
    assert_array_contains_string(&uvm_group["services"], "uvm-node");
    assert_array_contains_string(&uvm_group["services"], "uvm-observe");

    let workload_token = issue_workload_identity(
        address,
        bootstrap_token,
        "svc:wave3-rehearsal",
        &["ingress", "netsec", "storage", "uvm-node"],
        900,
    );

    let workload_operator_attempt =
        request_with_bearer_token(address, "GET", "/runtime/topology", None, &workload_token);
    assert_eq!(workload_operator_attempt.status, 401);

    let private_network = request_json_with_bearer_token(
        address,
        "POST",
        "/netsec/private-networks",
        Some(json!({
            "name": "wave3-private-network",
            "cidr": "10.42.0.0/16",
            "attachments": []
        })),
        &workload_token,
    );
    let private_network_id = private_network["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private network id"))
        .to_owned();
    seed_private_network_topology(
        address,
        &workload_token,
        &private_network_id,
        "10.42.1.0/24",
        "10.42.0.0/16",
    );

    let ingress_route = request_json_with_bearer_token(
        address,
        "POST",
        "/ingress/routes",
        Some(json!({
            "hostname": "private-api.example.com",
            "target": "http://127.0.0.1:18080",
            "backends": [],
            "protocol": "http",
            "sticky_sessions": false,
            "tls_mode": "offload",
            "change_request_id": ingress_change_request_id,
            "publication": {
                "exposure": "private",
                "private_network": {
                    "private_network_id": private_network_id.clone()
                }
            }
        })),
        &workload_token,
    );
    assert_eq!(
        ingress_route["publication"]["exposure"].as_str(),
        Some("private")
    );
    assert_eq!(
        ingress_route["publication"]["private_network"]["private_network_id"].as_str(),
        Some(private_network_id.as_str())
    );

    let ingress_evaluation = request_json_with_bearer_token(
        address,
        "POST",
        "/ingress/evaluate",
        Some(json!({
            "hostname": "private-api.example.com",
            "protocol": "http",
            "client_ip": "203.0.113.25",
            "private_network_id": private_network_id.clone()
        })),
        &workload_token,
    );
    assert!(ingress_evaluation["admitted"].as_bool().unwrap_or(false));

    let ingress_flow_summary = request_json_with_bearer_token(
        address,
        "GET",
        "/ingress/flow-audit/summary",
        None,
        &workload_token,
    );
    assert!(ingress_flow_summary["total"].as_u64().unwrap_or_default() >= 1);
    assert!(ingress_flow_summary["allow"].as_u64().unwrap_or_default() >= 1);

    let volume = request_json_with_bearer_token(
        address,
        "POST",
        "/storage/volumes",
        Some(json!({
            "name": "wave3-rehearsal-volume",
            "size_gb": 64
        })),
        &workload_token,
    );
    let volume_id = volume["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing volume id"));

    let snapshot_policy = read_collection_record(
        &state_dir
            .join("storage")
            .join("volume_snapshot_policies.json"),
        volume_id,
    );
    assert_eq!(snapshot_policy["deleted"].as_bool(), Some(false));
    assert_eq!(snapshot_policy["value"]["state"].as_str(), Some("active"));
    assert_eq!(
        snapshot_policy["value"]["metadata"]["lifecycle"].as_str(),
        Some("ready")
    );

    let snapshot_workflow = read_collection_record(
        &state_dir
            .join("storage")
            .join("volume_snapshot_workflows.json"),
        volume_id,
    );
    assert_eq!(snapshot_workflow["deleted"].as_bool(), Some(false));
    assert_eq!(
        snapshot_workflow["value"]["phase"].as_str(),
        Some("completed")
    );
    assert!(
        snapshot_workflow["value"]["steps"]
            .as_array()
            .map(|steps| steps
                .iter()
                .all(|step| step["state"].as_str() == Some("completed")))
            .unwrap_or(false)
    );

    let recovery_point = read_collection_record(
        &state_dir
            .join("storage")
            .join("volume_recovery_points.json"),
        volume_id,
    );
    assert_eq!(recovery_point["deleted"].as_bool(), Some(false));
    assert_eq!(
        recovery_point["value"]["capture_trigger"].as_str(),
        Some("policy_activation")
    );
    assert_eq!(recovery_point["value"]["execution_count"].as_u64(), Some(1));
    assert_eq!(
        recovery_point["value"]["metadata"]["lifecycle"].as_str(),
        Some("ready")
    );
    assert!(!recovery_point["value"]["latest_snapshot_at"].is_null());
    assert!(!recovery_point["value"]["next_snapshot_after"].is_null());

    let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let capability = request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(json!({
            "node_id": node_id.to_string(),
            "host_platform": "linux",
            "architecture": "x86_64",
            "accelerator_backends": ["software_dbt"],
            "max_vcpu": 8,
            "max_memory_mb": 16384,
            "numa_nodes": 1,
            "supports_secure_boot": false,
            "supports_live_migration": false,
            "supports_pci_passthrough": false,
            "software_runner_supported": true,
            "host_evidence_mode": "direct_host"
        })),
        bootstrap_token,
    );
    let capability_id = capability["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing capability id"));

    let preflight = request_json_with_bootstrap_token(
        address,
        "POST",
        "/uvm/runtime/preflight",
        Some(json!({
            "capability_id": capability_id,
            "guest_architecture": "x86_64",
            "guest_os": "linux",
            "vcpu": 2,
            "memory_mb": 2048,
            "migration_policy": "cold_only",
            "require_secure_boot": false,
            "requires_live_migration": false,
            "execution_intent": {
                "preferred_backend": "kvm",
                "fallback_policy": "allow_compatible",
                "required_portability_tier": "portable",
                "evidence_strictness": "allow_simulated"
            }
        })),
        bootstrap_token,
    );
    assert!(preflight["legal_allowed"].as_bool().unwrap_or(false));
    assert!(preflight["placement_admitted"].as_bool().unwrap_or(false));
    assert_eq!(preflight["selected_backend"].as_str(), Some("software_dbt"));
    assert_eq!(
        preflight["portability_assessment"]["supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        preflight["portability_assessment"]["selected_backend"].as_str(),
        Some("software_dbt")
    );
    assert_eq!(
        preflight["portability_assessment"]["selected_via_fallback"].as_bool(),
        Some(true)
    );
    assert_array_contains_string(
        &preflight["portability_assessment"]["eligible_backends"],
        "software_dbt",
    );
    assert!(
        preflight["portability_assessment"]["selection_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("preferred backend kvm unavailable"))
    );
}

#[test]
fn wave3_generated_benchmark_artifacts_are_present_and_coherent() {
    const GENERATED_VALIDATION_REPORT_MAX_SKEW_SECONDS: u64 = 72 * 60 * 60;
    const GENERATED_VALIDATION_REPORT_MAX_AGE_DAYS: i64 = 30;
    const GENERATED_BENCHMARK_MANIFEST_PATH: &str =
        "docs/benchmarks/generated/uvm-stack-validation-manifest.json";

    let comparison_doc = read_text_file("docs/benchmarks/uvm-qemu-comparison.md");
    for report_name in [
        "host-validation.md",
        "ubuntu-validation.md",
        "apple-validation.md",
    ] {
        assert!(
            comparison_doc.contains(&format!("- `{report_name}`")),
            "docs/benchmarks/uvm-qemu-comparison.md is missing `{report_name}`"
        );
    }
    assert!(
        comparison_doc.contains("- `uvm-stack-validation-manifest.json`"),
        "docs/benchmarks/uvm-qemu-comparison.md is missing `uvm-stack-validation-manifest.json`"
    );

    let stack_validation_script = read_text_file("scripts/run-uvm-stack-validation.sh");
    for expected in [
        "TARGETS=(host ubuntu apple)",
        "MANIFEST_PATH=\"$OUT_DIR/uvm-stack-validation-manifest.json\"",
        "script_sha=\"$(sha256_artifact \"scripts/run-uvm-stack-validation.sh\")\"",
        "focused_gate_sha=\"$(sha256_artifact \"ci/check-generated-benchmark-artifacts.sh\")\"",
        "wave3_evidence_test_sha=\"$(sha256_artifact \"cmd/uhostd/tests/wave3_evidence.rs\")\"",
        "host_report_references_json='[]'",
        "qemu_probe_evidence_references_json=\"$(json_array_of_strings \\",
        "ubuntu_report_references_json=\"$(json_array_of_strings \\",
        "\"script_sha256\": \"$script_sha\"",
        "\"verification\": {",
        "\"focused_gate\": {",
        "\"wave3_evidence_test\": {",
        "\"path\": \"ci/check-generated-benchmark-artifacts.sh\"",
        "\"path\": \"cmd/uhostd/tests/wave3_evidence.rs\"",
        "\"test_name\": \"wave3_generated_benchmark_artifacts_are_present_and_coherent\"",
        "\"evidence_class\": \"derived_summary\"",
        "\"evidence_class\": \"machine_verifiable\"",
        "\"reference_coverage\": \"partial\"",
        "\"references\": $ubuntu_report_references_json",
        "bash scripts/run-uvm-boot-witness.sh",
        "bash scripts/run-uvm-native-guest-control.sh",
        "bash scripts/run-qemu-tcg-boot-probe.sh",
        "bash scripts/run-qemu-tcg-cloudimg-guest-control.sh",
        "LEGACY_BOOT_PROBE_LOG_PATH=\"$OUT_DIR/qemu-tcg-ubuntu-26.04-boot-probe.log\"",
        "cleanup_manifest_excluded_artifacts",
        "emit_validation_manifest",
    ] {
        assert!(
            stack_validation_script.contains(expected),
            "scripts/run-uvm-stack-validation.sh is missing `{expected}`"
        );
    }

    let benchmark_artifact_gate = read_text_file("ci/check-generated-benchmark-artifacts.sh");
    assert!(
        benchmark_artifact_gate.contains(
            "cargo test -p uhostd --test wave3_evidence wave3_generated_benchmark_artifacts_are_present_and_coherent -- --exact"
        ),
        "ci/check-generated-benchmark-artifacts.sh must enforce the exact wave3 generated benchmark artifact evidence test"
    );
    assert!(
        benchmark_artifact_gate.contains(
            "cargo test -p uhostd --test uvm_generated_validation_runtime generated_validation_artifacts_auto_ingest_into_keyed_benchmark_rows_over_http -- --exact"
        ),
        "ci/check-generated-benchmark-artifacts.sh must enforce the exact generated validation runtime ingest test"
    );

    let wave3_gate = read_text_file("ci/wave3-evidence-gate.sh");
    assert!(
        wave3_gate.contains("bash \"$REPO_ROOT/ci/check-generated-benchmark-artifacts.sh\"")
            || wave3_gate.contains("bash ci/check-generated-benchmark-artifacts.sh"),
        "ci/wave3-evidence-gate.sh must run ci/check-generated-benchmark-artifacts.sh"
    );

    let hyperscale_script = read_text_file("scripts/run-hyperscale.sh");
    assert!(
        hyperscale_script.contains("bash \"$REPO_ROOT/ci/check-generated-benchmark-artifacts.sh\"")
            || hyperscale_script.contains("bash ci/check-generated-benchmark-artifacts.sh"),
        "scripts/run-hyperscale.sh must verify generated benchmark artifacts before running load profiles"
    );

    let manifest = read_json_file(GENERATED_BENCHMARK_MANIFEST_PATH);
    assert_eq!(manifest["schema_version"].as_u64(), Some(3));
    assert_eq!(
        manifest["bundle"].as_str(),
        Some("wave3-core-generated-benchmark-evidence")
    );
    let generator_script_path = manifest["generator"]["script"].as_str().unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing generator.script")
    });
    assert_eq!(generator_script_path, "scripts/run-uvm-stack-validation.sh");
    let generator_script_digest = manifest["generator"]["script_sha256"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing generator.script_sha256")
        });
    assert_sha256_hex(
        generator_script_digest,
        &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} generator.script_sha256"),
    );
    assert_eq!(
        generator_script_digest,
        file_sha256(generator_script_path),
        "generator script digest mismatch in {GENERATED_BENCHMARK_MANIFEST_PATH} for {generator_script_path}"
    );
    assert_eq!(
        manifest["generator"]["command"].as_str(),
        Some("bash scripts/run-uvm-stack-validation.sh")
    );
    assert_eq!(
        manifest["generator"]["generated_directory"].as_str(),
        Some("docs/benchmarks/generated")
    );
    assert_eq!(
        manifest["generator"]["directory_inventory"].as_str(),
        Some("exact_manifest_paths")
    );
    let verification = manifest["verification"]
        .as_object()
        .unwrap_or_else(|| panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification"));
    let verification_keys = verification.keys().cloned().collect::<BTreeSet<_>>();
    let expected_verification_keys = ["focused_gate", "wave3_evidence_test"]
        .into_iter()
        .map(|key| key.to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        verification_keys, expected_verification_keys,
        "unexpected verification bindings in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    let focused_gate = verification.get("focused_gate").unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.focused_gate")
    });
    let focused_gate_path = focused_gate["path"].as_str().unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.focused_gate.path")
    });
    assert_eq!(
        focused_gate_path,
        "ci/check-generated-benchmark-artifacts.sh"
    );
    let focused_gate_digest = focused_gate["sha256"].as_str().unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.focused_gate.sha256")
    });
    assert_sha256_hex(
        focused_gate_digest,
        &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} verification.focused_gate.sha256"),
    );
    assert_eq!(
        focused_gate_digest,
        file_sha256(focused_gate_path),
        "verification focused gate digest mismatch in {GENERATED_BENCHMARK_MANIFEST_PATH} for {focused_gate_path}"
    );
    let wave3_evidence_test = verification.get("wave3_evidence_test").unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.wave3_evidence_test")
    });
    let wave3_evidence_test_path = wave3_evidence_test["path"].as_str().unwrap_or_else(|| {
        panic!(
            "{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.wave3_evidence_test.path"
        )
    });
    assert_eq!(
        wave3_evidence_test_path,
        "cmd/uhostd/tests/wave3_evidence.rs"
    );
    assert_eq!(
        wave3_evidence_test["test_name"].as_str(),
        Some("wave3_generated_benchmark_artifacts_are_present_and_coherent")
    );
    let wave3_evidence_test_digest = wave3_evidence_test["sha256"].as_str().unwrap_or_else(|| {
        panic!(
            "{GENERATED_BENCHMARK_MANIFEST_PATH} is missing verification.wave3_evidence_test.sha256"
        )
    });
    assert_sha256_hex(
        wave3_evidence_test_digest,
        &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} verification.wave3_evidence_test.sha256"),
    );
    assert_eq!(
        wave3_evidence_test_digest,
        file_sha256(wave3_evidence_test_path),
        "verification wave3 evidence test digest mismatch in {GENERATED_BENCHMARK_MANIFEST_PATH} for {wave3_evidence_test_path}"
    );
    let generator_steps = json_string_array(
        &manifest["generator"]["steps"],
        &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} generator.steps"),
    );
    assert_eq!(
        generator_steps,
        vec![
            "cargo test -p uhost-uvm --lib".to_owned(),
            "cargo run -p uhost-uvm --example uvm_validation_report -- host".to_owned(),
            "cargo run -p uhost-uvm --example uvm_validation_report -- ubuntu".to_owned(),
            "cargo run -p uhost-uvm --example uvm_validation_report -- apple".to_owned(),
            "bash scripts/run-uvm-boot-witness.sh".to_owned(),
            "bash scripts/run-uvm-native-guest-control.sh".to_owned(),
            "bash scripts/run-qemu-tcg-boot-probe.sh".to_owned(),
        ],
        "unexpected generator step list in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    let optional_steps = manifest["generator"]["optional_steps"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing generator.optional_steps")
        });
    assert_eq!(
        optional_steps.len(),
        1,
        "unexpected generator.optional_steps length in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    let cloudimg_optional_step = find_named_object(
        optional_steps,
        "command",
        "bash scripts/run-qemu-tcg-cloudimg-guest-control.sh",
    );
    assert_eq!(
        cloudimg_optional_step["activation_env"].as_str(),
        Some("UHOST_RUN_CLOUDIMG_GUEST_CONTROL")
    );
    assert_eq!(
        cloudimg_optional_step["activation_value"].as_str(),
        Some("1")
    );
    let cloudimg_enabled = cloudimg_optional_step["enabled"].as_bool().unwrap_or_else(|| {
        panic!(
            "{GENERATED_BENCHMARK_MANIFEST_PATH} optional cloudimg step is missing a boolean enabled flag"
        )
    });
    let optional_artifact_groups = manifest["generator"]["optional_artifact_groups"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} is missing generator.optional_artifact_groups"
            )
        });
    assert_eq!(
        optional_artifact_groups.len(),
        1,
        "unexpected generator.optional_artifact_groups length in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    let cloudimg_optional_group = find_named_object(
        optional_artifact_groups,
        "name",
        "qemu_tcg_cloudimg_guest_control",
    );
    assert_eq!(
        cloudimg_optional_group["activation_env"].as_str(),
        Some("UHOST_RUN_CLOUDIMG_GUEST_CONTROL")
    );
    assert_eq!(
        cloudimg_optional_group["activation_value"].as_str(),
        Some("1")
    );
    assert_eq!(
        cloudimg_optional_group["enabled"].as_bool(),
        Some(cloudimg_enabled)
    );
    let cloudimg_candidate_paths = json_string_array(
        &cloudimg_optional_group["candidate_artifacts"],
        &format!(
            "{GENERATED_BENCHMARK_MANIFEST_PATH} qemu_tcg_cloudimg_guest_control candidate_artifacts"
        ),
    );
    assert_eq!(
        cloudimg_candidate_paths,
        vec![
            "docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json".to_owned(),
            "docs/benchmarks/generated/qemu-tcg-cloudimg-console.log".to_owned(),
            "docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log".to_owned(),
        ]
    );
    let cloudimg_present_paths = json_string_array(
        &cloudimg_optional_group["present_artifacts"],
        &format!(
            "{GENERATED_BENCHMARK_MANIFEST_PATH} qemu_tcg_cloudimg_guest_control present_artifacts"
        ),
    );
    let cloudimg_candidate_path_set = cloudimg_candidate_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let cloudimg_present_path_set = cloudimg_present_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        cloudimg_present_path_set.is_subset(&cloudimg_candidate_path_set),
        "present cloudimg artifacts must be a subset of candidate cloudimg artifacts in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    if cloudimg_enabled {
        for required in [
            "docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json",
            "docs/benchmarks/generated/qemu-tcg-cloudimg-console.log",
        ] {
            assert!(
                cloudimg_present_path_set.contains(required),
                "{GENERATED_BENCHMARK_MANIFEST_PATH} enabled the cloudimg optional step without recording `{required}`"
            );
        }
    } else {
        assert!(
            cloudimg_present_path_set.is_empty(),
            "{GENERATED_BENCHMARK_MANIFEST_PATH} disabled the cloudimg optional step but still reported present cloudimg artifacts"
        );
    }
    let manifest_generated_at = manifest["generated_at"]
        .as_str()
        .unwrap_or_else(|| panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing generated_at"));
    let manifest_generated_at =
        parse_generated_at(manifest_generated_at, GENERATED_BENCHMARK_MANIFEST_PATH);
    let manifest_age = OffsetDateTime::now_utc() - manifest_generated_at;
    assert!(
        manifest_age <= TimeDuration::days(GENERATED_VALIDATION_REPORT_MAX_AGE_DAYS),
        "generated benchmark manifest is stale: manifest age is {} days, which exceeds the {} day freshness budget; rerun `bash scripts/run-uvm-stack-validation.sh` and refresh docs/benchmarks/generated",
        manifest_age.whole_days(),
        GENERATED_VALIDATION_REPORT_MAX_AGE_DAYS,
    );

    let manifest_artifact_entries = manifest["artifacts"].as_array().unwrap_or_else(|| {
        panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing the artifacts array")
    });
    let mut manifest_artifacts = BTreeMap::new();
    for artifact in manifest_artifact_entries {
        let path = artifact["path"].as_str().unwrap_or_else(|| {
            panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} contains an artifact without a path")
        });
        assert!(
            path.starts_with("docs/benchmarks/generated/"),
            "{GENERATED_BENCHMARK_MANIFEST_PATH} contains an artifact outside docs/benchmarks/generated: {path}"
        );
        let kind = artifact["kind"].as_str().unwrap_or_else(|| {
            panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} contains an artifact without a kind")
        });
        assert!(
            matches!(
                kind,
                "validation_report"
                    | "boot_witness"
                    | "native_guest_control"
                    | "qemu_probe_summary"
                    | "qemu_probe_raw_log"
                    | "qemu_probe_text_log"
                    | "qemu_probe_kernel_log"
                    | "qemu_cloudimg_guest_control_summary"
                    | "qemu_cloudimg_console_log"
                    | "qemu_cloudimg_unixbench_log"
            ),
            "unexpected artifact kind `{kind}` for {path} in {GENERATED_BENCHMARK_MANIFEST_PATH}"
        );
        let evidence_class = artifact["evidence_class"].as_str().unwrap_or_else(|| {
            panic!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} contains an artifact without evidence_class"
            )
        });
        assert!(
            matches!(evidence_class, "derived_summary" | "machine_verifiable"),
            "unexpected evidence_class `{evidence_class}` for {path} in {GENERATED_BENCHMARK_MANIFEST_PATH}"
        );
        let digest = artifact["sha256"].as_str().unwrap_or_else(|| {
            panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} contains an artifact without sha256")
        });
        assert_sha256_hex(digest, &format!("manifest digest for {path}"));
        assert_nonempty_file(path);
        assert_eq!(
            digest,
            file_sha256(path),
            "sha256 mismatch for manifest artifact `{path}` in {GENERATED_BENCHMARK_MANIFEST_PATH}"
        );
        assert!(
            manifest_artifacts
                .insert(path.to_owned(), artifact.clone())
                .is_none(),
            "{GENERATED_BENCHMARK_MANIFEST_PATH} contains duplicate artifact entry `{path}`"
        );
    }

    let actual_manifest_paths = manifest_artifacts.keys().cloned().collect::<BTreeSet<_>>();
    let mut expected_manifest_paths = [
        "docs/benchmarks/generated/host-validation.md",
        "docs/benchmarks/generated/ubuntu-validation.md",
        "docs/benchmarks/generated/apple-validation.md",
        "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
        "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json",
        "docs/benchmarks/generated/uvm-native-guest-control.json",
        "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json",
        "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log",
        "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log",
        "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    expected_manifest_paths.extend(cloudimg_present_path_set.iter().cloned());
    assert_eq!(
        actual_manifest_paths, expected_manifest_paths,
        "unexpected artifact set in {GENERATED_BENCHMARK_MANIFEST_PATH}"
    );
    for candidate_path in &cloudimg_candidate_paths {
        let manifest_entry = manifest_artifacts.get(candidate_path.as_str());
        if cloudimg_present_path_set.contains(candidate_path) {
            assert!(
                manifest_entry.is_some(),
                "{GENERATED_BENCHMARK_MANIFEST_PATH} recorded present cloudimg artifact `{candidate_path}` outside the manifest artifacts list"
            );
        } else {
            assert!(
                manifest_entry.is_none(),
                "{GENERATED_BENCHMARK_MANIFEST_PATH} listed cloudimg artifact `{candidate_path}` without recording it as present"
            );
        }
    }
    let actual_generated_paths = generated_directory_files("docs/benchmarks/generated");
    let expected_generated_paths = expected_manifest_paths
        .iter()
        .cloned()
        .chain(std::iter::once(
            GENERATED_BENCHMARK_MANIFEST_PATH.to_owned(),
        ))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_generated_paths, expected_generated_paths,
        "docs/benchmarks/generated must exactly match {GENERATED_BENCHMARK_MANIFEST_PATH} plus the manifest itself"
    );
    for (path, artifact) in &manifest_artifacts {
        let evidence_class = artifact["evidence_class"].as_str().unwrap_or_else(|| {
            panic!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} artifact `{path}` is missing evidence_class"
            )
        });
        if evidence_class != "derived_summary" {
            continue;
        }
        let references = json_string_array(
            &artifact["references"],
            &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} references for {path}"),
        );
        for reference_path in references {
            let referenced_artifact = manifest_artifacts
                .get(reference_path.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{GENERATED_BENCHMARK_MANIFEST_PATH} derived summary `{path}` references missing artifact `{reference_path}`"
                    )
                });
            assert_eq!(
                referenced_artifact["evidence_class"].as_str(),
                Some("machine_verifiable"),
                "{GENERATED_BENCHMARK_MANIFEST_PATH} derived summary `{path}` must not launder evidence through derived summary `{reference_path}`"
            );
        }
    }

    let generated_times = [
        (
            "docs/benchmarks/generated/host-validation.md",
            "host",
            "host_only",
            "none",
            &[] as &[&str],
        ),
        (
            "docs/benchmarks/generated/ubuntu-validation.md",
            "ubuntu_22_04_vm",
            "x86_64",
            "partial",
            &[
                "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
                "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json",
                "docs/benchmarks/generated/uvm-native-guest-control.json",
                "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log",
                "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log",
                "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log",
            ][..],
        ),
        (
            "docs/benchmarks/generated/apple-validation.md",
            "apple_mac_studio_m1_pro_sim",
            "aarch64",
            "none",
            &[] as &[&str],
        ),
    ]
    .map(|(path, target, guest_architecture, reference_coverage, expected_references)| {
        let manifest_entry = manifest_artifacts
            .get(path)
            .unwrap_or_else(|| panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing `{path}`"));
        assert_eq!(manifest_entry["kind"].as_str(), Some("validation_report"));
        assert_eq!(manifest_entry["evidence_class"].as_str(), Some("derived_summary"));
        assert_eq!(manifest_entry["target"].as_str(), Some(target));
        assert_eq!(
            manifest_entry["reference_coverage"].as_str(),
            Some(reference_coverage),
            "unexpected validation report reference_coverage in {GENERATED_BENCHMARK_MANIFEST_PATH} for {path}"
        );
        let validation_report_references = json_string_array(
            &manifest_entry["references"],
            &format!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} validation report references for {path}"
            ),
        );
        assert_eq!(
            validation_report_references,
            expected_references
                .iter()
                .map(|reference| (*reference).to_owned())
                .collect::<Vec<_>>(),
            "unexpected validation report references in {GENERATED_BENCHMARK_MANIFEST_PATH} for {path}"
        );
        for reference_path in &validation_report_references {
            assert_ne!(
                reference_path, path,
                "{GENERATED_BENCHMARK_MANIFEST_PATH} must not self-reference validation report `{path}`"
            );
            assert!(
                manifest_artifacts.contains_key(reference_path.as_str()),
                "{GENERATED_BENCHMARK_MANIFEST_PATH} validation report `{path}` references missing artifact `{reference_path}`"
            );
        }
        let report = read_text_file(path);
        let report_generated_at = extract_markdown_field(&report, path, "- Generated at:");
        assert_eq!(
            manifest_entry["generated_at"].as_str(),
            Some(report_generated_at),
            "unexpected report generated_at in {GENERATED_BENCHMARK_MANIFEST_PATH} for {path}"
        );
        assert_markdown_field_equals(&report, path, "- Target:", &format!("`{target}`"));
        assert_markdown_field_equals(
            &report,
            path,
            "- Guest architecture:",
            &format!("`{guest_architecture}`"),
        );
        assert_markdown_field_equals(&report, path, "- Measurement mode:", "`hybrid`");
        assert!(
            report.contains("## Scenario matrix"),
            "{path} is missing the scenario matrix section"
        );
        assert!(
            report.contains("## Fault injection"),
            "{path} is missing the fault injection section"
        );
        parse_generated_at(report_generated_at, path)
    });

    let earliest = generated_times
        .iter()
        .min()
        .copied()
        .unwrap_or_else(|| panic!("missing validation report timestamps"));
    let latest = generated_times
        .iter()
        .max()
        .copied()
        .unwrap_or_else(|| panic!("missing validation report timestamps"));
    let skew_seconds = latest.unix_timestamp().abs_diff(earliest.unix_timestamp());
    assert!(
        skew_seconds <= GENERATED_VALIDATION_REPORT_MAX_SKEW_SECONDS,
        "generated validation reports drift by more than 72 hours ({skew_seconds} seconds)"
    );
    let manifest_skew_seconds = manifest_generated_at
        .unix_timestamp()
        .abs_diff(latest.unix_timestamp());
    assert!(
        manifest_skew_seconds <= GENERATED_VALIDATION_REPORT_MAX_SKEW_SECONDS,
        "generated benchmark manifest timestamp drifts by more than 72 hours from the newest validation report ({manifest_skew_seconds} seconds)"
    );

    let bundle_age = OffsetDateTime::now_utc() - latest;
    assert!(
        bundle_age <= TimeDuration::days(GENERATED_VALIDATION_REPORT_MAX_AGE_DAYS),
        "generated validation reports are stale: latest report age is {} days, which exceeds the {} day freshness budget; rerun `bash scripts/run-uvm-stack-validation.sh` and refresh docs/benchmarks/generated",
        bundle_age.whole_days(),
        GENERATED_VALIDATION_REPORT_MAX_AGE_DAYS,
    );

    let installer_boot =
        read_json_file("docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json");
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json")
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("boot_witness")
    );
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json")
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_eq!(installer_boot["backend"].as_str(), Some("software_dbt"));
    assert_eq!(installer_boot["firmware_profile"].as_str(), Some("bios"));
    assert_eq!(
        installer_boot["primary_boot_device"].as_str(),
        Some("cdrom")
    );
    assert_eq!(installer_boot["guest_control_ready"].as_bool(), Some(true));
    assert_eq!(
        installer_boot["guest_control"]["benchmark_runs"].as_u64(),
        Some(0)
    );
    assert!(installer_boot["cdrom_image"].as_str().is_some());
    assert_array_contains_string(&installer_boot["boot_stages"], "native_control:ready");
    assert_service_state(
        &installer_boot["guest_control"]["service_states"],
        "installer",
        "running",
    );
    assert_array_contains_string(&installer_boot["telemetry"], "heartbeat");

    let disk_boot = read_json_file("docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json");
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json")
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("boot_witness")
    );
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json")
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_eq!(disk_boot["backend"].as_str(), Some("software_dbt"));
    assert_eq!(
        disk_boot["firmware_profile"].as_str(),
        Some("uefi_standard")
    );
    assert_eq!(disk_boot["primary_boot_device"].as_str(), Some("disk"));
    assert_eq!(disk_boot["guest_control_ready"].as_bool(), Some(true));
    assert_eq!(
        disk_boot["guest_control"]["benchmark_runs"].as_u64(),
        Some(0)
    );
    assert!(disk_boot["cdrom_image"].is_null());
    assert_array_contains_string(&disk_boot["boot_stages"], "native_control:ready");
    assert_service_state(
        &disk_boot["guest_control"]["service_states"],
        "cloud-init",
        "running",
    );
    assert_array_contains_string(&disk_boot["telemetry"], "heartbeat");

    let native_guest_control =
        read_json_file("docs/benchmarks/generated/uvm-native-guest-control.json");
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/uvm-native-guest-control.json")
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("native_guest_control")
    );
    assert_eq!(
        manifest_artifacts
            .get("docs/benchmarks/generated/uvm-native-guest-control.json")
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_eq!(
        native_guest_control["backend"].as_str(),
        Some("software_dbt")
    );
    assert_eq!(
        native_guest_control["primary_boot_device"].as_str(),
        Some("disk")
    );
    assert_eq!(
        native_guest_control["guest_control_ready"].as_bool(),
        Some(true)
    );
    assert_eq!(
        native_guest_control["guest_control"]["benchmark_runs"].as_u64(),
        Some(1)
    );
    assert_array_contains_string(&native_guest_control["boot_stages"], "native_control:ready");
    assert!(
        native_guest_control["telemetry"]
            .as_array()
            .is_some_and(|items| items.is_empty()),
        "docs/benchmarks/generated/uvm-native-guest-control.json expected an empty telemetry list"
    );
    assert_service_state(
        &native_guest_control["guest_control"]["service_states"],
        "guest-control",
        "running",
    );
    let unixbench_command = find_guest_command(
        &native_guest_control,
        "docs/benchmarks/generated/uvm-native-guest-control.json",
        "unixbench --summary",
    );
    assert!(
        unixbench_command["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("System Benchmarks Index Score")),
        "docs/benchmarks/generated/uvm-native-guest-control.json is missing the UnixBench summary output"
    );
    let hash_command = find_guest_command(
        &native_guest_control,
        "docs/benchmarks/generated/uvm-native-guest-control.json",
        "sha256sum /var/log/unixbench/latest.log",
    );
    let digest = hash_command["stdout"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "docs/benchmarks/generated/uvm-native-guest-control.json missing stdout for unixbench digest"
            )
        })
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "docs/benchmarks/generated/uvm-native-guest-control.json missing digest content"
            )
        });
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    let meminfo_command = find_guest_command(
        &native_guest_control,
        "docs/benchmarks/generated/uvm-native-guest-control.json",
        "cat /proc/meminfo",
    );
    assert!(
        meminfo_command["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("MemTotal:")),
        "docs/benchmarks/generated/uvm-native-guest-control.json is missing /proc/meminfo output"
    );

    if cloudimg_enabled {
        let cloudimg_summary_path =
            "docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json";
        let cloudimg_console_log_path = "docs/benchmarks/generated/qemu-tcg-cloudimg-console.log";
        let cloudimg_unixbench_log_path =
            "docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log";
        let cloudimg_summary = read_json_file(cloudimg_summary_path);
        let cloudimg_summary_manifest = manifest_artifacts
            .get(cloudimg_summary_path)
            .unwrap_or_else(|| {
                panic!("{GENERATED_BENCHMARK_MANIFEST_PATH} is missing {cloudimg_summary_path}")
            });
        assert_eq!(
            cloudimg_summary_manifest["kind"].as_str(),
            Some("qemu_cloudimg_guest_control_summary")
        );
        assert_eq!(
            cloudimg_summary_manifest["evidence_class"].as_str(),
            Some("derived_summary")
        );
        assert_eq!(
            cloudimg_summary_manifest["reference_coverage"].as_str(),
            Some("complete")
        );
        let expected_cloudimg_references = {
            let mut references = vec![cloudimg_console_log_path.to_owned()];
            if cloudimg_present_path_set.contains(cloudimg_unixbench_log_path) {
                references.push(cloudimg_unixbench_log_path.to_owned());
            }
            references
        };
        assert_eq!(
            json_string_array(
                &cloudimg_summary_manifest["references"],
                &format!("{GENERATED_BENCHMARK_MANIFEST_PATH} qemu cloudimg summary references"),
            ),
            expected_cloudimg_references
        );
        assert_eq!(
            cloudimg_summary["console_log"].as_str(),
            Some(cloudimg_console_log_path)
        );
        assert_eq!(
            cloudimg_summary["unixbench_log"].as_str(),
            Some(cloudimg_unixbench_log_path)
        );
        assert_eq!(
            cloudimg_summary["unixbench_attempted"].as_bool(),
            Some(cloudimg_present_path_set.contains(cloudimg_unixbench_log_path))
        );
        assert_eq!(
            manifest_artifacts
                .get(cloudimg_console_log_path)
                .and_then(|artifact| artifact["kind"].as_str()),
            Some("qemu_cloudimg_console_log")
        );
        assert_eq!(
            manifest_artifacts
                .get(cloudimg_console_log_path)
                .and_then(|artifact| artifact["evidence_class"].as_str()),
            Some("machine_verifiable")
        );
        assert_nonempty_file(cloudimg_console_log_path);
        if cloudimg_present_path_set.contains(cloudimg_unixbench_log_path) {
            assert_eq!(
                manifest_artifacts
                    .get(cloudimg_unixbench_log_path)
                    .and_then(|artifact| artifact["kind"].as_str()),
                Some("qemu_cloudimg_unixbench_log")
            );
            assert_eq!(
                manifest_artifacts
                    .get(cloudimg_unixbench_log_path)
                    .and_then(|artifact| artifact["evidence_class"].as_str()),
                Some("machine_verifiable")
            );
            assert_nonempty_file(cloudimg_unixbench_log_path);
        }
    }

    let qemu_probe =
        read_json_file("docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json");
    let qemu_probe_manifest = manifest_artifacts
        .get("docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json")
        .unwrap_or_else(|| {
            panic!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} is missing docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json"
            )
        });
    assert_eq!(
        qemu_probe_manifest["kind"].as_str(),
        Some("qemu_probe_summary")
    );
    assert_eq!(
        qemu_probe_manifest["evidence_class"].as_str(),
        Some("derived_summary")
    );
    assert_eq!(
        qemu_probe_manifest["reference_coverage"].as_str(),
        Some("complete")
    );
    assert_eq!(qemu_probe["bios_probe_exit_code"].as_i64(), Some(124));
    assert_eq!(qemu_probe["kernel_probe_exit_code"].as_i64(), Some(124));
    for field in [
        "boot_menu_detected",
        "bios_installer_strings_detected",
        "kernel_boot_text_detected",
        "kernel_installer_progress_detected",
        "userspace_targets_detected",
        "serial_login_prompt_detected",
    ] {
        assert_eq!(
            qemu_probe[field].as_bool(),
            Some(true),
            "expected `{field}` to be true in docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json"
        );
    }
    for field in ["casper_cdrom_mismatch_detected", "kernel_panic_detected"] {
        assert_eq!(
            qemu_probe[field].as_bool(),
            Some(false),
            "expected `{field}` to be false in docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json"
        );
    }
    let raw_log_path = qemu_probe["raw_log"]
        .as_str()
        .unwrap_or_else(|| panic!("missing raw_log in qemu probe summary"));
    let text_log_path = qemu_probe["text_log"]
        .as_str()
        .unwrap_or_else(|| panic!("missing text_log in qemu probe summary"));
    let kernel_log_path = qemu_probe["kernel_log"]
        .as_str()
        .unwrap_or_else(|| panic!("missing kernel_log in qemu probe summary"));
    let manifest_references = qemu_probe_manifest["references"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "{GENERATED_BENCHMARK_MANIFEST_PATH} is missing references for the qemu probe summary artifact"
            )
        })
        .iter()
        .map(|value| {
            value.as_str().unwrap_or_else(|| {
                panic!(
                    "{GENERATED_BENCHMARK_MANIFEST_PATH} contains a non-string qemu probe reference: {value}"
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        manifest_references,
        vec![raw_log_path, text_log_path, kernel_log_path],
        "qemu probe references in {GENERATED_BENCHMARK_MANIFEST_PATH} do not match docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json"
    );
    assert_eq!(
        manifest_artifacts
            .get(raw_log_path)
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("qemu_probe_raw_log")
    );
    assert_eq!(
        manifest_artifacts
            .get(raw_log_path)
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_eq!(
        manifest_artifacts
            .get(text_log_path)
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("qemu_probe_text_log")
    );
    assert_eq!(
        manifest_artifacts
            .get(text_log_path)
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_eq!(
        manifest_artifacts
            .get(kernel_log_path)
            .and_then(|artifact| artifact["kind"].as_str()),
        Some("qemu_probe_kernel_log")
    );
    assert_eq!(
        manifest_artifacts
            .get(kernel_log_path)
            .and_then(|artifact| artifact["evidence_class"].as_str()),
        Some("machine_verifiable")
    );
    assert_nonempty_file(raw_log_path);
    assert_nonempty_file(text_log_path);
    assert_nonempty_file(kernel_log_path);
    let text_log = read_text_file(text_log_path);
    assert!(
        text_log.contains("GNU GRUB") || text_log.contains("Install Ubuntu"),
        "{text_log_path} does not contain expected BIOS/installer evidence"
    );
    let kernel_log = read_text_file(kernel_log_path);
    assert!(
        kernel_log.contains("Linux version"),
        "{kernel_log_path} does not contain kernel boot evidence"
    );
    assert!(
        kernel_log.contains("serial-getty@ttyS0.service")
            || kernel_log.contains("ubuntu-server ttyS0")
            || kernel_log.contains("ttyS0"),
        "{kernel_log_path} does not contain serial userspace evidence"
    );
}

fn find_named_object<'a>(items: &'a [Value], field: &str, expected: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing object where {field} == {expected}"))
}

fn assert_array_contains_string(value: &Value, expected: &str) {
    assert!(
        value
            .as_array()
            .map(|items| items.iter().any(|item| item.as_str() == Some(expected)))
            .unwrap_or(false),
        "expected array to contain `{expected}`, got {value}`"
    );
}

fn assert_service_state(value: &Value, name: &str, expected_state: &str) {
    let services = value
        .as_array()
        .unwrap_or_else(|| panic!("expected service state array, got {value}"));
    let service = services
        .iter()
        .find(|service| service["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing service state for `{name}`"));
    assert_eq!(service["state"].as_str(), Some(expected_state));
}

fn json_string_array(value: &Value, context: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context} is not an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{context} contains a non-string value: {item}"))
                .to_owned()
        })
        .collect()
}

fn find_guest_command<'a>(artifact: &'a Value, path: &str, command: &str) -> &'a Value {
    artifact["guest_control"]["commands"]
        .as_array()
        .unwrap_or_else(|| panic!("{path} is missing guest_control.commands"))
        .iter()
        .find(|entry| entry["command"].as_str() == Some(command))
        .unwrap_or_else(|| panic!("{path} is missing guest command `{command}`"))
}

fn assert_markdown_field_equals(contents: &str, path: &str, prefix: &str, expected: &str) {
    let actual = extract_markdown_field(contents, path, prefix);
    assert_eq!(
        actual, expected,
        "unexpected value for `{prefix}` in {path}"
    );
}

fn extract_markdown_field<'a>(contents: &'a str, path: &str, prefix: &str) -> &'a str {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .unwrap_or_else(|| panic!("missing `{prefix}` in {path}"))
}

fn read_text_file(path: &str) -> String {
    let resolved = workspace_path(path);
    fs::read_to_string(&resolved)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", resolved.display()))
}

fn read_json_file(path: &str) -> Value {
    let raw = read_text_file(path);
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("invalid json in {path}: {error}"))
}

fn assert_nonempty_file(path: &str) {
    let resolved = workspace_path(path);
    let metadata = fs::metadata(&resolved)
        .unwrap_or_else(|error| panic!("failed to stat {}: {error}", resolved.display()));
    assert!(metadata.is_file(), "{} is not a file", resolved.display());
    assert!(metadata.len() > 0, "{} is empty", resolved.display());
}

fn file_sha256(path: &str) -> String {
    let resolved = workspace_path(path);
    let bytes = fs::read(&resolved)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", resolved.display()));
    sha256_hex(&bytes)
}

fn assert_sha256_hex(value: &str, context: &str) {
    assert_eq!(
        value.len(),
        64,
        "{context} must be a 64-character SHA-256 hex digest"
    );
    assert!(
        value.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{context} must contain only hexadecimal characters"
    );
}

fn workspace_path(path: &str) -> PathBuf {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(candidate)
}

fn generated_directory_files(path: &str) -> BTreeSet<String> {
    let resolved = workspace_path(path);
    fs::read_dir(&resolved)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", resolved.display()))
        .map(|entry| {
            let entry = entry.unwrap_or_else(|error| {
                panic!(
                    "failed to read directory entry in {}: {error}",
                    resolved.display()
                )
            });
            let file_type = entry.file_type().unwrap_or_else(|error| {
                panic!(
                    "failed to read file type for {}: {error}",
                    entry.path().display()
                )
            });
            assert!(
                file_type.is_file(),
                "unexpected non-file entry in {}: {}",
                resolved.display(),
                entry.path().display()
            );
            format!("{path}/{}", entry.file_name().to_string_lossy())
        })
        .collect()
}

fn parse_generated_at(raw: &str, path: &str) -> OffsetDateTime {
    let mut parts = raw.split_whitespace();
    let date = parts
        .next()
        .unwrap_or_else(|| panic!("missing date component in `{raw}` from {path}"));
    let time = parts
        .next()
        .unwrap_or_else(|| panic!("missing time component in `{raw}` from {path}"));
    let offset = parts
        .next()
        .unwrap_or_else(|| panic!("missing offset component in `{raw}` from {path}"));
    assert!(
        parts.next().is_none(),
        "unexpected trailing data in generated timestamp `{raw}` from {path}"
    );
    PrimitiveDateTime::new(parse_date(date, path), parse_time(time, path))
        .assume_offset(parse_offset(offset, path))
}

fn parse_date(raw: &str, path: &str) -> Date {
    let mut parts = raw.split('-');
    let year = parse_i32(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing year in date `{raw}` from {path}")),
        "year",
        raw,
        path,
    );
    let month = parse_u8(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing month in date `{raw}` from {path}")),
        "month",
        raw,
        path,
    );
    let day = parse_u8(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing day in date `{raw}` from {path}")),
        "day",
        raw,
        path,
    );
    assert!(
        parts.next().is_none(),
        "unexpected trailing date data in `{raw}` from {path}"
    );
    Date::from_calendar_date(year, month_from_number(month, raw, path), day)
        .unwrap_or_else(|error| panic!("invalid calendar date `{raw}` in {path}: {error}"))
}

fn parse_time(raw: &str, path: &str) -> Time {
    let mut parts = raw.split('.');
    let clock = parts
        .next()
        .unwrap_or_else(|| panic!("missing clock component in time `{raw}` from {path}"));
    let fractional = parts.next().unwrap_or("0");
    assert!(
        parts.next().is_none(),
        "unexpected trailing time data in `{raw}` from {path}"
    );
    let mut clock_parts = clock.split(':');
    let hour = parse_u8(
        clock_parts
            .next()
            .unwrap_or_else(|| panic!("missing hour in time `{raw}` from {path}")),
        "hour",
        raw,
        path,
    );
    let minute = parse_u8(
        clock_parts
            .next()
            .unwrap_or_else(|| panic!("missing minute in time `{raw}` from {path}")),
        "minute",
        raw,
        path,
    );
    let second = parse_u8(
        clock_parts
            .next()
            .unwrap_or_else(|| panic!("missing second in time `{raw}` from {path}")),
        "second",
        raw,
        path,
    );
    assert!(
        clock_parts.next().is_none(),
        "unexpected trailing clock data in `{raw}` from {path}"
    );
    let mut nanos_text = fractional.to_owned();
    if nanos_text.len() > 9 {
        nanos_text.truncate(9);
    }
    while nanos_text.len() < 9 {
        nanos_text.push('0');
    }
    let nanos = nanos_text.parse::<u32>().unwrap_or_else(|error| {
        panic!("invalid fractional seconds `{fractional}` in `{raw}` from {path}: {error}")
    });
    Time::from_hms_nano(hour, minute, second, nanos)
        .unwrap_or_else(|error| panic!("invalid time `{raw}` in {path}: {error}"))
}

fn parse_offset(raw: &str, path: &str) -> UtcOffset {
    let sign: i8 = match raw.chars().next() {
        Some('+') => 1,
        Some('-') => -1,
        Some(other) => panic!("invalid offset sign `{other}` in `{raw}` from {path}"),
        None => panic!("missing offset data in generated timestamp from {path}"),
    };
    let offset = &raw[1..];
    let mut parts = offset.split(':');
    let hours = parse_i8(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing offset hour in `{raw}` from {path}")),
        "offset hour",
        raw,
        path,
    );
    let minutes = parse_i8(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing offset minute in `{raw}` from {path}")),
        "offset minute",
        raw,
        path,
    );
    let seconds = parse_i8(
        parts
            .next()
            .unwrap_or_else(|| panic!("missing offset second in `{raw}` from {path}")),
        "offset second",
        raw,
        path,
    );
    assert!(
        parts.next().is_none(),
        "unexpected trailing offset data in `{raw}` from {path}"
    );
    UtcOffset::from_hms(sign * hours, sign * minutes, sign * seconds)
        .unwrap_or_else(|error| panic!("invalid UTC offset `{raw}` in {path}: {error}"))
}

fn month_from_number(month: u8, raw: &str, path: &str) -> Month {
    match month {
        1 => Month::January,
        2 => Month::February,
        3 => Month::March,
        4 => Month::April,
        5 => Month::May,
        6 => Month::June,
        7 => Month::July,
        8 => Month::August,
        9 => Month::September,
        10 => Month::October,
        11 => Month::November,
        12 => Month::December,
        _ => panic!("invalid month `{month}` in `{raw}` from {path}"),
    }
}

fn parse_i32(raw: &str, field: &str, source: &str, path: &str) -> i32 {
    raw.parse::<i32>().unwrap_or_else(|error| {
        panic!("invalid {field} `{raw}` in `{source}` from {path}: {error}")
    })
}

fn parse_u8(raw: &str, field: &str, source: &str, path: &str) -> u8 {
    raw.parse::<u8>().unwrap_or_else(|error| {
        panic!("invalid {field} `{raw}` in `{source}` from {path}: {error}")
    })
}

fn parse_i8(raw: &str, field: &str, source: &str, path: &str) -> i8 {
    raw.parse::<i8>().unwrap_or_else(|error| {
        panic!("invalid {field} `{raw}` in `{source}` from {path}: {error}")
    })
}

fn read_collection_record(path: &Path, key: &str) -> Value {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let collection: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("invalid collection json in {}: {error}", path.display()));
    collection
        .get("records")
        .and_then(Value::as_object)
        .and_then(|records| records.get(key))
        .cloned()
        .unwrap_or_else(|| panic!("missing record `{key}` in {}", path.display()))
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

fn seed_governance_change_request(state_dir: &Path, state: &str) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("failed to build tokio runtime: {error}"));
    runtime.block_on(async {
        let store = DocumentStore::open(state_dir.join("governance").join("change_requests.json"))
            .await
            .unwrap_or_else(|error| panic!("failed to open governance change store: {error}"));
        let id = ChangeRequestId::generate()
            .unwrap_or_else(|error| panic!("failed to generate change request id: {error}"));
        let seeded_state = match state {
            "pending" => SeedGovernanceChangeRequestState::Pending,
            "approved" => SeedGovernanceChangeRequestState::Approved,
            "rejected" => SeedGovernanceChangeRequestState::Rejected,
            "applied" => SeedGovernanceChangeRequestState::Applied,
            other => panic!("unsupported governance change request state: {other}"),
        };
        let approved_by = match seeded_state {
            SeedGovernanceChangeRequestState::Approved
            | SeedGovernanceChangeRequestState::Rejected
            | SeedGovernanceChangeRequestState::Applied => {
                Some(String::from("operator:wave3-reviewer"))
            }
            SeedGovernanceChangeRequestState::Pending => None,
        };
        let reviewer_comment = approved_by
            .as_ref()
            .map(|_| String::from("seeded wave3 evidence governance approval"));
        store
            .create(
                id.as_str(),
                SeedGovernanceChangeRequest {
                    id: id.clone(),
                    title: String::from("Wave 3 evidence ingress publication rehearsal"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("operator:wave3-requester"),
                    approved_by,
                    reviewer_comment,
                    required_approvals: 1,
                    state: seeded_state,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed governance change request: {error}"));
        id.to_string()
    })
}

fn seed_private_network_topology(
    address: SocketAddr,
    token: &str,
    private_network_id: &str,
    subnet_cidr: &str,
    route_destination: &str,
) {
    let route_table = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/route-tables"),
        Some(json!({
            "name": "private-main"
        })),
        token,
    );
    let route_table_id = route_table["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private route table id"))
        .to_owned();

    let next_hop = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/next-hops"),
        Some(json!({
            "name": "local-ingress",
            "kind": "local"
        })),
        token,
    );
    let next_hop_id = next_hop["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing private next hop id"))
        .to_owned();

    let _subnet = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/netsec/private-networks/{private_network_id}/subnets"),
        Some(json!({
            "name": "private-app-a",
            "cidr": subnet_cidr,
            "route_table_id": route_table_id,
        })),
        token,
    );

    let _route = request_json_with_bearer_token(
        address,
        "POST",
        &format!(
            "/netsec/private-networks/{private_network_id}/route-tables/{route_table_id}/routes"
        ),
        Some(json!({
            "destination": route_destination,
            "next_hop_id": next_hop_id,
        })),
        token,
    );
}

fn write_test_config(
    temp: &TempState,
    path: &str,
    address: SocketAddr,
    state_dir: &Path,
    token: Option<&str>,
) -> std::path::PathBuf {
    let security = token.map_or_else(String::new, |token| {
        format!(
            r#"

[security]
bootstrap_admin_token = "{token}"
"#
        )
    });
    let config = format!(
        "listen = \"{address}\"\nstate_dir = '{}'\n\n[schema]\nschema_version = 1\nmode = \"all_in_one\"\nnode_name = \"wave3-evidence-test-node\"\n\n[secrets]\nmaster_key = \"{}\"\n{}",
        state_dir.display(),
        base64url_encode(&[0x33; 32]),
        security,
    );
    temp.write(path, config.as_bytes())
        .unwrap_or_else(|error| panic!("failed to write config: {error}"))
}

fn wait_for_health(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = try_request_with_auth(address, "GET", "/healthz", None, None, None)
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
    token: &str,
) -> Value {
    request_json(address, method, path, body, None, Some(token))
}

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> Value {
    request_json(address, method, path, body, Some(token), None)
}

fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> Value {
    let payload =
        body.map(|value| serde_json::to_vec(&value).unwrap_or_else(|error| panic!("{error}")));
    let response = request(
        address,
        method,
        path,
        payload
            .as_ref()
            .map(|bytes| ("application/json", bytes.as_slice())),
        bearer_token,
        admin_token,
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

fn request_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> RawResponse {
    request(address, method, path, body, Some(token), None)
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> RawResponse {
    try_request_with_auth(address, method, path, body, bearer_token, admin_token)
        .unwrap_or_else(|error| panic!("request {method} {path} failed: {error}"))
}

fn try_request_with_auth(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    bearer_token: Option<&str>,
    admin_token: Option<&str>,
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (content_type, payload) = body.unwrap_or(("application/json", b""));

    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = bearer_token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(token) = admin_token {
        request.push_str(&format!("X-UHost-Admin-Token: {token}\r\n"));
    }
    request.push_str(&format!(
        "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    ));

    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid HTTP response framing"))?;
    let (head, body) = response.split_at(split + 4);
    let status_line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP status line"))?;
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

fn issue_workload_identity(
    address: SocketAddr,
    bootstrap_token: &str,
    subject: &str,
    audiences: &[&str],
    ttl_seconds: u64,
) -> String {
    let normalized_subject = subject.to_ascii_lowercase();
    let payload = request_json_with_bootstrap_token(
        address,
        "POST",
        "/identity/workload-identities",
        Some(json!({
            "subject": subject,
            "display_name": format!("{subject} identity"),
            "audiences": audiences,
            "ttl_seconds": ttl_seconds,
        })),
        bootstrap_token,
    );
    let issued_token = payload["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned();
    assert_eq!(
        payload["identity"]["principal"]["subject"].as_str(),
        Some(normalized_subject.as_str())
    );
    issued_token
}
