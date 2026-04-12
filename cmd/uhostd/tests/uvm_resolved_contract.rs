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
use uhost_core::base64url_encode;
use uhost_types::{NodeId, ProjectId};

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
fn resolved_contract_route_joins_control_image_node_and_observe_truth_through_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("uvm-resolved-contract.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping resolved_contract_route_joins_control_image_node_and_observe_truth_through_uhostd: loopback bind not permitted"
        );
        return;
    };
    write_test_config(
        &config_path,
        address,
        &state_dir,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

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

    let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));

    let source_capability = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(
            json!({
                "node_id": source_node_id.to_string(),
                "architecture": uvm_guest_architecture(),
                "accelerator_backends": [uvm_primary_backend()],
                "max_vcpu": 64,
                "max_memory_mb": 131072,
                "numa_nodes": 2,
                "supports_secure_boot": true,
                "supports_live_migration": true,
                "supports_pci_passthrough": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let target_capability = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(
            json!({
                "node_id": target_node_id.to_string(),
                "architecture": uvm_guest_architecture(),
                "accelerator_backends": [uvm_primary_backend()],
                "max_vcpu": 64,
                "max_memory_mb": 131072,
                "numa_nodes": 2,
                "supports_secure_boot": true,
                "supports_live_migration": true,
                "supports_pci_passthrough": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let image = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/images",
        Some(
            json!({
                "source_kind": "qcow2",
                "source_uri": "registry://images/resolved-contract-linux.qcow2",
                "guest_os": "linux",
                "architecture": uvm_guest_architecture(),
                "signature_attestation": "sig:v1",
                "provenance_attestation": "prov:v1"
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let image_id = required_string(&image, "id");
    let _verified_image = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/images/{image_id}/verify"),
        Some(
            json!({
                "require_signature": true,
                "require_provenance": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

    let template = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/templates",
        Some(
            json!({
                "name": "resolved-contract-template",
                "architecture": uvm_guest_architecture(),
                "vcpu": 4,
                "memory_mb": 8192,
                "cpu_topology": "balanced",
                "numa_policy": "preferred_local",
                "firmware_profile": "uefi_secure",
                "device_profile": "cloud-balanced",
                "migration_policy": "best_effort_live",
                "apple_guest_allowed": false
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let template_id = required_string(&template, "id");

    let instance = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/instances",
        Some(
            json!({
                "project_id": project_id.to_string(),
                "name": "resolved-contract-instance",
                "template_id": template_id,
                "boot_image_id": image_id,
                "guest_os": "linux",
                "host_node_id": source_node_id.to_string()
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let instance_id = required_string(&instance, "id");

    let started_instance = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/instances/{instance_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_instance["state"].as_str(), Some("running"));

    let runtime_session = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/instances",
        Some(
            json!({
                "instance_id": instance_id,
                "node_id": source_node_id.to_string(),
                "capability_id": required_string(&source_capability, "id"),
                "guest_architecture": uvm_guest_architecture(),
                "guest_os": "linux",
                "disk_image": "object://images/resolved-contract-linux.qcow2",
                "vcpu": 4,
                "memory_mb": 8192,
                "firmware_profile": "uefi_secure",
                "cpu_topology": "balanced",
                "numa_policy": "preferred_local",
                "migration_policy": "best_effort_live",
                "require_secure_boot": true,
                "requires_live_migration": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let runtime_session_id = required_string(&runtime_session, "id");

    let started_runtime_session = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_runtime_session["state"].as_str(), Some("running"));

    let runtime_preflight = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(
            json!({
                "runtime_session_id": runtime_session_id,
                "to_node_id": target_node_id.to_string(),
                "target_capability_id": required_string(&target_capability, "id"),
                "require_secure_boot": true,
                "migration_max_downtime_ms": 500
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let runtime_preflight_id = required_string(&runtime_preflight, "id");
    assert_eq!(runtime_preflight["legal_allowed"].as_bool(), Some(true));
    assert_eq!(
        runtime_preflight["selected_backend"].as_str(),
        Some(uvm_primary_backend())
    );

    let host_evidence = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/host-evidence",
        Some(
            json!({
                "evidence_mode": "measured",
                "host_platform": host_platform_key(),
                "execution_environment": "bare_metal",
                "hardware_virtualization": true,
                "nested_virtualization": false,
                "qemu_available": true,
                "note": "uhostd integration resolved-contract"
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let host_evidence_id = required_string(&host_evidence, "id");

    for workload_class in [
        "general",
        "cpu_intensive",
        "io_intensive",
        "network_intensive",
    ] {
        let perf_attestation = request_json_with_admin_token(
            address,
            "POST",
            "/uvm/perf-attestations",
            Some(
                json!({
                    "instance_id": instance_id,
                    "workload_class": workload_class,
                    "cpu_overhead_pct": 4,
                    "memory_overhead_pct": 4,
                    "block_io_latency_overhead_pct": 8,
                    "network_latency_overhead_pct": 8,
                    "jitter_pct": 8
                })
                .to_string(),
            ),
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        );
        assert_eq!(
            perf_attestation["workload_class"].as_str(),
            Some(workload_class)
        );
    }

    let claim_decision = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/claim-decisions",
        Some(
            json!({
                "host_evidence_id": host_evidence_id,
                "runtime_preflight_id": runtime_preflight_id
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let claim_decision_id = required_string(&claim_decision, "id");
    assert_eq!(claim_decision["claim_status"].as_str(), Some("allowed"));

    let resolved = request_json_with_admin_token(
        address,
        "GET",
        &format!("/uvm/instances/{instance_id}/resolved-contract"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

    assert_eq!(resolved["instance"]["id"].as_str(), Some(instance_id));
    assert_eq!(resolved["template"]["id"].as_str(), Some(template_id));
    assert_eq!(resolved["boot_image"]["id"].as_str(), Some(image_id));
    assert_eq!(
        resolved["runtime_session"]["id"].as_str(),
        Some(runtime_session_id)
    );
    assert_eq!(
        resolved["runtime_session"]["state"].as_str(),
        Some("running")
    );
    assert_eq!(
        resolved["runtime_preflight"]["id"].as_str(),
        Some(runtime_preflight_id)
    );
    assert_eq!(
        resolved["runtime_preflight"]["selected_backend"].as_str(),
        Some(uvm_primary_backend())
    );
    assert_eq!(
        resolved["claim_decision"]["id"].as_str(),
        Some(claim_decision_id)
    );
    assert_eq!(
        resolved["claim_decision"]["runtime_session_id"].as_str(),
        Some(runtime_session_id)
    );
    assert_eq!(
        resolved["claim_decision"]["runtime_preflight_id"].as_str(),
        Some(runtime_preflight_id)
    );
    assert_eq!(
        resolved["host_evidence"]["id"].as_str(),
        Some(host_evidence_id)
    );
    assert_eq!(resolved["effective_claim_status"].as_str(), Some("allowed"));
    assert_eq!(
        resolved["effective_claim_tier"].as_str(),
        Some("compatible")
    );
    assert_eq!(
        resolved["portability_assessment_source"].as_str(),
        Some("first_placement_lineage")
    );
    assert_eq!(
        resolved["effective_portability_assessment"]["supported"].as_bool(),
        Some(true)
    );

    let perf_attestations = resolved["latest_perf_attestations"]
        .as_array()
        .unwrap_or_else(|| panic!("missing latest_perf_attestations array"));
    assert_eq!(perf_attestations.len(), 4);
    assert_workload_attestation_present(perf_attestations, "general");
    assert_workload_attestation_present(perf_attestations, "cpu_intensive");
    assert_workload_attestation_present(perf_attestations, "io_intensive");
    assert_workload_attestation_present(perf_attestations, "network_intensive");

    let resolution_notes = resolved["resolution_notes"]
        .as_array()
        .unwrap_or_else(|| panic!("missing resolution_notes array"));
    assert!(
        resolution_notes.is_empty(),
        "expected no resolution notes, found {resolution_notes:?}"
    );
}

#[test]
fn instance_scoped_runtime_session_and_checkpoint_routes_work_through_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("uvm-instance-runtime-routes.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping instance_scoped_runtime_session_and_checkpoint_routes_work_through_uhostd: loopback bind not permitted"
        );
        return;
    };
    write_test_config(
        &config_path,
        address,
        &state_dir,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

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

    let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
    let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

    let capability = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(
            json!({
                "node_id": source_node_id.to_string(),
                "architecture": uvm_guest_architecture(),
                "accelerator_backends": [uvm_primary_backend()],
                "max_vcpu": 64,
                "max_memory_mb": 131072,
                "numa_nodes": 2,
                "supports_secure_boot": true,
                "supports_live_migration": true,
                "supports_pci_passthrough": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let capability_id = required_string(&capability, "id").to_owned();

    let image = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/images",
        Some(
            json!({
                "source_kind": "qcow2",
                "source_uri": "registry://images/runtime-route-linux.qcow2",
                "guest_os": "linux",
                "architecture": uvm_guest_architecture(),
                "signature_attestation": "sig:v1",
                "provenance_attestation": "prov:v1"
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let image_id = required_string(&image, "id");
    let _verified_image = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/images/{image_id}/verify"),
        Some(
            json!({
                "require_signature": true,
                "require_provenance": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );

    let template = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/templates",
        Some(
            json!({
                "name": "runtime-route-template",
                "architecture": uvm_guest_architecture(),
                "vcpu": 4,
                "memory_mb": 8192,
                "cpu_topology": "balanced",
                "numa_policy": "preferred_local",
                "firmware_profile": "uefi_secure",
                "device_profile": "cloud-balanced",
                "migration_policy": "best_effort_live",
                "apple_guest_allowed": false
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let template_id = required_string(&template, "id");

    let target_instance = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/instances",
        Some(
            json!({
                "project_id": project_id.to_string(),
                "name": "runtime-route-instance",
                "template_id": template_id,
                "boot_image_id": image_id,
                "guest_os": "linux",
                "host_node_id": source_node_id.to_string()
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let target_instance_id = required_string(&target_instance, "id");

    let other_instance = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/instances",
        Some(
            json!({
                "project_id": project_id.to_string(),
                "name": "runtime-route-other-instance",
                "template_id": template_id,
                "boot_image_id": image_id,
                "guest_os": "linux",
                "host_node_id": source_node_id.to_string()
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let other_instance_id = required_string(&other_instance, "id");

    let started_target_instance = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/instances/{target_instance_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_target_instance["state"].as_str(), Some("running"));

    let started_other_instance = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/instances/{other_instance_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_other_instance["state"].as_str(), Some("running"));

    let target_runtime_session = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/instances",
        Some(
            json!({
                "instance_id": target_instance_id,
                "node_id": source_node_id.to_string(),
                "capability_id": capability_id.as_str(),
                "guest_architecture": uvm_guest_architecture(),
                "guest_os": "linux",
                "disk_image": "object://images/runtime-route-linux.qcow2",
                "vcpu": 4,
                "memory_mb": 8192,
                "firmware_profile": "uefi_secure",
                "cpu_topology": "balanced",
                "numa_policy": "preferred_local",
                "migration_policy": "best_effort_live",
                "require_secure_boot": true,
                "requires_live_migration": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let target_runtime_session_id = required_string(&target_runtime_session, "id").to_owned();

    let started_target_runtime = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{target_runtime_session_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_target_runtime["state"].as_str(), Some("running"));

    let other_runtime_session = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/instances",
        Some(
            json!({
                "instance_id": other_instance_id,
                "node_id": source_node_id.to_string(),
                "capability_id": capability_id.as_str(),
                "guest_architecture": uvm_guest_architecture(),
                "guest_os": "linux",
                "disk_image": "object://images/runtime-route-other-linux.qcow2",
                "vcpu": 4,
                "memory_mb": 8192,
                "firmware_profile": "uefi_secure",
                "cpu_topology": "balanced",
                "numa_policy": "preferred_local",
                "migration_policy": "best_effort_live",
                "require_secure_boot": true,
                "requires_live_migration": true
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let other_runtime_session_id = required_string(&other_runtime_session, "id").to_owned();

    let started_other_runtime = request_json_with_admin_token(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{other_runtime_session_id}/start"),
        Some(String::from("{}")),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(started_other_runtime["state"].as_str(), Some("running"));

    let target_checkpoint_one = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some(
            json!({
                "runtime_session_id": target_runtime_session_id.as_str(),
                "kind": "crash_consistent",
                "checkpoint_uri": "object://checkpoints/runtime-route-1",
                "memory_bitmap_hash": "a11ce",
                "disk_generation": 1
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let target_checkpoint_one_id = required_string(&target_checkpoint_one, "id").to_owned();

    let target_checkpoint_two = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some(
            json!({
                "runtime_session_id": target_runtime_session_id.as_str(),
                "kind": "live_precopy",
                "checkpoint_uri": "object://checkpoints/runtime-route-2",
                "memory_bitmap_hash": "b16b00b5",
                "disk_generation": 2
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let target_checkpoint_two_id = required_string(&target_checkpoint_two, "id").to_owned();

    let other_checkpoint = request_json_with_admin_token(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some(
            json!({
                "runtime_session_id": other_runtime_session_id.as_str(),
                "kind": "crash_consistent",
                "checkpoint_uri": "object://checkpoints/runtime-route-other",
                "memory_bitmap_hash": "c0ffee",
                "disk_generation": 3
            })
            .to_string(),
        ),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let other_checkpoint_id = required_string(&other_checkpoint, "id").to_owned();

    let runtime_sessions = request_json_with_admin_token(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-sessions"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let runtime_sessions = runtime_sessions
        .as_array()
        .unwrap_or_else(|| panic!("missing runtime sessions array"));
    assert_eq!(runtime_sessions.len(), 1);
    assert_eq!(
        runtime_sessions[0]["id"].as_str(),
        Some(target_runtime_session_id.as_str())
    );

    let paged_runtime_sessions = request_json_with_admin_token(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-sessions?limit=1"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let paged_runtime_sessions_items = paged_runtime_sessions["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing paged runtime sessions items"));
    assert_eq!(paged_runtime_sessions_items.len(), 1);
    assert_eq!(
        paged_runtime_sessions_items[0]["id"].as_str(),
        Some(target_runtime_session_id.as_str())
    );
    assert!(paged_runtime_sessions["next_cursor"].is_null());

    let auth_headers = [(
        "Authorization",
        format!("Bearer {DEFAULT_BOOTSTRAP_ADMIN_TOKEN}"),
    )];
    let runtime_session_detail = request_with_headers(
        address,
        "GET",
        &format!(
            "/uvm/instances/{target_instance_id}/runtime-sessions/{target_runtime_session_id}"
        ),
        None,
        &auth_headers,
    );
    assert_eq!(runtime_session_detail.status, 200);
    assert!(runtime_session_detail.headers.contains_key("etag"));
    let runtime_session_record_version = runtime_session_detail
        .headers
        .get("x-record-version")
        .unwrap_or_else(|| panic!("missing x-record-version on runtime session detail"))
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("invalid runtime session record version: {error}"));
    assert!(runtime_session_record_version >= 1);
    let runtime_session_detail: Value = serde_json::from_slice(&runtime_session_detail.body)
        .unwrap_or_else(|error| panic!("invalid runtime session detail json: {error}"));
    assert_eq!(
        runtime_session_detail["id"].as_str(),
        Some(target_runtime_session_id.as_str())
    );
    assert_eq!(
        runtime_session_detail["last_checkpoint_id"].as_str(),
        Some(target_checkpoint_two_id.as_str())
    );

    let hidden_runtime_session = request_with_headers(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-sessions/{other_runtime_session_id}"),
        None,
        &auth_headers,
    );
    assert_eq!(hidden_runtime_session.status, 404);

    let runtime_checkpoints = request_json_with_admin_token(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-checkpoints"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let runtime_checkpoints = runtime_checkpoints
        .as_array()
        .unwrap_or_else(|| panic!("missing runtime checkpoints array"));
    assert_eq!(runtime_checkpoints.len(), 2);
    assert!(runtime_checkpoints.iter().all(|value| {
        value["id"].as_str() != Some(other_checkpoint_id.as_str())
            && value["runtime_session_id"].as_str() == Some(target_runtime_session_id.as_str())
    }));

    let first_checkpoint_page = request_json_with_admin_token(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-checkpoints?limit=1"),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let first_checkpoint_items = first_checkpoint_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing first checkpoint page items"));
    assert_eq!(first_checkpoint_items.len(), 1);
    let next_cursor = first_checkpoint_page["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("missing checkpoint next_cursor"))
        .to_owned();

    let second_checkpoint_page = request_json_with_admin_token(
        address,
        "GET",
        &format!(
            "/uvm/instances/{target_instance_id}/runtime-checkpoints?limit=1&cursor={next_cursor}"
        ),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let second_checkpoint_items = second_checkpoint_page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("missing second checkpoint page items"));
    assert_eq!(second_checkpoint_items.len(), 1);
    assert!(second_checkpoint_page["next_cursor"].is_null());
    let paged_checkpoint_ids = [
        first_checkpoint_items[0]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing first paged checkpoint id")),
        second_checkpoint_items[0]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second paged checkpoint id")),
    ];
    assert!(paged_checkpoint_ids.contains(&target_checkpoint_one_id.as_str()));
    assert!(paged_checkpoint_ids.contains(&target_checkpoint_two_id.as_str()));

    let runtime_checkpoint_detail = request_with_headers(
        address,
        "GET",
        &format!(
            "/uvm/instances/{target_instance_id}/runtime-checkpoints/{target_checkpoint_two_id}"
        ),
        None,
        &auth_headers,
    );
    assert_eq!(runtime_checkpoint_detail.status, 200);
    assert!(runtime_checkpoint_detail.headers.contains_key("etag"));
    let runtime_checkpoint_record_version = runtime_checkpoint_detail
        .headers
        .get("x-record-version")
        .unwrap_or_else(|| panic!("missing x-record-version on runtime checkpoint detail"))
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("invalid runtime checkpoint record version: {error}"));
    assert!(runtime_checkpoint_record_version >= 1);
    let runtime_checkpoint_detail: Value = serde_json::from_slice(&runtime_checkpoint_detail.body)
        .unwrap_or_else(|error| panic!("invalid runtime checkpoint detail json: {error}"));
    assert_eq!(
        runtime_checkpoint_detail["id"].as_str(),
        Some(target_checkpoint_two_id.as_str())
    );
    assert_eq!(
        runtime_checkpoint_detail["runtime_session_id"].as_str(),
        Some(target_runtime_session_id.as_str())
    );

    let hidden_runtime_checkpoint = request_with_headers(
        address,
        "GET",
        &format!("/uvm/instances/{target_instance_id}/runtime-checkpoints/{other_checkpoint_id}"),
        None,
        &auth_headers,
    );
    assert_eq!(hidden_runtime_checkpoint.status, 404);
}

fn assert_workload_attestation_present(attestations: &[Value], workload_class: &str) {
    assert!(
        attestations
            .iter()
            .any(|entry| entry["workload_class"].as_str() == Some(workload_class)),
        "missing perf attestation for workload_class={workload_class}"
    );
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{field}` in {value}"))
}

fn uvm_primary_backend() -> &'static str {
    if cfg!(target_os = "linux") {
        "kvm"
    } else if cfg!(target_os = "windows") {
        "hyperv_whp"
    } else if cfg!(target_os = "macos") {
        "apple_virtualization"
    } else if cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        "bhyve"
    } else {
        "kvm"
    }
}

fn uvm_guest_architecture() -> &'static str {
    if cfg!(target_os = "macos") {
        "aarch64"
    } else {
        "x86_64"
    }
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path, token: &str) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "resolved-contract-test-node"

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

fn request_json_with_admin_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<String>,
    token: &str,
) -> Value {
    let response = request_with_headers(
        address,
        method,
        path,
        body.as_deref()
            .map(|raw| ("application/json", raw.as_bytes())),
        &[("Authorization", format!("Bearer {token}"))],
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
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn request_with_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    headers: &[(&str, String)],
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = is_idempotent_method(method);
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
    headers: &[(&str, String)],
) -> Result<RawResponse, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
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
    let head_text = std::str::from_utf8(head)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
    let mut headers_map = BTreeMap::new();
    for line in head_text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers_map.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    Ok(RawResponse {
        status,
        headers: headers_map,
        body: body.to_vec(),
    })
}
