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
use uhost_types::ProjectId;

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

fn test_child_stderr() -> Stdio {
    if std::env::var_os("UHOSTD_TEST_INHERIT_STDERR").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

#[test]
fn container_node_pools_and_summary_are_operational_from_all_in_one_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("container-runtime.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping container_node_pools_and_summary_are_operational_from_all_in_one_runtime: loopback bind not permitted"
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

    let project_id = ProjectId::generate()
        .unwrap_or_else(|error| panic!("failed to allocate project id: {error}"))
        .to_string();

    let alpha_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-general",
        "region": "us-east-1",
        "scheduler_pool": "general",
        "min_nodes": 1,
        "desired_nodes": 2,
        "max_nodes": 3
    })
    .to_string();
    let alpha_node_pool = request_json_with_bearer_token(
        address,
        "POST",
        "/container/node-pools",
        Some(alpha_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let alpha_node_pool_id = alpha_node_pool["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing alpha node pool id"))
        .to_owned();
    assert_eq!(
        alpha_node_pool["project_id"].as_str(),
        Some(project_id.as_str())
    );
    assert_eq!(alpha_node_pool["region"].as_str(), Some("us-east-1"));
    assert_eq!(alpha_node_pool["scheduler_pool"].as_str(), Some("general"));
    assert_eq!(alpha_node_pool["min_nodes"].as_u64(), Some(1));
    assert_eq!(alpha_node_pool["desired_nodes"].as_u64(), Some(2));
    assert_eq!(alpha_node_pool["max_nodes"].as_u64(), Some(3));
    assert!(
        alpha_node_pool["metadata"].is_object(),
        "alpha node pool metadata should be present"
    );

    let beta_payload = json!({
        "project_id": project_id.as_str(),
        "name": "beta-gpu",
        "region": "us-west-2",
        "scheduler_pool": "gpu",
        "min_nodes": 1,
        "desired_nodes": 1,
        "max_nodes": 2
    })
    .to_string();
    let beta_node_pool = request_json_with_bearer_token(
        address,
        "POST",
        "/container/node-pools",
        Some(beta_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let beta_node_pool_id = beta_node_pool["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing beta node pool id"))
        .to_owned();

    let node_pools = request_json_with_bearer_token(
        address,
        "GET",
        "/container/node-pools",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        node_pools
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("node pool list should be an array")),
        2
    );
    let alpha_list_entry = find_object_by_field(&node_pools, "id", alpha_node_pool_id.as_str());
    assert_eq!(alpha_list_entry["name"].as_str(), Some("alpha-general"));
    let beta_list_entry = find_object_by_field(&node_pools, "id", beta_node_pool_id.as_str());
    assert_eq!(beta_list_entry["name"].as_str(), Some("beta-gpu"));

    let cluster_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-cluster",
        "node_pool_id": alpha_node_pool_id.as_str()
    })
    .to_string();
    let cluster = request_json_with_bearer_token(
        address,
        "POST",
        "/container/clusters",
        Some(cluster_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let cluster_id = cluster["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing cluster id"))
        .to_owned();
    assert_eq!(
        cluster["node_pool_id"].as_str(),
        Some(alpha_node_pool_id.as_str())
    );
    assert_eq!(cluster["desired_nodes"].as_u64(), Some(2));

    let workload_payload = json!({
        "cluster_id": cluster_id.as_str(),
        "project_id": project_id.as_str(),
        "name": "api",
        "image": "registry.local/api:1",
        "desired_replicas": 3,
        "execution_class": "service",
        "command": ["/srv/start"]
    })
    .to_string();
    let workload = request_json_with_bearer_token(
        address,
        "POST",
        "/container/workloads",
        Some(workload_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let workload_id = workload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload id"))
        .to_owned();
    assert_eq!(workload["execution_class"].as_str(), Some("service"));
    assert_eq!(workload["desired_replicas"].as_u64(), Some(3));

    let reconciliations = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        reconciliations
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("reconciliations list should be an array")),
        1
    );
    let reconciliation =
        find_object_by_field(&reconciliations, "workload_id", workload_id.as_str());
    let reconciliation_idempotency_key = reconciliation["event_idempotency_key"]
        .as_str()
        .unwrap_or_else(|| panic!("missing reconciliation event idempotency key"));
    assert_eq!(
        reconciliation["cluster_id"].as_str(),
        Some(cluster_id.as_str())
    );
    assert_eq!(
        reconciliation["project_id"].as_str(),
        Some(project_id.as_str())
    );
    assert_eq!(
        reconciliation["node_pool_id"].as_str(),
        Some(alpha_node_pool_id.as_str())
    );
    assert_eq!(
        reconciliation["node_pool_name"].as_str(),
        Some("alpha-general")
    );
    assert_eq!(reconciliation["workload_name"].as_str(), Some("api"));
    assert_eq!(
        reconciliation["image"].as_str(),
        Some("registry.local/api:1")
    );
    assert_eq!(reconciliation["desired_replicas"].as_u64(), Some(3));
    assert_eq!(reconciliation["execution_class"].as_str(), Some("service"));
    assert_eq!(
        reconciliation["command"]
            .as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_str),
        Some("/srv/start")
    );
    assert_eq!(reconciliation["region"].as_str(), Some("us-east-1"));
    assert_eq!(reconciliation["scheduler_pool"].as_str(), Some("general"));
    assert_eq!(reconciliation["state"].as_str(), Some("planned"));
    let reconciliation_detail = reconciliation["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("missing reconciliation detail"));
    assert!(reconciliation_detail.contains(cluster_id.as_str()));
    assert!(reconciliation_detail.contains(alpha_node_pool_id.as_str()));
    assert!(reconciliation_detail.contains("us-east-1"));
    assert!(reconciliation_detail.contains("general"));
    assert!(
        reconciliation["reconcile_digest"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        !reconciliation["reconciled_at"].is_null(),
        "reconciled_at should be present"
    );
    assert!(
        reconciliation["metadata"].is_object(),
        "reconciliation metadata should be present"
    );

    let outbox = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        outbox
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("outbox should be an array")),
        1
    );
    let outbox_message = find_object_by_field(&outbox, "topic", "container.events.v1");
    assert_eq!(
        outbox_message["idempotency_key"].as_str(),
        Some(reconciliation_idempotency_key)
    );
    assert!(!outbox_message["created_at"].is_null());
    assert!(!outbox_message["updated_at"].is_null());
    assert_eq!(
        outbox_message["payload"]["header"]["event_type"].as_str(),
        Some("container.workload.reconciled.v1")
    );
    assert_eq!(
        outbox_message["payload"]["header"]["source_service"].as_str(),
        Some("container")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["kind"].as_str(),
        Some("service")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["resource_kind"].as_str(),
        Some("container_workload_reconciliation")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["resource_id"].as_str(),
        Some(workload_id.as_str())
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["action"].as_str(),
        Some("reconciled")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["workload_id"].as_str(),
        Some(workload_id.as_str())
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["cluster_id"].as_str(),
        Some(cluster_id.as_str())
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["node_pool_id"].as_str(),
        Some(alpha_node_pool_id.as_str())
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["node_pool_name"].as_str(),
        Some("alpha-general")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("planned")
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["detail"].as_str(),
        Some(reconciliation_detail)
    );
    assert_eq!(
        outbox_message["payload"]["payload"]["data"]["details"]["event_idempotency_key"].as_str(),
        Some(reconciliation_idempotency_key)
    );

    let replay_summary = request_json_with_bearer_token(
        address,
        "POST",
        "/container/reconcile",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(replay_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(replay_summary["created_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["updated_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["replayed_records"].as_u64(), Some(1));
    assert_eq!(replay_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["blocked_records"].as_u64(), Some(0));

    let outbox_after_replay = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        outbox_after_replay
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("outbox should be an array after replay")),
        1
    );
    let replayed_outbox_message =
        find_object_by_field(&outbox_after_replay, "topic", "container.events.v1");
    assert_eq!(
        replayed_outbox_message["idempotency_key"].as_str(),
        Some(reconciliation_idempotency_key)
    );

    let summary = request_json_with_bearer_token(
        address,
        "GET",
        "/container/summary",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(summary["node_pool_count"].as_u64(), Some(2));
    assert_eq!(summary["cluster_count"].as_u64(), Some(1));
    assert_eq!(summary["workload_count"].as_u64(), Some(1));
    assert_eq!(summary["total_min_nodes"].as_u64(), Some(2));
    assert_eq!(summary["total_desired_nodes"].as_u64(), Some(3));
    assert_eq!(summary["total_max_nodes"].as_u64(), Some(5));
    assert_eq!(summary["total_desired_replicas"].as_u64(), Some(3));
    assert_eq!(summary["active_project_count"].as_u64(), Some(1));
    assert_eq!(
        summary_count_by_value(&summary["execution_class_totals"], "service"),
        Some(1)
    );
    assert_eq!(
        summary_count_by_value(&summary["region_totals"], "us-east-1"),
        Some(1)
    );
    assert_eq!(
        summary_count_by_value(&summary["region_totals"], "us-west-2"),
        Some(1)
    );

    let alpha_pool_summary = find_object_by_field(
        &summary["node_pool_summaries"],
        "node_pool_id",
        alpha_node_pool_id.as_str(),
    );
    assert_eq!(
        alpha_pool_summary["cluster_id"].as_str(),
        Some(cluster_id.as_str())
    );
    assert_eq!(alpha_pool_summary["desired_nodes"].as_u64(), Some(2));
    assert_eq!(alpha_pool_summary["workload_count"].as_u64(), Some(1));
    assert_eq!(
        alpha_pool_summary["total_desired_replicas"].as_u64(),
        Some(3)
    );

    let beta_pool_summary = find_object_by_field(
        &summary["node_pool_summaries"],
        "node_pool_id",
        beta_node_pool_id.as_str(),
    );
    assert!(beta_pool_summary["cluster_id"].is_null());
    assert_eq!(beta_pool_summary["workload_count"].as_u64(), Some(0));
    assert_eq!(
        beta_pool_summary["total_desired_replicas"].as_u64(),
        Some(0)
    );

    let cluster_summary = find_object_by_field(
        &summary["cluster_summaries"],
        "cluster_id",
        cluster_id.as_str(),
    );
    assert_eq!(
        cluster_summary["node_pool_id"].as_str(),
        Some(alpha_node_pool_id.as_str())
    );
    assert_eq!(cluster_summary["region"].as_str(), Some("us-east-1"));
    assert_eq!(cluster_summary["scheduler_pool"].as_str(), Some("general"));
    assert_eq!(cluster_summary["desired_nodes"].as_u64(), Some(2));
    assert_eq!(cluster_summary["workload_count"].as_u64(), Some(1));
    assert_eq!(cluster_summary["total_desired_replicas"].as_u64(), Some(3));

    assert_error_envelope(
        request_with_bearer_token(
            address,
            "DELETE",
            format!("/container/clusters/{cluster_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        409,
        "conflict",
        "cluster still has active workloads attached",
        None,
    );
    assert_error_envelope(
        request_with_bearer_token(
            address,
            "DELETE",
            format!("/container/node-pools/{alpha_node_pool_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        409,
        "conflict",
        "node pool is still attached to an active cluster",
        None,
    );

    let workload_detail = request_with_bearer_token(
        address,
        "GET",
        format!("/container/workloads/{workload_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        workload_detail.status,
        200,
        "unexpected workload detail status with body {}",
        String::from_utf8_lossy(&workload_detail.body)
    );
    let workload_record_version = required_header(&workload_detail, "x-record-version").to_owned();
    let workload_etag = required_header(&workload_detail, "etag").to_owned();
    let stale_workload_record_version = workload_record_version
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("invalid workload x-record-version header: {error}"))
        .saturating_add(1)
        .to_string();
    assert_error_envelope(
        request_with_bearer_token_and_extra_headers(
            address,
            "DELETE",
            format!("/container/workloads/{workload_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
            &[
                ("If-Match", workload_etag.as_str()),
                ("x-record-version", stale_workload_record_version.as_str()),
            ],
        ),
        409,
        "conflict",
        "record version does not match",
        None,
    );
    let stale_workload_etag = format!("\"stale-{workload_id}\"");
    assert_error_envelope(
        request_with_bearer_token_and_extra_headers(
            address,
            "DELETE",
            format!("/container/workloads/{workload_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
            &[
                ("If-Match", stale_workload_etag.as_str()),
                ("x-record-version", workload_record_version.as_str()),
            ],
        ),
        409,
        "conflict",
        "etag does not match",
        None,
    );
    let deleted_workload = request_with_bearer_token_and_extra_headers(
        address,
        "DELETE",
        format!("/container/workloads/{workload_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        &[
            ("If-Match", workload_etag.as_str()),
            ("x-record-version", workload_record_version.as_str()),
        ],
    );
    assert_eq!(
        deleted_workload.status,
        204,
        "unexpected workload delete status with body {}",
        String::from_utf8_lossy(&deleted_workload.body)
    );

    let reconciliations_after_workload_delete = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert!(
        reconciliations_after_workload_delete
            .as_array()
            .is_some_and(|items| items.is_empty()),
        "expected workload delete to retire the reconciliation record"
    );

    let outbox_after_workload_delete = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        outbox_after_workload_delete
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("outbox should be an array after workload delete")),
        2
    );
    let retired_event = outbox_after_workload_delete
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array"))
        .iter()
        .find(|message| {
            message["payload"]["payload"]["data"]["action"].as_str() == Some("retired")
                && message["payload"]["payload"]["data"]["resource_id"].as_str()
                    == Some(workload_id.as_str())
        })
        .unwrap_or_else(|| panic!("missing retired reconciliation event in outbox"));
    assert_eq!(
        retired_event["payload"]["payload"]["data"]["details"]["final_state"].as_str(),
        Some("planned")
    );

    let cluster_detail = request_with_bearer_token(
        address,
        "GET",
        format!("/container/clusters/{cluster_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        cluster_detail.status,
        200,
        "unexpected cluster detail status with body {}",
        String::from_utf8_lossy(&cluster_detail.body)
    );
    let cluster_record_version = required_header(&cluster_detail, "x-record-version").to_owned();
    let cluster_etag = required_header(&cluster_detail, "etag").to_owned();
    let deleted_cluster = request_with_bearer_token_and_extra_headers(
        address,
        "DELETE",
        format!("/container/clusters/{cluster_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        &[
            ("If-Match", cluster_etag.as_str()),
            ("x-record-version", cluster_record_version.as_str()),
        ],
    );
    assert_eq!(
        deleted_cluster.status,
        204,
        "unexpected cluster delete status with body {}",
        String::from_utf8_lossy(&deleted_cluster.body)
    );
    assert_error_envelope(
        request_with_bearer_token(
            address,
            "GET",
            format!("/container/clusters/{cluster_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "cluster does not exist",
        None,
    );

    let node_pool_detail = request_with_bearer_token(
        address,
        "GET",
        format!("/container/node-pools/{alpha_node_pool_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        node_pool_detail.status,
        200,
        "unexpected node pool detail status with body {}",
        String::from_utf8_lossy(&node_pool_detail.body)
    );
    let node_pool_record_version =
        required_header(&node_pool_detail, "x-record-version").to_owned();
    let node_pool_etag = required_header(&node_pool_detail, "etag").to_owned();
    let deleted_node_pool = request_with_bearer_token_and_extra_headers(
        address,
        "DELETE",
        format!("/container/node-pools/{alpha_node_pool_id}").as_str(),
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        &[
            ("If-Match", node_pool_etag.as_str()),
            ("x-record-version", node_pool_record_version.as_str()),
        ],
    );
    assert_eq!(
        deleted_node_pool.status,
        204,
        "unexpected node pool delete status with body {}",
        String::from_utf8_lossy(&deleted_node_pool.body)
    );
    assert_error_envelope(
        request_with_bearer_token(
            address,
            "GET",
            format!("/container/node-pools/{alpha_node_pool_id}").as_str(),
            None,
            DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        ),
        404,
        "not_found",
        "node pool does not exist",
        None,
    );

    let node_pools_after_teardown = request_json_with_bearer_token(
        address,
        "GET",
        "/container/node-pools",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        node_pools_after_teardown
            .as_array()
            .map(Vec::len)
            .unwrap_or_else(|| panic!("node pool list should be an array after teardown")),
        1
    );
    let remaining_pool =
        find_object_by_field(&node_pools_after_teardown, "id", beta_node_pool_id.as_str());
    assert_eq!(remaining_pool["name"].as_str(), Some("beta-gpu"));

    let clusters_after_teardown = request_json_with_bearer_token(
        address,
        "GET",
        "/container/clusters",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert!(
        clusters_after_teardown
            .as_array()
            .is_some_and(|items| items.is_empty()),
        "expected cluster delete to remove the attached cluster"
    );

    let summary_after_teardown = request_json_with_bearer_token(
        address,
        "GET",
        "/container/summary",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(summary_after_teardown["node_pool_count"].as_u64(), Some(1));
    assert_eq!(summary_after_teardown["cluster_count"].as_u64(), Some(0));
    assert_eq!(summary_after_teardown["workload_count"].as_u64(), Some(0));
    assert_eq!(
        summary_after_teardown["total_desired_replicas"].as_u64(),
        Some(0)
    );
}

#[test]
fn container_reconcile_respects_scheduler_pool_capacity_in_all_in_one_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("container-runtime-scheduler-pools.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping container_reconcile_respects_scheduler_pool_capacity_in_all_in_one_runtime: loopback bind not permitted"
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

    let project_id = ProjectId::generate()
        .unwrap_or_else(|error| panic!("failed to allocate project id: {error}"))
        .to_string();
    let node_pool_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-general",
        "region": "us-east-1",
        "scheduler_pool": "general",
        "min_nodes": 1,
        "desired_nodes": 2,
        "max_nodes": 3
    })
    .to_string();
    let node_pool = request_json_with_bearer_token(
        address,
        "POST",
        "/container/node-pools",
        Some(node_pool_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let node_pool_id = node_pool["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing node pool id"))
        .to_owned();

    let cluster_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-cluster",
        "node_pool_id": node_pool_id.as_str()
    })
    .to_string();
    let cluster = request_json_with_bearer_token(
        address,
        "POST",
        "/container/clusters",
        Some(cluster_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let cluster_id = cluster["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing cluster id"))
        .to_owned();

    let first_general_node_payload = json!({
        "region": "us-east-1",
        "scheduler_pool": "general",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let first_general_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(first_general_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        first_general_node["scheduler_pool"].as_str(),
        Some("general")
    );
    assert_eq!(first_general_node["region"].as_str(), Some("us-east-1"));

    let gpu_node_payload = json!({
        "region": "us-east-1",
        "scheduler_pool": "gpu",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let gpu_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(gpu_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(gpu_node["scheduler_pool"].as_str(), Some("gpu"));
    assert_eq!(gpu_node["region"].as_str(), Some("us-east-1"));

    let scheduler_nodes = request_json_with_bearer_token(
        address,
        "GET",
        "/scheduler/nodes",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let scheduler_node_list = scheduler_nodes
        .as_array()
        .unwrap_or_else(|| panic!("scheduler node list should be an array"));
    assert_eq!(scheduler_node_list.len(), 2);
    assert_eq!(
        scheduler_node_list
            .iter()
            .filter(|node| node["scheduler_pool"].as_str() == Some("general"))
            .count(),
        1
    );
    assert_eq!(
        scheduler_node_list
            .iter()
            .filter(|node| node["scheduler_pool"].as_str() == Some("gpu"))
            .count(),
        1
    );

    let workload_payload = json!({
        "cluster_id": cluster_id.as_str(),
        "project_id": project_id.as_str(),
        "name": "api",
        "image": "registry.local/api:1",
        "desired_replicas": 2,
        "execution_class": "service",
        "command": ["/srv/start"]
    })
    .to_string();
    let workload = request_json_with_bearer_token(
        address,
        "POST",
        "/container/workloads",
        Some(workload_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let workload_id = workload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload id"))
        .to_owned();

    let reconciliations = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let blocked_reconciliation =
        find_object_by_field(&reconciliations, "workload_id", workload_id.as_str());
    let blocked_idempotency_key = blocked_reconciliation["event_idempotency_key"]
        .as_str()
        .unwrap_or_else(|| panic!("missing blocked reconciliation event idempotency key"))
        .to_owned();
    assert_eq!(blocked_reconciliation["state"].as_str(), Some("blocked"));
    assert_eq!(
        blocked_reconciliation["cluster_id"].as_str(),
        Some(cluster_id.as_str())
    );
    assert_eq!(
        blocked_reconciliation["node_pool_id"].as_str(),
        Some(node_pool_id.as_str())
    );
    assert_eq!(blocked_reconciliation["region"].as_str(), Some("us-east-1"));
    assert_eq!(
        blocked_reconciliation["scheduler_pool"].as_str(),
        Some("general")
    );
    let blocked_detail = blocked_reconciliation["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("missing blocked reconciliation detail"));
    assert!(blocked_detail.contains(node_pool_id.as_str()));
    assert!(blocked_detail.contains("us-east-1"));
    assert!(blocked_detail.contains("general"));
    assert!(blocked_detail.contains("requires 2 active scheduler node(s)"));
    assert!(blocked_detail.contains("only 1 matching node(s)"));

    let blocked_summary = request_json_with_bearer_token(
        address,
        "POST",
        "/container/reconcile",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(blocked_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(blocked_summary["created_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["updated_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["replayed_records"].as_u64(), Some(1));
    assert_eq!(blocked_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["blocked_records"].as_u64(), Some(1));

    let outbox_while_blocked = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let blocked_outbox_message = outbox_while_blocked
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array while blocked"))
        .iter()
        .find(|message| {
            message["idempotency_key"].as_str() == Some(blocked_idempotency_key.as_str())
        })
        .unwrap_or_else(|| panic!("missing blocked reconciliation outbox message"));
    assert_eq!(
        blocked_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("blocked")
    );

    let second_general_node_payload = json!({
        "region": "us-east-1",
        "scheduler_pool": "general",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let second_general_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(second_general_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        second_general_node["scheduler_pool"].as_str(),
        Some("general")
    );

    let scheduler_nodes_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/scheduler/nodes",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let scheduler_nodes_after_scale = scheduler_nodes_after_scale
        .as_array()
        .unwrap_or_else(|| panic!("scheduler node list should be an array after scale"));
    assert_eq!(scheduler_nodes_after_scale.len(), 3);
    assert_eq!(
        scheduler_nodes_after_scale
            .iter()
            .filter(|node| node["scheduler_pool"].as_str() == Some("general"))
            .count(),
        2
    );
    assert_eq!(
        scheduler_nodes_after_scale
            .iter()
            .filter(|node| node["scheduler_pool"].as_str() == Some("gpu"))
            .count(),
        1
    );

    let planned_summary = request_json_with_bearer_token(
        address,
        "POST",
        "/container/reconcile",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(planned_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(planned_summary["created_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["updated_records"].as_u64(), Some(1));
    assert_eq!(planned_summary["replayed_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["blocked_records"].as_u64(), Some(0));

    let reconciliations_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let planned_reconciliation = find_object_by_field(
        &reconciliations_after_scale,
        "workload_id",
        workload_id.as_str(),
    );
    let planned_idempotency_key = planned_reconciliation["event_idempotency_key"]
        .as_str()
        .unwrap_or_else(|| panic!("missing planned reconciliation event idempotency key"));
    assert_ne!(planned_idempotency_key, blocked_idempotency_key.as_str());
    assert_eq!(planned_reconciliation["state"].as_str(), Some("planned"));
    let planned_detail = planned_reconciliation["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("missing planned reconciliation detail"));
    assert!(planned_detail.contains(cluster_id.as_str()));
    assert!(planned_detail.contains(node_pool_id.as_str()));
    assert!(planned_detail.contains("us-east-1"));
    assert!(planned_detail.contains("general"));

    let outbox_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let outbox_after_scale = outbox_after_scale
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array after scale"));
    assert_eq!(outbox_after_scale.len(), 2);
    let planned_outbox_message = outbox_after_scale
        .iter()
        .find(|message| message["idempotency_key"].as_str() == Some(planned_idempotency_key))
        .unwrap_or_else(|| panic!("missing planned reconciliation outbox message"));
    assert_eq!(
        planned_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("planned")
    );

    assert_noop_reconcile_keeps_transition_outbox_stable(
        address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        blocked_idempotency_key.as_str(),
        planned_idempotency_key,
    );
}

#[test]
fn container_reconcile_requires_region_matching_scheduler_capacity_in_all_in_one_runtime() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("container-runtime-scheduler-regions.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping container_reconcile_requires_region_matching_scheduler_capacity_in_all_in_one_runtime: loopback bind not permitted"
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

    let project_id = ProjectId::generate()
        .unwrap_or_else(|error| panic!("failed to allocate project id: {error}"))
        .to_string();
    let node_pool_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-general-east",
        "region": "us-east-1",
        "scheduler_pool": "general",
        "min_nodes": 1,
        "desired_nodes": 2,
        "max_nodes": 3
    })
    .to_string();
    let node_pool = request_json_with_bearer_token(
        address,
        "POST",
        "/container/node-pools",
        Some(node_pool_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let node_pool_id = node_pool["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing node pool id"))
        .to_owned();

    let cluster_payload = json!({
        "project_id": project_id.as_str(),
        "name": "alpha-cluster",
        "node_pool_id": node_pool_id.as_str()
    })
    .to_string();
    let cluster = request_json_with_bearer_token(
        address,
        "POST",
        "/container/clusters",
        Some(cluster_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let cluster_id = cluster["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing cluster id"))
        .to_owned();

    let east_general_node_payload = json!({
        "region": "us-east-1",
        "scheduler_pool": "general",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let east_general_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(east_general_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(east_general_node["region"].as_str(), Some("us-east-1"));
    assert_eq!(
        east_general_node["scheduler_pool"].as_str(),
        Some("general")
    );

    let west_general_node_payload = json!({
        "region": "us-west-2",
        "scheduler_pool": "general",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let west_general_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(west_general_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(west_general_node["region"].as_str(), Some("us-west-2"));
    assert_eq!(
        west_general_node["scheduler_pool"].as_str(),
        Some("general")
    );

    let scheduler_nodes = request_json_with_bearer_token(
        address,
        "GET",
        "/scheduler/nodes",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let scheduler_node_list = scheduler_nodes
        .as_array()
        .unwrap_or_else(|| panic!("scheduler node list should be an array"));
    assert_eq!(scheduler_node_list.len(), 2);
    assert_eq!(
        scheduler_node_list
            .iter()
            .filter(|node| node["scheduler_pool"].as_str() == Some("general"))
            .count(),
        2
    );
    assert_eq!(
        scheduler_node_list
            .iter()
            .filter(|node| {
                node["scheduler_pool"].as_str() == Some("general")
                    && node["region"].as_str() == Some("us-east-1")
            })
            .count(),
        1
    );
    assert_eq!(
        scheduler_node_list
            .iter()
            .filter(|node| {
                node["scheduler_pool"].as_str() == Some("general")
                    && node["region"].as_str() == Some("us-west-2")
            })
            .count(),
        1
    );

    let workload_payload = json!({
        "cluster_id": cluster_id.as_str(),
        "project_id": project_id.as_str(),
        "name": "api",
        "image": "registry.local/api:1",
        "desired_replicas": 2,
        "execution_class": "service",
        "command": ["/srv/start"]
    })
    .to_string();
    let workload = request_json_with_bearer_token(
        address,
        "POST",
        "/container/workloads",
        Some(workload_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let workload_id = workload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload id"))
        .to_owned();

    let reconciliations = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let blocked_reconciliation =
        find_object_by_field(&reconciliations, "workload_id", workload_id.as_str());
    let blocked_idempotency_key = blocked_reconciliation["event_idempotency_key"]
        .as_str()
        .unwrap_or_else(|| panic!("missing blocked reconciliation event idempotency key"))
        .to_owned();
    assert_eq!(blocked_reconciliation["state"].as_str(), Some("blocked"));
    assert_eq!(
        blocked_reconciliation["cluster_id"].as_str(),
        Some(cluster_id.as_str())
    );
    assert_eq!(
        blocked_reconciliation["node_pool_id"].as_str(),
        Some(node_pool_id.as_str())
    );
    assert_eq!(blocked_reconciliation["region"].as_str(), Some("us-east-1"));
    assert_eq!(
        blocked_reconciliation["scheduler_pool"].as_str(),
        Some("general")
    );
    let blocked_detail = blocked_reconciliation["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("missing blocked reconciliation detail"));
    assert!(blocked_detail.contains(node_pool_id.as_str()));
    assert!(blocked_detail.contains("us-east-1"));
    assert!(blocked_detail.contains("general"));
    assert!(blocked_detail.contains("requires 2 active scheduler node(s)"));
    assert!(blocked_detail.contains("only 1 matching node(s)"));

    let blocked_summary = request_json_with_bearer_token(
        address,
        "POST",
        "/container/reconcile",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(blocked_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(blocked_summary["created_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["updated_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["replayed_records"].as_u64(), Some(1));
    assert_eq!(blocked_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(blocked_summary["blocked_records"].as_u64(), Some(1));

    let outbox_while_blocked = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let blocked_outbox_message = outbox_while_blocked
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array while blocked"))
        .iter()
        .find(|message| {
            message["idempotency_key"].as_str() == Some(blocked_idempotency_key.as_str())
        })
        .unwrap_or_else(|| panic!("missing blocked reconciliation outbox message"));
    assert_eq!(
        blocked_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("blocked")
    );

    let second_east_general_node_payload = json!({
        "region": "us-east-1",
        "scheduler_pool": "general",
        "cpu_millis": 4_000,
        "memory_mb": 8_192
    })
    .to_string();
    let second_east_general_node = request_json_with_bearer_token(
        address,
        "POST",
        "/scheduler/nodes",
        Some(second_east_general_node_payload.as_str()),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        second_east_general_node["region"].as_str(),
        Some("us-east-1")
    );
    assert_eq!(
        second_east_general_node["scheduler_pool"].as_str(),
        Some("general")
    );

    let scheduler_nodes_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/scheduler/nodes",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let scheduler_nodes_after_scale = scheduler_nodes_after_scale
        .as_array()
        .unwrap_or_else(|| panic!("scheduler node list should be an array after scale"));
    assert_eq!(scheduler_nodes_after_scale.len(), 3);
    assert_eq!(
        scheduler_nodes_after_scale
            .iter()
            .filter(|node| {
                node["scheduler_pool"].as_str() == Some("general")
                    && node["region"].as_str() == Some("us-east-1")
            })
            .count(),
        2
    );
    assert_eq!(
        scheduler_nodes_after_scale
            .iter()
            .filter(|node| {
                node["scheduler_pool"].as_str() == Some("general")
                    && node["region"].as_str() == Some("us-west-2")
            })
            .count(),
        1
    );

    let planned_summary = request_json_with_bearer_token(
        address,
        "POST",
        "/container/reconcile",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(planned_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(planned_summary["created_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["updated_records"].as_u64(), Some(1));
    assert_eq!(planned_summary["replayed_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(planned_summary["blocked_records"].as_u64(), Some(0));

    let reconciliations_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/container/reconciliations",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let planned_reconciliation = find_object_by_field(
        &reconciliations_after_scale,
        "workload_id",
        workload_id.as_str(),
    );
    let planned_idempotency_key = planned_reconciliation["event_idempotency_key"]
        .as_str()
        .unwrap_or_else(|| panic!("missing planned reconciliation event idempotency key"));
    assert_ne!(planned_idempotency_key, blocked_idempotency_key.as_str());
    assert_eq!(planned_reconciliation["state"].as_str(), Some("planned"));
    let planned_detail = planned_reconciliation["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("missing planned reconciliation detail"));
    assert!(planned_detail.contains(cluster_id.as_str()));
    assert!(planned_detail.contains(node_pool_id.as_str()));
    assert!(planned_detail.contains("us-east-1"));
    assert!(planned_detail.contains("general"));

    let outbox_after_scale = request_json_with_bearer_token(
        address,
        "GET",
        "/container/outbox",
        None,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    let outbox_after_scale = outbox_after_scale
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array after scale"));
    assert_eq!(outbox_after_scale.len(), 2);
    let planned_outbox_message = outbox_after_scale
        .iter()
        .find(|message| message["idempotency_key"].as_str() == Some(planned_idempotency_key))
        .unwrap_or_else(|| panic!("missing planned reconciliation outbox message"));
    assert_eq!(
        planned_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("planned")
    );

    assert_noop_reconcile_keeps_transition_outbox_stable(
        address,
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
        blocked_idempotency_key.as_str(),
        planned_idempotency_key,
    );
}

fn assert_noop_reconcile_keeps_transition_outbox_stable(
    address: SocketAddr,
    token: &str,
    blocked_idempotency_key: &str,
    planned_idempotency_key: &str,
) {
    let replay_summary =
        request_json_with_bearer_token(address, "POST", "/container/reconcile", None, token);
    assert_eq!(replay_summary["reconciled_workloads"].as_u64(), Some(1));
    assert_eq!(replay_summary["created_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["updated_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["replayed_records"].as_u64(), Some(1));
    assert_eq!(replay_summary["retired_records"].as_u64(), Some(0));
    assert_eq!(replay_summary["blocked_records"].as_u64(), Some(0));

    let outbox_after_replay =
        request_json_with_bearer_token(address, "GET", "/container/outbox", None, token);
    let outbox_after_replay = outbox_after_replay
        .as_array()
        .unwrap_or_else(|| panic!("outbox should be an array after planned replay"));
    assert_eq!(outbox_after_replay.len(), 2);

    let blocked_outbox_message = outbox_after_replay
        .iter()
        .find(|message| message["idempotency_key"].as_str() == Some(blocked_idempotency_key))
        .unwrap_or_else(|| panic!("missing blocked reconciliation outbox message after replay"));
    assert_eq!(
        blocked_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("blocked")
    );

    let planned_outbox_message = outbox_after_replay
        .iter()
        .find(|message| message["idempotency_key"].as_str() == Some(planned_idempotency_key))
        .unwrap_or_else(|| panic!("missing planned reconciliation outbox message after replay"));
    assert_eq!(
        planned_outbox_message["payload"]["payload"]["data"]["details"]["state"].as_str(),
        Some("planned")
    );
}

fn find_object_by_field<'a>(items: &'a Value, field: &str, expected: &str) -> &'a Value {
    items
        .as_array()
        .unwrap_or_else(|| panic!("expected array for field search"))
        .iter()
        .find(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing object with {field}={expected}"))
}

fn summary_count_by_value(items: &Value, value: &str) -> Option<u64> {
    items.as_array().and_then(|entries| {
        entries.iter().find_map(|entry| {
            (entry.get("value").and_then(Value::as_str) == Some(value))
                .then(|| entry.get("count").and_then(Value::as_u64))
                .flatten()
        })
    })
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
node_name = "container-runtime-node"

[secrets]
master_key = "{}"

[security]
bootstrap_admin_token = "{token}"
"#,
        state_dir.display(),
        base64url_encode(&[0x33; 32]),
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

fn request_json_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: &str,
) -> Value {
    let response = request_with_bearer_token(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        token,
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

fn assert_error_envelope(
    response: RawResponse,
    expected_status: u16,
    expected_code: &str,
    expected_message: &str,
    expected_detail_contains: Option<&str>,
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
    match expected_detail_contains {
        Some(fragment) => {
            let detail = error["detail"]
                .as_str()
                .unwrap_or_else(|| panic!("expected detail string in {payload}"));
            assert!(
                detail.contains(fragment),
                "expected detail containing `{fragment}`, got `{detail}`"
            );
        }
        None => assert!(
            error["detail"].is_null(),
            "expected null detail in {payload}"
        ),
    }
}

struct RawResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn required_header<'a>(response: &'a RawResponse, name: &str) -> &'a str {
    response
        .headers
        .get(name)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("missing {name} header"))
}

fn request_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> RawResponse {
    request_with_bearer_token_and_extra_headers(address, method, path, body, token, &[])
}

fn request_with_bearer_token_and_extra_headers(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = is_idempotent_method(method);
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request_with_bearer_token_and_extra_headers(
            address,
            method,
            path,
            body,
            token,
            extra_headers,
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

    parse_http_response(response)
}

fn try_request_with_bearer_token_and_extra_headers(
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

    parse_http_response(response)
}

fn parse_http_response(response: Vec<u8>) -> Result<RawResponse, Error> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid http response framing"))?;
    let (head, body) = response.split_at(split + 4);
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

    Ok(RawResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}
