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
fn routed_secret_reveal_cli_grant_flows_work_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping routed_secret_reveal_cli_grant_flows_work_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "routed_secret_reveal_cli_grant_flows_work_against_uhostd",
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

    let ready = request_json(address, "GET", "/readyz", None);
    assert_eq!(
        ready["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing readyz status")),
        "ready"
    );

    let endpoint = format!("http://{address}");

    let approval_secret_payload = json!({
        "name": "approval-secret",
        "value": "approval-cli-runtime-value"
    })
    .to_string();
    let approval_secret = request_json(
        address,
        "POST",
        "/secrets/items",
        Some(approval_secret_payload.as_str()),
    );
    let approval_secret_id = required_string(&approval_secret, "id").to_owned();

    let approval_grant = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "approval-create",
            "--secret-id",
            approval_secret_id.as_str(),
            "--reason",
            "cli approval verification",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let approval_grant_id = required_string(&approval_grant, "id").to_owned();
    assert_eq!(
        approval_grant["secret_id"].as_str(),
        Some(approval_secret_id.as_str())
    );
    assert_eq!(approval_grant["grant_kind"].as_str(), Some("approval"));
    assert_eq!(
        approval_grant["reason"].as_str(),
        Some("cli approval verification")
    );
    assert_eq!(
        approval_grant["granted_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(approval_grant["reveal_count"].as_u64(), Some(0));
    assert!(approval_grant["expires_at"].is_null());

    let approval_reveal = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "grant-reveal",
            "--secret-id",
            approval_secret_id.as_str(),
            "--grant-id",
            approval_grant_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(
        approval_reveal["value"].as_str(),
        Some("approval-cli-runtime-value")
    );

    let lease_secret_payload = json!({
        "name": "lease-secret",
        "value": "lease-cli-runtime-value"
    })
    .to_string();
    let lease_secret = request_json(
        address,
        "POST",
        "/secrets/items",
        Some(lease_secret_payload.as_str()),
    );
    let lease_secret_id = required_string(&lease_secret, "id").to_owned();

    let lease_grant = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "lease-create",
            "--secret-id",
            lease_secret_id.as_str(),
            "--reason",
            "cli lease verification",
            "--lease-seconds",
            "45",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let lease_grant_id = required_string(&lease_grant, "id").to_owned();
    assert_eq!(
        lease_grant["secret_id"].as_str(),
        Some(lease_secret_id.as_str())
    );
    assert_eq!(lease_grant["grant_kind"].as_str(), Some("lease"));
    assert_eq!(
        lease_grant["reason"].as_str(),
        Some("cli lease verification")
    );
    assert_eq!(lease_grant["granted_by"].as_str(), Some("bootstrap_admin"));
    assert_eq!(lease_grant["reveal_count"].as_u64(), Some(0));
    assert!(!lease_grant["expires_at"].is_null());

    for attempt in 1..=2 {
        let lease_reveal = run_uhostctl_json(
            &uhostctl_binary,
            &[
                "secrets",
                "grant-reveal",
                "--secret-id",
                lease_secret_id.as_str(),
                "--grant-id",
                lease_grant_id.as_str(),
                "--endpoint",
                endpoint.as_str(),
            ],
        );
        assert_eq!(
            lease_reveal["value"].as_str(),
            Some("lease-cli-runtime-value"),
            "unexpected lease reveal {attempt}: {lease_reveal}"
        );
    }

    let secrets_root = state_dir.join("secrets");
    let reveal_grants = read_json_file(&secrets_root.join("reveal_grants.json"));
    let stored_approval_grant = stored_record_value(&reveal_grants, &approval_grant_id);
    assert_eq!(
        stored_approval_grant["secret_id"].as_str(),
        Some(approval_secret_id.as_str())
    );
    assert_eq!(
        stored_approval_grant["grant_kind"].as_str(),
        Some("approval")
    );
    assert_eq!(stored_approval_grant["reveal_count"].as_u64(), Some(1));
    assert_eq!(
        stored_approval_grant["last_revealed_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert!(!stored_approval_grant["last_revealed_at"].is_null());

    let stored_lease_grant = stored_record_value(&reveal_grants, &lease_grant_id);
    assert_eq!(
        stored_lease_grant["secret_id"].as_str(),
        Some(lease_secret_id.as_str())
    );
    assert_eq!(stored_lease_grant["grant_kind"].as_str(), Some("lease"));
    assert_eq!(stored_lease_grant["reveal_count"].as_u64(), Some(2));
    assert_eq!(
        stored_lease_grant["last_revealed_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert!(!stored_lease_grant["last_revealed_at"].is_null());
    assert_eq!(stored_lease_grant["expires_at"], lease_grant["expires_at"]);
}

#[test]
fn secrets_inventory_create_and_direct_reveal_cli_flows_work_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping secrets_inventory_create_and_direct_reveal_cli_flows_work_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "secrets_inventory_create_and_direct_reveal_cli_flows_work_against_uhostd",
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

    let created_v1 = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "create",
            "--name",
            "incident/db-root",
            "--value",
            "cli-direct-v1",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let secret_id_v1 = required_string(&created_v1, "id").to_owned();
    assert_eq!(created_v1["name"].as_str(), Some("incident/db-root"));
    assert_eq!(created_v1["version"].as_u64(), Some(1));

    let created_v2 = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "create",
            "--name",
            "incident/db-root",
            "--value",
            "cli-direct-v2",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let secret_id_v2 = required_string(&created_v2, "id").to_owned();
    assert_eq!(created_v2["name"].as_str(), Some("incident/db-root"));
    assert_eq!(created_v2["version"].as_u64(), Some(2));

    let items = run_uhostctl_json(
        &uhostctl_binary,
        &["secrets", "items", "--endpoint", endpoint.as_str()],
    );
    let items = items
        .as_array()
        .unwrap_or_else(|| panic!("items response should be an array: {items}"));
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|item| {
        item["id"].as_str() == Some(secret_id_v1.as_str())
            && item["name"].as_str() == Some("incident/db-root")
            && item["version"].as_u64() == Some(1)
    }));
    assert!(items.iter().any(|item| {
        item["id"].as_str() == Some(secret_id_v2.as_str())
            && item["name"].as_str() == Some("incident/db-root")
            && item["version"].as_u64() == Some(2)
    }));

    let summary = run_uhostctl_json(
        &uhostctl_binary,
        &["secrets", "summary", "--endpoint", endpoint.as_str()],
    );
    assert_eq!(summary["secret_count"].as_u64(), Some(2));
    assert_eq!(summary["unique_secret_name_count"].as_u64(), Some(1));
    assert_eq!(summary["highest_version"].as_u64(), Some(2));
    assert_eq!(
        summary["latest_version_by_name"]["incident/db-root"].as_u64(),
        Some(2)
    );
    assert_eq!(
        summary["ownership_scope_totals"]["project"].as_u64(),
        Some(2)
    );

    let direct_reveal = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "secrets",
            "reveal",
            "--secret-id",
            secret_id_v2.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(direct_reveal["id"].as_str(), Some(secret_id_v2.as_str()));
    assert_eq!(direct_reveal["name"].as_str(), Some("incident/db-root"));
    assert_eq!(direct_reveal["version"].as_u64(), Some(2));
    assert_eq!(direct_reveal["value"].as_str(), Some("cli-direct-v2"));

    let secrets_root = state_dir.join("secrets");
    let stored_secrets = read_json_file(&secrets_root.join("secrets.json"));
    let stored_v1 = stored_record_value(&stored_secrets, &secret_id_v1);
    assert_eq!(stored_v1["name"].as_str(), Some("incident/db-root"));
    assert_eq!(stored_v1["version"].as_u64(), Some(1));
    assert_ne!(stored_v1["ciphertext"].as_str(), Some("cli-direct-v1"));

    let stored_v2 = stored_record_value(&stored_secrets, &secret_id_v2);
    assert_eq!(stored_v2["name"].as_str(), Some("incident/db-root"));
    assert_eq!(stored_v2["version"].as_u64(), Some(2));
    assert_ne!(stored_v2["ciphertext"].as_str(), Some("cli-direct-v2"));
}

#[test]
fn abuse_remediation_case_cli_runtime_flow_works_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_remediation_case_cli_runtime_flow_works_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "abuse_remediation_case_cli_runtime_flow_works_against_uhostd",
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
        "reason": "cli remediation runtime seed",
    })
    .to_string();
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(abuse_case_payload.as_str()),
    );
    let abuse_case_id = required_string(&abuse_case, "id").to_owned();

    let created = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "cli remediation runtime verification",
            "--owner",
            "operator:incident",
            "--sla-target-seconds",
            "900",
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
    let remediation_case_id = required_string(&created, "id").to_owned();
    let expected_workflow_id = format!("abuse.remediation.{remediation_case_id}");
    assert_eq!(created["tenant_subject"].as_str(), Some("tenant:org_1"));
    assert_eq!(created["opened_by"].as_str(), Some("bootstrap_admin"));
    assert_eq!(created["owner"].as_str(), Some("operator:incident"));
    assert_eq!(
        created["reason"].as_str(),
        Some("cli remediation runtime verification")
    );
    assert_eq!(created["evidence_state"].as_str(), Some("ready"));
    assert_eq!(created["sla_target_seconds"].as_u64(), Some(900));
    assert_eq!(created["sla_state"].as_str(), Some("within_sla"));
    assert_eq!(created["escalation_state"].as_str(), Some("none"));
    assert_eq!(created["escalation_count"].as_u64(), Some(0));
    assert_eq!(
        created["workflow_id"].as_str(),
        Some(expected_workflow_id.as_str())
    );
    assert_eq!(created["abuse_case_ids"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        created["abuse_case_ids"][0].as_str(),
        Some(abuse_case_id.as_str())
    );
    assert_eq!(created["workflow_steps"].as_array().map(Vec::len), Some(5));
    assert_eq!(
        workflow_step(&created, "dry_run")["state"].as_str(),
        Some("completed")
    );
    assert_eq!(
        workflow_step(&created, "checkpoint")["state"].as_str(),
        Some("completed")
    );
    assert_eq!(
        workflow_step(&created, "rollback")["state"].as_str(),
        Some("completed")
    );
    assert_eq!(
        workflow_step(&created, "verification")["state"].as_str(),
        Some("completed")
    );
    let created_fanout_step = workflow_step(&created, "downstream_fanout");
    assert_eq!(created_fanout_step["state"].as_str(), Some("completed"));
    assert_eq!(
        created_fanout_step["detail"].as_str(),
        Some("no downstream fanout required")
    );

    let listed = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-cases",
            "--tenant-subject",
            "tenant:org_1",
            "--owner",
            "operator:incident",
            "--evidence-state",
            "ready",
            "--sla-state",
            "within_sla",
            "--escalation-state",
            "none",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--limit",
            "5",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let listed = listed
        .as_array()
        .unwrap_or_else(|| panic!("remediation list response should be an array: {listed}"));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"].as_str(), Some(remediation_case_id.as_str()));
    assert_eq!(
        listed[0]["workflow_id"].as_str(),
        Some(expected_workflow_id.as_str())
    );
    assert_eq!(
        listed[0]["workflow_steps"].as_array().map(Vec::len),
        Some(5)
    );

    let fetched = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-get",
            "--remediation-case-id",
            remediation_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(fetched["id"].as_str(), Some(remediation_case_id.as_str()));
    assert_eq!(
        fetched["workflow_id"].as_str(),
        Some(expected_workflow_id.as_str())
    );
    assert_eq!(fetched["evidence_state"].as_str(), Some("ready"));
    assert_eq!(
        workflow_step(&fetched, "downstream_fanout")["detail"].as_str(),
        Some("no downstream fanout required")
    );

    let escalated = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-escalate",
            "--remediation-case-id",
            remediation_case_id.as_str(),
            "--reason",
            "handoff to incident command",
            "--owner",
            "operator:lead",
            "--change-request-id",
            "chg_cli234",
            "--notify-message-id",
            "ntf_cli234",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert_eq!(escalated["id"].as_str(), Some(remediation_case_id.as_str()));
    assert_eq!(
        escalated["workflow_id"].as_str(),
        Some(expected_workflow_id.as_str())
    );
    assert_eq!(escalated["owner"].as_str(), Some("operator:lead"));
    assert_eq!(escalated["evidence_state"].as_str(), Some("ready"));
    assert_eq!(escalated["escalation_state"].as_str(), Some("escalated"));
    assert_eq!(escalated["escalation_count"].as_u64(), Some(1));
    assert_eq!(
        escalated["last_escalated_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(
        escalated["last_escalation_reason"].as_str(),
        Some("handoff to incident command")
    );
    assert_eq!(
        escalated["change_request_ids"][0].as_str(),
        Some("chg_cli234")
    );
    assert_eq!(
        escalated["notify_message_ids"][0].as_str(),
        Some("ntf_cli234")
    );
    assert_eq!(
        workflow_step(&escalated, "rollback")["state"].as_str(),
        Some("completed")
    );
    assert_eq!(
        workflow_step(&escalated, "verification")["state"].as_str(),
        Some("completed")
    );
    let escalated_fanout_step = workflow_step(&escalated, "downstream_fanout");
    assert_eq!(escalated_fanout_step["state"].as_str(), Some("completed"));
    assert_eq!(
        escalated_fanout_step["detail"].as_str(),
        Some("1 change request and 1 notify message linked")
    );

    let abuse_root = state_dir.join("abuse");
    let stored_remediation_cases = read_json_file(&abuse_root.join("remediation_cases.json"));
    let stored_remediation = stored_record_value(&stored_remediation_cases, &remediation_case_id);
    assert_eq!(
        stored_remediation["workflow_id"].as_str(),
        Some(expected_workflow_id.as_str())
    );
    assert_eq!(stored_remediation["owner"].as_str(), Some("operator:lead"));
    assert_eq!(stored_remediation["evidence_state"].as_str(), Some("ready"));
    assert_eq!(
        stored_remediation["escalation_state"].as_str(),
        Some("escalated")
    );
    assert_eq!(stored_remediation["escalation_count"].as_u64(), Some(1));
    assert_eq!(
        stored_remediation["change_request_ids"][0].as_str(),
        Some("chg_cli234")
    );
    assert_eq!(
        stored_remediation["notify_message_ids"][0].as_str(),
        Some("ntf_cli234")
    );
    assert_eq!(
        workflow_step(stored_remediation, "downstream_fanout")["detail"].as_str(),
        Some("1 change request and 1 notify message linked")
    );
}

#[test]
fn abuse_remediation_case_cli_rejects_missing_and_invalid_evidence_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_remediation_case_cli_rejects_missing_and_invalid_evidence_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "abuse_remediation_case_cli_rejects_missing_and_invalid_evidence_against_uhostd",
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
        "reason": "cli remediation negative runtime seed",
    })
    .to_string();
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(abuse_case_payload.as_str()),
    );
    let abuse_case_id = required_string(&abuse_case, "id").to_owned();

    let missing_evidence_stderr = run_uhostctl_failure(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "missing rollback evidence",
            "--verification-evidence",
            "checklist:tenant-verification",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert!(
        missing_evidence_stderr.contains("control plane request failed with status 400"),
        "missing evidence stderr should include HTTP status: {missing_evidence_stderr}"
    );
    assert!(
        missing_evidence_stderr
            .contains("rollback_evidence_refs must include at least one evidence reference"),
        "missing evidence stderr should include validation message: {missing_evidence_stderr}"
    );

    let invalid_evidence_stderr = run_uhostctl_failure(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "invalid verification evidence",
            "--rollback-evidence",
            "runbook:tenant-rollback",
            "--verification-evidence",
            "evidence-ref-that-is-deliberately-over-256-characters-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert!(
        invalid_evidence_stderr.contains("control plane request failed with status 400"),
        "invalid evidence stderr should include HTTP status: {invalid_evidence_stderr}"
    );
    assert!(
        invalid_evidence_stderr.contains("each evidence reference must be 256 chars or less"),
        "invalid evidence stderr should include validation message: {invalid_evidence_stderr}"
    );

    let listed = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-cases",
            "--tenant-subject",
            "tenant:org_1",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let listed = listed
        .as_array()
        .unwrap_or_else(|| panic!("remediation list response should be an array: {listed}"));
    assert!(
        listed.is_empty(),
        "expected no remediation cases: {listed:?}"
    );

    let remediation_cases_path = state_dir.join("abuse").join("remediation_cases.json");
    if remediation_cases_path.is_file() {
        let stored_remediation_cases = read_json_file(&remediation_cases_path);
        let records = stored_remediation_cases["records"]
            .as_object()
            .unwrap_or_else(|| panic!("records should be an object: {stored_remediation_cases}"));
        assert!(
            records.is_empty(),
            "rejected remediation creates should not persist records: {stored_remediation_cases}"
        );
    }
}

#[test]
fn abuse_remediation_case_cli_rejects_invalid_sla_target_seconds_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_remediation_case_cli_rejects_invalid_sla_target_seconds_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "abuse_remediation_case_cli_rejects_invalid_sla_target_seconds_against_uhostd",
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
        "reason": "cli remediation invalid sla runtime seed",
    })
    .to_string();
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(abuse_case_payload.as_str()),
    );
    let abuse_case_id = required_string(&abuse_case, "id").to_owned();

    let invalid_sla_stderr = run_uhostctl_failure(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-create",
            "--tenant-subject",
            "tenant:org_1",
            "--reason",
            "invalid sla target",
            "--owner",
            "operator:incident",
            "--sla-target-seconds",
            "fast",
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
    assert!(
        invalid_sla_stderr.contains("--sla-target-seconds must be an integer"),
        "invalid SLA stderr should include CLI validation message: {invalid_sla_stderr}"
    );
    assert!(
        invalid_sla_stderr.contains("invalid digit found in string"),
        "invalid SLA stderr should include parse detail: {invalid_sla_stderr}"
    );

    let listed = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-cases",
            "--tenant-subject",
            "tenant:org_1",
            "--abuse-case-id",
            abuse_case_id.as_str(),
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let listed = listed
        .as_array()
        .unwrap_or_else(|| panic!("remediation list response should be an array: {listed}"));
    assert!(
        listed.is_empty(),
        "expected no remediation cases: {listed:?}"
    );

    let remediation_cases_path = state_dir.join("abuse").join("remediation_cases.json");
    if remediation_cases_path.is_file() {
        let stored_remediation_cases = read_json_file(&remediation_cases_path);
        let records = stored_remediation_cases["records"]
            .as_object()
            .unwrap_or_else(|| panic!("records should be an object: {stored_remediation_cases}"));
        assert!(
            records.is_empty(),
            "CLI-local SLA validation should fail before any remediation record is written: {stored_remediation_cases}"
        );
    }
}

#[test]
fn abuse_remediation_case_cli_rejects_nonexistent_get_and_escalate_against_uhostd() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping abuse_remediation_case_cli_rejects_nonexistent_get_and_escalate_against_uhostd: loopback bind not permitted in this environment"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let uhostctl_binary = std::env::var("CARGO_BIN_EXE_uhostctl")
        .map(PathBuf::from)
        .unwrap_or_else(|error| panic!("missing uhostctl test binary path: {error}"));
    let Some(uhostd_binary) = resolve_uhostd_binary(
        &uhostctl_binary,
        "abuse_remediation_case_cli_rejects_nonexistent_get_and_escalate_against_uhostd",
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
    let missing_case_id = "aud_missingcase234";

    let get_stderr = run_uhostctl_failure(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-get",
            "--remediation-case-id",
            missing_case_id,
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert!(
        get_stderr.contains("control plane request failed with status 404"),
        "missing remediation get stderr should include HTTP status: {get_stderr}"
    );
    assert!(
        get_stderr.contains("remediation case does not exist"),
        "missing remediation get stderr should include not-found message: {get_stderr}"
    );

    let escalate_stderr = run_uhostctl_failure(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-case-escalate",
            "--remediation-case-id",
            missing_case_id,
            "--reason",
            "handoff to incident command",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    assert!(
        escalate_stderr.contains("control plane request failed with status 404"),
        "missing remediation escalate stderr should include HTTP status: {escalate_stderr}"
    );
    assert!(
        escalate_stderr.contains("remediation case does not exist"),
        "missing remediation escalate stderr should include not-found message: {escalate_stderr}"
    );

    let listed = run_uhostctl_json(
        &uhostctl_binary,
        &[
            "abuse",
            "remediation-cases",
            "--endpoint",
            endpoint.as_str(),
        ],
    );
    let listed = listed
        .as_array()
        .unwrap_or_else(|| panic!("remediation list response should be an array: {listed}"));
    assert!(
        listed.is_empty(),
        "not-found remediation CLI reads should not create records: {listed:?}"
    );

    let remediation_cases_path = state_dir.join("abuse").join("remediation_cases.json");
    if remediation_cases_path.is_file() {
        let stored_remediation_cases = read_json_file(&remediation_cases_path);
        let records = stored_remediation_cases["records"]
            .as_object()
            .unwrap_or_else(|| panic!("records should be an object: {stored_remediation_cases}"));
        assert!(
            records.is_empty(),
            "not-found remediation CLI reads should not persist records: {stored_remediation_cases}"
        );
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

fn run_uhostctl_failure(binary: &Path, args: &[&str]) -> String {
    let output = run_uhostctl(binary, args);
    assert!(
        !output.status.success(),
        "uhostctl {:?} unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("invalid UTF-8 in uhostctl stderr: {error}"))
}

fn run_uhostctl(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .env("UHOSTCTL_ADMIN_TOKEN", DEFAULT_BOOTSTRAP_ADMIN_TOKEN)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run uhostctl {:?}: {error}", args))
}

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Value {
    request_json_with_status(address, method, path, body).1
}

fn request_json_with_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, Value) {
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
    (response.status, json_from_bytes(&response.body))
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

fn workflow_step<'a>(record: &'a Value, name: &str) -> &'a Value {
    record["workflow_steps"]
        .as_array()
        .and_then(|steps| {
            steps.iter().find(|step| {
                step["name"]
                    .as_str()
                    .is_some_and(|step_name| step_name == name)
            })
        })
        .unwrap_or_else(|| panic!("missing workflow step `{name}` in {record}"))
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

    let (content_type, payload) = body.unwrap_or(("application/json", b""));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
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
