use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::tempdir;
use time::{
    Date, Duration as TimeDuration, OffsetDateTime, UtcOffset,
    format_description::well_known::Rfc3339,
};
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::{DocumentStore, WorkflowStep, WorkflowStepState};
use uhost_svc_abuse::{AbuseCase, RemediationCaseRecord};
use uhost_types::{AbuseCaseId, AuditId, OwnershipScope, ResourceMetadata};

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
fn console_workbench_surfaces_remediation_workflow_state_from_all_in_one() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping console_workbench_surfaces_remediation_workflow_state_from_all_in_one: loopback bind not permitted in this environment"
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

    let abuse_case_body = json!({
        "subject_kind": "service_identity",
        "subject": "svc:console-runtime-auth",
        "reason": "runtime console remediation coverage",
        "priority": "high",
        "signal_ids": [],
        "evidence_refs": ["ticket:runtime-console-coverage"]
    })
    .to_string();
    let abuse_case =
        request_json_with_status(address, "POST", "/abuse/cases", Some(&abuse_case_body), 201);
    let abuse_case_id = required_string(&abuse_case, "id").to_owned();

    let remediation_case_body = json!({
        "tenant_subject": "tenant.runtime.console",
        "reason": "operator remediation verification through console",
        "owner": "operator:abuse",
        "sla_target_seconds": 900,
        "rollback_evidence_refs": ["runbook:runtime-console-rollback"],
        "verification_evidence_refs": ["checklist:runtime-console-verify"],
        "abuse_case_ids": [abuse_case_id],
        "quarantine_ids": [],
        "change_request_ids": [],
        "notify_message_ids": []
    })
    .to_string();
    let remediation_case = request_json_with_status(
        address,
        "POST",
        "/abuse/remediation-cases",
        Some(&remediation_case_body),
        201,
    );
    let remediation_case_id = required_string(&remediation_case, "id").to_owned();
    assert_eq!(remediation_case["owner"].as_str(), Some("operator:abuse"));
    assert_eq!(remediation_case["evidence_state"].as_str(), Some("ready"));
    assert_eq!(remediation_case["sla_target_seconds"].as_u64(), Some(900));
    assert_eq!(
        remediation_case["workflow_id"].as_str(),
        Some(format!("abuse.remediation.{remediation_case_id}").as_str())
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "dry_run"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "verification"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "downstream_fanout"),
        Some("completed")
    );

    let escalation_body = json!({
        "reason": "handoff to incident commander",
        "owner": "operator:incident",
        "rollback_evidence_refs": [],
        "verification_evidence_refs": [],
        "change_request_ids": [],
        "notify_message_ids": []
    })
    .to_string();
    let escalated_case = request_json_with_status(
        address,
        "POST",
        &format!("/abuse/remediation-cases/{remediation_case_id}/escalate"),
        Some(&escalation_body),
        200,
    );
    assert_eq!(escalated_case["owner"].as_str(), Some("operator:incident"));
    assert_eq!(escalated_case["evidence_state"].as_str(), Some("ready"));
    assert_eq!(
        escalated_case["escalation_state"].as_str(),
        Some("escalated")
    );
    assert_eq!(escalated_case["escalation_count"].as_u64(), Some(1));
    assert_eq!(
        escalated_case["last_escalated_by"].as_str(),
        Some("bootstrap_admin")
    );
    assert_eq!(
        remediation_workflow_step_state(&escalated_case, "rollback"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&escalated_case, "verification"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&escalated_case, "downstream_fanout"),
        Some("active")
    );

    let workbench = request_json(address, "GET", "/console/workbench", None);
    let case_entries = workbench["cases"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing console case entries: {workbench}"));
    let remediation_entry = case_entries
        .iter()
        .find(|entry| entry["id"].as_str() == Some(remediation_case_id.as_str()))
        .unwrap_or_else(|| {
            panic!("missing remediation case entry for {remediation_case_id}: {workbench}")
        });

    assert_eq!(remediation_entry["source"].as_str(), Some("remediation"));
    assert_eq!(remediation_entry["status"].as_str(), Some("escalated"));
    assert_eq!(
        required_display_string(remediation_entry, "updated_at"),
        required_display_string(&escalated_case, "updated_at")
    );

    let context = required_string(remediation_entry, "context");
    let workflow_trail = remediation_workflow_trail(&escalated_case);
    assert!(context.contains(&format!(
        "tenant {}",
        required_string(&escalated_case, "tenant_subject")
    )));
    assert!(context.contains(&format!(
        "owner {}",
        required_string(&escalated_case, "owner")
    )));

    let owner_assigned_at = required_display_string(&escalated_case, "owner_assigned_at");
    assert!(context.contains(&format!("owned since {owner_assigned_at}")));

    let evidence_state = required_string(&escalated_case, "evidence_state");
    assert!(context.contains(&format!("evidence {}", display_status(evidence_state))));
    assert!(context.contains("1 rollback evidence ref"));
    assert!(context.contains("1 verification evidence ref"));

    let sla_target_seconds = escalated_case["sla_target_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing sla_target_seconds in {escalated_case}"));
    assert!(context.contains(&format!("SLA target {sla_target_seconds}s")));

    let sla_state = required_string(&escalated_case, "sla_state");
    let sla_deadline_at = required_display_string(&escalated_case, "sla_deadline_at");
    assert!(context.contains(&format!(
        "SLA {} by {sla_deadline_at}",
        display_status(sla_state)
    )));

    let escalation_state = required_string(&escalated_case, "escalation_state");
    assert!(context.contains(&format!(
        "escalation posture {}",
        display_status(escalation_state)
    )));

    let escalation_count = escalated_case["escalation_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing escalation_count in {escalated_case}"));
    assert!(context.contains(&format!("{escalation_count} escalation")));

    let last_escalated_at = required_display_string(&escalated_case, "last_escalated_at");
    assert!(context.contains(&format!("last escalation {last_escalated_at}")));

    let last_escalated_by = required_string(&escalated_case, "last_escalated_by");
    assert!(context.contains(&format!("last escalated by {last_escalated_by}")));

    let last_escalation_reason = required_string(&escalated_case, "last_escalation_reason");
    assert!(context.contains(&format!("escalation reason {last_escalation_reason}")));
    assert!(context.contains(&workflow_trail));

    let console_html = request_text_with_status(address, "GET", "/console", None, 200);
    assert!(console_html.contains("Operator workbench"));
    assert!(console_html.contains(required_string(&escalated_case, "reason")));
    assert!(console_html.contains(&format!(
        "tenant {}",
        required_string(&escalated_case, "tenant_subject")
    )));
    assert!(console_html.contains(&format!(
        "owner {}",
        required_string(&escalated_case, "owner")
    )));
    assert!(console_html.contains(&format!("owned since {owner_assigned_at}")));
    assert!(console_html.contains(&format!("evidence {}", display_status(evidence_state))));
    assert!(console_html.contains(&format!(
        "SLA {} by {sla_deadline_at}",
        display_status(sla_state)
    )));
    assert!(console_html.contains(&format!(
        "escalation posture {}",
        display_status(escalation_state)
    )));
    assert!(console_html.contains(&html_escape(&workflow_trail)));
    assert!(console_html.contains(&format!("last escalated by {last_escalated_by}")));
    assert!(console_html.contains(&format!("escalation reason {last_escalation_reason}")));
}

#[test]
fn console_workbench_threads_billing_support_entitlements_from_all_in_one() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("console-billing.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping console_workbench_threads_billing_support_entitlements_from_all_in_one: loopback bind not permitted in this environment"
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

    let account = request_json_with_status(
        address,
        "POST",
        "/billing/accounts",
        Some(r#"{"owner_id":"tenant-console-billing","plan":"pro","credits_cents":5000}"#),
        201,
    );
    let account_id = required_string(&account, "id");

    let _subscription = request_json_with_status(
        address,
        "POST",
        "/billing/subscriptions",
        Some(
            &json!({
                "billing_account_id": account_id,
                "plan": "enterprise",
            })
            .to_string(),
        ),
        201,
    );

    let _budget = request_json_with_status(
        address,
        "POST",
        "/billing/budgets",
        Some(
            &json!({
                "billing_account_id": account_id,
                "name": "tenant console quota",
                "amount_cents": 10000,
            })
            .to_string(),
        ),
        201,
    );

    let workbench = request_json(address, "GET", "/console/workbench", None);
    let quotas = &workbench["quotas"];
    assert_eq!(quotas["count"]["available"].as_bool(), Some(true));
    assert_eq!(quotas["count"]["count"].as_u64(), Some(1));
    assert_eq!(quotas["support_entitlement_count"].as_u64(), Some(2));
    assert_eq!(quotas["support_tier_totals"]["business"].as_u64(), Some(1));
    assert_eq!(
        quotas["support_tier_totals"]["enterprise"].as_u64(),
        Some(1)
    );
    assert_eq!(
        quotas["support_tier_totals"]
            .as_object()
            .unwrap_or_else(|| panic!("missing support_tier_totals object in {workbench}"))
            .len(),
        2
    );

    let quotas_note = required_string(quotas, "note");
    assert!(quotas_note.contains("Support entitlements: 2 total"));
    assert!(quotas_note.contains("business (1), enterprise (1)"));

    let entitlement_source = find_object_by_field(
        &quotas["sources"],
        "path",
        "billing/support_entitlements.json",
    );
    assert_eq!(entitlement_source["available"].as_bool(), Some(true));
    assert_eq!(entitlement_source["count"].as_u64(), Some(2));

    let quota_entry = workbench["quotas"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing quota entries in {workbench}"))
        .iter()
        .find(|entry| entry["summary"].as_str() == Some("tenant console quota (soft cap)"))
        .unwrap_or_else(|| panic!("missing quota entry in {workbench}"));
    let quota_context = required_string(quota_entry, "context");
    assert!(quota_context.contains(account_id));

    let console_html = request_text_with_status(address, "GET", "/console", None, 200);
    assert!(console_html.contains("Support entitlements: 2 total"));
    assert!(console_html.contains("business (1), enterprise (1)"));
}

#[test]
fn console_workbench_surfaces_mixed_remediation_workflow_trail_from_all_in_one() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let remediation_case_id = seed_mixed_remediation_workflow_case(&state_dir);
    let config_path = temp.path().join("console-remediation-mixed.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping console_workbench_surfaces_mixed_remediation_workflow_trail_from_all_in_one: loopback bind not permitted in this environment"
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

    let remediation_case = request_json_with_status(
        address,
        "GET",
        &format!("/abuse/remediation-cases/{remediation_case_id}"),
        None,
        200,
    );
    assert_eq!(
        remediation_case["owner"].as_str(),
        Some("operator:recovery")
    );
    assert_eq!(
        remediation_case["evidence_state"].as_str(),
        Some("verification_missing")
    );
    assert_eq!(remediation_case["escalation_state"].as_str(), Some("none"));
    assert_eq!(
        remediation_case["workflow_id"].as_str(),
        Some(format!("abuse.remediation.{remediation_case_id}").as_str())
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "dry_run"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "checkpoint"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "rollback"),
        Some("completed")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "verification"),
        Some("active")
    );
    assert_eq!(
        remediation_workflow_step_state(&remediation_case, "downstream_fanout"),
        Some("completed")
    );

    let workbench = request_json(address, "GET", "/console/workbench", None);
    let case_entries = workbench["cases"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing console case entries: {workbench}"));
    let remediation_entry = case_entries
        .iter()
        .find(|entry| entry["id"].as_str() == Some(remediation_case_id.as_str()))
        .unwrap_or_else(|| {
            panic!("missing remediation case entry for {remediation_case_id}: {workbench}")
        });

    assert_eq!(remediation_entry["source"].as_str(), Some("remediation"));
    assert_eq!(
        remediation_entry["status"].as_str(),
        Some("verification_missing")
    );
    assert_eq!(
        required_display_string(remediation_entry, "updated_at"),
        required_display_string(&remediation_case, "updated_at")
    );

    let context = required_string(remediation_entry, "context");
    let workflow_trail = remediation_workflow_trail(&remediation_case);
    assert!(context.contains(&format!(
        "tenant {}",
        required_string(&remediation_case, "tenant_subject")
    )));
    assert!(context.contains(&format!(
        "owner {}",
        required_string(&remediation_case, "owner")
    )));

    let owner_assigned_at = required_display_string(&remediation_case, "owner_assigned_at");
    assert!(context.contains(&format!("owned since {owner_assigned_at}")));
    assert!(context.contains("4/5 workflow steps completed"));
    assert!(context.contains("workflow verification active"));
    assert!(context.contains("awaiting verification evidence refs"));
    assert!(context.contains(&workflow_trail));

    let evidence_state = required_string(&remediation_case, "evidence_state");
    assert!(context.contains(&format!("evidence {}", display_status(evidence_state))));
    assert!(context.contains("1 rollback evidence ref"));
    assert!(context.contains("0 verification evidence refs"));

    let sla_target_seconds = remediation_case["sla_target_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing sla_target_seconds in {remediation_case}"));
    assert!(context.contains(&format!("SLA target {sla_target_seconds}s")));

    let sla_state = required_string(&remediation_case, "sla_state");
    let sla_deadline_at = required_display_string(&remediation_case, "sla_deadline_at");
    assert!(context.contains(&format!(
        "SLA {} by {sla_deadline_at}",
        display_status(sla_state)
    )));

    let console_html = request_text_with_status(address, "GET", "/console", None, 200);
    assert!(console_html.contains("Operator workbench"));
    assert!(console_html.contains(required_string(&remediation_case, "reason")));
    assert!(console_html.contains(&format!(
        "tenant {}",
        required_string(&remediation_case, "tenant_subject")
    )));
    assert!(console_html.contains(&format!(
        "owner {}",
        required_string(&remediation_case, "owner")
    )));
    assert!(console_html.contains(&format!("owned since {owner_assigned_at}")));
    assert!(console_html.contains("4/5 workflow steps completed"));
    assert!(console_html.contains("workflow verification active"));
    assert!(console_html.contains("awaiting verification evidence refs"));
    assert!(console_html.contains(&html_escape(&workflow_trail)));
    assert!(console_html.contains(&format!("evidence {}", display_status(evidence_state))));
    assert!(console_html.contains("1 rollback evidence ref"));
    assert!(console_html.contains("0 verification evidence refs"));
    assert!(console_html.contains(&format!("SLA target {sla_target_seconds}s")));
    assert!(console_html.contains(&format!(
        "SLA {} by {sla_deadline_at}",
        display_status(sla_state)
    )));
}

fn seed_mixed_remediation_workflow_case(state_dir: &Path) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("failed to build tokio runtime: {error}"));
    runtime.block_on(async {
        let cases = DocumentStore::open(state_dir.join("abuse").join("cases.json"))
            .await
            .unwrap_or_else(|error| panic!("failed to open abuse case store: {error}"));
        let remediation_cases =
            DocumentStore::open(state_dir.join("abuse").join("remediation_cases.json"))
                .await
                .unwrap_or_else(|error| panic!("failed to open remediation case store: {error}"));

        let abuse_case_id = AbuseCaseId::generate()
            .unwrap_or_else(|error| panic!("failed to generate id: {error}"));
        let remediation_case_id =
            AuditId::generate().unwrap_or_else(|error| panic!("failed to generate id: {error}"));

        let opened_at = OffsetDateTime::now_utc() - TimeDuration::minutes(10);
        let updated_at = opened_at + TimeDuration::minutes(5);
        let owner_assigned_at = opened_at + TimeDuration::minutes(1);
        let sla_deadline_at = opened_at + TimeDuration::hours(1);

        cases
            .create(
                abuse_case_id.as_str(),
                AbuseCase {
                    id: abuse_case_id.clone(),
                    subject_kind: String::from("service_identity"),
                    subject: String::from("svc:console-runtime-verify"),
                    reason: String::from("runtime console mixed remediation coverage"),
                    status: String::from("open"),
                    priority: String::from("normal"),
                    assigned_to: None,
                    escalation_count: 0,
                    signal_ids: Vec::new(),
                    evidence_refs: vec![String::from("ticket:runtime-console-mixed")],
                    quarantine_id: None,
                    decision_note: None,
                    opened_at,
                    updated_at,
                    closed_at: None,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(abuse_case_id.to_string()),
                        sha256_hex(abuse_case_id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed abuse case: {error}"));

        remediation_cases
            .create(
                remediation_case_id.as_str(),
                RemediationCaseRecord {
                    id: remediation_case_id.clone(),
                    workflow_id: Some(format!("abuse.remediation.{remediation_case_id}")),
                    workflow_steps: vec![
                        WorkflowStep {
                            name: String::from("dry_run"),
                            index: 0,
                            state: WorkflowStepState::Completed,
                            detail: Some(String::from(
                                "linked priorities normal; no active quarantines",
                            )),
                            effect_journal: Vec::new(),
                            updated_at: opened_at,
                        },
                        WorkflowStep {
                            name: String::from("checkpoint"),
                            index: 1,
                            state: WorkflowStepState::Completed,
                            detail: Some(String::from(
                                "workflow checkpoint persisted for 1 abuse case and 0 quarantines",
                            )),
                            effect_journal: Vec::new(),
                            updated_at,
                        },
                        WorkflowStep {
                            name: String::from("rollback"),
                            index: 2,
                            state: WorkflowStepState::Completed,
                            detail: Some(String::from("1 rollback evidence ref ready")),
                            effect_journal: Vec::new(),
                            updated_at,
                        },
                        WorkflowStep {
                            name: String::from("verification"),
                            index: 3,
                            state: WorkflowStepState::Active,
                            detail: Some(String::from("awaiting verification evidence refs")),
                            effect_journal: Vec::new(),
                            updated_at,
                        },
                        WorkflowStep {
                            name: String::from("downstream_fanout"),
                            index: 4,
                            state: WorkflowStepState::Completed,
                            detail: Some(String::from("no downstream fanout required")),
                            effect_journal: Vec::new(),
                            updated_at,
                        },
                    ],
                    tenant_subject: String::from("tenant.runtime.console.verify"),
                    opened_by: Some(String::from("operator:abuse")),
                    owner: Some(String::from("operator:recovery")),
                    owner_assigned_at: Some(owner_assigned_at),
                    abuse_case_ids: vec![abuse_case_id],
                    quarantine_ids: Vec::new(),
                    change_request_ids: Vec::new(),
                    notify_message_ids: Vec::new(),
                    rollback_evidence_refs: vec![String::from("runbook:runtime-console-rollback")],
                    verification_evidence_refs: Vec::new(),
                    evidence_state: String::from("verification_missing"),
                    sla_target_seconds: 3600,
                    sla_deadline_at: Some(sla_deadline_at),
                    sla_state: String::from("within_sla"),
                    escalation_state: String::from("none"),
                    escalation_count: 0,
                    last_escalated_at: None,
                    last_escalated_by: None,
                    last_escalation_reason: None,
                    reason: String::from(
                        "operator remediation awaiting verification through console",
                    ),
                    created_at: opened_at,
                    updated_at,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(remediation_case_id.to_string()),
                        sha256_hex(remediation_case_id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed remediation case: {error}"));

        remediation_case_id.to_string()
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

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "console-workbench-test-node"

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

fn remediation_workflow_step_state<'a>(record: &'a Value, step_name: &str) -> Option<&'a str> {
    record["workflow_steps"]
        .as_array()?
        .iter()
        .find(|step| step["name"].as_str() == Some(step_name))
        .and_then(|step| step["state"].as_str())
}

fn remediation_workflow_trail(record: &Value) -> String {
    let mut steps = record["workflow_steps"]
        .as_array()
        .unwrap_or_else(|| panic!("missing workflow_steps in {record}"))
        .iter()
        .enumerate()
        .map(|(position, step)| {
            let index = step["index"].as_u64().unwrap_or(position as u64);
            let name = step["name"]
                .as_str()
                .unwrap_or_else(|| panic!("missing workflow step name in {step}"));
            let state = step["state"]
                .as_str()
                .unwrap_or_else(|| panic!("missing workflow step state in {step}"));
            let detail = step["detail"]
                .as_str()
                .filter(|detail| !detail.trim().is_empty());
            let updated_at = step.get("updated_at").and_then(value_to_display_string);
            (index, name, state, detail, updated_at)
        })
        .collect::<Vec<_>>();
    steps.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));

    let trail = steps
        .into_iter()
        .map(|(_index, name, state, detail, updated_at)| {
            let detail = detail
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default();
            let label = format!("{} {}{detail}", display_status(name), display_status(state));
            match updated_at {
                Some(updated_at) if !updated_at.trim().is_empty() => {
                    format!("{updated_at} {label}")
                }
                _ => label,
            }
        })
        .collect::<Vec<_>>()
        .join(" -> ");

    format!("workflow trail {trail}")
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

fn request_json(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Value {
    request_json_with_status(address, method, path, body, 200)
}

fn request_json_with_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    expected_status: u16,
) -> Value {
    let response = request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        response.status,
        expected_status,
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    json_from_bytes(&response.body)
}

fn request_text_with_status(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    expected_status: u16,
) -> String {
    let response = request(
        address,
        method,
        path,
        body.map(|raw| ("application/json", raw.as_bytes())),
        DEFAULT_BOOTSTRAP_ADMIN_TOKEN,
    );
    assert_eq!(
        response.status,
        expected_status,
        "unexpected status {} with body {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    String::from_utf8(response.body)
        .unwrap_or_else(|error| panic!("invalid utf-8 response body: {error}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> &'a str {
    if let Some(raw) = value[field].as_str() {
        return raw;
    }
    panic!("missing string field `{field}` in {value}")
}

fn required_display_string(value: &Value, field: &str) -> String {
    value_to_display_string(&value[field])
        .unwrap_or_else(|| panic!("missing displayable field `{field}` in {value}"))
}

fn find_object_by_field<'a>(items: &'a Value, field: &str, expected: &str) -> &'a Value {
    items
        .as_array()
        .unwrap_or_else(|| panic!("expected array for field search in {items}"))
        .iter()
        .find(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing object with {field}={expected} in {items}"))
}

fn value_to_display_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(raw) => Some(raw.clone()),
        Value::Number(raw) => Some(raw.to_string()),
        Value::Bool(raw) => Some(raw.to_string()),
        Value::Array(entries) => offset_datetime_array_to_rfc3339(entries),
        _ => None,
    }
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn offset_datetime_array_to_rfc3339(entries: &[Value]) -> Option<String> {
    let [
        year,
        ordinal,
        hour,
        minute,
        second,
        nanosecond,
        offset_hours,
        offset_minutes,
        offset_seconds,
    ] = entries
    else {
        return None;
    };

    let year = i32::try_from(year.as_i64()?).ok()?;
    let ordinal = u16::try_from(ordinal.as_u64()?).ok()?;
    let hour = u8::try_from(hour.as_u64()?).ok()?;
    let minute = u8::try_from(minute.as_u64()?).ok()?;
    let second = u8::try_from(second.as_u64()?).ok()?;
    let nanosecond = u32::try_from(nanosecond.as_u64()?).ok()?;
    let offset_hours = i8::try_from(offset_hours.as_i64()?).ok()?;
    let offset_minutes = i8::try_from(offset_minutes.as_i64()?).ok()?;
    let offset_seconds = i8::try_from(offset_seconds.as_i64()?).ok()?;

    let date = Date::from_ordinal_date(year, ordinal).ok()?;
    let datetime = date.with_hms_nano(hour, minute, second, nanosecond).ok()?;
    let offset = UtcOffset::from_hms(offset_hours, offset_minutes, offset_seconds).ok()?;

    datetime.assume_offset(offset).format(&Rfc3339).ok()
}

fn display_status(status: &str) -> String {
    status.replace('_', " ")
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
