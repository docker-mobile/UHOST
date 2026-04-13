use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::tempdir;
use uhost_core::{base64url_encode, sha256_hex};
use uhost_store::DocumentStore;
use uhost_types::{ChangeRequestId, OwnershipScope, ResourceMetadata};

const DEFAULT_BOOTSTRAP_ADMIN_TOKEN: &str = "integration-bootstrap-admin-token";

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
    state: String,
    metadata: ResourceMetadata,
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
fn all_in_one_end_to_end_flow() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let ingress_change_request_id = seed_governance_change_request(&state_dir, "approved");
    let config_path = temp.path().join("all-in-one.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping all_in_one_end_to_end_flow: loopback bind not permitted in this environment"
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

    let health = request_json(address, "GET", "/healthz", None);
    assert_eq!(
        health["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing status")),
        "ok"
    );
    let ready = request_json(address, "GET", "/readyz", None);
    assert_eq!(
        ready["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing readyz status")),
        "ready"
    );

    let created_user = request_json(
        address,
        "POST",
        "/identity/users",
        Some(
            r#"{"email":"alice@example.com","display_name":"Alice","password":"correct horse battery staple"}"#,
        ),
    );
    assert!(
        created_user["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .starts_with("usr_")
    );
    let bulk_users = request_json(
        address,
        "POST",
        "/identity/users/bulk",
        Some(
            r#"{"users":[{"email":"bulk-1@example.com","display_name":"Bulk One","password":"pw-1"},{"email":"bulk-2@example.com","display_name":"Bulk Two","password":"pw-2"},{"email":"bulk-1@example.com","display_name":"Bulk Duplicate","password":"pw-3"}],"fail_fast":false}"#,
        ),
    );
    assert_eq!(bulk_users["created_count"].as_u64().unwrap_or_default(), 2);
    assert_eq!(bulk_users["failed_count"].as_u64().unwrap_or_default(), 1);

    let users = request_json(address, "GET", "/identity/users", None);
    assert_eq!(
        users
            .as_array()
            .map(|items| items.len())
            .unwrap_or_default(),
        3
    );
    let alice_id = created_user["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing alice user id"))
        .to_owned();
    let bulk_one_id = find_user_id_by_email(&users, "bulk-1@example.com");
    let bulk_two_id = find_user_id_by_email(&users, "bulk-2@example.com");
    let alice_api_key = create_api_key_secret(address, &alice_id, "alice-governance-cli");
    let bulk_one_api_key = create_api_key_secret(address, &bulk_one_id, "bulk-one-governance-cli");
    let bulk_two_api_key = create_api_key_secret(address, &bulk_two_id, "bulk-two-governance-cli");
    let identity_outbox = request_json(address, "GET", "/identity/outbox", None);
    assert!(
        identity_outbox
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );

    let organization = request_json(
        address,
        "POST",
        "/tenancy/organizations",
        Some(r#"{"name":"Example Org","slug":"example-org"}"#),
    );
    let project = request_json(
        address,
        "POST",
        "/tenancy/projects",
        Some(&format!(
            r#"{{"organization_id":"{}","name":"Core","slug":"core"}}"#,
            organization["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing organization id"))
        )),
    );
    let _workload = request_json(
        address,
        "POST",
        "/control/workloads",
        Some(&format!(
            r#"{{"project_id":"{}","name":"api","kind":"container","image":"registry.local/api:1","command":["/srv/start"],"replicas":2,"priority":"standard"}}"#,
            project["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing project id"))
        )),
    );
    let control_outbox = request_json(address, "GET", "/control/outbox", None);
    assert!(
        control_outbox
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );

    let ingress_route = request_json(
        address,
        "POST",
        "/ingress/routes",
        Some(&format!(
            r#"{{"hostname":"api.example.com","protocol":"https","tls_mode":"strict_https","backends":[{{"target":"http://10.0.0.10:8080","weight":1}},{{"target":"http://10.0.0.11:8080","weight":1}}],"sticky_sessions":true,"change_request_id":"{}"}}"#,
            ingress_change_request_id
        )),
    );
    let ingress_route_id = ingress_route["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing ingress route id"));
    let ingress_eval = request_json(
        address,
        "POST",
        "/ingress/evaluate",
        Some(
            r#"{"hostname":"api.example.com","protocol":"https","client_ip":"203.0.113.2","session_key":"session-a"}"#,
        ),
    );
    assert!(
        ingress_eval["admitted"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing ingress admitted"))
    );
    let first_backend_id = ingress_eval["selected_backend_id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing selected backend id"));
    let _health_report = request_json(
        address,
        "POST",
        &format!("/ingress/routes/{ingress_route_id}/health-report"),
        Some(&format!(
            r#"{{"backend_id":"{}","healthy":false,"observed_latency_ms":18000,"message":"probe timeout"}}"#,
            first_backend_id
        )),
    );
    let _circuit_event = request_json(
        address,
        "POST",
        &format!("/ingress/routes/{ingress_route_id}/circuit-event"),
        Some(r#"{"success":false,"reason":"upstream 5xx burst"}"#),
    );
    let ingress_flow_summary = request_json(address, "GET", "/ingress/flow-audit/summary", None);
    assert!(ingress_flow_summary["total"].as_u64().unwrap_or_default() >= 1);

    let database = request_json(
        address,
        "POST",
        "/data/databases",
        Some(
            r#"{"engine":"postgres","version":"16.2","storage_gb":50,"replicas":2,"tls_required":true,"primary_region":"us-east-1"}"#,
        ),
    );
    let database_id = database["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing database id"));
    let backup = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/backups"),
        Some(r#"{"kind":"full","reason":"integration-checkpoint"}"#),
    );
    let backup_id = backup["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing backup id"));
    let _restore = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/restore"),
        Some(&format!(
            r#"{{"backup_id":"{}","reason":"integration-restore-check"}}"#,
            backup_id
        )),
    );
    let failover = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/failover"),
        Some(r#"{"target_replica_id":"replica-2","reason":"integration-failover-check"}"#),
    );
    assert_eq!(
        failover["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failover state")),
        "completed"
    );
    let maintenance = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/maintenance"),
        Some(r#"{"enabled":true,"reason":"maintenance window"}"#),
    );
    assert!(
        maintenance["maintenance_mode"]
            .as_bool()
            .unwrap_or_default()
    );
    let _maintenance_exit = request_json(
        address,
        "POST",
        &format!("/data/databases/{database_id}/maintenance"),
        Some(r#"{"enabled":false}"#),
    );

    let bucket = request_json(
        address,
        "POST",
        "/storage/buckets",
        Some(r#"{"name":"media","owner_id":"prj_demo"}"#),
    );
    let upload = request_json(
        address,
        "POST",
        "/storage/uploads",
        Some(&format!(
            r#"{{"bucket_id":"{}","object_key":"hello.txt"}}"#,
            bucket["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing bucket id"))
        )),
    );
    let upload_id = upload["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing upload id"));
    let part = request(
        address,
        "PUT",
        &format!("/storage/uploads/{upload_id}/parts/1"),
        Some(("application/octet-stream", b"hello world")),
    );
    assert_eq!(part.status, 200);
    let completed = request_json(
        address,
        "POST",
        &format!("/storage/uploads/{upload_id}/complete"),
        Some("{}"),
    );
    let object_digest = completed["object_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("missing object digest"));
    let object = request(
        address,
        "GET",
        &format!("/storage/objects/{object_digest}"),
        None,
    );
    assert_eq!(object.status, 200);
    assert_eq!(object.body, b"hello world");

    let _egress_rule = request_json(
        address,
        "POST",
        "/netsec/egress-rules",
        Some(
            r#"{"target_kind":"cidr","target_value":"10.0.0.0/8","action":"allow","reason":"allow private destinations"}"#,
        ),
    );
    let _netsec_policy = request_json(
        address,
        "POST",
        "/netsec/policies",
        Some(
            r#"{"name":"backend-egress","selector":{"tier":"backend"},"default_action":"deny","mtls_mode":"strict","rules":[{"priority":1,"action":"allow","direction":"egress","protocol":"tcp","cidr":"10.0.0.0/8","port_start":443,"port_end":443,"require_identity":true}]}"#,
        ),
    );
    let _netsec_identity = request_json(
        address,
        "POST",
        "/netsec/service-identities",
        Some(
            r#"{"subject":"svc:api","mtls_cert_fingerprint":"sha256:api-cert","labels":{"tier":"backend"},"allowed_private_networks":[]}"#,
        ),
    );
    let decision = request_json(
        address,
        "POST",
        "/netsec/policy-verify",
        Some(
            r#"{"source_identity":"svc:api","destination":"10.1.2.3","protocol":"tcp","port":443,"labels":{"tier":"backend"}}"#,
        ),
    );
    assert_eq!(
        decision["verdict"]
            .as_str()
            .unwrap_or_else(|| panic!("missing netsec verdict")),
        "allow"
    );
    let abuse_signal = request_json(
        address,
        "POST",
        "/abuse/signals",
        Some(
            r#"{"subject_kind":"service_identity","subject":"svc:api","signal_kind":"api_abuse","severity":"high","confidence_bps":9500,"source_service":"ingress","reason":"rate anomaly exceeded threshold","evidence_refs":["flow:abc123"]}"#,
        ),
    );
    assert!(
        abuse_signal
            .get("signal")
            .and_then(|signal| signal.get("id"))
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    let abuse_case = request_json(
        address,
        "POST",
        "/abuse/cases",
        Some(&format!(
            r#"{{"subject_kind":"service_identity","subject":"svc:api","reason":"contain high-risk service identity","priority":"high","signal_ids":["{}"],"evidence_refs":["ticket:INC-42"]}}"#,
            abuse_signal["signal"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing abuse signal id"))
        )),
    );
    let abuse_case_id = abuse_case["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing abuse case id"));
    let reviewed_case = request_json(
        address,
        "POST",
        &format!("/abuse/cases/{abuse_case_id}/review"),
        Some(
            r#"{"action":"quarantine","reviewer":"sec.manager","note":"isolating while triage runs","escalate":true}"#,
        ),
    );
    assert_eq!(
        reviewed_case["case"]["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing reviewed abuse case status")),
        "quarantined"
    );

    let blocked_decision = request_json(
        address,
        "POST",
        "/netsec/policy-verify",
        Some(
            r#"{"source_identity":"svc:api","destination":"10.1.2.3","protocol":"tcp","port":443,"labels":{"tier":"backend"}}"#,
        ),
    );
    assert_eq!(
        blocked_decision["verdict"]
            .as_str()
            .unwrap_or_else(|| panic!("missing blocked netsec verdict")),
        "deny"
    );

    let appeal = request_json(
        address,
        "POST",
        "/abuse/appeals",
        Some(&format!(
            r#"{{"case_id":"{}","requested_by":"tenant.owner","reason":"false positive during load test"}}"#,
            abuse_case_id
        )),
    );
    let appeal_id = appeal["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing appeal id"));
    let _appeal_review = request_json(
        address,
        "POST",
        &format!("/abuse/appeals/{appeal_id}/review"),
        Some(r#"{"reviewer":"sec.director","action":"accept","note":"release and monitor"}"#),
    );
    let risk = request_json(
        address,
        "POST",
        "/abuse/evaluate",
        Some(r#"{"subject_kind":"service_identity","subject":"svc:api"}"#),
    );
    assert!(
        risk["active_case_ids"]
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );

    let recovered_decision = request_json(
        address,
        "POST",
        "/netsec/policy-verify",
        Some(
            r#"{"source_identity":"svc:api","destination":"10.1.2.3","protocol":"tcp","port":443,"labels":{"tier":"backend"}}"#,
        ),
    );
    assert_eq!(
        recovered_decision["verdict"]
            .as_str()
            .unwrap_or_else(|| panic!("missing recovered netsec verdict")),
        "allow"
    );
    let deny_flow_audit = request_json(
        address,
        "GET",
        "/netsec/flow-audit?verdict=deny&source_identity=svc%3Aapi&limit=5",
        None,
    );
    assert!(
        deny_flow_audit
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let flow_audit_summary = request_json(
        address,
        "GET",
        "/netsec/flow-audit/summary?source_identity=svc%3Aapi",
        None,
    );
    assert!(flow_audit_summary["total"].as_u64().unwrap_or_default() >= 1);
    assert!(flow_audit_summary["deny"].as_u64().unwrap_or_default() >= 1);

    let zone = request_json(
        address,
        "POST",
        "/dns/zones",
        Some(r#"{"domain":"example.com"}"#),
    );
    let verified_zone = request_json(
        address,
        "POST",
        &format!(
            "/dns/zones/{}/verify",
            zone["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing zone id"))
        ),
        None,
    );
    assert!(
        verified_zone["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing zone verification state"))
    );
    let mail_domain = request_json(
        address,
        "POST",
        "/mail/domains",
        Some(&format!(
            r#"{{"domain":"example.com","zone_id":"{}"}}"#,
            zone["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing zone id"))
        )),
    );
    let auth_check = request_json(
        address,
        "POST",
        &format!(
            "/mail/domains/{}/verify-auth",
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        ),
        Some(r#"{"reconcile_missing":true,"ttl":120}"#),
    );
    assert!(
        !auth_check["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing auth verification status"))
    );
    assert!(
        auth_check["reconciled_records"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );
    let dns_provider_tasks = request_json(address, "GET", "/dns/provider-tasks", None);
    let deliverable_task_ids = dns_provider_tasks
        .as_array()
        .unwrap_or_else(|| panic!("provider tasks response should be an array"))
        .iter()
        .filter(|task| {
            task["action"].as_str().unwrap_or_default() == "upsert_record"
                && task["status"].as_str().unwrap_or_default() != "delivered"
        })
        .filter_map(|task| task["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(!deliverable_task_ids.is_empty());
    for task_id in deliverable_task_ids {
        let _ = request_json(
            address,
            "POST",
            &format!("/dns/provider-tasks/{task_id}/deliver"),
            None,
        );
    }
    let verified_auth_check = request_json(
        address,
        "POST",
        &format!(
            "/mail/domains/{}/verify-auth",
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        ),
        Some("{}"),
    );
    assert!(
        verified_auth_check["verified"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing delivered auth verification status"))
    );
    let filtered_auth_records = request_json(
        address,
        "GET",
        &format!(
            "/mail/auth-records?domain_id={}",
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        ),
        None,
    );
    assert_eq!(
        filtered_auth_records
            .as_array()
            .map(|items| items.len())
            .unwrap_or_default(),
        1
    );
    assert!(
        filtered_auth_records[0]["required_records"]
            .as_array()
            .map(|records| records.iter().all(|entry| {
                entry
                    .get("present")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            }))
            .unwrap_or(false)
    );
    let _relay_route = request_json(
        address,
        "POST",
        "/mail/relay-routes",
        Some(&format!(
            r#"{{"domain_id":"{}","destination":"smtp.relay.local:587","auth_mode":"mtls"}}"#,
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        )),
    );
    let mail_quarantine = request_json(
        address,
        "POST",
        "/abuse/quarantines",
        Some(
            r#"{"subject_kind":"mail_domain","subject":"example.com","reason":"mail abuse drill","deny_network":false,"deny_mail_relay":true}"#,
        ),
    );
    let blocked_mail_message = request_json(
        address,
        "POST",
        "/mail/message-events",
        Some(&format!(
            r#"{{"domain_id":"{}","direction":"outbound","from":"alerts@example.com","to":"ops@example.net","subject":"blocked","max_attempts":1}}"#,
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        )),
    );
    let blocked_message_id = blocked_mail_message["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing blocked message id"));
    let blocked_dispatch = request_json(
        address,
        "POST",
        &format!("/mail/message-events/{blocked_message_id}/dispatch"),
        Some("{}"),
    );
    assert_eq!(
        blocked_dispatch["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing blocked dispatch state")),
        "dead_lettered"
    );
    let blocked_dead_letters = request_json(address, "GET", "/mail/dead-letters", None);
    let blocked_dead_letter_id = blocked_dead_letters
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|item| {
                let message_id = item.get("message_id").and_then(serde_json::Value::as_str)?;
                if message_id == blocked_message_id {
                    item.get("id").and_then(serde_json::Value::as_str)
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| panic!("missing dead letter for blocked mail message"));
    let _release_mail_quarantine = request_json(
        address,
        "POST",
        &format!(
            "/abuse/quarantines/{}/release",
            mail_quarantine["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail quarantine id"))
        ),
        Some(r#"{"reason":"mail remediation complete"}"#),
    );
    let replayed_blocked_message = request_json(
        address,
        "POST",
        &format!("/mail/dead-letters/{blocked_dead_letter_id}/replay"),
        Some(r#"{"reason":"quarantine released"}"#),
    );
    assert_eq!(
        replayed_blocked_message["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing replayed blocked mail state")),
        "queued"
    );
    let delivered_after_release = request_json(
        address,
        "POST",
        &format!("/mail/message-events/{blocked_message_id}/dispatch"),
        Some("{}"),
    );
    assert_eq!(
        delivered_after_release["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing delivered-after-release state")),
        "delivered"
    );

    let dns_provider_tasks = request_json(address, "GET", "/dns/provider-tasks", None);
    assert!(
        dns_provider_tasks
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let message = request_json(
        address,
        "POST",
        "/mail/message-events",
        Some(&format!(
            r#"{{"domain_id":"{}","direction":"outbound","from":"alerts@example.com","to":"ops@example.net","subject":"hello"}}"#,
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        )),
    );
    let _dispatched = request_json(
        address,
        "POST",
        &format!(
            "/mail/message-events/{}/dispatch",
            message["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing message id"))
        ),
        Some("{}"),
    );
    let dead_letter_candidate = request_json(
        address,
        "POST",
        "/mail/message-events",
        Some(&format!(
            r#"{{"domain_id":"{}","direction":"inbound","from":"alerts@example.com","to":"nobody@example.com","subject":"dead-letter","max_attempts":1}}"#,
            mail_domain["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing mail domain id"))
        )),
    );
    let mail_dispatch_summary =
        request_json(address, "POST", "/mail/dispatch", Some(r#"{"limit":50}"#));
    assert!(
        mail_dispatch_summary["dead_lettered"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );
    let mail_dead_letters = request_json(address, "GET", "/mail/dead-letters", None);
    assert!(
        mail_dead_letters
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let replayed_mail = request_json(
        address,
        "POST",
        &format!(
            "/mail/dead-letters/{}/replay",
            mail_dead_letters
                .as_array()
                .and_then(|items| {
                    items.iter().find_map(|item| {
                        let message_id =
                            item.get("message_id").and_then(serde_json::Value::as_str)?;
                        if message_id
                            == dead_letter_candidate["id"]
                                .as_str()
                                .unwrap_or_else(|| panic!("missing dead-letter candidate id"))
                        {
                            item.get("id").and_then(serde_json::Value::as_str)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| panic!("missing mail dead letter id"))
        ),
        Some(r#"{"reason":"drill replay"}"#),
    );
    assert_eq!(
        replayed_mail["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing replayed mail state")),
        "queued"
    );
    let notify_webhook = request_json(
        address,
        "POST",
        "/notify/webhook-endpoints",
        Some(
            r#"{"name":"ops-webhook","url":"https://hooks.example/ops","signing_secret":"s3cr3t","max_attempts":3,"timeout_ms":5000,"backoff_base_seconds":2}"#,
        ),
    );
    let _notify_template = request_json(
        address,
        "POST",
        "/notify/templates",
        Some(
            r#"{"name":"incident","channel":"webhook","locale":"en-us","subject_template":"Incident {{id}}","body_template":"Service {{service}} degraded"}"#,
        ),
    );
    let _notify_pref = request_json(
        address,
        "POST",
        "/notify/preferences",
        Some(
            r#"{"subject_key":"tenant:demo","channel":"webhook","enabled":true,"digest_mode":"immediate","locale":"en-us"}"#,
        ),
    );
    let _notify_alert_route = request_json(
        address,
        "POST",
        "/notify/alert-routes",
        Some(&format!(
            r#"{{"name":"ops-critical","min_severity":"critical","channel":"webhook","destination":"https://hooks.example/ops","subject_key":"tenant:demo","webhook_endpoint_id":"{}","cooldown_seconds":600}}"#,
            notify_webhook["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing notify webhook id"))
        )),
    );
    let alert_trigger = request_json(
        address,
        "POST",
        "/notify/alerts/trigger",
        Some(
            r#"{"severity":"critical","title":"DB failover","body":"leader lost","subject_key":"tenant:demo","dedupe_key":"db-failover-1","labels":{"service":"postgres"}}"#,
        ),
    );
    assert!(
        alert_trigger["routed"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing routed count"))
            >= 1
    );
    let alert_trigger_dedupe = request_json(
        address,
        "POST",
        "/notify/alerts/trigger",
        Some(
            r#"{"severity":"critical","title":"DB failover","body":"leader lost","subject_key":"tenant:demo","dedupe_key":"db-failover-1","labels":{"service":"postgres"}}"#,
        ),
    );
    assert!(
        alert_trigger_dedupe["suppressed_by_cooldown"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing suppressed_by_cooldown count"))
            >= 1
    );
    let notify_message = request_json(
        address,
        "POST",
        "/notify/messages",
        Some(&format!(
            r#"{{"channel":"webhook","destination":"https://hooks.example/ops","subject":"","body":"","template_id":"{}","template_vars":{{"id":"INC-42","service":"api"}},"subject_key":"tenant:demo","webhook_endpoint_id":"{}"}}"#,
            _notify_template["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing notify template id")),
            notify_webhook["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing notify webhook id"))
        )),
    );
    let _notify_dispatch =
        request_json(address, "POST", "/notify/dispatch", Some(r#"{"limit":50}"#));
    let notify_messages = request_json(address, "GET", "/notify/messages", None);
    assert!(
        notify_messages
            .as_array()
            .map(|items| {
                items.iter().any(|item| {
                    item.get("id").and_then(serde_json::Value::as_str)
                        == notify_message["id"].as_str()
                })
            })
            .unwrap_or(false)
    );

    let change = request_json_with_bearer_token(
        address,
        "POST",
        "/governance/change-requests",
        Some(&format!(
            r#"{{"title":"Rotate key","change_type":"security_change","requested_by":"user:{alice_id}"}}"#
        )),
        &alice_api_key,
    );
    let change_id = change["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing change request id"))
        .to_owned();
    let _approved = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/governance/change-requests/{change_id}/approve"),
        Some(&format!(
            r#"{{"approver":"user:{bulk_one_id}","comment":"approved"}}"#
        )),
        &bulk_one_api_key,
    );
    let _approved_second = request_json_with_bearer_token(
        address,
        "POST",
        &format!("/governance/change-requests/{change_id}/approve"),
        Some(&format!(
            r#"{{"approver":"user:{bulk_two_id}","comment":"approved"}}"#
        )),
        &bulk_two_api_key,
    );
    let _applied = request_json(
        address,
        "POST",
        &format!("/governance/change-requests/{change_id}/apply"),
        Some(r#"{"executor":"bootstrap_admin","note":"window approved"}"#),
    );
    let _retention_policy = request_json(
        address,
        "POST",
        "/governance/retention-policies",
        Some(
            r#"{"name":"object-default","resource_kind":"object","retain_days":7,"hard_delete_after_days":30,"residency_tags":["us"]}"#,
        ),
    );
    let retention = request_json(
        address,
        "POST",
        "/governance/retention-evaluate",
        Some(
            r#"{"subject_kind":"tenant","subject_id":"tnt_demo","resource_kind":"object","residency_tag":"us","age_days":40}"#,
        ),
    );
    assert!(
        retention["can_delete"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing retention can_delete"))
    );
    let checkpoints = request_json(address, "GET", "/governance/audit-checkpoints", None);
    assert!(
        checkpoints
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let integrity = request_json(address, "GET", "/governance/audit-integrity", None);
    assert!(
        integrity["valid"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing governance integrity validity"))
    );

    let active = request_json(
        address,
        "POST",
        "/scheduler/nodes",
        Some(r#"{"region":"us-east","cpu_millis":4000,"memory_mb":8192}"#),
    );
    let passive = request_json(
        address,
        "POST",
        "/scheduler/nodes",
        Some(r#"{"region":"us-east","cpu_millis":4000,"memory_mb":8192}"#),
    );
    let _role_active = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(&format!(
            r#"{{"node_id":"{}","role":"active","healthy":true}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let _role_passive = request_json(
        address,
        "POST",
        "/ha/roles",
        Some(&format!(
            r#"{{"node_id":"{}","role":"passive","healthy":true}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let _replication = request_json(
        address,
        "POST",
        "/ha/replication-status",
        Some(&format!(
            r#"{{"source_node_id":"{}","target_node_id":"{}","lag_seconds":2,"healthy":true}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let _quorum_active = request_json(
        address,
        "POST",
        "/ha/regional-quorum",
        Some(&format!(
            r#"{{"region":"us-east-1","node_id":"{}","role":"leader","term":5,"vote_weight":1,"healthy":true,"replicated_log_index":1200,"applied_log_index":1200,"lease_seconds":90}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let _quorum_passive = request_json(
        address,
        "POST",
        "/ha/regional-quorum",
        Some(&format!(
            r#"{{"region":"us-east-1","node_id":"{}","role":"follower","term":5,"vote_weight":1,"healthy":true,"replicated_log_index":1199,"applied_log_index":1199,"lease_seconds":90}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let quorum_summary = request_json(address, "GET", "/ha/quorum-summary", None);
    assert!(
        quorum_summary["quorum_satisfied"]
            .as_bool()
            .unwrap_or(false)
    );
    let _consensus_entry = request_json(
        address,
        "POST",
        "/ha/consensus-log",
        Some(&format!(
            r#"{{"region":"us-east-1","term":5,"log_index":1,"operation_kind":"failover_plan","payload_hash":"feedface","leader_node_id":"{}"}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let preflight_blocked_on_consensus = request_json(
        address,
        "POST",
        "/ha/failover-preflight",
        Some(&format!(
            r#"{{"from_node_id":"{}","to_node_id":"{}","max_replication_lag_seconds":30}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    assert!(
        !preflight_blocked_on_consensus["allowed"]
            .as_bool()
            .unwrap_or(true)
    );
    assert!(
        preflight_blocked_on_consensus["consensus_uncommitted_entries"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    let _shipment_applied = request_json(
        address,
        "POST",
        "/ha/replication-shipping",
        Some(&format!(
            r#"{{"region":"us-east-1","log_index":1,"term":5,"source_node_id":"{}","target_node_id":"{}","status":"applied"}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let failover_preflight = request_json(
        address,
        "POST",
        "/ha/failover-preflight",
        Some(&format!(
            r#"{{"from_node_id":"{}","to_node_id":"{}","max_replication_lag_seconds":30}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    assert!(failover_preflight["allowed"].as_bool().unwrap_or(false));
    let failover = request_json(
        address,
        "POST",
        "/ha/failover",
        Some(&format!(
            r#"{{"from_node_id":"{}","to_node_id":"{}","reason":"test failover","max_replication_lag_seconds":30}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    assert_eq!(
        failover["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failover state")),
        "completed"
    );
    let _reverse_replication = request_json(
        address,
        "POST",
        "/ha/replication-status",
        Some(&format!(
            r#"{{"source_node_id":"{}","target_node_id":"{}","lag_seconds":3,"healthy":true}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id")),
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let evacuation = request_json(
        address,
        "POST",
        "/ha/evacuation",
        Some(&format!(
            r#"{{"from_node_id":"{}","to_node_id":"{}","reason":"regional evacuation test","max_replication_lag_seconds":30}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id")),
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    assert_eq!(
        evacuation["operation_kind"]
            .as_str()
            .unwrap_or_else(|| panic!("missing evacuation operation kind")),
        "evacuation"
    );

    let _migration = request_json(
        address,
        "POST",
        "/lifecycle/migrations/apply",
        Some(&format!(
            r#"{{"scope":"schema","from_version":1,"to_version":2,"name":"lifecycle_extension_registry","checksum":"eae471336f91281a3587df5311b9ccd1ac523849fd89fb20053d3d2a444450f5","compatibility_window_days":30,"change_request_id":"{}"}}"#,
            change["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing change request id"))
        )),
    );
    let _maintenance = request_json(
        address,
        "POST",
        "/lifecycle/maintenance",
        Some(&format!(
            r#"{{"service":"scheduler","enabled":true,"reason":"migration window","change_request_id":"{}"}}"#,
            change["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing change request id"))
        )),
    );
    let rollout = request_json(
        address,
        "POST",
        "/lifecycle/rollout-plans",
        Some(
            r#"{"service":"scheduler","channel":"canary","canary_steps":[10,50,100],"compatibility_window_days":7}"#,
        ),
    );
    let rollout_id = rollout["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rollout id"));
    let started_rollout = request_json(
        address,
        "POST",
        &format!("/lifecycle/rollout-plans/{rollout_id}/start"),
        Some(r#"{"reason":"kickoff"}"#),
    );
    assert_eq!(
        started_rollout["phase"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rollout phase after start")),
        "in_progress"
    );
    let paused_rollout = request_json(
        address,
        "POST",
        &format!("/lifecycle/rollout-plans/{rollout_id}/pause"),
        Some(r#"{"reason":"hold for metric check"}"#),
    );
    assert_eq!(
        paused_rollout["phase"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rollout phase after pause")),
        "paused"
    );
    let resumed_rollout = request_json(
        address,
        "POST",
        &format!("/lifecycle/rollout-plans/{rollout_id}/resume"),
        Some(r#"{}"#),
    );
    assert_eq!(
        resumed_rollout["phase"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rollout phase after resume")),
        "in_progress"
    );
    let advanced_rollout = request_json(
        address,
        "POST",
        &format!("/lifecycle/rollout-plans/{rollout_id}/advance"),
        Some(r#"{"reason":"progress canary"}"#),
    );
    assert_eq!(
        advanced_rollout["current_traffic_percent"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing rollout traffic percent")),
        50
    );
    let rolled_back_rollout = request_json(
        address,
        "POST",
        &format!("/lifecycle/rollout-plans/{rollout_id}/rollback"),
        Some(r#"{"reason":"synthetic rollback drill"}"#),
    );
    assert_eq!(
        rolled_back_rollout["phase"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rollout phase after rollback")),
        "rolled_back"
    );
    let integrity = request_json(address, "GET", "/lifecycle/integrity", None);
    assert!(
        integrity["valid"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing lifecycle integrity status"))
    );
    let _dead_letter = request_json(
        address,
        "POST",
        "/lifecycle/dead-letters",
        Some(
            r#"{"topic":"control.events.v1","payload":{"id":"evt1"},"error":"sink unavailable","attempts":3}"#,
        ),
    );
    let repair = request_json(
        address,
        "POST",
        "/lifecycle/dead-letter/replay",
        Some(r#"{"limit":100}"#),
    );
    assert_eq!(
        repair["job_type"]
            .as_str()
            .unwrap_or_else(|| panic!("missing repair job type")),
        "dead_letter_replay"
    );
    assert_eq!(
        repair["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing repair job status")),
        "pending_confirmation"
    );
    let repair_id = repair["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing repair job id"));
    let dead_letters = request_json(address, "GET", "/lifecycle/dead-letters", None);
    let dead_letter = dead_letters
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or_else(|| panic!("missing lifecycle dead letter after repair enqueue"));
    assert!(
        !dead_letter["replayed"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing lifecycle dead-letter replay state"))
    );
    assert_eq!(
        dead_letter["repair_job_id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing lifecycle dead-letter repair job id")),
        repair_id
    );
    let confirmed_repair = request_json(
        address,
        "POST",
        &format!("/lifecycle/repair-jobs/{repair_id}/confirm"),
        Some(r#"{"success":true,"detail":"downstream replay verified"}"#),
    );
    assert_eq!(
        confirmed_repair["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing confirmed repair job status")),
        "completed"
    );
    let replayed_dead_letters = request_json(address, "GET", "/lifecycle/dead-letters", None);
    assert!(
        replayed_dead_letters
            .as_array()
            .and_then(|items| items.first())
            .and_then(|dead_letter| dead_letter["replayed"].as_bool())
            .unwrap_or_else(|| panic!("missing confirmed lifecycle dead-letter replay state"))
    );

    // This integration test models a Linux accelerator node explicitly so the
    // portability and live-migration contract stays stable across CI hosts.
    let uvm_accelerator_backends = r#"["kvm"]"#;
    let uvm_guest_architecture = "x86_64";
    let uvm_capability = request_json(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(&format!(
            r#"{{"node_id":"{}","host_platform":"linux","architecture":"{}","accelerator_backends":{},"max_vcpu":64,"max_memory_mb":131072,"numa_nodes":2,"supports_secure_boot":true,"supports_live_migration":true,"supports_pci_passthrough":true}}"#,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            uvm_guest_architecture,
            uvm_accelerator_backends
        )),
    );
    let uvm_capability_passive = request_json(
        address,
        "POST",
        "/uvm/node-capabilities",
        Some(&format!(
            r#"{{"node_id":"{}","host_platform":"linux","architecture":"{}","accelerator_backends":{},"max_vcpu":64,"max_memory_mb":131072,"numa_nodes":2,"supports_secure_boot":true,"supports_live_migration":true,"supports_pci_passthrough":true}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id")),
            uvm_guest_architecture,
            uvm_accelerator_backends
        )),
    );
    let uvm_device_profile = request_json(
        address,
        "POST",
        "/uvm/device-profiles",
        Some(
            r#"{"name":"general-x86","legacy_devices":["pit","rtc","ioapic"],"modern_devices":["virtio-net","virtio-block","virtio-rng"],"passthrough_enabled":false}"#,
        ),
    );
    let uvm_image = request_json(
        address,
        "POST",
        "/uvm/images",
        Some(
            r#"{"source_kind":"qcow2","source_uri":"registry://images/linux-general.qcow2","guest_os":"linux","architecture":"x86_64","signature_attestation":"sig:v1","provenance_attestation":"prov:v1"}"#,
        ),
    );
    let uvm_image_id = uvm_image["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing uvm image id"));
    let _verified_image = request_json(
        address,
        "POST",
        &format!("/uvm/images/{uvm_image_id}/verify"),
        Some(r#"{"require_signature":true,"require_provenance":true}"#),
    );
    let _promoted_image = request_json(
        address,
        "POST",
        &format!("/uvm/images/{uvm_image_id}/promote"),
        Some(r#"{"channel":"stable"}"#),
    );
    let uvm_template = request_json(
        address,
        "POST",
        "/uvm/templates",
        Some(&format!(
            r#"{{"name":"x86-general","architecture":"x86_64","vcpu":4,"memory_mb":8192,"cpu_topology":"balanced","numa_policy":"prefer_local","firmware_profile":"uefi_secure","device_profile":"{}","migration_policy":"best_effort_live","apple_guest_allowed":false}}"#,
            uvm_device_profile["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm device profile id"))
        )),
    );
    let uvm_instance = request_json(
        address,
        "POST",
        "/uvm/instances",
        Some(&format!(
            r#"{{"project_id":"{}","name":"api-vm","template_id":"{}","boot_image_id":"{}","guest_os":"linux","host_node_id":"{}"}}"#,
            project["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing project id")),
            uvm_template["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm template id")),
            uvm_image_id,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let uvm_instance_id = uvm_instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing uvm instance id"));
    let started_instance = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/start"),
        Some("{}"),
    );
    assert_eq!(
        started_instance["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing uvm started state")),
        "running"
    );
    let runtime_preflight = request_json(
        address,
        "POST",
        "/uvm/runtime/preflight",
        Some(&format!(
            r#"{{"capability_id":"{}","guest_architecture":"x86_64","guest_os":"linux","vcpu":4,"memory_mb":8192,"cpu_topology":"balanced","numa_policy":"preferred_local","migration_policy":"best_effort_live","require_secure_boot":true,"requires_live_migration":true,"apple_guest_approved":false}}"#,
            uvm_capability["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm capability id"))
        )),
    );
    assert!(
        runtime_preflight["legal_allowed"]
            .as_bool()
            .unwrap_or(false)
    );
    assert!(
        runtime_preflight["placement_admitted"]
            .as_bool()
            .unwrap_or(false)
    );
    assert!(
        runtime_preflight["migration_recommended_checkpoint_kind"]
            .as_str()
            .is_some_and(|value| value == "live_precopy")
    );
    let runtime_session = request_json(
        address,
        "POST",
        "/uvm/runtime/instances",
        Some(&format!(
            r#"{{"instance_id":"{}","node_id":"{}","capability_id":"{}","guest_architecture":"x86_64","guest_os":"linux","disk_image":"object://images/linux-general.qcow2","vcpu":4,"memory_mb":8192,"firmware_profile":"uefi_secure","cpu_topology":"balanced","numa_policy":"preferred_local","migration_policy":"best_effort_live","require_secure_boot":true,"requires_live_migration":true,"isolation_profile":"cgroup_v2","restart_policy":"on-failure","max_restarts":4,"apple_guest_approved":false}}"#,
            uvm_instance_id,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id")),
            uvm_capability["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm capability id"))
        )),
    );
    assert_eq!(
        runtime_session["planned_migration_checkpoint_kind"]
            .as_str()
            .unwrap_or_else(|| panic!("missing planned checkpoint kind")),
        "live_precopy"
    );
    assert!(
        runtime_session["planned_pinned_numa_nodes"]
            .as_array()
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    );
    let runtime_session_id = runtime_session["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing runtime session id"));
    let started_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/start"),
        Some("{}"),
    );
    assert_eq!(
        started_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime started state")),
        "running"
    );
    let runtime_checkpoint = request_json(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some(&format!(
            r#"{{"runtime_session_id":"{}","kind":"crash_consistent","checkpoint_uri":"object://checkpoints/uvm/runtime-c1","memory_bitmap_hash":"a11ce","disk_generation":11}}"#,
            runtime_session_id
        )),
    );
    assert!(
        runtime_checkpoint["envelope_digest"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    let _failed_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/mark-failed"),
        Some(r#"{"error":"synthetic failure for recovery drill"}"#),
    );
    let recovering_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/recover"),
        Some(r#"{"reason":"drill"}"#),
    );
    assert_eq!(
        recovering_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime recovering state")),
        "recovering"
    );
    let recovered_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/recover-complete"),
        Some("{}"),
    );
    assert_eq!(
        recovered_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime recovered state")),
        "running"
    );
    let stopped_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/stop"),
        Some("{}"),
    );
    assert_eq!(
        stopped_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime stopped state")),
        "stopped"
    );
    let stopped_cross_node_checkpoint = request(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some((
            "application/json",
            format!(
                r#"{{"runtime_session_id":"{}","kind":"crash_consistent","checkpoint_uri":"object://checkpoints/uvm/runtime-stopped-cross","memory_bitmap_hash":"d00d","disk_generation":13,"target_node_id":"{}"}}"#,
                runtime_session_id,
                passive["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing passive node id"))
            )
            .as_bytes(),
        )),
    );
    assert_eq!(stopped_cross_node_checkpoint.status, 409);
    let restarted_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/start"),
        Some("{}"),
    );
    assert_eq!(
        restarted_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime restarted state")),
        "running"
    );
    let same_node_migration = request(
        address,
        "POST",
        "/uvm/runtime/migrations",
        Some((
            "application/json",
            format!(
                r#"{{"runtime_session_id":"{}","to_node_id":"{}","target_capability_id":"{}","kind":"live_precopy","checkpoint_uri":"object://checkpoints/uvm/runtime-same-node","memory_bitmap_hash":"b16b00b5","disk_generation":12,"reason":"same-node should reject"}}"#,
                runtime_session_id,
                active["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing active node id")),
                uvm_capability["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing uvm capability id"))
            )
            .as_bytes(),
        )),
    );
    assert_eq!(same_node_migration.status, 409);
    let runtime_migration_preflight = request_json(
        address,
        "POST",
        "/uvm/runtime/migrations/preflight",
        Some(&format!(
            r#"{{"runtime_session_id":"{}","to_node_id":"{}","target_capability_id":"{}","require_secure_boot":true,"migration_max_downtime_ms":500}}"#,
            runtime_session_id,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id")),
            uvm_capability_passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive capability id"))
        )),
    );
    assert!(
        runtime_migration_preflight["legal_allowed"]
            .as_bool()
            .unwrap_or(false)
    );
    assert!(
        runtime_migration_preflight["migration_recommended_checkpoint_kind"]
            .as_str()
            .is_some_and(|value| value == "live_precopy")
    );
    let runtime_migration = request_json(
        address,
        "POST",
        "/uvm/runtime/migrations",
        Some(&format!(
            r#"{{"runtime_session_id":"{}","to_node_id":"{}","target_capability_id":"{}","kind":"live_precopy","checkpoint_uri":"object://checkpoints/uvm/runtime-live-1","memory_bitmap_hash":"b16b00b5","disk_generation":12,"reason":"ha drill"}}"#,
            runtime_session_id,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id")),
            uvm_capability_passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive capability id"))
        )),
    );
    let runtime_migration_id = runtime_migration["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing runtime migration id"));
    let duplicate_migration = request(
        address,
        "POST",
        "/uvm/runtime/migrations",
        Some((
            "application/json",
            format!(
                r#"{{"runtime_session_id":"{}","to_node_id":"{}","target_capability_id":"{}","kind":"live_precopy","checkpoint_uri":"object://checkpoints/uvm/runtime-live-duplicate","memory_bitmap_hash":"b16b00b5","disk_generation":12,"reason":"duplicate should reject"}}"#,
                runtime_session_id,
                passive["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing passive node id")),
                uvm_capability_passive["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing passive capability id"))
            )
            .as_bytes(),
        )),
    );
    assert_eq!(duplicate_migration.status, 409);
    let committed_runtime_migration = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/migrations/{runtime_migration_id}/commit"),
        Some("{}"),
    );
    assert_eq!(
        committed_runtime_migration["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing committed migration state")),
        "committed"
    );
    let stopped_runtime = request_json(
        address,
        "POST",
        &format!("/uvm/runtime/instances/{runtime_session_id}/stop"),
        Some("{}"),
    );
    assert_eq!(
        stopped_runtime["state"]
            .as_str()
            .unwrap_or_else(|| panic!("missing runtime stopped state")),
        "stopped"
    );
    let local_checkpoint_after_migration = request(
        address,
        "POST",
        "/uvm/runtime/checkpoints",
        Some((
            "application/json",
            format!(
                r#"{{"runtime_session_id":"{}","kind":"crash_consistent","checkpoint_uri":"object://checkpoints/uvm/runtime-cross-node","memory_bitmap_hash":"c0ffee","disk_generation":13,"target_node_id":"{}"}}"#,
                runtime_session_id,
                passive["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing passive node id"))
            )
            .as_bytes(),
        )),
    );
    assert_eq!(local_checkpoint_after_migration.status, 201);
    let uvm_snapshot = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/snapshot"),
        Some(r#"{"name":"pre-deploy","crash_consistent":true}"#),
    );
    let uvm_snapshot_repeat = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/snapshot"),
        Some(r#"{"name":"pre-deploy","crash_consistent":true}"#),
    );
    assert_eq!(
        uvm_snapshot_repeat["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing uvm snapshot repeat id")),
        uvm_snapshot["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing uvm snapshot id"))
    );
    let uvm_snapshot_conflict = request(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/snapshot"),
        Some((
            "application/json",
            br#"{"name":"pre-deploy","crash_consistent":false}"#,
        )),
    );
    assert_eq!(uvm_snapshot_conflict.status, 409);
    let _uvm_migration = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/migrate"),
        Some(&format!(
            r#"{{"to_node_id":"{}","reason":"rebalance test"}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let _same_node_migration = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/migrate"),
        Some(&format!(
            r#"{{"to_node_id":"{}","reason":"same-node idempotency"}}"#,
            passive["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing passive node id"))
        )),
    );
    let uvm_instance_other = request_json(
        address,
        "POST",
        "/uvm/instances",
        Some(&format!(
            r#"{{"project_id":"{}","name":"api-vm-2","template_id":"{}","boot_image_id":"{}","guest_os":"linux","host_node_id":"{}"}}"#,
            project["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing project id")),
            uvm_template["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm template id")),
            uvm_image_id,
            active["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing active node id"))
        )),
    );
    let uvm_instance_other_id = uvm_instance_other["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing other uvm instance id"));
    let uvm_snapshot_other = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_other_id}/snapshot"),
        Some(r#"{"name":"other-predeploy","crash_consistent":true}"#),
    );
    let wrong_restore = request(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/restore"),
        Some((
            "application/json",
            format!(
                r#"{{"snapshot_id":"{}"}}"#,
                uvm_snapshot_other["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing other snapshot id"))
            )
            .as_bytes(),
        )),
    );
    assert_eq!(wrong_restore.status, 409);
    let _restored_instance = request_json(
        address,
        "POST",
        &format!("/uvm/instances/{uvm_instance_id}/restore"),
        Some(&format!(
            r#"{{"snapshot_id":"{}"}}"#,
            uvm_snapshot["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing uvm snapshot id"))
        )),
    );
    let perf_attestation = request_json(
        address,
        "POST",
        "/uvm/perf-attestations",
        Some(&format!(
            r#"{{"instance_id":"{}","workload_class":"general","cpu_overhead_pct":4,"memory_overhead_pct":4,"block_io_latency_overhead_pct":8,"network_latency_overhead_pct":8,"jitter_pct":8}}"#,
            uvm_instance_id
        )),
    );
    let perf_attestation_repeat = request_json(
        address,
        "POST",
        "/uvm/perf-attestations",
        Some(&format!(
            r#"{{"instance_id":"{}","workload_class":"general","cpu_overhead_pct":4,"memory_overhead_pct":4,"block_io_latency_overhead_pct":8,"network_latency_overhead_pct":8,"jitter_pct":8}}"#,
            uvm_instance_id
        )),
    );
    assert_eq!(
        perf_attestation["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing perf attestation id")),
        perf_attestation_repeat["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing repeat perf attestation id"))
    );
    let _cpu_perf_attestation = request_json(
        address,
        "POST",
        "/uvm/perf-attestations",
        Some(&format!(
            r#"{{"instance_id":"{}","workload_class":"cpu_intensive","cpu_overhead_pct":4,"memory_overhead_pct":4,"block_io_latency_overhead_pct":8,"network_latency_overhead_pct":8,"jitter_pct":8}}"#,
            uvm_instance_id
        )),
    );
    let _io_perf_attestation = request_json(
        address,
        "POST",
        "/uvm/perf-attestations",
        Some(&format!(
            r#"{{"instance_id":"{}","workload_class":"io_intensive","cpu_overhead_pct":4,"memory_overhead_pct":4,"block_io_latency_overhead_pct":8,"network_latency_overhead_pct":8,"jitter_pct":8}}"#,
            uvm_instance_id
        )),
    );
    let _network_perf_attestation = request_json(
        address,
        "POST",
        "/uvm/perf-attestations",
        Some(&format!(
            r#"{{"instance_id":"{}","workload_class":"network_intensive","cpu_overhead_pct":4,"memory_overhead_pct":4,"block_io_latency_overhead_pct":8,"network_latency_overhead_pct":8,"jitter_pct":8}}"#,
            uvm_instance_id
        )),
    );
    let failure_report = request_json(
        address,
        "POST",
        "/uvm/failure-reports",
        Some(&format!(
            r#"{{"instance_id":"{}","category":"host_failure","severity":"critical","summary":"recovered on failover","recovered":true,"forensic_capture_requested":true}}"#,
            uvm_instance_id
        )),
    );
    let failure_report_repeat = request_json(
        address,
        "POST",
        "/uvm/failure-reports",
        Some(&format!(
            r#"{{"instance_id":"{}","category":"host_failure","severity":"critical","summary":"recovered on failover","recovered":true,"forensic_capture_requested":true}}"#,
            uvm_instance_id
        )),
    );
    assert_eq!(
        failure_report["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failure report id")),
        failure_report_repeat["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing repeat failure report id"))
    );
    let uvm_observe = request_json(address, "GET", "/uvm/observe", None);
    assert_eq!(
        uvm_observe["service"]
            .as_str()
            .unwrap_or_else(|| panic!("missing uvm observe service name")),
        "uvm-observe"
    );
    let native_claim = request_json(address, "GET", "/uvm/native-claim-status", None);
    assert!(
        native_claim["native_indistinguishable_status"]
            .as_bool()
            .unwrap_or(false)
    );
    let _critical_failure = request_json(
        address,
        "POST",
        "/uvm/failure-reports",
        Some(&format!(
            r#"{{"instance_id":"{}","category":"host_failure","severity":"critical","summary":"unrecovered failure","recovered":false,"forensic_capture_requested":true}}"#,
            uvm_instance_id
        )),
    );
    let native_claim_after_failure = request_json(address, "GET", "/uvm/native-claim-status", None);
    assert!(
        !native_claim_after_failure["native_indistinguishable_status"]
            .as_bool()
            .unwrap_or(true)
    );
    let _unrecovered_failure = request_json(
        address,
        "POST",
        "/uvm/failure-reports",
        Some(&format!(
            r#"{{"instance_id":"{}","category":"host_failure","severity":"critical","summary":"unrecovered crash","recovered":false,"forensic_capture_requested":true}}"#,
            uvm_instance_id
        )),
    );
    let native_claim_after_failure = request_json(address, "GET", "/uvm/native-claim-status", None);
    assert!(
        !native_claim_after_failure["native_indistinguishable_status"]
            .as_bool()
            .unwrap_or(true)
    );
    let compatibility_matrix = request_json(address, "GET", "/uvm/compatibility-matrix", None);
    assert!(
        compatibility_matrix
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let uvm_outbox = request_json(address, "GET", "/uvm/outbox", None);
    assert!(
        uvm_outbox
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let uvm_runtime_outbox = request_json(address, "GET", "/uvm/node-outbox", None);
    assert!(
        uvm_runtime_outbox
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let runtime_migrations = request_json(address, "GET", "/uvm/runtime/migrations", None);
    assert!(
        runtime_migrations
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );

    let billing_account = request_json(
        address,
        "POST",
        "/billing/accounts",
        Some(r#"{"owner_id":"tnt_demo","plan":"pro","credits_cents":5000}"#),
    );
    let _invoice = request_json(
        address,
        "POST",
        "/billing/invoices",
        Some(&format!(
            r#"{{"billing_account_id":"{}","description":"monthly","total_cents":1200}}"#,
            billing_account["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing billing account id"))
        )),
    );
    let billing_sync = request_json(address, "GET", "/billing/provider-sync", None);
    assert!(
        billing_sync
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );

    let exporter = request_json(
        address,
        "POST",
        "/observe/otlp-exporters",
        Some(
            r#"{"signal":"traces","endpoint":"https://otlp.example.local/v1/traces","insecure":false,"headers":{}}"#,
        ),
    );
    let _dispatch = request_json(
        address,
        "POST",
        "/observe/otlp-dispatch",
        Some(&format!(
            r#"{{"exporter_id":"{}","batch_items":32,"payload_bytes":64000}}"#,
            exporter["id"]
                .as_str()
                .unwrap_or_else(|| panic!("missing exporter id"))
        )),
    );
    let dispatches = request_json(address, "GET", "/observe/otlp-dispatch", None);
    assert!(
        dispatches
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
    let route = request_json(
        address,
        "POST",
        "/observe/alert-routes",
        Some(
            r#"{"name":"ops-pager","destination":"pager://ops","severity_filter":["high","critical"]}"#,
        ),
    );
    let route_id = route["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing alert route id"));
    let _slo = request_json(
        address,
        "POST",
        "/observe/slos",
        Some(&format!(
            r#"{{"name":"api-availability","sli_kind":"request","target_success_per_million":999000,"window_minutes":60,"alert_route_id":"{}"}}"#,
            route_id
        )),
    );
    let _alert_rule = request_json(
        address,
        "POST",
        "/observe/alert-rules",
        Some(r#"{"name":"high-latency","expression":"latency_ms>1000","severity":"high"}"#),
    );
    let _activity = request_json(
        address,
        "POST",
        "/observe/activity",
        Some(r#"{"category":"request","summary":"request completed","correlation_id":"trace-1"}"#),
    );
    let _slow_path = request_json(
        address,
        "POST",
        "/observe/slow-paths",
        Some(
            r#"{"category":"request","resource":"/api/v1/items","latency_ms":2200,"exemplar_trace_id":"trace-1"}"#,
        ),
    );
    let incident_eval = request_json(
        address,
        "POST",
        "/observe/incidents/evaluate",
        Some(r#"{"include_alert_rules":true,"include_slos":true}"#),
    );
    assert!(incident_eval["incidents_created"].as_u64().unwrap_or(0) >= 1);
    let incidents = request_json(address, "GET", "/observe/incidents", None);
    let incident_id = incidents
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("missing incident id"));
    let resolved_incident = request_json(
        address,
        "POST",
        &format!("/observe/incidents/{incident_id}/resolve"),
        Some(r#"{"reason":"drill resolved"}"#),
    );
    assert_eq!(
        resolved_incident["status"]
            .as_str()
            .unwrap_or_else(|| panic!("missing resolved incident status")),
        "resolved"
    );
}

#[test]
fn summary_endpoints_smoke() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("summary-config.toml");
    let token = "integration-bootstrap-admin-token";
    let Some(address) = reserve_loopback_port() else {
        eprintln!("skipping summary_endpoints_smoke: loopback bind not permitted");
        return;
    };
    write_test_config_with_token(&config_path, address, &state_dir, Some(token));

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

    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/governance/change-requests",
        Some(r#"{"title":"smoke change","change_type":"deploy","requested_by":"bootstrap_admin"}"#),
        token,
    );
    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/governance/legal-holds",
        Some(r#"{"subject_kind":"tenant","subject_id":"tenant-smoke","reason":"summary test"}"#),
        token,
    );

    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/node/heartbeats",
        Some(
            r#"{"node_id":"nod_aaaaaaaaaaaaaaaaaaaa","hostname":"node-a","healthy":true,"agent_version":"0.1","cache_bytes":10}"#,
        ),
        token,
    );
    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/node/heartbeats",
        Some(
            r#"{"node_id":"nod_bbbbbbbbbbbbbbbbbbbb","hostname":"node-b","healthy":false,"agent_version":"0.1","cache_bytes":20}"#,
        ),
        token,
    );
    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/node/process-reports",
        Some(
            r#"{"node_id":"nod_aaaaaaaaaaaaaaaaaaaa","workload_id":"wrk_aaaaaaaaaaaaaaaaaaaa","state":"running","exit_code":0}"#,
        ),
        token,
    );
    let _ = request_json_with_bearer_token(
        address,
        "POST",
        "/node/process-reports",
        Some(
            r#"{"node_id":"nod_bbbbbbbbbbbbbbbbbbbb","workload_id":"wrk_bbbbbbbbbbbbbbbbbbbb","state":"failed","exit_code":1}"#,
        ),
        token,
    );

    let governance_summary =
        request_json_with_bearer_token(address, "GET", "/governance/summary", None, token);
    assert_eq!(
        governance_summary["change_requests"]["total"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert_eq!(
        governance_summary["legal_holds"]["total"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert!(
        governance_summary["audit"]["total_checkpoints"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );

    let node_summary = request_json_with_bearer_token(address, "GET", "/node/summary", None, token);
    assert_eq!(
        node_summary["heartbeats"]["total"]
            .as_u64()
            .unwrap_or_default(),
        2
    );
    assert_eq!(
        node_summary["heartbeats"]["healthy"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert_eq!(
        node_summary["heartbeats"]["degraded"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert_eq!(
        node_summary["heartbeats"]["stale"]
            .as_u64()
            .unwrap_or_default(),
        0
    );
    assert_eq!(
        node_summary["heartbeats"]["unique_nodes"]
            .as_u64()
            .unwrap_or_default(),
        2
    );
    assert!(!node_summary["heartbeats"]["last_seen"].is_null());
    assert_eq!(
        node_summary["process_reports"]["total"]
            .as_u64()
            .unwrap_or_default(),
        2
    );
    assert_eq!(
        node_summary["process_reports"]["states"]["running"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert_eq!(
        node_summary["process_reports"]["states"]["failed"]
            .as_u64()
            .unwrap_or_default(),
        1
    );
    assert!(
        node_summary["outbox"]["pending_messages"]
            .as_u64()
            .unwrap_or_default()
            >= 4
    );
}

#[test]
fn credential_rotate_and_revoke_cutover_persists_across_restart_smoke() {
    let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    let config_path = temp.path().join("credential-restart.toml");
    let Some(address) = reserve_loopback_port() else {
        eprintln!(
            "skipping credential_rotate_and_revoke_cutover_persists_across_restart_smoke: loopback bind not permitted"
        );
        return;
    };
    write_test_config(&config_path, address, &state_dir);

    let mut guard = spawn_uhostd(&config_path, address);

    let created_user = request_json(
        address,
        "POST",
        "/identity/users",
        Some(
            r#"{"email":"restart-rotate@example.com","display_name":"Restart Rotate","password":"correct horse battery staple"}"#,
        ),
    );
    let user_id = created_user["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing created user id"))
        .to_owned();
    let created_api_key = request_json(
        address,
        "POST",
        "/identity/api-keys",
        Some(&format!(
            r#"{{"user_id":"{user_id}","name":"restart-rotating-cli"}}"#
        )),
    );
    let api_key_id = created_api_key["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing api key id"))
        .to_owned();
    let issued_api_key_secret = created_api_key["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued api key secret"))
        .to_owned();

    let issued_workload_identity = request_json(
        address,
        "POST",
        "/identity/workload-identities",
        Some(
            r#"{"subject":"svc:restart-rotate","display_name":"Restart Rotate Identity","audiences":["identity"],"ttl_seconds":900}"#,
        ),
    );
    let workload_identity_id = issued_workload_identity["identity"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing workload identity id"))
        .to_owned();
    let issued_workload_token = issued_workload_identity["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing issued workload token"))
        .to_owned();

    let initial_governance =
        request_json_with_bearer_token(address, "GET", "/governance", None, &issued_api_key_secret);
    assert_eq!(initial_governance["service"], "governance");
    let initial_identity =
        request_json_with_bearer_token(address, "GET", "/identity", None, &issued_workload_token);
    assert_eq!(initial_identity["service"], "identity");

    let rotated_api_key = request_json(
        address,
        "POST",
        &format!("/identity/api-keys/{api_key_id}/rotate"),
        None,
    );
    assert_eq!(rotated_api_key["version"].as_u64(), Some(2));
    let rotated_api_key_secret = rotated_api_key["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rotated api key secret"))
        .to_owned();
    assert_ne!(rotated_api_key_secret, issued_api_key_secret);

    let rotated_workload_identity = request_json(
        address,
        "POST",
        &format!("/identity/workload-identities/{workload_identity_id}/rotate"),
        None,
    );
    assert_eq!(
        rotated_workload_identity["identity"]["credential"]["version"].as_u64(),
        Some(2)
    );
    let rotated_workload_token = rotated_workload_identity["token"]
        .as_str()
        .unwrap_or_else(|| panic!("missing rotated workload token"))
        .to_owned();
    assert_ne!(rotated_workload_token, issued_workload_token);

    let stale_governance =
        request_with_bearer_token(address, "GET", "/governance", None, &issued_api_key_secret);
    assert_eq!(stale_governance.status, 401);
    let stale_identity =
        request_with_bearer_token(address, "GET", "/identity", None, &issued_workload_token);
    assert_eq!(stale_identity.status, 401);

    let fresh_governance = request_json_with_bearer_token(
        address,
        "GET",
        "/governance",
        None,
        &rotated_api_key_secret,
    );
    assert_eq!(fresh_governance["service"], "governance");
    let fresh_identity =
        request_json_with_bearer_token(address, "GET", "/identity", None, &rotated_workload_token);
    assert_eq!(fresh_identity["service"], "identity");

    guard = restart_uhostd(guard, &config_path, address);

    let stale_governance_after_restart =
        request_with_bearer_token(address, "GET", "/governance", None, &issued_api_key_secret);
    assert_eq!(stale_governance_after_restart.status, 401);
    let fresh_governance_after_restart = request_json_with_bearer_token(
        address,
        "GET",
        "/governance",
        None,
        &rotated_api_key_secret,
    );
    assert_eq!(fresh_governance_after_restart["service"], "governance");
    let stale_identity_after_restart =
        request_with_bearer_token(address, "GET", "/identity", None, &issued_workload_token);
    assert_eq!(stale_identity_after_restart.status, 401);
    let fresh_identity_after_restart =
        request_json_with_bearer_token(address, "GET", "/identity", None, &rotated_workload_token);
    assert_eq!(fresh_identity_after_restart["service"], "identity");

    let lifecycle_after_rotate_restart =
        request_json(address, "GET", "/identity/credential-lifecycle", None);
    let rotate_entries = lifecycle_after_rotate_restart["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"));
    assert!(rotate_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("secret_version")
            && entry["source_id"].as_str() == Some(api_key_id.as_str())
            && entry["source_kind"].as_str() == Some("api_key")
            && entry["version"].as_u64() == Some(1)
            && entry["state"].as_str() == Some("revoked")
    }));
    assert!(rotate_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("secret_version")
            && entry["source_id"].as_str() == Some(api_key_id.as_str())
            && entry["source_kind"].as_str() == Some("api_key")
            && entry["version"].as_u64() == Some(2)
            && entry["state"].as_str() == Some("active")
    }));
    assert!(rotate_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("secret_version")
            && entry["source_id"].as_str() == Some(workload_identity_id.as_str())
            && entry["source_kind"].as_str() == Some("workload_token")
            && entry["version"].as_u64() == Some(1)
            && entry["state"].as_str() == Some("revoked")
    }));
    assert!(rotate_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("secret_version")
            && entry["source_id"].as_str() == Some(workload_identity_id.as_str())
            && entry["source_kind"].as_str() == Some("workload_token")
            && entry["version"].as_u64() == Some(2)
            && entry["state"].as_str() == Some("active")
    }));

    let revoked_api_key = request_json(
        address,
        "POST",
        &format!("/identity/api-keys/{api_key_id}/revoke"),
        None,
    );
    assert_eq!(revoked_api_key["active"].as_bool(), Some(false));
    let revoked_workload_identity = request_json(
        address,
        "POST",
        &format!("/identity/workload-identities/{workload_identity_id}/revoke"),
        None,
    );
    assert_eq!(revoked_workload_identity["active"].as_bool(), Some(false));

    let revoked_governance =
        request_with_bearer_token(address, "GET", "/governance", None, &rotated_api_key_secret);
    assert_eq!(revoked_governance.status, 401);
    let revoked_identity =
        request_with_bearer_token(address, "GET", "/identity", None, &rotated_workload_token);
    assert_eq!(revoked_identity.status, 401);

    let _guard = restart_uhostd(guard, &config_path, address);

    let revoked_governance_after_restart =
        request_with_bearer_token(address, "GET", "/governance", None, &rotated_api_key_secret);
    assert_eq!(revoked_governance_after_restart.status, 401);
    let revoked_identity_after_restart =
        request_with_bearer_token(address, "GET", "/identity", None, &rotated_workload_token);
    assert_eq!(revoked_identity_after_restart.status, 401);

    let lifecycle_after_revoke_restart =
        request_json(address, "GET", "/identity/credential-lifecycle", None);
    let revoke_entries = lifecycle_after_revoke_restart["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("missing credential lifecycle entries"));
    assert!(revoke_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("api_key")
            && entry["id"].as_str() == Some(api_key_id.as_str())
            && entry["state"].as_str() == Some("revoked")
    }));
    assert!(revoke_entries.iter().any(|entry| {
        entry["kind"].as_str() == Some("workload_token")
            && entry["id"].as_str() == Some(workload_identity_id.as_str())
            && entry["state"].as_str() == Some("revoked")
    }));
    assert!(
        revoke_entries
            .iter()
            .filter(|entry| entry["source_id"].as_str() == Some(api_key_id.as_str()))
            .all(|entry| entry["state"].as_str() == Some("revoked"))
    );
    assert!(
        revoke_entries
            .iter()
            .filter(|entry| entry["source_id"].as_str() == Some(workload_identity_id.as_str()))
            .all(|entry| entry["state"].as_str() == Some("revoked"))
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
        let normalized_state = state.trim().to_ascii_lowercase();
        let approved_by = matches!(normalized_state.as_str(), "approved" | "applied")
            .then(|| String::from("bootstrap-reviewer"));
        store
            .create(
                id.as_str(),
                SeedGovernanceChangeRequest {
                    id: id.clone(),
                    title: String::from("seeded integration change request"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("bootstrap-admin"),
                    approved_by,
                    reviewer_comment: None,
                    required_approvals: 1,
                    state: normalized_state,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("failed to seed governance change request: {error}"));
        if std::env::var_os("UHOSTD_TEST_DEBUG_SEED").is_some() {
            let seeded =
                fs::read_to_string(state_dir.join("governance").join("change_requests.json"))
                    .unwrap_or_else(|error| {
                        panic!("failed to read seeded governance change store: {error}")
                    });
            eprintln!("SEEDED_GOVERNANCE_CHANGE_STORE={seeded}");
        }
        id.to_string()
    })
}

fn write_test_config(path: &Path, address: SocketAddr, state_dir: &Path) {
    write_test_config_with_token(
        path,
        address,
        state_dir,
        Some(DEFAULT_BOOTSTRAP_ADMIN_TOKEN),
    );
}

fn write_test_config_with_token(
    path: &Path,
    address: SocketAddr,
    state_dir: &Path,
    token: Option<&str>,
) {
    let security = token
        .map(|value| format!("\n[security]\nbootstrap_admin_token = \"{value}\"\n"))
        .unwrap_or_default();
    let config = format!(
        r#"listen = "{address}"
state_dir = "{}"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "test-node"

[secrets]
master_key = "{}"
{}"#,
        state_dir.display(),
        base64url_encode(&[0x42; 32]),
        security,
    );
    fs::write(path, config).unwrap_or_else(|error| panic!("failed to write config: {error}"));
}

fn spawn_uhostd(config_path: &Path, address: SocketAddr) -> ChildGuard {
    let binary = std::env::var("CARGO_BIN_EXE_uhostd")
        .unwrap_or_else(|error| panic!("missing test binary path: {error}"));
    let child = Command::new(binary)
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(test_child_stderr())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn uhostd: {error}"));
    let guard = ChildGuard { child };
    wait_for_health(address);
    guard
}

fn restart_uhostd(guard: ChildGuard, config_path: &Path, address: SocketAddr) -> ChildGuard {
    drop(guard);
    thread::sleep(Duration::from_millis(150));
    spawn_uhostd(config_path, address)
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

fn find_user_id_by_email(users: &Value, email: &str) -> String {
    users
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|item| {
                (item["email"].as_str() == Some(email))
                    .then(|| item["id"].as_str().map(str::to_owned))
                    .flatten()
            })
        })
        .unwrap_or_else(|| panic!("missing user id for {email}"))
}

fn create_api_key_secret(address: SocketAddr, user_id: &str, name: &str) -> String {
    let payload = format!(r#"{{"user_id":"{user_id}","name":"{name}"}}"#);
    request_json(address, "POST", "/identity/api-keys", Some(&payload))["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("missing api key secret for {user_id}"))
        .to_owned()
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

fn request_with_bearer_token(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    token: &str,
) -> RawResponse {
    const MAX_REQUEST_ATTEMPTS: u64 = 16;
    let allow_retry = is_idempotent_method(method);
    let mut last_error = None;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        match try_request_with_bearer_token(address, method, path, body, token) {
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
    try_request_with_bearer_token(address, method, path, body, DEFAULT_BOOTSTRAP_ADMIN_TOKEN)
}

fn try_request_with_bearer_token(
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
