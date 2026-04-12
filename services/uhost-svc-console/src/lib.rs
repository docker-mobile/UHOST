//! Operator and tenant-facing HTML console.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use http::{Method, Request, Response, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime, UtcOffset};
use uhost_core::RequestContext;
use uhost_runtime::{HttpService, ResponseFuture};

/// Console service.
#[derive(Debug, Clone)]
pub struct ConsoleService {
    state_root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConsoleSnapshot {
    state_root: String,
    updated_at: String,
    metrics: Vec<Metric>,
    uvm: UvmSummary,
    workbench: OperatorWorkbench,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConsoleSummary {
    state_root: String,
    updated_at: String,
    identity_users: CountSummary,
    tenancy_organizations: CountSummary,
    control_workloads: CountSummary,
    scheduler_nodes: CountSummary,
    uvm_instances: CountSummary,
    uvm_instance_statuses: Vec<StatusSummary>,
    uvm_runtime_sessions: CountSummary,
    uvm_runtime_session_statuses: Vec<StatusSummary>,
    metrics_available: u64,
    metrics_unavailable: u64,
    operator_workbench: OperatorWorkbenchSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metric {
    label: String,
    count: u64,
    available: bool,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UvmSummary {
    instance_count: CountSummary,
    instance_statuses: Vec<StatusSummary>,
    runtime_session_count: CountSummary,
    runtime_session_statuses: Vec<StatusSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OperatorWorkbench {
    approvals: WorkbenchLane,
    grants: WorkbenchLane,
    quotas: WorkbenchLane,
    cases: WorkbenchLane,
    appeals: WorkbenchLane,
    dead_letters: WorkbenchLane,
}

#[derive(Debug, Serialize, Deserialize)]
struct OperatorWorkbenchSummary {
    approvals: WorkbenchLaneSummary,
    grants: WorkbenchLaneSummary,
    quotas: WorkbenchLaneSummary,
    cases: WorkbenchLaneSummary,
    appeals: WorkbenchLaneSummary,
    dead_letters: WorkbenchLaneSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkbenchLaneSummary {
    count: CountSummary,
    attention_count: u64,
    statuses: Vec<StatusSummary>,
    note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkbenchLane {
    count: CountSummary,
    attention_count: u64,
    attention_label: String,
    statuses: Vec<StatusSummary>,
    sources: Vec<WorkbenchSource>,
    entries: Vec<WorkbenchEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    support_entitlement_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    support_tier_totals: Option<BTreeMap<String, u64>>,
    note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkbenchSource {
    label: String,
    path: String,
    count: u64,
    available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkbenchEntry {
    id: String,
    source: String,
    status: String,
    summary: String,
    context: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CountSummary {
    count: u64,
    available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusSummary {
    status: String,
    count: u64,
}

#[derive(Debug)]
struct WorkbenchRecord {
    id: String,
    source: String,
    status: String,
    summary: String,
    context: Option<String>,
    updated_at: Option<String>,
    sort_at: Option<OffsetDateTime>,
    attention: bool,
}

#[derive(Debug, Default)]
struct NotifyCaseWorkflowSummary {
    notification_count: u64,
    acknowledged_count: u64,
    snoozed_count: u64,
    escalated_count: u64,
    dead_lettered_count: u64,
    latest_delivery_state: Option<String>,
    latest_updated_at: Option<String>,
    latest_sort_at: Option<OffsetDateTime>,
    latest_acknowledged_by: Option<String>,
    latest_acknowledgement_note: Option<String>,
    latest_ack_sort_at: Option<OffsetDateTime>,
    latest_snoozed_until: Option<String>,
    latest_snoozed_by: Option<String>,
    latest_snooze_reason: Option<String>,
    latest_snooze_sort_at: Option<OffsetDateTime>,
    latest_escalated_by: Option<String>,
    latest_escalated_notification_id: Option<String>,
    latest_escalate_sort_at: Option<OffsetDateTime>,
    latest_workflow_event: Option<String>,
    latest_event_sort_at: Option<OffsetDateTime>,
}

#[derive(Debug, Default)]
struct RemediationCaseWorkflowSummary {
    opened_by: Option<String>,
    owner: Option<String>,
    owner_assigned_at: Option<String>,
    rollback_evidence_count: u64,
    verification_evidence_count: u64,
    evidence_state: Option<String>,
    sla_target_seconds: Option<u64>,
    sla_deadline_at: Option<String>,
    sla_state: Option<String>,
    escalation_state: Option<String>,
    escalation_count: u64,
    last_escalated_at: Option<String>,
    last_escalated_by: Option<String>,
    last_escalation_reason: Option<String>,
    workflow_steps: Vec<RemediationWorkflowStepSummary>,
}

#[derive(Debug, Default)]
struct RemediationWorkflowStepSummary {
    name: String,
    index: u64,
    state: String,
    detail: Option<String>,
    updated_at: Option<String>,
}

struct MetricDefinition {
    label: &'static str,
    relative_path: &'static str,
}

impl MetricDefinition {
    const fn new(label: &'static str, relative_path: &'static str) -> Self {
        Self {
            label,
            relative_path,
        }
    }
}

const METRIC_DEFINITIONS: &[MetricDefinition] = &[
    MetricDefinition::new("Identity users", "identity/users.json"),
    MetricDefinition::new("Tenancy organizations", "tenancy/organizations.json"),
    MetricDefinition::new("Control workloads", "control/workloads.json"),
    MetricDefinition::new("Scheduler nodes", "scheduler/nodes.json"),
    MetricDefinition::new("Billing accounts", "billing/accounts.json"),
    MetricDefinition::new("Storage buckets", "storage/buckets.json"),
    MetricDefinition::new("Data databases", "data/databases.json"),
    MetricDefinition::new("Ingress routes", "ingress/routes.json"),
    MetricDefinition::new("Network policies", "netsec/policies.json"),
    MetricDefinition::new("Mail domains", "mail/domains.json"),
];

const WORKBENCH_ENTRY_LIMIT: usize = 6;

impl NotifyCaseWorkflowSummary {
    fn status(&self) -> &str {
        if self.dead_lettered_count > 0 {
            "dead_lettered"
        } else if self.snoozed_count > 0 {
            "snoozed"
        } else if self.acknowledged_count == self.notification_count && self.notification_count > 0
        {
            "acknowledged"
        } else if self.escalated_count > 0 {
            "escalated"
        } else {
            self.latest_delivery_state.as_deref().unwrap_or("tracked")
        }
    }

    fn needs_attention(&self) -> bool {
        !matches!(self.status(), "acknowledged" | "delivered" | "snoozed")
    }
}

impl RemediationCaseWorkflowSummary {
    fn has_operator_workflow_state(&self) -> bool {
        self.owner.is_some()
            || self.owner_assigned_at.is_some()
            || self.rollback_evidence_count > 0
            || self.verification_evidence_count > 0
            || self.evidence_state.is_some()
            || self.sla_target_seconds.is_some_and(|value| value > 0)
            || self.sla_deadline_at.is_some()
            || self.sla_state.is_some()
            || self.escalation_state.is_some()
            || self.escalation_count > 0
            || self.last_escalated_at.is_some()
            || self.last_escalated_by.is_some()
            || self.last_escalation_reason.is_some()
            || !self.workflow_steps.is_empty()
    }

    fn status(&self, notify_summary: Option<&NotifyCaseWorkflowSummary>) -> String {
        if !self.has_operator_workflow_state() {
            return notify_summary
                .map(NotifyCaseWorkflowSummary::status)
                .map(str::to_owned)
                .unwrap_or_else(|| String::from("tracked"));
        }

        if self.escalation_count > 0 || self.escalation_state.as_deref() == Some("escalated") {
            return String::from("escalated");
        }
        if self.owner.is_none() || self.escalation_state.as_deref() == Some("queued") {
            return String::from("queued");
        }
        if let Some(evidence_status) = self.evidence_attention_status() {
            return evidence_status;
        }
        if let Some(sla_state) = self
            .sla_state
            .as_deref()
            .filter(|state| !state.trim().is_empty())
        {
            return sla_state.to_string();
        }
        if let Some(escalation_state) = self
            .escalation_state
            .as_deref()
            .filter(|state| !state.trim().is_empty() && *state != "none")
        {
            return escalation_state.to_string();
        }

        notify_summary
            .map(NotifyCaseWorkflowSummary::status)
            .map(str::to_owned)
            .unwrap_or_else(|| String::from("tracked"))
    }

    fn rollback_evidence_missing(&self) -> bool {
        (self.has_operator_workflow_state() && self.rollback_evidence_count == 0)
            || matches!(
                self.evidence_state.as_deref(),
                Some("rollback_missing" | "rollback_and_verification_missing")
            )
    }

    fn verification_evidence_missing(&self) -> bool {
        (self.has_operator_workflow_state() && self.verification_evidence_count == 0)
            || matches!(
                self.evidence_state.as_deref(),
                Some("verification_missing" | "rollback_and_verification_missing")
            )
    }

    fn evidence_attention_status(&self) -> Option<String> {
        match (
            self.rollback_evidence_missing(),
            self.verification_evidence_missing(),
        ) {
            (true, true) => Some(String::from("rollback_and_verification_missing")),
            (true, false) => Some(String::from("rollback_missing")),
            (false, true) => Some(String::from("verification_missing")),
            (false, false) => self
                .evidence_state
                .as_deref()
                .filter(|state| !state.trim().is_empty() && *state != "ready")
                .map(str::to_owned),
        }
    }

    fn needs_attention(&self, notify_summary: Option<&NotifyCaseWorkflowSummary>) -> bool {
        if !self.has_operator_workflow_state() {
            return notify_summary
                .map(NotifyCaseWorkflowSummary::needs_attention)
                .unwrap_or(true);
        }

        let missing_evidence_attention = self.evidence_attention_status().is_some();

        self.owner.is_none()
            || missing_evidence_attention
            || self.escalation_count > 0
            || self
                .escalation_state
                .as_deref()
                .is_some_and(|state| state != "none")
            || self
                .sla_state
                .as_deref()
                .is_some_and(|state| state != "within_sla")
            || notify_summary.is_some_and(NotifyCaseWorkflowSummary::needs_attention)
    }
}

impl ConsoleService {
    /// Open the console state.
    pub async fn open(state_root: impl AsRef<Path>) -> uhost_core::Result<Self> {
        Ok(Self {
            state_root: state_root.as_ref().join("console"),
        })
    }

    fn escape_html(value: &str) -> String {
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

    fn response_html(
        status: StatusCode,
        html: String,
    ) -> uhost_core::Result<Response<uhost_api::ApiBody>> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(header::REFERRER_POLICY, "no-referrer")
            .header(header::X_FRAME_OPTIONS, "DENY")
            .header(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; style-src 'unsafe-inline'",
            )
            .body(uhost_api::full_body(bytes::Bytes::from(html)))
            .map_err(|error| {
                uhost_core::PlatformError::new(
                    uhost_core::ErrorCode::Internal,
                    "failed to build console response",
                )
                .with_detail(error.to_string())
            })
    }

    fn response_json<T: Serialize>(
        status: StatusCode,
        body: &T,
    ) -> uhost_core::Result<Response<uhost_api::ApiBody>> {
        let encoded = serde_json::to_vec(body).map_err(|error| {
            uhost_core::PlatformError::new(
                uhost_core::ErrorCode::Internal,
                "failed to serialize console status",
            )
            .with_detail(error.to_string())
        })?;

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(uhost_api::full_body(bytes::Bytes::from(encoded)))
            .map_err(|error| {
                uhost_core::PlatformError::new(
                    uhost_core::ErrorCode::Internal,
                    "failed to build console response",
                )
                .with_detail(error.to_string())
            })
    }

    fn platform_root(&self) -> &Path {
        self.state_root
            .parent()
            .unwrap_or_else(|| self.state_root.as_ref())
    }

    fn dashboard_snapshot(&self) -> ConsoleSnapshot {
        let root = self.platform_root();
        let metrics = METRIC_DEFINITIONS
            .iter()
            .map(|definition| {
                let path = root.join(definition.relative_path);
                let (count, available) = Self::count_entries(&path);

                Metric {
                    label: definition.label.to_string(),
                    count,
                    available,
                    path: definition.relative_path.to_string(),
                }
            })
            .collect();

        let (instance_count, instance_statuses) = Self::count_and_status(
            &root.join("uvm-control/instances.json"),
            &["status", "state", "phase"],
        );
        let (runtime_count, runtime_statuses) = Self::count_and_status(
            &root.join("uvm-node/runtime_sessions.json"),
            &["state", "status"],
        );

        let updated_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let workbench = Self::workbench_snapshot(root);

        ConsoleSnapshot {
            state_root: root.display().to_string(),
            updated_at,
            metrics,
            uvm: UvmSummary {
                instance_count,
                instance_statuses,
                runtime_session_count: runtime_count,
                runtime_session_statuses: runtime_statuses,
            },
            workbench,
        }
    }

    fn summary_snapshot(&self) -> ConsoleSummary {
        let dashboard = self.dashboard_snapshot();
        let metric_count = |label: &str| -> CountSummary {
            dashboard
                .metrics
                .iter()
                .find(|metric| metric.label == label)
                .map(|metric| CountSummary {
                    count: metric.count,
                    available: metric.available,
                })
                .unwrap_or(CountSummary {
                    count: 0,
                    available: false,
                })
        };
        let metrics_available = dashboard
            .metrics
            .iter()
            .filter(|metric| metric.available)
            .count();
        let metrics_unavailable = dashboard.metrics.len().saturating_sub(metrics_available);

        ConsoleSummary {
            state_root: dashboard.state_root,
            updated_at: dashboard.updated_at,
            identity_users: metric_count("Identity users"),
            tenancy_organizations: metric_count("Tenancy organizations"),
            control_workloads: metric_count("Control workloads"),
            scheduler_nodes: metric_count("Scheduler nodes"),
            uvm_instances: dashboard.uvm.instance_count,
            uvm_instance_statuses: dashboard.uvm.instance_statuses,
            uvm_runtime_sessions: dashboard.uvm.runtime_session_count,
            uvm_runtime_session_statuses: dashboard.uvm.runtime_session_statuses,
            metrics_available: metrics_available as u64,
            metrics_unavailable: metrics_unavailable as u64,
            operator_workbench: Self::summarize_workbench(&dashboard.workbench),
        }
    }

    fn workbench_snapshot(root: &Path) -> OperatorWorkbench {
        OperatorWorkbench {
            approvals: Self::approval_lane(root),
            grants: Self::grant_lane(root),
            quotas: Self::quota_lane(root),
            cases: Self::case_lane(root),
            appeals: Self::appeal_lane(root),
            dead_letters: Self::dead_letter_lane(root),
        }
    }

    fn summarize_workbench(workbench: &OperatorWorkbench) -> OperatorWorkbenchSummary {
        OperatorWorkbenchSummary {
            approvals: Self::summarize_lane(&workbench.approvals),
            grants: Self::summarize_lane(&workbench.grants),
            quotas: Self::summarize_lane(&workbench.quotas),
            cases: Self::summarize_lane(&workbench.cases),
            appeals: Self::summarize_lane(&workbench.appeals),
            dead_letters: Self::summarize_lane(&workbench.dead_letters),
        }
    }

    fn summarize_lane(lane: &WorkbenchLane) -> WorkbenchLaneSummary {
        WorkbenchLaneSummary {
            count: CountSummary {
                count: lane.count.count,
                available: lane.count.available,
            },
            attention_count: lane.attention_count,
            statuses: lane
                .statuses
                .iter()
                .map(|entry| StatusSummary {
                    status: entry.status.clone(),
                    count: entry.count,
                })
                .collect(),
            note: lane.note.clone(),
        }
    }

    fn approval_lane(root: &Path) -> WorkbenchLane {
        let (policy_source, policy_entries) =
            Self::read_source_entries(root, "Policy approvals", "policy/approvals.json");
        let (request_source, request_entries) = Self::read_source_entries(
            root,
            "Governance change requests",
            "governance/change_requests.json",
        );
        let (evidence_source, evidence_entries) = Self::read_source_entries(
            root,
            "Governance approval evidence",
            "governance/change_approvals.json",
        );

        let mut records = Vec::new();

        for entry in policy_entries {
            let approved = Self::first_bool(&entry, &[&["approved"]]).unwrap_or(false);
            let status = if approved { "approved" } else { "pending" };
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let subject = Self::first_scalar(&entry, &[&["subject"]])
                .unwrap_or_else(|| String::from("approval subject unavailable"));
            let required_approvers =
                Self::first_u64(&entry, &[&["required_approvers"]]).map(|value| {
                    format!(
                        "{value} required approver{}",
                        if value == 1 { "" } else { "s" }
                    )
                });

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("policy-approval")),
                source: String::from("policy"),
                status: String::from(status),
                summary: subject,
                context: required_approvers,
                updated_at,
                sort_at,
                attention: !approved,
            });
        }

        for entry in request_entries {
            let status = Self::first_scalar(&entry, &[&["state"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("pending"));
            let title =
                Self::first_scalar(&entry, &[&["title"]]).filter(|value| !value.trim().is_empty());
            let change_type = Self::first_scalar(&entry, &[&["change_type"]])
                .unwrap_or_else(|| String::from("change"));
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["requested_by"]])
                    .map(|value| format!("requested by {value}")),
                Self::first_u64(&entry, &[&["required_approvals"]]).map(|value| {
                    format!(
                        "{value} required approval{}",
                        if value == 1 { "" } else { "s" }
                    )
                }),
                Self::first_scalar(&entry, &[&["approved_by"]])
                    .map(|value| format!("reviewed by {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("change-request")),
                source: String::from("governance"),
                status: status.clone(),
                summary: title.unwrap_or_else(|| format!("{change_type} change request")),
                context,
                updated_at,
                sort_at,
                attention: matches!(status.as_str(), "pending" | "approved"),
            });
        }

        for entry in evidence_entries {
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let change_request_id = Self::first_scalar(&entry, &[&["change_request_id"]])
                .unwrap_or_else(|| String::from("unknown change request"));
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["approver"]])
                    .map(|value| format!("approved by {value}")),
                Self::first_scalar(&entry, &[&["comment"]]),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("approval-evidence")),
                source: String::from("approval evidence"),
                status: String::from("recorded"),
                summary: format!("approval recorded for {change_request_id}"),
                context,
                updated_at,
                sort_at,
                attention: false,
            });
        }

        Self::build_lane(
            records,
            vec![policy_source, request_source, evidence_source],
            "needs action",
            Some(String::from(
                "Aggregates policy approvals, governance change requests, and immutable approval evidence.",
            )),
        )
    }

    fn grant_lane(root: &Path) -> WorkbenchLane {
        let now = OffsetDateTime::now_utc();
        let (override_source, override_entries) = Self::read_source_entries(
            root,
            "Governance exposure overrides",
            "governance/exposure_overrides.json",
        );
        let (reveal_source, reveal_entries) =
            Self::read_source_entries(root, "Secret reveal grants", "secrets/reveal_grants.json");
        let mut records = Vec::new();

        for entry in override_entries {
            let status = Self::first_scalar(&entry, &[&["state"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("pending"));
            let surface = Self::first_scalar(&entry, &[&["surface"]])
                .unwrap_or_else(|| String::from("surface"));
            let override_kind = Self::first_scalar(&entry, &[&["override_kind"]])
                .unwrap_or_else(|| String::from("override"));
            let target = Self::target_label(
                Self::first_scalar(&entry, &[&["target_kind"]]).as_deref(),
                Self::first_scalar(&entry, &[&["target_id"]]).as_deref(),
            );
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["reason"]]),
                Self::first_scalar(&entry, &[&["requested_by"]])
                    .map(|value| format!("requested by {value}")),
                Self::first_scalar(&entry, &[&["activated_by"]])
                    .map(|value| format!("activated by {value}")),
                Self::first_scalar(&entry, &[&["reverted_by"]])
                    .map(|value| format!("reverted by {value}")),
                Self::first_scalar(&entry, &[&["expires_at"]])
                    .map(|value| format!("expires {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("override")),
                source: String::from("governance"),
                status: status.clone(),
                summary: format!("{surface} {override_kind} override for {target}"),
                context,
                updated_at,
                sort_at,
                attention: matches!(status.as_str(), "pending" | "active"),
            });
        }

        for entry in reveal_entries {
            let grant_kind = Self::first_scalar(&entry, &[&["grant_kind"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("grant"));
            let reveal_count = Self::first_u64(&entry, &[&["reveal_count"]]).unwrap_or(0);
            let expires_at = Self::first_scalar(&entry, &[&["expires_at"]]);
            let status = if expires_at
                .as_deref()
                .and_then(Self::parse_timestamp)
                .is_some_and(|expires_at| now > expires_at)
            {
                String::from("expired")
            } else if grant_kind == "approval" && reveal_count > 0 {
                String::from("consumed")
            } else {
                String::from("active")
            };
            let secret_id = Self::first_scalar(&entry, &[&["secret_id"]])
                .unwrap_or_else(|| String::from("unknown secret"));
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["reason"]]),
                Self::first_scalar(&entry, &[&["granted_by"]])
                    .map(|value| format!("granted by {value}")),
                expires_at.map(|value| format!("expires {value}")),
                (reveal_count > 0).then(|| {
                    format!(
                        "{reveal_count} reveal{}",
                        if reveal_count == 1 { "" } else { "s" }
                    )
                }),
                Self::first_scalar(&entry, &[&["last_revealed_by"]])
                    .map(|value| format!("last used by {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("reveal-grant")),
                source: String::from("secrets"),
                status: status.clone(),
                summary: format!(
                    "{} reveal grant for {secret_id}",
                    Self::display_status(&grant_kind)
                ),
                context,
                updated_at,
                sort_at,
                attention: status == "active",
            });
        }

        Self::build_lane(
            records,
            vec![override_source, reveal_source],
            "pending or active",
            Some(String::from(
                "Aggregates governance exposure overrides and secret reveal grants as the current auditable operator grant surface.",
            )),
        )
    }

    fn quota_lane(root: &Path) -> WorkbenchLane {
        let (budget_source, budget_entries) =
            Self::read_source_entries(root, "Billing budgets", "billing/budgets.json");
        let (burn_source, burn_entries) =
            Self::read_source_entries(root, "Budget burn tracking", "billing/budget_burn.json");
        let (notification_source, notification_entries) = Self::read_source_entries(
            root,
            "Budget notifications",
            "billing/budget_notifications.json",
        );
        let (support_entitlement_source, support_entitlement_entries) = Self::read_source_entries(
            root,
            "Billing support entitlements",
            "billing/support_entitlements.json",
        );
        let (support_entitlement_count, support_tier_totals) =
            Self::summarize_support_entitlements(&support_entitlement_entries);
        let mut latest_burn_by_budget =
            BTreeMap::<String, (u64, Option<String>, Option<OffsetDateTime>)>::new();
        let mut notification_counts = BTreeMap::<String, u64>::new();
        let mut latest_notification_by_budget = BTreeMap::<
            String,
            (
                String,
                Option<u64>,
                Option<String>,
                Option<String>,
                Option<OffsetDateTime>,
            ),
        >::new();

        for entry in burn_entries {
            let Some(budget_id) = Self::first_scalar(&entry, &[&["budget_id"]]) else {
                continue;
            };
            let burn_cents = Self::first_u64(&entry, &[&["resulting_burn_cents"]]).unwrap_or(0);
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let replace = latest_burn_by_budget
                .get(&budget_id)
                .map(|(_, _, existing_sort_at)| {
                    Self::timestamp_is_newer(sort_at, *existing_sort_at)
                })
                .unwrap_or(true);
            if replace {
                latest_burn_by_budget.insert(budget_id, (burn_cents, updated_at, sort_at));
            }
        }

        for entry in notification_entries {
            let Some(budget_id) = Self::first_scalar(&entry, &[&["budget_id"]]) else {
                continue;
            };
            *notification_counts.entry(budget_id.clone()).or_default() += 1;
            let status = Self::first_scalar(&entry, &[&["kind"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("threshold_reached"));
            let threshold_percentage = Self::first_u64(&entry, &[&["threshold_percentage"]]);
            let message = Self::first_scalar(&entry, &[&["message"]]);
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let replace = latest_notification_by_budget
                .get(&budget_id)
                .map(|(_, _, _, _, existing_sort_at)| {
                    Self::timestamp_is_newer(sort_at, *existing_sort_at)
                })
                .unwrap_or(true);
            if replace {
                latest_notification_by_budget.insert(
                    budget_id,
                    (status, threshold_percentage, message, updated_at, sort_at),
                );
            }
        }

        let mut records = Vec::new();
        for entry in budget_entries {
            let budget_id =
                Self::first_scalar(&entry, &[&["id"]]).unwrap_or_else(|| String::from("budget"));
            let budget_name = Self::first_scalar(&entry, &[&["name"]])
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| budget_id.clone());
            let active = Self::first_bool(&entry, &[&["active"]]).unwrap_or(true);
            let amount_cents = Self::first_u64(&entry, &[&["amount_cents"]]).unwrap_or(0);
            let cap_behavior = Self::first_scalar(&entry, &[&["cap_behavior"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("soft"));
            let burn = latest_burn_by_budget.get(&budget_id);
            let current_burn_cents = burn.map(|(burn, _, _)| *burn).unwrap_or(0);
            let latest_notification = latest_notification_by_budget.get(&budget_id);
            let status = if !active {
                String::from("inactive")
            } else if let Some((kind, _, _, _, _)) = latest_notification {
                match kind.as_str() {
                    "hard_cap_blocked" => String::from("hard_cap_blocked"),
                    "soft_cap_exceeded" => String::from("soft_cap_exceeded"),
                    "threshold_reached" => String::from("threshold_reached"),
                    _ if amount_cents > 0 && current_burn_cents >= amount_cents => {
                        String::from("over_cap")
                    }
                    _ if current_burn_cents > 0 => String::from("tracking"),
                    _ => String::from("healthy"),
                }
            } else if amount_cents > 0 && current_burn_cents >= amount_cents {
                String::from("over_cap")
            } else if current_burn_cents > 0 {
                String::from("tracking")
            } else {
                String::from("healthy")
            };
            let usage = if amount_cents > 0 {
                format!(
                    "burn {current_burn_cents}/{amount_cents} cents ({}%)",
                    current_burn_cents.saturating_mul(100) / amount_cents
                )
            } else if current_burn_cents > 0 {
                format!("burn {current_burn_cents} cents")
            } else {
                String::from("no burn recorded")
            };
            let notification_context =
                latest_notification.map(|(kind, threshold_percentage, message, _, _)| {
                    let mut summary = match (kind.as_str(), threshold_percentage) {
                        ("threshold_reached", Some(percentage)) => {
                            format!("latest threshold {percentage}% reached")
                        }
                        ("threshold_reached", None) => String::from("latest threshold reached"),
                        _ => format!("latest {}", Self::display_status(kind)),
                    };
                    if let Some(message) = message.as_deref()
                        && !message.trim().is_empty()
                    {
                        summary.push_str(": ");
                        summary.push_str(message);
                    }
                    summary
                });
            let notification_count = notification_counts
                .get(&budget_id)
                .copied()
                .filter(|count| *count > 0)
                .map(|count| format!("{count} notification{}", if count == 1 { "" } else { "s" }));
            let (budget_updated_at, budget_sort_at) = Self::record_timestamp(&entry);
            let updated_at = latest_notification
                .and_then(|(_, _, _, updated_at, _)| updated_at.clone())
                .or_else(|| burn.and_then(|(_, updated_at, _)| updated_at.clone()))
                .or(budget_updated_at);
            let sort_at = latest_notification
                .and_then(|(_, _, _, _, sort_at)| *sort_at)
                .or_else(|| burn.and_then(|(_, _, sort_at)| *sort_at))
                .or(budget_sort_at);
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["billing_account_id"]])
                    .map(|value| format!("billing account {value}")),
                Some(format!("{} cap", Self::display_status(&cap_behavior))),
                Some(usage),
                notification_context,
                notification_count,
            ]);

            records.push(WorkbenchRecord {
                id: budget_id,
                source: String::from("billing"),
                status: status.clone(),
                summary: format!(
                    "{budget_name} ({} cap)",
                    Self::display_status(&cap_behavior)
                ),
                context,
                updated_at,
                sort_at,
                attention: matches!(
                    status.as_str(),
                    "threshold_reached" | "soft_cap_exceeded" | "hard_cap_blocked" | "over_cap"
                ),
            });
        }

        let note = Some(Self::quota_lane_note(
            support_entitlement_source.available,
            support_entitlement_count,
            &support_tier_totals,
        ));
        let mut lane = Self::build_lane(
            records,
            vec![
                budget_source,
                burn_source,
                notification_source,
                support_entitlement_source,
            ],
            "at risk or over cap",
            note,
        );
        if lane
            .sources
            .iter()
            .any(|source| source.path == "billing/support_entitlements.json" && source.available)
        {
            lane.support_entitlement_count = Some(support_entitlement_count);
            lane.support_tier_totals = Some(support_tier_totals);
        }
        lane
    }

    fn case_lane(root: &Path) -> WorkbenchLane {
        let now = OffsetDateTime::now_utc();
        let (case_source, case_entries) =
            Self::read_source_entries(root, "Abuse cases", "abuse/cases.json");
        let (support_case_source, support_case_entries) =
            Self::read_source_entries(root, "Support cases", "abuse/support_cases.json");
        let (remediation_source, remediation_entries) =
            Self::read_source_entries(root, "Remediation cases", "abuse/remediation_cases.json");
        let (notify_source, notify_entries) = Self::read_source_entries(
            root,
            "Case-linked notifications",
            "notify/notifications.json",
        );
        let notify_by_id = Self::entries_by_id(&notify_entries);
        let notify_by_case_reference = Self::entries_by_case_reference(&notify_entries);
        let mut claimed_case_references = BTreeSet::new();
        let mut claimed_notification_ids = BTreeSet::new();
        let mut records = Vec::new();

        for entry in case_entries {
            let case_id =
                Self::first_scalar(&entry, &[&["id"]]).unwrap_or_else(|| String::from("case"));
            claimed_case_references.insert(case_id.clone());
            let status = Self::first_scalar(&entry, &[&["status"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("open"));
            let subject = Self::target_label(
                Self::first_scalar(&entry, &[&["subject_kind"]]).as_deref(),
                Self::first_scalar(&entry, &[&["subject"]]).as_deref(),
            );
            let reason = Self::first_scalar(&entry, &[&["reason"]])
                .unwrap_or_else(|| String::from("no reason provided"));
            let notify_summary = notify_by_case_reference
                .get(&case_id)
                .map(|entries| Self::summarize_notify_case_workflow(entries, now));
            let (case_updated_at, case_sort_at) = Self::record_timestamp(&entry);
            let notify_updated_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_updated_at.clone());
            let notify_sort_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_sort_at);
            let (updated_at, sort_at) = Self::newest_timestamp_pair(
                case_updated_at,
                case_sort_at,
                notify_updated_at,
                notify_sort_at,
            );
            let context = Self::join_context(vec![
                Self::first_scalar(&entry, &[&["priority"]])
                    .map(|value| format!("priority {value}")),
                Self::first_scalar(&entry, &[&["assigned_to"]])
                    .map(|value| format!("assigned to {value}")),
                Self::first_u64(&entry, &[&["escalation_count"]])
                    .filter(|value| *value > 0)
                    .map(|value| {
                        format!("{value} escalation{}", if value == 1 { "" } else { "s" })
                    }),
                notify_summary
                    .as_ref()
                    .and_then(Self::notify_case_workflow_context),
            ]);

            records.push(WorkbenchRecord {
                id: case_id,
                source: String::from("abuse"),
                status: status.clone(),
                summary: format!("{subject} · {reason}"),
                context,
                updated_at,
                sort_at,
                attention: !matches!(status.as_str(), "resolved" | "dismissed" | "closed")
                    || notify_summary
                        .as_ref()
                        .is_some_and(NotifyCaseWorkflowSummary::needs_attention),
            });
        }

        for entry in support_case_entries {
            let support_case_id = Self::first_scalar(&entry, &[&["id"]])
                .unwrap_or_else(|| String::from("support-case"));
            claimed_case_references.insert(support_case_id.clone());
            let linked_notifications = Self::linked_notifications_for_support_case(
                &entry,
                &notify_by_id,
                &notify_by_case_reference,
            );
            claimed_notification_ids.extend(Self::notification_ids(&linked_notifications));
            let notify_summary = (!linked_notifications.is_empty())
                .then(|| Self::summarize_notify_case_workflow(&linked_notifications, now));
            let support_status = Self::first_scalar(&entry, &[&["status"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("open"));
            let tenant_subject = Self::first_scalar(&entry, &[&["tenant_subject"]])
                .unwrap_or_else(|| String::from("unknown tenant"));
            let reason = Self::first_scalar(&entry, &[&["reason"]])
                .unwrap_or_else(|| String::from("operator support workflow"));
            let (case_updated_at, case_sort_at) = Self::record_timestamp(&entry);
            let notify_updated_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_updated_at.clone());
            let notify_sort_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_sort_at);
            let (updated_at, sort_at) = Self::newest_timestamp_pair(
                case_updated_at,
                case_sort_at,
                notify_updated_at,
                notify_sort_at,
            );
            let status = notify_summary
                .as_ref()
                .map(|summary| summary.status().to_owned())
                .unwrap_or_else(|| support_status.clone());
            let context = Self::join_context(vec![
                Self::support_case_lane_context(&entry),
                notify_summary
                    .as_ref()
                    .and_then(Self::notify_case_workflow_context),
            ]);

            records.push(WorkbenchRecord {
                id: support_case_id,
                source: String::from("support"),
                status,
                summary: format!("{tenant_subject} · {reason}"),
                context,
                updated_at,
                sort_at,
                attention: notify_summary
                    .as_ref()
                    .is_none_or(NotifyCaseWorkflowSummary::needs_attention),
            });
        }

        for entry in remediation_entries {
            let remediation_id = Self::first_scalar(&entry, &[&["id"]])
                .unwrap_or_else(|| String::from("remediation-case"));
            claimed_case_references.insert(remediation_id.clone());
            let linked_notifications = Self::string_list_at_path(&entry, &["notify_message_ids"])
                .into_iter()
                .filter_map(|notification_id| notify_by_id.get(&notification_id).cloned())
                .collect::<Vec<_>>();
            let notify_summary = (!linked_notifications.is_empty())
                .then(|| Self::summarize_notify_case_workflow(&linked_notifications, now));
            let remediation_summary = Self::remediation_case_workflow_summary(&entry);
            let tenant_subject = Self::first_scalar(&entry, &[&["tenant_subject"]])
                .unwrap_or_else(|| String::from("unknown tenant"));
            let reason = Self::first_scalar(&entry, &[&["reason"]])
                .unwrap_or_else(|| String::from("operator remediation workflow"));
            let abuse_case_count =
                Self::string_list_at_path(&entry, &["abuse_case_ids"]).len() as u64;
            let quarantine_count =
                Self::string_list_at_path(&entry, &["quarantine_ids"]).len() as u64;
            let change_request_count =
                Self::string_list_at_path(&entry, &["change_request_ids"]).len() as u64;
            let (case_updated_at, case_sort_at) = Self::record_timestamp(&entry);
            let notify_updated_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_updated_at.clone());
            let notify_sort_at = notify_summary
                .as_ref()
                .and_then(|summary| summary.latest_sort_at);
            let (updated_at, sort_at) = Self::newest_timestamp_pair(
                case_updated_at,
                case_sort_at,
                notify_updated_at,
                notify_sort_at,
            );
            let status = remediation_summary.status(notify_summary.as_ref());
            let context = Self::join_context(vec![
                Some(format!("tenant {tenant_subject}")),
                Self::remediation_case_workflow_context(&remediation_summary),
                (abuse_case_count > 0).then(|| {
                    format!(
                        "{abuse_case_count} abuse case{}",
                        if abuse_case_count == 1 { "" } else { "s" }
                    )
                }),
                (quarantine_count > 0).then(|| {
                    format!(
                        "{quarantine_count} quarantine{}",
                        if quarantine_count == 1 { "" } else { "s" }
                    )
                }),
                (change_request_count > 0).then(|| {
                    format!(
                        "{change_request_count} change request{}",
                        if change_request_count == 1 { "" } else { "s" }
                    )
                }),
                notify_summary
                    .as_ref()
                    .and_then(Self::notify_case_workflow_context),
            ]);

            records.push(WorkbenchRecord {
                id: remediation_id,
                source: String::from("remediation"),
                status: status.clone(),
                summary: format!("{tenant_subject} · {reason}"),
                context,
                updated_at,
                sort_at,
                attention: remediation_summary.needs_attention(notify_summary.as_ref()),
            });
        }

        for (case_reference, entries) in notify_by_case_reference {
            let entries = entries
                .into_iter()
                .filter(|entry| {
                    Self::first_scalar(entry, &[&["id"]]).is_none_or(|notification_id| {
                        !claimed_notification_ids.contains(&notification_id)
                    })
                })
                .collect::<Vec<_>>();
            if entries.is_empty() {
                continue;
            }
            if claimed_case_references.contains(&case_reference) {
                continue;
            }
            let notify_summary = Self::summarize_notify_case_workflow(&entries, now);
            records.push(WorkbenchRecord {
                id: case_reference.clone(),
                source: String::from("notify"),
                status: notify_summary.status().to_owned(),
                summary: format!("notify workflow for {case_reference}"),
                context: Self::notify_case_workflow_context(&notify_summary),
                updated_at: notify_summary.latest_updated_at.clone(),
                sort_at: notify_summary.latest_sort_at,
                attention: notify_summary.needs_attention(),
            });
        }

        Self::build_lane(
            records,
            vec![
                case_source,
                support_case_source,
                remediation_source,
                notify_source,
            ],
            "open, escalated, or missing evidence",
            Some(String::from(
                "Read-only queue of abuse cases, support cases, remediation cases, and case-linked notify workflows, including remediation evidence posture.",
            )),
        )
    }

    fn appeal_lane(root: &Path) -> WorkbenchLane {
        let (source, entries) = Self::read_source_entries(root, "Appeals", "abuse/appeals.json");
        let mut records = Vec::new();

        for entry in entries {
            let status = Self::first_scalar(&entry, &[&["status"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("pending"));
            let case_id = Self::first_scalar(&entry, &[&["case_id"]])
                .unwrap_or_else(|| String::from("unknown case"));
            let subject = Self::target_label(
                Self::first_scalar(&entry, &[&["subject_kind"]]).as_deref(),
                Self::first_scalar(&entry, &[&["subject"]]).as_deref(),
            );
            let reason = Self::first_scalar(&entry, &[&["reason"]])
                .unwrap_or_else(|| String::from("no reason provided"));
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let context = Self::join_context(vec![
                Some(format!("case {case_id}")),
                Some(subject),
                Self::first_scalar(&entry, &[&["requested_by"]])
                    .map(|value| format!("requested by {value}")),
                Self::first_scalar(&entry, &[&["reviewed_by"]])
                    .map(|value| format!("reviewed by {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("appeal")),
                source: String::from("abuse"),
                status: status.clone(),
                summary: reason,
                context,
                updated_at,
                sort_at,
                attention: status == "pending",
            });
        }

        Self::build_lane(
            records,
            vec![source],
            "pending review",
            Some(String::from(
                "Appeals queue for quarantine, suspension, and case review reversals.",
            )),
        )
    }

    fn dead_letter_lane(root: &Path) -> WorkbenchLane {
        let now = OffsetDateTime::now_utc();
        let (notify_source, notify_entries) = Self::read_source_entries(
            root,
            "Notification dead letters",
            "notify/dead_letters.json",
        );
        let (notify_workflow_source, notify_workflow_entries) = Self::read_source_entries(
            root,
            "Notification workflow state",
            "notify/notifications.json",
        );
        let (support_case_source, support_case_entries) =
            Self::read_source_entries(root, "Support cases", "abuse/support_cases.json");
        let (mail_source, mail_entries) =
            Self::read_source_entries(root, "Mail dead letters", "mail/dead_letters.json");
        let (lifecycle_source, lifecycle_entries) = Self::read_source_entries(
            root,
            "Lifecycle dead letters",
            "lifecycle/dead_letters.json",
        );
        let notify_by_id = Self::entries_by_id(&notify_workflow_entries);
        let support_cases_by_id = Self::entries_by_id(&support_case_entries);
        let support_cases_by_notify_message_id =
            Self::entries_by_notify_message_id(&support_case_entries);
        let mut records = Vec::new();

        for entry in notify_entries {
            let replay_count = Self::first_u64(&entry, &[&["replay_count"]]).unwrap_or(0);
            let replayed_at = Self::first_scalar(&entry, &[&["last_replayed_at"]]);
            let status = if replay_count > 0 || replayed_at.is_some() {
                String::from("replayed")
            } else {
                String::from("pending_replay")
            };
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let channel = Self::first_scalar(&entry, &[&["channel"]])
                .unwrap_or_else(|| String::from("notification"));
            let destination = Self::first_scalar(&entry, &[&["destination"]])
                .unwrap_or_else(|| String::from("unknown destination"));
            let notify_context = Self::first_scalar(&entry, &[&["notification_id"]])
                .and_then(|notification_id| notify_by_id.get(&notification_id))
                .and_then(|notification| {
                    let support_case = Self::support_case_for_notification(
                        notification,
                        &support_cases_by_id,
                        &support_cases_by_notify_message_id,
                    );
                    Self::notification_workflow_context(notification, now, support_case)
                });
            let context = Self::join_context(vec![
                Self::first_u64(&entry, &[&["attempts"]])
                    .map(|value| format!("{value} attempt{}", if value == 1 { "" } else { "s" })),
                Self::first_scalar(&entry, &[&["last_error"]]),
                Self::first_scalar(&entry, &[&["last_replay_reason"]])
                    .map(|value| format!("last replay: {value}")),
                notify_context,
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("notify-dead-letter")),
                source: String::from("notify"),
                status: status.clone(),
                summary: format!("{channel} to {destination}"),
                context,
                updated_at,
                sort_at,
                attention: status == "pending_replay",
            });
        }

        for entry in mail_entries {
            let replay_count = Self::first_u64(&entry, &[&["replay_count"]]).unwrap_or(0);
            let replayed_at = Self::first_scalar(&entry, &[&["last_replayed_at"]]);
            let status = if replay_count > 0 || replayed_at.is_some() {
                String::from("replayed")
            } else {
                String::from("pending_replay")
            };
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let direction = Self::first_scalar(&entry, &[&["direction"]])
                .unwrap_or_else(|| String::from("mail"));
            let from = Self::first_scalar(&entry, &[&["from"]])
                .unwrap_or_else(|| String::from("unknown sender"));
            let to = Self::first_scalar(&entry, &[&["to"]])
                .unwrap_or_else(|| String::from("unknown recipient"));
            let context = Self::join_context(vec![
                Self::first_u64(&entry, &[&["attempts"]])
                    .map(|value| format!("{value} attempt{}", if value == 1 { "" } else { "s" })),
                Self::first_scalar(&entry, &[&["last_error"]]),
                Self::first_scalar(&entry, &[&["domain_id"]])
                    .map(|value| format!("domain {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("mail-dead-letter")),
                source: String::from("mail"),
                status: status.clone(),
                summary: format!("{direction} {from} -> {to}"),
                context,
                updated_at,
                sort_at,
                attention: status == "pending_replay",
            });
        }

        for entry in lifecycle_entries {
            let replayed = Self::first_bool(&entry, &[&["replayed"]]).unwrap_or(false);
            let repair_job_id = Self::first_scalar(&entry, &[&["repair_job_id"]]);
            let status = if replayed {
                String::from("replayed")
            } else if repair_job_id.is_some()
                || Self::first_scalar(&entry, &[&["repair_requested_at"]]).is_some()
            {
                String::from("repair_requested")
            } else {
                String::from("pending_replay")
            };
            let (updated_at, sort_at) = Self::record_timestamp(&entry);
            let context = Self::join_context(vec![
                Self::first_u64(&entry, &[&["attempts"]])
                    .map(|value| format!("{value} attempt{}", if value == 1 { "" } else { "s" })),
                Self::first_scalar(&entry, &[&["error"]]),
                repair_job_id.map(|value| format!("repair job {value}")),
            ]);

            records.push(WorkbenchRecord {
                id: Self::first_scalar(&entry, &[&["id"]])
                    .unwrap_or_else(|| String::from("lifecycle-dead-letter")),
                source: String::from("lifecycle"),
                status: status.clone(),
                summary: Self::first_scalar(&entry, &[&["topic"]])
                    .unwrap_or_else(|| String::from("lifecycle dead letter")),
                context,
                updated_at,
                sort_at,
                attention: !replayed,
            });
        }

        Self::build_lane(
            records,
            vec![
                notify_source,
                notify_workflow_source,
                support_case_source,
                mail_source,
                lifecycle_source,
            ],
            "await replay",
            Some(String::from(
                "Aggregates dead letters across notify, mail, and lifecycle operators, enriched with notify acknowledgment and escalation state when available.",
            )),
        )
    }

    fn entries_by_id(entries: &[Value]) -> BTreeMap<String, Value> {
        let mut indexed = BTreeMap::new();
        for entry in entries {
            if let Some(id) = Self::first_scalar(entry, &[&["id"]]) {
                indexed.insert(id, entry.clone());
            }
        }
        indexed
    }

    fn entries_by_case_reference(entries: &[Value]) -> BTreeMap<String, Vec<Value>> {
        let mut indexed = BTreeMap::new();
        for entry in entries {
            if let Some(case_reference) = Self::first_scalar(entry, &[&["case_reference"]]) {
                indexed
                    .entry(case_reference)
                    .or_insert_with(Vec::new)
                    .push(entry.clone());
            }
        }
        indexed
    }

    fn entries_by_notify_message_id(entries: &[Value]) -> BTreeMap<String, Vec<Value>> {
        let mut indexed = BTreeMap::new();
        for entry in entries {
            for notification_id in Self::string_list_at_path(entry, &["notify_message_ids"]) {
                indexed
                    .entry(notification_id)
                    .or_insert_with(Vec::new)
                    .push(entry.clone());
            }
        }
        indexed
    }

    fn notification_ids(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .filter_map(|entry| Self::first_scalar(entry, &[&["id"]]))
            .collect()
    }

    fn linked_notifications_for_support_case(
        entry: &Value,
        notify_by_id: &BTreeMap<String, Value>,
        notify_by_case_reference: &BTreeMap<String, Vec<Value>>,
    ) -> Vec<Value> {
        let mut linked = BTreeMap::new();

        for notification_id in Self::string_list_at_path(entry, &["notify_message_ids"]) {
            if let Some(notification) = notify_by_id.get(&notification_id) {
                linked.insert(notification_id, notification.clone());
            }
        }

        if let Some(case_id) = Self::first_scalar(entry, &[&["id"]])
            && let Some(entries) = notify_by_case_reference.get(&case_id)
        {
            for notification in entries {
                if let Some(notification_id) = Self::first_scalar(notification, &[&["id"]]) {
                    linked
                        .entry(notification_id)
                        .or_insert_with(|| notification.clone());
                }
            }
        }

        linked.into_values().collect()
    }

    fn support_case_for_notification<'a>(
        notification: &Value,
        support_cases_by_id: &'a BTreeMap<String, Value>,
        support_cases_by_notify_message_id: &'a BTreeMap<String, Vec<Value>>,
    ) -> Option<&'a Value> {
        let mut matches = notification
            .as_object()
            .and_then(|_| Self::first_scalar(notification, &[&["id"]]))
            .and_then(|notification_id| {
                support_cases_by_notify_message_id
                    .get(&notification_id)
                    .cloned()
            })
            .unwrap_or_default();

        if let Some(case_reference) = Self::first_scalar(notification, &[&["case_reference"]])
            && let Some(support_case) = support_cases_by_id.get(&case_reference)
        {
            matches.push(support_case.clone());
        }

        matches
            .iter()
            .max_by(|left, right| {
                let (_, left_sort_at) = Self::record_timestamp(left);
                let (_, right_sort_at) = Self::record_timestamp(right);
                left_sort_at.cmp(&right_sort_at)
            })
            .and_then(|selected| {
                Self::first_scalar(selected, &[&["id"]])
                    .and_then(|support_case_id| support_cases_by_id.get(&support_case_id))
            })
    }

    fn string_list_at_path(value: &Value, path: &[&str]) -> Vec<String> {
        Self::value_at_path(value, path)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn summarize_notify_case_workflow(
        entries: &[Value],
        now: OffsetDateTime,
    ) -> NotifyCaseWorkflowSummary {
        let mut summary = NotifyCaseWorkflowSummary::default();

        for entry in entries {
            summary.notification_count = summary.notification_count.saturating_add(1);
            let (updated_at, sort_at) = Self::record_timestamp(entry);
            let delivery_state = Self::first_scalar(entry, &[&["state"]])
                .map(Self::normalize_status)
                .unwrap_or_else(|| String::from("tracked"));
            if Self::timestamp_is_newer(sort_at, summary.latest_sort_at) {
                summary.latest_sort_at = sort_at;
                summary.latest_updated_at = updated_at;
                summary.latest_delivery_state = Some(delivery_state.clone());
            }

            if let Some(acknowledged_at) = Self::first_scalar(entry, &[&["acknowledged_at"]]) {
                summary.acknowledged_count = summary.acknowledged_count.saturating_add(1);
                let acknowledged_sort_at = Self::parse_timestamp(&acknowledged_at);
                if Self::timestamp_is_newer(acknowledged_sort_at, summary.latest_ack_sort_at) {
                    summary.latest_ack_sort_at = acknowledged_sort_at;
                    summary.latest_acknowledged_by =
                        Self::first_scalar(entry, &[&["acknowledged_by"]]);
                    summary.latest_acknowledgement_note =
                        Self::first_scalar(entry, &[&["acknowledgement_note"]]);
                }
            }

            let active_snooze_until =
                Self::first_scalar(entry, &[&["snoozed_until"]]).filter(|timestamp| {
                    Self::parse_timestamp(timestamp).is_some_and(|until| until > now)
                });
            if active_snooze_until.is_some() {
                summary.snoozed_count = summary.snoozed_count.saturating_add(1);
                let snooze_sort_at = active_snooze_until
                    .as_deref()
                    .and_then(Self::parse_timestamp);
                if Self::timestamp_is_newer(snooze_sort_at, summary.latest_snooze_sort_at) {
                    summary.latest_snooze_sort_at = snooze_sort_at;
                    summary.latest_snoozed_until = active_snooze_until;
                    summary.latest_snoozed_by = Self::first_scalar(entry, &[&["snoozed_by"]]);
                    summary.latest_snooze_reason = Self::first_scalar(entry, &[&["snooze_reason"]]);
                }
            }

            let escalation_count = Self::first_u64(entry, &[&["escalation_count"]]).unwrap_or(0);
            let latest_escalated_notification_id =
                Self::first_scalar(entry, &[&["last_escalated_notification_id"]]);
            if escalation_count > 0 || latest_escalated_notification_id.is_some() {
                summary.escalated_count = summary
                    .escalated_count
                    .saturating_add(escalation_count.max(1));
                let escalate_sort_at = Self::first_scalar(entry, &[&["last_escalated_at"]])
                    .as_deref()
                    .and_then(Self::parse_timestamp)
                    .or(sort_at);
                if Self::timestamp_is_newer(escalate_sort_at, summary.latest_escalate_sort_at) {
                    summary.latest_escalate_sort_at = escalate_sort_at;
                    summary.latest_escalated_by =
                        Self::first_scalar(entry, &[&["last_escalated_by"]]);
                    summary.latest_escalated_notification_id = latest_escalated_notification_id;
                }
            }

            if delivery_state == "dead_lettered" {
                summary.dead_lettered_count = summary.dead_lettered_count.saturating_add(1);
            }

            if let Some((event_summary, event_sort_at)) =
                Self::latest_notification_history_summary(entry)
                && Self::timestamp_is_newer(event_sort_at, summary.latest_event_sort_at)
            {
                summary.latest_event_sort_at = event_sort_at;
                summary.latest_workflow_event = Some(event_summary);
            }
        }

        summary
    }

    fn notify_case_workflow_context(summary: &NotifyCaseWorkflowSummary) -> Option<String> {
        Self::join_context(vec![
            (summary.notification_count > 0).then(|| {
                format!(
                    "{} notify message{}",
                    summary.notification_count,
                    if summary.notification_count == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            }),
            (summary.acknowledged_count > 0).then(|| {
                match summary.latest_acknowledged_by.as_deref() {
                    Some(actor) => {
                        format!("{} acknowledged by {actor}", summary.acknowledged_count)
                    }
                    None => format!("{} acknowledged", summary.acknowledged_count),
                }
            }),
            summary
                .latest_acknowledgement_note
                .as_ref()
                .map(|note| format!("ack note {note}")),
            (summary.snoozed_count > 0).then(|| match summary.latest_snoozed_until.as_deref() {
                Some(until) => format!("{} snoozed until {until}", summary.snoozed_count),
                None => format!("{} snoozed", summary.snoozed_count),
            }),
            summary
                .latest_snoozed_by
                .as_ref()
                .map(|actor| format!("snoozed by {actor}")),
            summary
                .latest_snooze_reason
                .as_ref()
                .map(|reason| format!("snooze reason {reason}")),
            (summary.escalated_count > 0).then(|| {
                format!(
                    "{} escalation{}",
                    summary.escalated_count,
                    if summary.escalated_count == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            }),
            summary
                .latest_escalated_by
                .as_ref()
                .map(|actor| format!("last escalated by {actor}")),
            summary
                .latest_escalated_notification_id
                .as_ref()
                .map(|notification_id| format!("follow-up {notification_id}")),
            (summary.dead_lettered_count > 0)
                .then(|| format!("{} dead-lettered", summary.dead_lettered_count)),
            summary.latest_workflow_event.clone(),
        ])
    }

    fn support_case_lane_context(entry: &Value) -> Option<String> {
        let remediation_case_count =
            Self::string_list_at_path(entry, &["remediation_case_ids"]).len() as u64;
        let change_request_count =
            Self::string_list_at_path(entry, &["change_request_ids"]).len() as u64;

        Self::join_context(vec![
            Some(format!(
                "tenant {}",
                Self::first_scalar(entry, &[&["tenant_subject"]])
                    .unwrap_or_else(|| String::from("unknown tenant"))
            )),
            Self::first_scalar(entry, &[&["owner"]]).map(|value| format!("owner {value}")),
            Self::first_scalar(entry, &[&["owner_assigned_at"]])
                .map(|value| format!("owned since {value}")),
            Self::first_scalar(entry, &[&["opened_by"]]).map(|value| format!("opened by {value}")),
            Self::first_scalar(entry, &[&["status"]])
                .map(Self::normalize_status)
                .map(|value| format!("support status {}", Self::display_status(&value))),
            Self::first_scalar(entry, &[&["priority"]]).map(|value| format!("priority {value}")),
            (remediation_case_count > 0).then(|| {
                format!(
                    "{remediation_case_count} remediation case{}",
                    if remediation_case_count == 1 { "" } else { "s" }
                )
            }),
            (change_request_count > 0).then(|| {
                format!(
                    "{change_request_count} change request{}",
                    if change_request_count == 1 { "" } else { "s" }
                )
            }),
        ])
    }

    fn support_case_notification_context(entry: &Value) -> Option<String> {
        Self::join_context(vec![
            Self::first_scalar(entry, &[&["id"]]).map(|value| format!("support case {value}")),
            Self::first_scalar(entry, &[&["tenant_subject"]])
                .map(|value| format!("tenant {value}")),
            Self::first_scalar(entry, &[&["owner"]]).map(|value| format!("support owner {value}")),
            Self::first_scalar(entry, &[&["status"]])
                .map(Self::normalize_status)
                .map(|value| format!("support status {}", Self::display_status(&value))),
            Self::first_scalar(entry, &[&["priority"]])
                .map(|value| format!("support priority {value}")),
        ])
    }

    fn remediation_case_workflow_summary(entry: &Value) -> RemediationCaseWorkflowSummary {
        RemediationCaseWorkflowSummary {
            opened_by: Self::first_scalar(entry, &[&["opened_by"]]),
            owner: Self::first_scalar(entry, &[&["owner"]]),
            owner_assigned_at: Self::first_scalar(entry, &[&["owner_assigned_at"]]),
            rollback_evidence_count: Self::string_list_at_path(entry, &["rollback_evidence_refs"])
                .len() as u64,
            verification_evidence_count: Self::string_list_at_path(
                entry,
                &["verification_evidence_refs"],
            )
            .len() as u64,
            evidence_state: Self::first_scalar(entry, &[&["evidence_state"]])
                .map(Self::normalize_status),
            sla_target_seconds: Self::first_u64(entry, &[&["sla_target_seconds"]])
                .filter(|value| *value > 0),
            sla_deadline_at: Self::first_scalar(entry, &[&["sla_deadline_at"]]),
            sla_state: Self::first_scalar(entry, &[&["sla_state"]]).map(Self::normalize_status),
            escalation_state: Self::first_scalar(entry, &[&["escalation_state"]])
                .map(Self::normalize_status),
            escalation_count: Self::first_u64(entry, &[&["escalation_count"]]).unwrap_or(0),
            last_escalated_at: Self::first_scalar(entry, &[&["last_escalated_at"]]),
            last_escalated_by: Self::first_scalar(entry, &[&["last_escalated_by"]]),
            last_escalation_reason: Self::first_scalar(entry, &[&["last_escalation_reason"]]),
            workflow_steps: Self::remediation_workflow_steps(entry),
        }
    }

    fn remediation_workflow_steps(entry: &Value) -> Vec<RemediationWorkflowStepSummary> {
        let mut steps = Self::value_at_path(entry, &["workflow_steps"])
            .and_then(Value::as_array)
            .map(|steps| {
                steps
                    .iter()
                    .enumerate()
                    .filter_map(|(position, step)| {
                        let name =
                            Self::first_scalar(step, &[&["name"]]).map(Self::normalize_status)?;
                        let state =
                            Self::first_scalar(step, &[&["state"]]).map(Self::normalize_status)?;
                        Some(RemediationWorkflowStepSummary {
                            name,
                            index: Self::first_u64(step, &[&["index"]]).unwrap_or(position as u64),
                            state,
                            detail: Self::first_scalar(step, &[&["detail"]]),
                            updated_at: Self::first_scalar(step, &[&["updated_at"]]),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        steps.sort_by(|left, right| {
            left.index
                .cmp(&right.index)
                .then_with(|| left.name.cmp(&right.name))
        });
        steps
    }

    fn remediation_workflow_step_context(
        steps: &[RemediationWorkflowStepSummary],
    ) -> Option<String> {
        if steps.is_empty() {
            return None;
        }

        let completed_count = steps
            .iter()
            .filter(|step| step.state == "completed")
            .count();
        let focal_step = steps
            .iter()
            .find(|step| step.state == "failed")
            .or_else(|| steps.iter().find(|step| step.state == "active"))
            .or_else(|| steps.iter().find(|step| step.state == "pending"))
            .or_else(|| steps.iter().find(|step| step.state == "rolled_back"));

        Self::join_context(vec![
            Some(format!(
                "{completed_count}/{} workflow steps completed",
                steps.len()
            )),
            focal_step.map(|step| {
                format!(
                    "workflow {} {}",
                    Self::display_status(&step.name),
                    Self::display_status(&step.state)
                )
            }),
            focal_step.and_then(|step| step.detail.clone()),
        ])
    }

    fn remediation_workflow_trail_context(
        steps: &[RemediationWorkflowStepSummary],
    ) -> Option<String> {
        if steps.is_empty() {
            return None;
        }

        let trail = steps
            .iter()
            .map(|step| {
                let name = Self::display_status(&step.name);
                let state = Self::display_status(&step.state);
                let detail = step
                    .detail
                    .as_ref()
                    .filter(|detail| !detail.trim().is_empty())
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default();
                match step.updated_at.as_deref() {
                    Some(updated_at) if !updated_at.trim().is_empty() => {
                        format!("{updated_at} {name} {state}{detail}")
                    }
                    _ => format!("{name} {state}{detail}"),
                }
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        Some(format!("workflow trail {trail}"))
    }

    fn remediation_case_workflow_context(
        summary: &RemediationCaseWorkflowSummary,
    ) -> Option<String> {
        if !summary.has_operator_workflow_state() {
            return None;
        }

        let evidence_summary = summary
            .evidence_attention_status()
            .or_else(|| {
                summary
                    .evidence_state
                    .as_deref()
                    .filter(|state| !state.trim().is_empty())
                    .map(str::to_owned)
            })
            .map(|state| format!("evidence {}", Self::display_status(&state)));
        let opened_by = summary
            .opened_by
            .as_ref()
            .filter(|opened_by| summary.owner.as_deref() != Some(opened_by.as_str()))
            .map(|opened_by| format!("opened by {opened_by}"));
        let owner = Some(match summary.owner.as_deref() {
            Some(owner) => format!("owner {owner}"),
            None => String::from("owner unassigned"),
        });
        let sla_summary = match (
            summary.sla_state.as_deref(),
            summary.sla_deadline_at.as_deref(),
        ) {
            (Some(state), Some(deadline_at)) => Some(format!(
                "SLA {} by {deadline_at}",
                Self::display_status(state)
            )),
            (Some(state), None) => Some(format!("SLA {}", Self::display_status(state))),
            (None, Some(deadline_at)) => Some(format!("SLA deadline {deadline_at}")),
            (None, None) => None,
        };

        Self::join_context(vec![
            owner,
            opened_by,
            summary
                .owner_assigned_at
                .as_ref()
                .map(|assigned_at| format!("owned since {assigned_at}")),
            Self::remediation_workflow_step_context(&summary.workflow_steps),
            Self::remediation_workflow_trail_context(&summary.workflow_steps),
            evidence_summary,
            Some(format!(
                "{} rollback evidence ref{}",
                summary.rollback_evidence_count,
                if summary.rollback_evidence_count == 1 {
                    ""
                } else {
                    "s"
                }
            )),
            Some(format!(
                "{} verification evidence ref{}",
                summary.verification_evidence_count,
                if summary.verification_evidence_count == 1 {
                    ""
                } else {
                    "s"
                }
            )),
            summary
                .sla_target_seconds
                .map(|target_seconds| format!("SLA target {target_seconds}s")),
            sla_summary,
            summary
                .escalation_state
                .as_deref()
                .filter(|state| *state != "none")
                .map(|state| format!("escalation posture {}", Self::display_status(state))),
            (summary.escalation_count > 0).then(|| {
                format!(
                    "{} escalation{}",
                    summary.escalation_count,
                    if summary.escalation_count == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            }),
            summary
                .last_escalated_at
                .as_ref()
                .map(|escalated_at| format!("last escalation {escalated_at}")),
            summary
                .last_escalated_by
                .as_ref()
                .map(|actor| format!("last escalated by {actor}")),
            summary
                .last_escalation_reason
                .as_ref()
                .map(|reason| format!("escalation reason {reason}")),
        ])
    }

    fn notification_workflow_context(
        entry: &Value,
        now: OffsetDateTime,
        support_case: Option<&Value>,
    ) -> Option<String> {
        let active_snooze_until = Self::first_scalar(entry, &[&["snoozed_until"]])
            .filter(|timestamp| Self::parse_timestamp(timestamp).is_some_and(|until| until > now));
        let escalation_count = Self::first_u64(entry, &[&["escalation_count"]]).unwrap_or(0);

        Self::join_context(vec![
            support_case
                .and_then(Self::support_case_notification_context)
                .or_else(|| {
                    Self::first_scalar(entry, &[&["case_reference"]])
                        .map(|value| format!("case {value}"))
                }),
            Self::first_scalar(entry, &[&["acknowledged_by"]])
                .map(|value| format!("acknowledged by {value}")),
            Self::first_scalar(entry, &[&["acknowledgement_note"]])
                .map(|value| format!("ack note {value}")),
            active_snooze_until
                .clone()
                .map(|value| format!("snoozed until {value}")),
            active_snooze_until.as_ref().and_then(|_| {
                Self::first_scalar(entry, &[&["snoozed_by"]])
                    .map(|value| format!("snoozed by {value}"))
            }),
            active_snooze_until.as_ref().and_then(|_| {
                Self::first_scalar(entry, &[&["snooze_reason"]])
                    .map(|value| format!("snooze reason {value}"))
            }),
            (escalation_count > 0).then(|| {
                format!(
                    "{escalation_count} escalation{}",
                    if escalation_count == 1 { "" } else { "s" }
                )
            }),
            Self::first_scalar(entry, &[&["last_escalated_by"]])
                .map(|value| format!("last escalated by {value}")),
            Self::first_scalar(entry, &[&["last_escalated_notification_id"]])
                .map(|value| format!("follow-up {value}")),
            Self::latest_notification_history_summary(entry).map(|(summary, _)| summary),
        ])
    }

    fn latest_notification_history_summary(
        entry: &Value,
    ) -> Option<(String, Option<OffsetDateTime>)> {
        let history = Self::value_at_path(entry, &["history"])?.as_array()?;
        let latest = history.iter().max_by(|left, right| {
            let left_sequence = Self::first_u64(left, &[&["sequence"]]).unwrap_or(0);
            let right_sequence = Self::first_u64(right, &[&["sequence"]]).unwrap_or(0);
            left_sequence.cmp(&right_sequence)
        })?;
        let event = Self::first_scalar(latest, &[&["event"]]).map(Self::normalize_status)?;
        let detail = Self::first_scalar(latest, &[&["detail"]]);
        let summary = match detail {
            Some(detail) if !detail.trim().is_empty() => {
                format!(
                    "latest notify event {}: {detail}",
                    Self::display_status(&event)
                )
            }
            _ => format!("latest notify event {}", Self::display_status(&event)),
        };
        let occurred_at = Self::first_scalar(latest, &[&["occurred_at"]])
            .as_deref()
            .and_then(Self::parse_timestamp);
        Some((summary, occurred_at))
    }

    fn build_lane(
        mut records: Vec<WorkbenchRecord>,
        sources: Vec<WorkbenchSource>,
        attention_label: &str,
        note: Option<String>,
    ) -> WorkbenchLane {
        let statuses = Self::workbench_status_breakdown(&records);
        let attention_count = records.iter().filter(|record| record.attention).count() as u64;
        let available = sources.iter().any(|source| source.available);
        records.sort_by(|left, right| {
            right
                .sort_at
                .cmp(&left.sort_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        let entries = records
            .into_iter()
            .take(WORKBENCH_ENTRY_LIMIT)
            .map(|record| WorkbenchEntry {
                id: record.id,
                source: record.source,
                status: record.status,
                summary: record.summary,
                context: record.context,
                updated_at: record.updated_at,
            })
            .collect::<Vec<_>>();

        WorkbenchLane {
            count: CountSummary {
                count: statuses.iter().map(|entry| entry.count).sum(),
                available,
            },
            attention_count,
            attention_label: attention_label.to_string(),
            statuses,
            sources,
            entries,
            support_entitlement_count: None,
            support_tier_totals: None,
            note,
        }
    }

    fn summarize_support_entitlements(entries: &[Value]) -> (u64, BTreeMap<String, u64>) {
        let mut support_tier_totals = BTreeMap::new();
        for entry in entries {
            let Some(tier) = Self::first_scalar(entry, &[&["support_tier"]])
                .filter(|value| !value.trim().is_empty())
                .map(Self::normalize_status)
            else {
                continue;
            };
            *support_tier_totals.entry(tier).or_default() += 1;
        }

        (entries.len() as u64, support_tier_totals)
    }

    fn quota_lane_note(
        support_entitlements_available: bool,
        support_entitlement_count: u64,
        support_tier_totals: &BTreeMap<String, u64>,
    ) -> String {
        let mut note = String::from(
            "Derived from billing budgets, burn tracking, and threshold notifications as the current durable quota signal.",
        );
        if support_entitlements_available {
            note.push_str(" Support entitlements: ");
            note.push_str(&support_entitlement_count.to_string());
            note.push_str(" total");
            if let Some(tier_summary) = Self::support_tier_totals_summary(support_tier_totals) {
                note.push_str(" across ");
                note.push_str(&tier_summary);
            }
            note.push('.');
        }
        note
    }

    fn support_tier_totals_summary(totals: &BTreeMap<String, u64>) -> Option<String> {
        if totals.is_empty() {
            return None;
        }

        Some(
            totals
                .iter()
                .map(|(tier, count)| format!("{} ({count})", Self::display_status(tier)))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }

    fn read_source_entries(
        root: &Path,
        label: &str,
        relative_path: &str,
    ) -> (WorkbenchSource, Vec<Value>) {
        let path = root.join(relative_path);
        match Self::read_entries(&path) {
            Some(entries) => (
                WorkbenchSource {
                    label: label.to_string(),
                    path: relative_path.to_string(),
                    count: entries.len() as u64,
                    available: true,
                },
                entries,
            ),
            None => (
                WorkbenchSource {
                    label: label.to_string(),
                    path: relative_path.to_string(),
                    count: 0,
                    available: false,
                },
                Vec::new(),
            ),
        }
    }

    fn workbench_status_breakdown(records: &[WorkbenchRecord]) -> Vec<StatusSummary> {
        let mut counters: BTreeMap<String, u64> = BTreeMap::new();
        for record in records {
            *counters.entry(record.status.clone()).or_default() += 1;
        }

        let mut entries = counters
            .into_iter()
            .map(|(status, count)| StatusSummary { status, count })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| right.count.cmp(&left.count));
        entries
    }

    fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
        let mut current = value;
        for segment in path {
            let map = current.as_object()?;
            current = map.get(*segment)?;
        }
        Some(current)
    }

    fn first_scalar(value: &Value, paths: &[&[&str]]) -> Option<String> {
        paths
            .iter()
            .find_map(|path| Self::value_at_path(value, path).and_then(Self::scalar_string))
    }

    fn scalar_string(value: &Value) -> Option<String> {
        match value {
            Value::Null => None,
            Value::String(raw) => Some(raw.clone()),
            Value::Number(raw) => Some(raw.to_string()),
            Value::Bool(raw) => Some(raw.to_string()),
            // Persisted `time::OffsetDateTime` values use the crate's tuple form when
            // services serialize records directly to JSON. Normalize those real runtime
            // shapes so console aggregation can render operator-facing timestamps.
            Value::Array(entries) => Self::offset_datetime_array_to_rfc3339(entries),
            _ => None,
        }
    }

    fn first_bool(value: &Value, paths: &[&[&str]]) -> Option<bool> {
        paths.iter().find_map(|path| {
            Self::value_at_path(value, path).and_then(|value| match value {
                Value::Bool(raw) => Some(*raw),
                Value::String(raw) => match raw.as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                },
                _ => None,
            })
        })
    }

    fn first_u64(value: &Value, paths: &[&[&str]]) -> Option<u64> {
        paths.iter().find_map(|path| {
            Self::value_at_path(value, path).and_then(|value| match value {
                Value::Number(raw) => raw.as_u64(),
                Value::String(raw) => raw.parse::<u64>().ok(),
                _ => None,
            })
        })
    }

    fn record_timestamp(value: &Value) -> (Option<String>, Option<OffsetDateTime>) {
        let raw = Self::first_scalar(
            value,
            &[
                &["updated_at"],
                &["last_revealed_at"],
                &["reviewed_at"],
                &["approved_at"],
                &["reverted_at"],
                &["activated_at"],
                &["granted_at"],
                &["last_replayed_at"],
                &["repair_requested_at"],
                &["replayed_at"],
                &["recorded_at"],
                &["created_at"],
                &["captured_at"],
                &["opened_at"],
                &["metadata", "updated_at"],
            ],
        );
        let parsed = raw.as_deref().and_then(Self::parse_timestamp);
        (raw, parsed)
    }

    fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(value, &Rfc3339).ok()
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

    fn timestamp_is_newer(
        candidate: Option<OffsetDateTime>,
        current: Option<OffsetDateTime>,
    ) -> bool {
        match (candidate, current) {
            (Some(candidate), Some(current)) => candidate >= current,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => true,
        }
    }

    fn newest_timestamp_pair(
        current_raw: Option<String>,
        current_sort: Option<OffsetDateTime>,
        candidate_raw: Option<String>,
        candidate_sort: Option<OffsetDateTime>,
    ) -> (Option<String>, Option<OffsetDateTime>) {
        if Self::timestamp_is_newer(candidate_sort, current_sort) {
            (candidate_raw, candidate_sort)
        } else {
            (current_raw, current_sort)
        }
    }

    fn join_context(parts: Vec<Option<String>>) -> Option<String> {
        let values = parts
            .into_iter()
            .flatten()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if values.is_empty() {
            None
        } else {
            Some(values.join(" · "))
        }
    }

    fn target_label(kind: Option<&str>, id: Option<&str>) -> String {
        match (kind, id) {
            (Some(kind), Some(id)) if !kind.is_empty() && !id.is_empty() => format!("{kind}:{id}"),
            (_, Some(id)) if !id.is_empty() => id.to_string(),
            (Some(kind), _) if !kind.is_empty() => kind.to_string(),
            _ => String::from("unknown target"),
        }
    }

    fn normalize_status(value: String) -> String {
        value.trim().replace(' ', "_").to_ascii_lowercase()
    }

    fn count_entries(path: &Path) -> (u64, bool) {
        match Self::read_entries(path) {
            Some(entries) => (entries.len() as u64, true),
            None => (0, false),
        }
    }

    fn count_and_status(path: &Path, status_keys: &[&str]) -> (CountSummary, Vec<StatusSummary>) {
        if let Some(entries) = Self::read_entries(path) {
            let statuses = Self::collect_status_breakdown(&entries, status_keys);
            (
                CountSummary {
                    count: entries.len() as u64,
                    available: true,
                },
                statuses,
            )
        } else {
            (
                CountSummary {
                    count: 0,
                    available: false,
                },
                Vec::new(),
            )
        }
    }

    fn read_entries(path: &Path) -> Option<Vec<Value>> {
        let file = File::open(path).ok()?;
        let value: Value = serde_json::from_reader(file).ok()?;
        Some(Self::extract_entries(value))
    }

    fn extract_entries(value: Value) -> Vec<Value> {
        match value {
            Value::Null => Vec::new(),
            Value::Array(entries) => entries,
            Value::Object(mut map) => {
                if let Some(Value::Object(records)) = map.remove("records") {
                    return records
                        .into_values()
                        .filter_map(|record| match record {
                            Value::Object(mut stored) => {
                                if stored
                                    .get("deleted")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false)
                                {
                                    None
                                } else {
                                    stored.remove("value")
                                }
                            }
                            _ => None,
                        })
                        .collect();
                }
                map.into_values().collect()
            }
            other => vec![other],
        }
    }

    fn collect_status_breakdown(entries: &[Value], status_keys: &[&str]) -> Vec<StatusSummary> {
        let mut counters: BTreeMap<String, u64> = BTreeMap::new();
        for entry in entries {
            if let Value::Object(map) = entry
                && let Some(status) = Self::find_status_value(map, status_keys)
            {
                *counters.entry(status).or_default() += 1;
            }
        }

        let mut entries: Vec<_> = counters
            .into_iter()
            .map(|(status, count)| StatusSummary { status, count })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries
    }

    fn find_status_value(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
        for key in keys {
            if let Some(Value::String(value)) = map.get(*key)
                && !value.is_empty()
            {
                return Some(value.clone());
            }
        }

        None
    }

    fn render_index(&self, snapshot: &ConsoleSnapshot) -> String {
        let state_root = Self::escape_html(&snapshot.state_root);
        let updated_at = Self::escape_html(&snapshot.updated_at);
        let metric_cards: String = snapshot
            .metrics
            .iter()
            .map(|metric| {
                let label = Self::escape_html(&metric.label);
                let path = Self::escape_html(&metric.path);
                let value = if metric.available {
                    metric.count.to_string()
                } else {
                    "unavailable".to_string()
                };

                format!(
                    r#"<div class="card">
  <div class="value">{value}</div>
  <div class="label">{label}</div>
  <div class="path">{path}</div>
</div>"#
                )
            })
            .collect();

        let instance_list = Self::render_status_list(
            &snapshot.uvm.instance_statuses,
            "No instance status data available",
        );
        let runtime_list = Self::render_status_list(
            &snapshot.uvm.runtime_session_statuses,
            "No runtime session status data available",
        );

        let instance_summary = if snapshot.uvm.instance_count.available {
            format!("{}", snapshot.uvm.instance_count.count)
        } else {
            "unavailable".into()
        };
        let runtime_summary = if snapshot.uvm.runtime_session_count.available {
            format!("{}", snapshot.uvm.runtime_session_count.count)
        } else {
            "unavailable".into()
        };
        let workbench_cards = [
            ("Approvals", &snapshot.workbench.approvals),
            ("Grants", &snapshot.workbench.grants),
            ("Quotas", &snapshot.workbench.quotas),
            ("Cases", &snapshot.workbench.cases),
            ("Appeals", &snapshot.workbench.appeals),
            ("Dead letters", &snapshot.workbench.dead_letters),
        ]
        .into_iter()
        .map(|(title, lane)| Self::render_lane_card(title, lane))
        .collect::<String>();
        let workbench_panels = [
            ("Approvals", &snapshot.workbench.approvals),
            ("Grants", &snapshot.workbench.grants),
            ("Quotas", &snapshot.workbench.quotas),
            ("Cases", &snapshot.workbench.cases),
            ("Appeals", &snapshot.workbench.appeals),
            ("Dead letters", &snapshot.workbench.dead_letters),
        ]
        .into_iter()
        .map(|(title, lane)| Self::render_lane_detail(title, lane))
        .collect::<String>();

        format!(
            r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project UHost Console</title>
  <style>
    :root {{
      --bg: #f2efe8;
      --panel: #fffdf8;
      --ink: #1a1d24;
      --accent: #0b774b;
      --muted: #6a6d75;
      --edge: #d8d1c4;
    }}
    body {{ margin: 0; font-family: "Inter", "Segoe UI", system-ui, sans-serif; background: radial-gradient(circle at top, #f9f4ec 0%, var(--bg) 65%, #e8e0cf 100%); color: var(--ink); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 48px 24px 72px; }}
    header {{ border-bottom: 1px solid var(--edge); padding-bottom: 24px; margin-bottom: 32px; }}
    header h1 {{ margin: 0; font-size: 2.25rem; }}
    header p {{ margin: 8px 0 0; color: var(--muted); }}
    .hero-links {{ display: flex; flex-wrap: wrap; gap: 16px; margin-top: 14px; font-size: 0.92rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--edge);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 18px 40px rgba(27, 35, 44, 0.08);
    }}
    .card .value {{ font-size: 2.1rem; margin-bottom: 6px; }}
    .card .label {{ font-weight: 600; margin-bottom: 4px; }}
    .card .path {{ font-size: 0.85rem; color: var(--muted); word-break: break-all; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--edge);
      border-radius: 16px;
      padding: 26px;
      margin-top: 32px;
      box-shadow: 0 20px 60px rgba(27, 35, 44, 0.08);
    }}
    .panel h2 {{ margin-top: 0; }}
    .panel h3 {{ margin: 0; font-size: 1.05rem; }}
    .panel ul {{ margin: 8px 0 0 16px; padding: 0; color: var(--muted); }}
    .status-tag {{ display: inline-flex; align-items: center; gap: 6px; font-size: 0.85rem; color: var(--muted); }}
    .eyebrow {{ font-size: 0.74rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }}
    .subtle {{ color: var(--muted); font-size: 0.9rem; }}
    .chip-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }}
    .chip {{ display: inline-flex; align-items: center; border-radius: 999px; background: #ece2d1; color: #3c403f; padding: 6px 10px; font-size: 0.82rem; }}
    .detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    .detail-card {{ background: #fffaf2; border: 1px solid var(--edge); border-radius: 14px; padding: 20px; }}
    .detail-card table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    .detail-card th {{ text-align: left; font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); padding: 0 0 8px; }}
    .detail-card td {{ padding: 10px 0; border-top: 1px solid #ece2d1; vertical-align: top; word-break: break-word; }}
    .detail-card strong {{ display: block; }}
    .lane-note {{ margin: 12px 0 0; color: var(--muted); }}
    a {{ color: var(--accent); text-decoration: none; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Project UHost console</h1>
      <p>Read-only snapshot of the local platform state root {state_root} · updated {updated_at}</p>
      <p>Operator workbench queues are sourced directly from persisted sibling service state with no synthetic writes.</p>
      <div class="hero-links">
        <a href="/console/status">/console/status</a>
        <a href="/console/summary">/console/summary</a>
        <a href="/console/workbench">/console/workbench</a>
      </div>
    </header>
    <section>
      <h2>Platform metrics</h2>
      <div class="grid">
{metric_cards}
      </div>
    </section>
    <section class="panel">
      <h2>UVM control summary</h2>
      <p>Instances: {instance_summary} · runtime sessions: {runtime_summary}</p>
      <div class="grid">
        <div class="card">
          <div class="label">Instance status breakdown</div>
          <ul>
{instance_list}
          </ul>
        </div>
        <div class="card">
          <div class="label">Runtime session status breakdown</div>
          <ul>
{runtime_list}
          </ul>
        </div>
      </div>
    </section>
    <section class="panel">
      <h2>Operator workbench</h2>
      <p class="subtle">Approvals, break-glass controls, quotas, cases, appeals, and dead-letter queues from the local control-plane state root.</p>
      <div class="grid">
{workbench_cards}
      </div>
    </section>
    <section class="panel">
      <h2>Queue drill-downs</h2>
      <div class="detail-grid">
{workbench_panels}
      </div>
    </section>
  </main>
</body>
</html>"#
        )
    }

    fn render_status_list(statuses: &[StatusSummary], empty_message: &str) -> String {
        if statuses.is_empty() {
            return format!(r#"<li>{}</li>"#, Self::escape_html(empty_message));
        }

        statuses
            .iter()
            .map(|entry| {
                format!(
                    r#"<li>{} <strong>({})</strong></li>"#,
                    Self::escape_html(&Self::display_status(&entry.status)),
                    entry.count
                )
            })
            .collect()
    }

    fn render_lane_card(title: &str, lane: &WorkbenchLane) -> String {
        let title = Self::escape_html(title);
        let count = if lane.count.available {
            lane.count.count.to_string()
        } else {
            String::from("unavailable")
        };
        let attention = if lane.count.available {
            format!(
                "{} {}",
                lane.attention_count,
                Self::escape_html(&lane.attention_label)
            )
        } else {
            String::from("No durable source file yet")
        };
        let source_summary = Self::escape_html(&Self::source_availability_summary(&lane.sources));
        let note = lane
            .note
            .as_ref()
            .map(|note| format!(r#"<p class="lane-note">{}</p>"#, Self::escape_html(note)))
            .unwrap_or_default();
        let statuses = Self::render_status_badges(&lane.statuses, "No queue data");

        format!(
            r#"<div class="card">
  <div class="eyebrow">Operator lane</div>
  <div class="label">{title}</div>
  <div class="value">{count}</div>
  <div class="subtle">{attention}</div>
  <div class="subtle">{source_summary}</div>
  <div class="chip-row">{statuses}</div>
  {note}
</div>"#
        )
    }

    fn render_lane_detail(title: &str, lane: &WorkbenchLane) -> String {
        let title = Self::escape_html(title);
        let source_list = Self::render_source_list(&lane.sources);
        let statuses = Self::render_status_badges(&lane.statuses, "No queue data");
        let entries = Self::render_workbench_entries(&lane.entries);
        let count = if lane.count.available {
            lane.count.count.to_string()
        } else {
            String::from("unavailable")
        };
        let note = lane
            .note
            .as_ref()
            .map(|note| format!(r#"<p class="lane-note">{}</p>"#, Self::escape_html(note)))
            .unwrap_or_default();

        format!(
            r#"<section class="detail-card">
  <h3>{title}</h3>
  <p class="subtle">{count} total · {} {}</p>
  {note}
  <div class="chip-row">{statuses}</div>
  <ul class="source-list">
{source_list}
  </ul>
  <table>
    <thead>
      <tr>
        <th>Summary</th>
        <th>Status</th>
        <th>Source</th>
        <th>Context</th>
        <th>Updated</th>
      </tr>
    </thead>
    <tbody>
{entries}
    </tbody>
  </table>
</section>"#,
            lane.attention_count,
            Self::escape_html(&lane.attention_label),
        )
    }

    fn render_status_badges(statuses: &[StatusSummary], empty_message: &str) -> String {
        if statuses.is_empty() {
            return format!(
                r#"<span class="chip">{}</span>"#,
                Self::escape_html(empty_message)
            );
        }

        statuses
            .iter()
            .map(|entry| {
                format!(
                    r#"<span class="chip">{} ({})</span>"#,
                    Self::escape_html(&Self::display_status(&entry.status)),
                    entry.count
                )
            })
            .collect()
    }

    fn render_source_list(sources: &[WorkbenchSource]) -> String {
        if sources.is_empty() {
            return String::from(
                r#"    <li>No persisted source file is available for this lane yet.</li>"#,
            );
        }

        sources
            .iter()
            .map(|source| {
                let label = Self::escape_html(&source.label);
                let path = Self::escape_html(&source.path);
                let count = if source.available {
                    source.count.to_string()
                } else {
                    String::from("unavailable")
                };
                format!(r#"    <li>{label}: {count} · {path}</li>"#)
            })
            .collect()
    }

    fn render_workbench_entries(entries: &[WorkbenchEntry]) -> String {
        if entries.is_empty() {
            return String::from(
                r#"      <tr><td colspan="5" class="subtle">No recent records available.</td></tr>"#,
            );
        }

        entries
            .iter()
            .map(|entry| {
                let summary = Self::escape_html(&entry.summary);
                let id = Self::escape_html(&entry.id);
                let status = Self::escape_html(&Self::display_status(&entry.status));
                let source = Self::escape_html(&entry.source);
                let context = entry
                    .context
                    .as_deref()
                    .map(Self::escape_html)
                    .unwrap_or_else(|| String::from("—"));
                let updated_at = entry
                    .updated_at
                    .as_deref()
                    .map(Self::escape_html)
                    .unwrap_or_else(|| String::from("—"));
                format!(
                    r#"      <tr>
        <td><strong>{summary}</strong><span class="subtle">{id}</span></td>
        <td>{status}</td>
        <td>{source}</td>
        <td>{context}</td>
        <td>{updated_at}</td>
      </tr>"#
                )
            })
            .collect()
    }

    fn source_availability_summary(sources: &[WorkbenchSource]) -> String {
        if sources.is_empty() {
            return String::from("No persisted source file");
        }

        let available = sources.iter().filter(|source| source.available).count();
        format!("{available} of {} source files available", sources.len())
    }

    fn display_status(status: &str) -> String {
        status.replace('_', " ")
    }

    fn render_not_found(&self, path: &str) -> String {
        let path = Self::escape_html(path);
        let state_root = Self::escape_html(&self.state_root.display().to_string());
        format!(
            r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project UHost Console</title>
  <style>
    :root {{
      --bg: #f6f2ea;
      --panel: #fffdf8;
      --ink: #17212b;
      --accent: #0b6e4f;
      --edge: #d8cfbf;
    }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, #efe7da 0%, var(--bg) 100%); color: var(--ink); }}
    main {{ max-width: 980px; margin: 0 auto; padding: 48px 24px 72px; }}
    .hero {{ padding: 32px; border: 1px solid var(--edge); background: var(--panel); box-shadow: 0 20px 60px rgba(23, 33, 43, 0.08); }}
    a {{ color: var(--accent); text-decoration: none; }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Console route not found</h1>
      <p>The console does not have a page at <strong>{path}</strong>.</p>
      <p><a href="/console">Return to the console home page</a>.</p>
      <p><strong>State root:</strong> {state_root}</p>
    </section>
  </main>
</body>
</html>"#
        )
    }

    fn response_for(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<uhost_core::Result<Response<uhost_api::ApiBody>>> {
        if method != Method::GET {
            return None;
        }

        let snapshot = self.dashboard_snapshot();

        match path {
            "/" | "/console" | "/console/" => Some(Self::response_html(
                StatusCode::OK,
                self.render_index(&snapshot),
            )),
            "/console/status" => Some(Self::response_json(StatusCode::OK, &snapshot)),
            "/console/workbench" => Some(Self::response_json(StatusCode::OK, &snapshot.workbench)),
            "/console/summary" => {
                let summary = self.summary_snapshot();
                Some(Self::response_json(StatusCode::OK, &summary))
            }
            path if path.starts_with("/console/") => Some(Self::response_html(
                StatusCode::NOT_FOUND,
                self.render_not_found(path),
            )),
            _ => None,
        }
    }
}

impl HttpService for ConsoleService {
    fn name(&self) -> &'static str {
        "console"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/"),
            uhost_runtime::RouteClaim::prefix("/console"),
        ];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        _context: RequestContext,
    ) -> ResponseFuture<'a> {
        Box::pin(async move {
            self.response_for(request.method(), request.uri().path())
                .transpose()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::Method;
    use http_body_util::BodyExt as _;
    use serde_json::json;
    use std::fs::{create_dir_all, write};
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn write_document_collection(path: &Path, records: &[(&str, Value)]) {
        let Some(parent) = path.parent() else {
            panic!("document collection path must have a parent");
        };
        create_dir_all(parent).unwrap_or_else(|error| panic!("{error}"));

        let payload = json!({
            "schema_version": 1,
            "revision": records.len(),
            "records": records
                .iter()
                .map(|(key, value)| {
                    (
                        (*key).to_owned(),
                        json!({
                            "version": 1,
                            "updated_at": "2026-04-08T00:00:00Z",
                            "deleted": false,
                            "value": value,
                        }),
                    )
                })
                .collect::<Map<String, Value>>(),
            "changes": [],
        });
        let encoded = serde_json::to_vec(&payload).unwrap_or_else(|error| panic!("{error}"));
        write(path, encoded).unwrap_or_else(|error| panic!("{error}"));
    }

    fn timestamp_tuple(year: i32, ordinal: u16, hour: u8, minute: u8, second: u8) -> Value {
        json!([year, ordinal, hour, minute, second, 0, 0, 0, 0])
    }

    fn write_workbench_fixture(root: &Path) {
        write_document_collection(
            &root.join("policy/approvals.json"),
            &[
                (
                    "apr_1",
                    json!({
                        "id": "apr_1",
                        "subject": "svc:edge",
                        "required_approvers": 2,
                        "approved": false,
                        "metadata": { "updated_at": "2026-04-08T01:00:00Z" }
                    }),
                ),
                (
                    "apr_2",
                    json!({
                        "id": "apr_2",
                        "subject": "svc:ops",
                        "required_approvers": 1,
                        "approved": true,
                        "metadata": { "updated_at": "2026-04-08T02:00:00Z" }
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("governance/change_requests.json"),
            &[(
                "chg_1",
                json!({
                    "id": "chg_1",
                    "title": "Publish ingress override",
                    "change_type": "policy_change",
                    "requested_by": "ops:oncall",
                    "required_approvals": 2,
                    "state": "pending",
                    "metadata": { "updated_at": "2026-04-08T03:00:00Z" }
                }),
            )],
        );
        write_document_collection(
            &root.join("governance/change_approvals.json"),
            &[(
                "aud_1",
                json!({
                    "id": "aud_1",
                    "change_request_id": "chg_9",
                    "approver": "ops:reviewer",
                    "comment": "approved for drill",
                    "approved_at": "2026-04-08T04:00:00Z"
                }),
            )],
        );
        write_document_collection(
            &root.join("governance/exposure_overrides.json"),
            &[(
                "ovr_1",
                json!({
                    "id": "ovr_1",
                    "surface": "dns",
                    "target_kind": "zone",
                    "target_id": "example.com",
                    "override_kind": "publishability",
                    "reason": "incident mitigation",
                    "requested_by": "ops:oncall",
                    "activated_by": "ops:lead",
                    "state": "active",
                    "created_at": "2026-04-08T05:00:00Z",
                    "activated_at": "2026-04-08T05:05:00Z"
                }),
            )],
        );
        write_document_collection(
            &root.join("billing/budgets.json"),
            &[
                (
                    "bdg_1",
                    json!({
                        "id": "bdg_1",
                        "billing_account_id": "bac_1",
                        "name": "tenant burn watch",
                        "cap_behavior": "soft",
                        "amount_cents": 10000,
                        "active": true,
                        "metadata": { "updated_at": "2026-04-08T05:30:00Z" }
                    }),
                ),
                (
                    "bdg_2",
                    json!({
                        "id": "bdg_2",
                        "billing_account_id": "bac_2",
                        "name": "incident hard cap",
                        "cap_behavior": "hard",
                        "amount_cents": 5000,
                        "active": true,
                        "metadata": { "updated_at": "2026-04-08T05:40:00Z" }
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("billing/budget_burn.json"),
            &[
                (
                    "brn_1",
                    json!({
                        "id": "brn_1",
                        "budget_id": "bdg_1",
                        "resulting_burn_cents": 7000,
                        "recorded_at": "2026-04-08T05:45:00Z"
                    }),
                ),
                (
                    "brn_2",
                    json!({
                        "id": "brn_2",
                        "budget_id": "bdg_2",
                        "resulting_burn_cents": 5200,
                        "recorded_at": "2026-04-08T05:50:00Z"
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("billing/budget_notifications.json"),
            &[
                (
                    "bnt_1",
                    json!({
                        "id": "bnt_1",
                        "budget_id": "bdg_1",
                        "kind": "threshold_reached",
                        "threshold_percentage": 70,
                        "message": "tenant spend crossed 70%",
                        "created_at": "2026-04-08T05:46:00Z"
                    }),
                ),
                (
                    "bnt_2",
                    json!({
                        "id": "bnt_2",
                        "budget_id": "bdg_2",
                        "kind": "hard_cap_blocked",
                        "message": "invoice would exceed hard cap",
                        "created_at": "2026-04-08T05:51:00Z"
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("billing/support_entitlements.json"),
            &[
                (
                    "sen_1",
                    json!({
                        "id": "sen_1",
                        "billing_account_id": "bac_1",
                        "subscription_id": Value::Null,
                        "source_kind": "billing_account",
                        "source_plan": "pro",
                        "support_tier": "business",
                        "channels": ["portal", "email", "phone"],
                        "initial_response_sla_minutes": 240,
                        "active": true,
                        "metadata": { "updated_at": "2026-04-08T05:35:00Z" }
                    }),
                ),
                (
                    "sen_2",
                    json!({
                        "id": "sen_2",
                        "billing_account_id": "bac_1",
                        "subscription_id": "sub_1",
                        "source_kind": "subscription",
                        "source_plan": "enterprise",
                        "support_tier": "enterprise",
                        "channels": ["portal", "email", "phone", "slack"],
                        "initial_response_sla_minutes": 60,
                        "active": true,
                        "metadata": { "updated_at": "2026-04-08T05:36:00Z" }
                    }),
                ),
                (
                    "sen_3",
                    json!({
                        "id": "sen_3",
                        "billing_account_id": "bac_2",
                        "subscription_id": Value::Null,
                        "source_kind": "billing_account",
                        "source_plan": "business",
                        "support_tier": "business",
                        "channels": ["portal", "email", "phone"],
                        "initial_response_sla_minutes": 240,
                        "active": false,
                        "metadata": { "updated_at": "2026-04-08T05:37:00Z" }
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("secrets/reveal_grants.json"),
            &[
                (
                    "grt_1",
                    json!({
                        "id": "grt_1",
                        "secret_id": "sec_1",
                        "grant_kind": "approval",
                        "reason": "incident inspection",
                        "granted_by": "ops:oncall",
                        "granted_at": "2026-04-08T05:10:00Z",
                        "reveal_count": 0
                    }),
                ),
                (
                    "grt_2",
                    json!({
                        "id": "grt_2",
                        "secret_id": "sec_2",
                        "grant_kind": "lease",
                        "reason": "postmortem validation",
                        "granted_by": "ops:lead",
                        "granted_at": "2026-04-08T05:20:00Z",
                        "expires_at": "2000-01-01T00:00:00Z",
                        "reveal_count": 0
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("abuse/cases.json"),
            &[
                (
                    "abc_1",
                    json!({
                        "id": "abc_1",
                        "subject_kind": "tenant",
                        "subject": "org_1",
                        "reason": "suspicious spend spike",
                        "status": "open",
                        "priority": "high",
                        "assigned_to": "ops:trust",
                        "escalation_count": 1,
                        "opened_at": "2026-04-08T06:00:00Z",
                        "updated_at": "2026-04-08T06:30:00Z"
                    }),
                ),
                (
                    "abc_2",
                    json!({
                        "id": "abc_2",
                        "subject_kind": "project",
                        "subject": "proj_2",
                        "reason": "already resolved",
                        "status": "resolved",
                        "priority": "normal",
                        "opened_at": "2026-04-08T06:45:00Z",
                        "updated_at": "2026-04-08T07:00:00Z"
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("abuse/appeals.json"),
            &[(
                "apl_1",
                json!({
                    "id": "apl_1",
                    "case_id": "abc_1",
                    "subject_kind": "tenant",
                    "subject": "org_1",
                    "requested_by": "user:owner",
                    "reason": "request manual review",
                    "status": "pending",
                    "created_at": "2026-04-08T07:30:00Z"
                }),
            )],
        );
        write_document_collection(
            &root.join("abuse/remediation_cases.json"),
            &[
                (
                    "rem_1",
                    json!({
                        "id": "rem_1",
                        "workflow_id": "abuse.remediation.rem_1",
                        "workflow_steps": [
                            {
                                "name": "dry_run",
                                "index": 0,
                                "state": "completed",
                                "detail": "linked priorities high; no active quarantines",
                                "updated_at": "2026-04-08T08:05:00Z"
                            },
                            {
                                "name": "checkpoint",
                                "index": 1,
                                "state": "completed",
                                "detail": "workflow checkpoint persisted for 1 abuse case and 0 quarantines",
                                "updated_at": "2026-04-08T08:16:00Z"
                            },
                            {
                                "name": "rollback",
                                "index": 2,
                                "state": "completed",
                                "detail": "1 rollback evidence ref ready",
                                "updated_at": "2026-04-08T08:16:00Z"
                            },
                            {
                                "name": "verification",
                                "index": 3,
                                "state": "completed",
                                "detail": "1 verification evidence ref ready",
                                "updated_at": "2026-04-08T08:16:00Z"
                            },
                            {
                                "name": "downstream_fanout",
                                "index": 4,
                                "state": "completed",
                                "detail": "1 change request and 2 notify messages linked",
                                "updated_at": "2026-04-08T08:16:00Z"
                            }
                        ],
                        "tenant_subject": "tenant:org_1",
                        "opened_by": "operator:abuse",
                        "owner": "operator:incident",
                        "owner_assigned_at": "2026-04-08T08:06:00Z",
                        "abuse_case_ids": ["abc_1"],
                        "quarantine_ids": [],
                        "change_request_ids": ["chg_1"],
                        "notify_message_ids": ["ntf_1", "ntf_2"],
                        "rollback_evidence_refs": ["runbook:tenant-rollback"],
                        "verification_evidence_refs": ["checklist:tenant-verify"],
                        "evidence_state": "ready",
                        "sla_target_seconds": 900,
                        "sla_deadline_at": "2026-04-08T08:20:00Z",
                        "sla_state": "at_risk",
                        "escalation_state": "escalated",
                        "escalation_count": 1,
                        "last_escalated_at": "2026-04-08T08:14:00Z",
                        "last_escalated_by": "operator:lead",
                        "last_escalation_reason": "handoff to incident commander",
                        "reason": "manual remediation handoff",
                        "created_at": "2026-04-08T08:05:00Z",
                        "updated_at": "2026-04-08T08:16:00Z"
                    }),
                ),
                (
                    "rem_2",
                    json!({
                        "id": "rem_2",
                        "workflow_id": "abuse.remediation.rem_2",
                        "workflow_steps": [
                            {
                                "name": "dry_run",
                                "index": 0,
                                "state": "completed",
                                "detail": "linked priorities normal; no active quarantines",
                                "updated_at": "2026-04-08T09:00:00Z"
                            },
                            {
                                "name": "checkpoint",
                                "index": 1,
                                "state": "completed",
                                "detail": "workflow checkpoint persisted for 1 abuse case and 0 quarantines",
                                "updated_at": "2026-04-08T09:10:00Z"
                            },
                            {
                                "name": "rollback",
                                "index": 2,
                                "state": "completed",
                                "detail": "1 rollback evidence ref ready",
                                "updated_at": "2026-04-08T09:10:00Z"
                            },
                            {
                                "name": "verification",
                                "index": 3,
                                "state": "active",
                                "detail": "awaiting verification evidence refs",
                                "updated_at": "2026-04-08T09:10:00Z"
                            },
                            {
                                "name": "downstream_fanout",
                                "index": 4,
                                "state": "completed",
                                "detail": "no downstream fanout required",
                                "updated_at": "2026-04-08T09:10:00Z"
                            }
                        ],
                        "tenant_subject": "tenant:org_2",
                        "opened_by": "operator:abuse",
                        "owner": "operator:recovery",
                        "owner_assigned_at": "2026-04-08T09:05:00Z",
                        "abuse_case_ids": ["abc_2"],
                        "quarantine_ids": [],
                        "change_request_ids": [],
                        "notify_message_ids": [],
                        "rollback_evidence_refs": ["runbook:project-rollback"],
                        "verification_evidence_refs": [],
                        "evidence_state": "verification_missing",
                        "sla_target_seconds": 3600,
                        "sla_deadline_at": "2026-04-08T10:05:00Z",
                        "sla_state": "within_sla",
                        "escalation_state": "none",
                        "escalation_count": 0,
                        "reason": "waiting for verification steps",
                        "created_at": "2026-04-08T09:00:00Z",
                        "updated_at": "2026-04-08T09:10:00Z"
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("notify/notifications.json"),
            &[
                (
                    "ntf_1",
                    json!({
                        "id": "ntf_1",
                        "channel": "email",
                        "destination": "ops@example.com",
                        "subject": "dead letter requires review",
                        "body": "review notify delivery failure",
                        "case_reference": "abc_1",
                        "locale": "en-US",
                        "state": "dead_lettered",
                        "attempts": 4,
                        "max_attempts": 4,
                        "last_error": "smtp timeout",
                        "acknowledged_at": "2026-04-08T08:07:00Z",
                        "acknowledged_by": "operator:carver",
                        "acknowledgement_note": "operator reviewed dead letter",
                        "escalation_count": 1,
                        "last_escalated_at": "2026-04-08T08:02:00Z",
                        "last_escalated_by": "operator:duty",
                        "last_escalated_notification_id": "ntf_2",
                        "signature": "sig-ntf-1",
                        "created_at": "2026-04-08T07:45:00Z",
                        "updated_at": "2026-04-08T08:07:00Z",
                        "history": [
                            {
                                "sequence": 1,
                                "event": "delivered",
                                "occurred_at": "2026-04-08T07:46:00Z",
                                "actor": "system",
                                "state": "delivered",
                                "attempts": 1,
                                "case_reference": "abc_1"
                            },
                            {
                                "sequence": 2,
                                "event": "dead_lettered",
                                "occurred_at": "2026-04-08T08:00:00Z",
                                "actor": "system",
                                "state": "dead_lettered",
                                "attempts": 4,
                                "detail": "retry budget exhausted",
                                "case_reference": "abc_1"
                            },
                            {
                                "sequence": 3,
                                "event": "escalated",
                                "occurred_at": "2026-04-08T08:02:00Z",
                                "actor": "operator:duty",
                                "state": "dead_lettered",
                                "attempts": 4,
                                "detail": "escalated to incident:incident@example.com",
                                "case_reference": "abc_1",
                                "related_notification_id": "ntf_2"
                            },
                            {
                                "sequence": 4,
                                "event": "acknowledged",
                                "occurred_at": "2026-04-08T08:07:00Z",
                                "actor": "operator:carver",
                                "state": "dead_lettered",
                                "attempts": 4,
                                "detail": "operator reviewed dead letter",
                                "case_reference": "abc_1"
                            }
                        ]
                    }),
                ),
                (
                    "ntf_2",
                    json!({
                        "id": "ntf_2",
                        "channel": "incident",
                        "destination": "incident@example.com",
                        "subject": "[ESCALATED] dead letter requires review",
                        "body": "manual handoff pending",
                        "case_reference": "support:case-123",
                        "locale": "en-US",
                        "state": "failed",
                        "attempts": 1,
                        "max_attempts": 4,
                        "next_attempt_at": "2099-01-01T00:00:00Z",
                        "last_error": "incident webhook timeout",
                        "snoozed_until": "2099-01-01T00:00:00Z",
                        "snoozed_by": "operator:carver",
                        "snooze_reason": "waiting on operator handoff",
                        "escalation_count": 0,
                        "signature": "sig-ntf-2",
                        "created_at": "2026-04-08T08:02:00Z",
                        "updated_at": "2026-04-08T08:10:00Z",
                        "history": [
                            {
                                "sequence": 1,
                                "event": "created",
                                "occurred_at": "2026-04-08T08:02:00Z",
                                "actor": "operator:duty",
                                "state": "queued",
                                "attempts": 0,
                                "case_reference": "support:case-123"
                            },
                            {
                                "sequence": 2,
                                "event": "snoozed",
                                "occurred_at": "2026-04-08T08:10:00Z",
                                "actor": "operator:carver",
                                "state": "failed",
                                "attempts": 1,
                                "detail": "snoozed for 900 seconds: waiting on operator handoff",
                                "case_reference": "support:case-123"
                            }
                        ]
                    }),
                ),
                (
                    "ntf_3",
                    json!({
                        "id": "ntf_3",
                        "channel": "email",
                        "destination": "owner@example.com",
                        "subject": "case acknowledged",
                        "body": "owner responded",
                        "case_reference": "support:case-123",
                        "locale": "en-US",
                        "state": "delivered",
                        "attempts": 1,
                        "max_attempts": 4,
                        "acknowledged_at": "2026-04-08T08:15:00Z",
                        "acknowledged_by": "operator:carver",
                        "acknowledgement_note": "owner replied",
                        "escalation_count": 0,
                        "signature": "sig-ntf-3",
                        "created_at": "2026-04-08T08:11:00Z",
                        "updated_at": "2026-04-08T08:15:00Z",
                        "history": [
                            {
                                "sequence": 1,
                                "event": "delivered",
                                "occurred_at": "2026-04-08T08:12:00Z",
                                "actor": "system",
                                "state": "delivered",
                                "attempts": 1,
                                "case_reference": "support:case-123"
                            },
                            {
                                "sequence": 2,
                                "event": "acknowledged",
                                "occurred_at": "2026-04-08T08:15:00Z",
                                "actor": "operator:carver",
                                "state": "delivered",
                                "attempts": 1,
                                "detail": "owner replied",
                                "case_reference": "support:case-123"
                            }
                        ]
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("notify/dead_letters.json"),
            &[(
                "dln_1",
                json!({
                    "id": "dln_1",
                    "notification_id": "ntf_1",
                    "channel": "email",
                    "destination": "ops@example.com",
                    "attempts": 4,
                    "last_error": "smtp timeout",
                    "captured_at": "2026-04-08T08:00:00Z",
                    "replay_count": 0,
                    "last_replayed_at": null
                }),
            )],
        );
        write_document_collection(
            &root.join("mail/dead_letters.json"),
            &[(
                "dlm_1",
                json!({
                    "id": "dlm_1",
                    "message_id": "aud_42",
                    "domain_id": "mld_1",
                    "direction": "outbound",
                    "from": "alerts@example.com",
                    "to": "user@example.net",
                    "attempts": 3,
                    "last_error": "remote 421",
                    "captured_at": "2026-04-08T08:30:00Z",
                    "replay_count": 1,
                    "last_replayed_at": "2026-04-08T09:00:00Z"
                }),
            )],
        );
        write_document_collection(
            &root.join("lifecycle/dead_letters.json"),
            &[(
                "dll_1",
                json!({
                    "id": "dll_1",
                    "topic": "repair.replay",
                    "error": "downstream consumer unavailable",
                    "attempts": 2,
                    "replayed": false,
                    "created_at": "2026-04-08T10:00:00Z"
                }),
            )],
        );
    }

    #[test]
    fn renders_index_for_console_root_and_trailing_slash() {
        let service = ConsoleService {
            state_root: PathBuf::from("/tmp/uhost/console"),
        };

        for path in ["/", "/console", "/console/"] {
            let response = service
                .response_for(&Method::GET, path)
                .unwrap_or_else(|| panic!("expected console route to match"))
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
        }
    }

    #[tokio::test]
    async fn renders_friendly_not_found_for_console_subpaths() {
        let service = ConsoleService {
            state_root: PathBuf::from("/tmp/<danger>/console"),
        };

        let response = service
            .response_for(&Method::GET, "/console/missing")
            .unwrap_or_else(|| panic!("expected console not-found route to match"))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let body = std::str::from_utf8(&body).unwrap_or_else(|error| panic!("{error}"));
        assert!(body.contains("&lt;danger&gt;"));
        assert!(!body.contains("<danger>"));
    }

    #[test]
    fn matches_console_routes_only() {
        let service = ConsoleService {
            state_root: PathBuf::from("/tmp/uhost/console"),
        };

        assert!(service.matches("/"));
        assert!(service.matches("/console"));
        assert!(service.matches("/console/"));
        assert!(service.matches("/console/settings"));
        assert!(!service.matches("/consolex"));
        assert!(!service.matches("/control"));
    }

    #[tokio::test]
    async fn status_route_returns_aggregated_json() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_document_collection(
            &root.join("identity/users.json"),
            &[(
                "usr_1",
                json!({ "id": "usr_1", "email": "user@example.com" }),
            )],
        );
        write_document_collection(
            &root.join("control/workloads.json"),
            &[(
                "wrk_1",
                json!({ "id": "wrk_1", "state": "deployed", "name": "core-api" }),
            )],
        );
        write_document_collection(
            &root.join("uvm-control/instances.json"),
            &[
                ("uvi_1", json!({ "id": "uvi_1", "status": "running" })),
                ("uvi_2", json!({ "id": "uvi_2", "status": "stopped" })),
            ],
        );
        write_document_collection(
            &root.join("uvm-node/runtime_sessions.json"),
            &[("urs_1", json!({ "id": "urs_1", "state": "running" }))],
        );

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/status")
            .unwrap_or_else(|| panic!("expected console status route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let snapshot: ConsoleSnapshot =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let identity_metric = snapshot
            .metrics
            .iter()
            .find(|metric| metric.label == "Identity users")
            .unwrap_or_else(|| panic!("missing identity users metric"));
        assert_eq!(identity_metric.count, 1);
        assert!(identity_metric.available);

        let instance_status = snapshot
            .uvm
            .instance_statuses
            .iter()
            .find(|entry| entry.status == "running")
            .unwrap_or_else(|| panic!("missing running instance status"));
        assert_eq!(instance_status.count, 1);

        let runtime_summary = snapshot.uvm.runtime_session_count;
        assert_eq!(runtime_summary.count, 1);
        assert!(runtime_summary.available);
    }

    #[tokio::test]
    async fn status_route_defaults_to_zero_when_files_missing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ConsoleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/status")
            .unwrap_or_else(|| panic!("expected console status route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let snapshot: ConsoleSnapshot =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        assert!(snapshot.metrics.iter().any(|metric| !metric.available));
        assert_eq!(snapshot.uvm.instance_count.count, 0);
        assert!(!snapshot.uvm.instance_count.available);
        assert!(!snapshot.workbench.quotas.count.available);
    }

    #[tokio::test]
    async fn summary_route_reflects_persisted_console_visible_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_document_collection(
            &root.join("identity/users.json"),
            &[
                ("usr_1", json!({ "id": "usr_1" })),
                ("usr_2", json!({ "id": "usr_2" })),
            ],
        );
        write_document_collection(
            &root.join("tenancy/organizations.json"),
            &[("org_1", json!({ "id": "org_1" }))],
        );
        write_document_collection(
            &root.join("control/workloads.json"),
            &[
                ("wrk_1", json!({ "id": "wrk_1", "state": "deployed" })),
                ("wrk_2", json!({ "id": "wrk_2", "state": "pending" })),
            ],
        );
        write_document_collection(
            &root.join("scheduler/nodes.json"),
            &[("node_1", json!({ "id": "node_1" }))],
        );
        write_document_collection(
            &root.join("uvm-control/instances.json"),
            &[
                ("uvi_1", json!({ "id": "uvi_1", "status": "running" })),
                ("uvi_2", json!({ "id": "uvi_2", "status": "running" })),
                ("uvi_3", json!({ "id": "uvi_3", "status": "stopped" })),
            ],
        );
        write_document_collection(
            &root.join("uvm-node/runtime_sessions.json"),
            &[
                ("urs_1", json!({ "id": "urs_1", "state": "running" })),
                ("urs_2", json!({ "id": "urs_2", "state": "paused" })),
            ],
        );

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .response_for(&Method::GET, "/console/summary")
            .unwrap_or_else(|| panic!("expected console summary route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let summary: ConsoleSummary =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary.identity_users.count, 2);
        assert!(summary.identity_users.available);
        assert_eq!(summary.tenancy_organizations.count, 1);
        assert!(summary.tenancy_organizations.available);
        assert_eq!(summary.control_workloads.count, 2);
        assert!(summary.control_workloads.available);
        assert_eq!(summary.scheduler_nodes.count, 1);
        assert!(summary.scheduler_nodes.available);
        assert_eq!(summary.uvm_instances.count, 3);
        assert!(summary.uvm_instances.available);
        assert_eq!(summary.uvm_runtime_sessions.count, 2);
        assert!(summary.uvm_runtime_sessions.available);
        assert!(summary.metrics_available >= 4);
        assert!(summary.metrics_unavailable >= 1);

        let running_instances = summary
            .uvm_instance_statuses
            .iter()
            .find(|entry| entry.status == "running")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(running_instances, 2);
        assert!(!summary.operator_workbench.quotas.count.available);
    }

    #[tokio::test]
    async fn workbench_route_aggregates_operator_queues_and_real_quota_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_workbench_fixture(root);

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/workbench")
            .unwrap_or_else(|| panic!("expected console workbench route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let workbench: OperatorWorkbench =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(workbench.approvals.count.count, 4);
        assert_eq!(workbench.approvals.attention_count, 2);
        assert_eq!(workbench.grants.count.count, 3);
        assert_eq!(workbench.grants.attention_count, 2);
        assert!(workbench.quotas.count.available);
        assert_eq!(workbench.quotas.count.count, 2);
        assert_eq!(workbench.quotas.attention_count, 2);
        assert_eq!(workbench.quotas.support_entitlement_count, Some(3));
        assert_eq!(
            workbench
                .quotas
                .support_tier_totals
                .as_ref()
                .and_then(|totals| totals.get("business")),
            Some(&2)
        );
        assert_eq!(
            workbench
                .quotas
                .support_tier_totals
                .as_ref()
                .and_then(|totals| totals.get("enterprise")),
            Some(&1)
        );
        assert!(
            workbench
                .quotas
                .sources
                .iter()
                .any(|source| source.path == "billing/support_entitlements.json"
                    && source.available
                    && source.count == 3)
        );
        assert!(
            workbench
                .quotas
                .note
                .as_deref()
                .is_some_and(|note| note.contains("Support entitlements: 3 total"))
        );
        assert!(
            workbench
                .quotas
                .note
                .as_deref()
                .is_some_and(|note| note.contains("business (2), enterprise (1)"))
        );
        assert_eq!(workbench.cases.count.count, 5);
        assert_eq!(workbench.cases.attention_count, 3);
        assert_eq!(
            workbench.cases.attention_label,
            "open, escalated, or missing evidence"
        );
        assert_eq!(workbench.appeals.count.count, 1);
        assert_eq!(workbench.appeals.attention_count, 1);
        assert_eq!(workbench.dead_letters.count.count, 3);
        assert_eq!(workbench.dead_letters.attention_count, 2);
        let expired_grants = workbench
            .grants
            .statuses
            .iter()
            .find(|entry| entry.status == "expired")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(expired_grants, 1);

        let thresholded_quotas = workbench
            .quotas
            .statuses
            .iter()
            .find(|entry| entry.status == "threshold_reached")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(thresholded_quotas, 1);

        let blocked_quotas = workbench
            .quotas
            .statuses
            .iter()
            .find(|entry| entry.status == "hard_cap_blocked")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(blocked_quotas, 1);

        let pending_dead_letters = workbench
            .dead_letters
            .statuses
            .iter()
            .find(|entry| entry.status == "pending_replay")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(pending_dead_letters, 2);

        let snoozed_cases = workbench
            .cases
            .statuses
            .iter()
            .find(|entry| entry.status == "snoozed")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(snoozed_cases, 1);

        let escalated_cases = workbench
            .cases
            .statuses
            .iter()
            .find(|entry| entry.status == "escalated")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(escalated_cases, 1);

        let verification_missing_cases = workbench
            .cases
            .statuses
            .iter()
            .find(|entry| entry.status == "verification_missing")
            .map(|entry| entry.count)
            .unwrap_or_default();
        assert_eq!(verification_missing_cases, 1);
    }

    #[tokio::test]
    async fn workbench_threads_notify_state_into_case_and_dead_letter_context() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_workbench_fixture(root);

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/workbench")
            .unwrap_or_else(|| panic!("expected console workbench route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let workbench: OperatorWorkbench =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let abuse_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "abc_1")
            .unwrap_or_else(|| panic!("missing abuse case entry"));
        let abuse_case_context = abuse_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing abuse case context"));
        assert!(abuse_case_context.contains("1 notify message"));
        assert!(abuse_case_context.contains("1 acknowledged by operator:carver"));
        assert!(abuse_case_context.contains("1 escalation"));
        assert!(abuse_case_context.contains("follow-up ntf_2"));

        let remediation_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "rem_1")
            .unwrap_or_else(|| panic!("missing remediation case entry"));
        assert_eq!(remediation_case.status, "escalated");
        assert_eq!(
            remediation_case.updated_at.as_deref(),
            Some("2026-04-08T08:16:00Z")
        );
        let remediation_context = remediation_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing remediation case context"));
        assert!(remediation_context.contains("tenant tenant:org_1"));
        assert!(remediation_context.contains("owner operator:incident"));
        assert!(remediation_context.contains("owned since 2026-04-08T08:06:00Z"));
        assert!(remediation_context.contains("5/5 workflow steps completed"));
        assert!(remediation_context.contains("workflow trail 2026-04-08T08:05:00Z dry run completed: linked priorities high; no active quarantines -> 2026-04-08T08:16:00Z checkpoint completed: workflow checkpoint persisted for 1 abuse case and 0 quarantines -> 2026-04-08T08:16:00Z rollback completed: 1 rollback evidence ref ready -> 2026-04-08T08:16:00Z verification completed: 1 verification evidence ref ready -> 2026-04-08T08:16:00Z downstream fanout completed: 1 change request and 2 notify messages linked"));
        assert!(remediation_context.contains("evidence ready"));
        assert!(remediation_context.contains("1 rollback evidence ref"));
        assert!(remediation_context.contains("1 verification evidence ref"));
        assert!(remediation_context.contains("SLA target 900s"));
        assert!(remediation_context.contains("SLA at risk by 2026-04-08T08:20:00Z"));
        assert!(remediation_context.contains("escalation posture escalated"));
        assert!(remediation_context.contains("1 escalation"));
        assert!(remediation_context.contains("last escalation 2026-04-08T08:14:00Z"));
        assert!(remediation_context.contains("last escalated by operator:lead"));
        assert!(remediation_context.contains("escalation reason handoff to incident commander"));
        assert!(remediation_context.contains("2 notify messages"));
        assert!(remediation_context.contains("1 snoozed until 2099-01-01T00:00:00Z"));

        let missing_evidence_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "rem_2")
            .unwrap_or_else(|| panic!("missing missing-evidence remediation entry"));
        assert_eq!(missing_evidence_case.status, "verification_missing");
        assert_eq!(
            missing_evidence_case.updated_at.as_deref(),
            Some("2026-04-08T09:10:00Z")
        );
        let missing_evidence_context = missing_evidence_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing missing-evidence remediation context"));
        assert!(missing_evidence_context.contains("tenant tenant:org_2"));
        assert!(missing_evidence_context.contains("owner operator:recovery"));
        assert!(missing_evidence_context.contains("owned since 2026-04-08T09:05:00Z"));
        assert!(missing_evidence_context.contains("4/5 workflow steps completed"));
        assert!(missing_evidence_context.contains("workflow verification active"));
        assert!(missing_evidence_context.contains("awaiting verification evidence refs"));
        assert!(missing_evidence_context.contains("workflow trail 2026-04-08T09:00:00Z dry run completed: linked priorities normal; no active quarantines -> 2026-04-08T09:10:00Z checkpoint completed: workflow checkpoint persisted for 1 abuse case and 0 quarantines -> 2026-04-08T09:10:00Z rollback completed: 1 rollback evidence ref ready -> 2026-04-08T09:10:00Z verification active: awaiting verification evidence refs -> 2026-04-08T09:10:00Z downstream fanout completed: no downstream fanout required"));
        assert!(missing_evidence_context.contains("evidence verification missing"));
        assert!(missing_evidence_context.contains("1 rollback evidence ref"));
        assert!(missing_evidence_context.contains("0 verification evidence refs"));
        assert!(missing_evidence_context.contains("SLA target 3600s"));
        assert!(missing_evidence_context.contains("SLA within sla by 2026-04-08T10:05:00Z"));

        let notify_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "support:case-123")
            .unwrap_or_else(|| panic!("missing notify case entry"));
        assert_eq!(notify_case.status, "snoozed");
        let notify_case_context = notify_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing notify case context"));
        assert!(notify_case_context.contains("2 notify messages"));
        assert!(notify_case_context.contains("1 acknowledged by operator:carver"));
        assert!(notify_case_context.contains("1 snoozed until 2099-01-01T00:00:00Z"));

        let dead_letter = workbench
            .dead_letters
            .entries
            .iter()
            .find(|entry| entry.id == "dln_1")
            .unwrap_or_else(|| panic!("missing notify dead letter entry"));
        let dead_letter_context = dead_letter
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing dead letter context"));
        assert!(dead_letter_context.contains("case abc_1"));
        assert!(dead_letter_context.contains("acknowledged by operator:carver"));
        assert!(dead_letter_context.contains("1 escalation"));
        assert!(dead_letter_context.contains("follow-up ntf_2"));
    }

    #[tokio::test]
    async fn workbench_prefers_support_case_records_over_opaque_notify_case_references() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_document_collection(
            &root.join("abuse/support_cases.json"),
            &[(
                "aud_support205",
                json!({
                    "id": "aud_support205",
                    "tenant_subject": "tenant.support.console",
                    "opened_by": "operator:abuse",
                    "owner": "ops.support",
                    "owner_assigned_at": "2026-04-08T08:06:00Z",
                    "status": "open",
                    "priority": "high",
                    "remediation_case_ids": ["rem_1"],
                    "change_request_ids": ["chg_1"],
                    "notify_message_ids": ["ntf_support_dead", "ntf_support_snooze"],
                    "reason": "operator support follow-up",
                    "created_at": "2026-04-08T08:05:00Z",
                    "updated_at": "2026-04-08T08:16:00Z"
                }),
            )],
        );
        write_document_collection(
            &root.join("notify/notifications.json"),
            &[
                (
                    "ntf_support_dead",
                    json!({
                        "id": "ntf_support_dead",
                        "channel": "email",
                        "destination": "ops@example.com",
                        "subject": "dead letter requires review",
                        "body": "review notify delivery failure",
                        "case_reference": "support:legacy-case",
                        "locale": "en-US",
                        "state": "dead_lettered",
                        "attempts": 4,
                        "max_attempts": 4,
                        "last_error": "smtp timeout",
                        "acknowledged_at": "2026-04-08T08:07:00Z",
                        "acknowledged_by": "operator:carver",
                        "acknowledgement_note": "operator reviewed dead letter",
                        "escalation_count": 1,
                        "last_escalated_at": "2026-04-08T08:02:00Z",
                        "last_escalated_by": "operator:duty",
                        "last_escalated_notification_id": "ntf_support_snooze",
                        "signature": "sig-support-dead",
                        "created_at": "2026-04-08T07:45:00Z",
                        "updated_at": "2026-04-08T08:07:00Z",
                        "history": [
                            {
                                "sequence": 1,
                                "event": "dead_lettered",
                                "occurred_at": "2026-04-08T08:00:00Z",
                                "actor": "system",
                                "state": "dead_lettered",
                                "attempts": 4,
                                "detail": "retry budget exhausted",
                                "case_reference": "support:legacy-case"
                            }
                        ]
                    }),
                ),
                (
                    "ntf_support_snooze",
                    json!({
                        "id": "ntf_support_snooze",
                        "channel": "incident",
                        "destination": "incident@example.com",
                        "subject": "[ESCALATED] dead letter requires review",
                        "body": "manual handoff pending",
                        "case_reference": "support:legacy-case",
                        "locale": "en-US",
                        "state": "failed",
                        "attempts": 1,
                        "max_attempts": 4,
                        "next_attempt_at": "2099-01-01T00:00:00Z",
                        "last_error": "incident webhook timeout",
                        "snoozed_until": "2099-01-01T00:00:00Z",
                        "snoozed_by": "operator:carver",
                        "snooze_reason": "waiting on operator handoff",
                        "signature": "sig-support-snooze",
                        "created_at": "2026-04-08T08:02:00Z",
                        "updated_at": "2026-04-08T08:10:00Z",
                        "history": [
                            {
                                "sequence": 1,
                                "event": "snoozed",
                                "occurred_at": "2026-04-08T08:10:00Z",
                                "actor": "operator:carver",
                                "state": "failed",
                                "attempts": 1,
                                "detail": "snoozed for 900 seconds: waiting on operator handoff",
                                "case_reference": "support:legacy-case"
                            }
                        ]
                    }),
                ),
            ],
        );
        write_document_collection(
            &root.join("notify/dead_letters.json"),
            &[(
                "dln_support",
                json!({
                    "id": "dln_support",
                    "notification_id": "ntf_support_dead",
                    "channel": "email",
                    "destination": "ops@example.com",
                    "attempts": 4,
                    "last_error": "smtp timeout",
                    "captured_at": "2026-04-08T08:00:00Z",
                    "replay_count": 0,
                    "created_at": "2026-04-08T08:00:00Z",
                    "updated_at": "2026-04-08T08:00:00Z"
                }),
            )],
        );

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/workbench")
            .unwrap_or_else(|| panic!("expected console workbench route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let workbench: OperatorWorkbench =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let support_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "aud_support205")
            .unwrap_or_else(|| panic!("missing support case entry"));
        assert_eq!(support_case.source, "support");
        assert_eq!(support_case.status, "dead_lettered");
        assert_eq!(
            support_case.summary,
            "tenant.support.console · operator support follow-up"
        );
        let support_case_context = support_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing support case context"));
        assert!(support_case_context.contains("tenant tenant.support.console"));
        assert!(support_case_context.contains("owner ops.support"));
        assert!(support_case_context.contains("support status open"));
        assert!(support_case_context.contains("priority high"));
        assert!(support_case_context.contains("2 notify messages"));
        assert!(support_case_context.contains("1 snoozed until 2099-01-01T00:00:00Z"));
        assert!(support_case_context.contains("1 dead-lettered"));
        assert!(
            workbench
                .cases
                .entries
                .iter()
                .all(|entry| entry.id != "support:legacy-case"),
            "support case records should replace opaque legacy case_reference entries"
        );

        let dead_letter = workbench
            .dead_letters
            .entries
            .iter()
            .find(|entry| entry.id == "dln_support")
            .unwrap_or_else(|| panic!("missing support dead letter entry"));
        let dead_letter_context = dead_letter
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing support dead letter context"));
        assert!(dead_letter_context.contains("support case aud_support205"));
        assert!(dead_letter_context.contains("tenant tenant.support.console"));
        assert!(dead_letter_context.contains("support owner ops.support"));
        assert!(dead_letter_context.contains("support status open"));

        let response = service
            .response_for(&Method::GET, "/console")
            .unwrap_or_else(|| panic!("expected console route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let body = std::str::from_utf8(&body).unwrap_or_else(|error| panic!("{error}"));

        assert!(body.contains("tenant.support.console · operator support follow-up"));
        assert!(body.contains("2 notify messages"));
        assert!(body.contains("support case aud_support205"));
        assert!(body.contains("support owner ops.support"));
        assert!(!body.contains("notify workflow for support:legacy-case"));
    }

    #[tokio::test]
    async fn workbench_normalizes_tuple_array_notify_timestamps() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_document_collection(
            &root.join("notify/notifications.json"),
            &[
                (
                    "ntf_tuple_1",
                    json!({
                        "id": "ntf_tuple_1",
                        "channel": "email",
                        "destination": "ops@example.com",
                        "subject": "tuple notify old",
                        "body": "older tuple-backed notify workflow",
                        "case_reference": "support:tuple-case",
                        "locale": "en-US",
                        "state": "failed",
                        "attempts": 1,
                        "max_attempts": 4,
                        "acknowledged_at": timestamp_tuple(2026, 98, 8, 7, 0),
                        "acknowledged_by": "operator:older",
                        "acknowledgement_note": "older ack note",
                        "snoozed_until": timestamp_tuple(2099, 1, 0, 0, 0),
                        "snoozed_by": "operator:older",
                        "snooze_reason": "older snooze reason",
                        "escalation_count": 1,
                        "last_escalated_at": timestamp_tuple(2026, 98, 8, 2, 0),
                        "last_escalated_by": "operator:older-escalation",
                        "last_escalated_notification_id": "ntf_follow_up_1",
                        "signature": "sig-ntf-tuple-1",
                        "created_at": timestamp_tuple(2026, 98, 7, 45, 0),
                        "updated_at": timestamp_tuple(2026, 98, 8, 7, 0),
                        "history": [
                            {
                                "sequence": 1,
                                "event": "snoozed",
                                "occurred_at": timestamp_tuple(2026, 98, 8, 1, 0),
                                "actor": "operator:older",
                                "state": "failed",
                                "attempts": 1,
                                "detail": "older tuple-backed notify event",
                                "case_reference": "support:tuple-case"
                            }
                        ]
                    }),
                ),
                (
                    "ntf_tuple_2",
                    json!({
                        "id": "ntf_tuple_2",
                        "channel": "email",
                        "destination": "incident@example.com",
                        "subject": "tuple notify new",
                        "body": "newer tuple-backed notify workflow",
                        "case_reference": "support:tuple-case",
                        "locale": "en-US",
                        "state": "failed",
                        "attempts": 2,
                        "max_attempts": 4,
                        "acknowledged_at": timestamp_tuple(2026, 98, 8, 15, 0),
                        "acknowledged_by": "operator:newer",
                        "acknowledgement_note": "newer ack note",
                        "snoozed_until": timestamp_tuple(2099, 2, 0, 0, 0),
                        "snoozed_by": "operator:newer",
                        "snooze_reason": "newer snooze reason",
                        "escalation_count": 1,
                        "last_escalated_at": timestamp_tuple(2026, 98, 8, 18, 0),
                        "last_escalated_by": "operator:newer-escalation",
                        "last_escalated_notification_id": "ntf_follow_up_2",
                        "signature": "sig-ntf-tuple-2",
                        "created_at": timestamp_tuple(2026, 98, 8, 10, 0),
                        "updated_at": timestamp_tuple(2026, 98, 8, 16, 0),
                        "history": [
                            {
                                "sequence": 1,
                                "event": "escalated",
                                "occurred_at": timestamp_tuple(2026, 98, 8, 20, 0),
                                "actor": "operator:newer-escalation",
                                "state": "failed",
                                "attempts": 2,
                                "detail": "tuple-backed latest event",
                                "case_reference": "support:tuple-case",
                                "related_notification_id": "ntf_follow_up_2"
                            }
                        ]
                    }),
                ),
            ],
        );

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/workbench")
            .unwrap_or_else(|| panic!("expected console workbench route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let workbench: OperatorWorkbench =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let notify_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "support:tuple-case")
            .unwrap_or_else(|| panic!("missing tuple notify case entry"));
        assert_eq!(notify_case.source, "notify");
        assert_eq!(notify_case.status, "snoozed");
        assert_eq!(
            notify_case.updated_at.as_deref(),
            Some("2026-04-08T08:16:00Z")
        );

        let notify_context = notify_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing tuple notify case context"));
        assert!(notify_context.contains("2 notify messages"));
        assert!(notify_context.contains("2 acknowledged by operator:newer"));
        assert!(notify_context.contains("ack note newer ack note"));
        assert!(notify_context.contains("2 snoozed until 2099-01-02T00:00:00Z"));
        assert!(notify_context.contains("snoozed by operator:newer"));
        assert!(notify_context.contains("snooze reason newer snooze reason"));
        assert!(notify_context.contains("2 escalations"));
        assert!(notify_context.contains("last escalated by operator:newer-escalation"));
        assert!(notify_context.contains("follow-up ntf_follow_up_2"));
        assert!(
            notify_context.contains("latest notify event escalated: tuple-backed latest event")
        );

        let response = service
            .response_for(&Method::GET, "/console")
            .unwrap_or_else(|| panic!("expected console route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let body = std::str::from_utf8(&body).unwrap_or_else(|error| panic!("{error}"));

        assert!(body.contains("notify workflow for support:tuple-case"));
        assert!(body.contains("2 acknowledged by operator:newer"));
        assert!(body.contains("2 snoozed until 2099-01-02T00:00:00Z"));
        assert!(body.contains("last escalated by operator:newer-escalation"));
        assert!(body.contains("latest notify event escalated: tuple-backed latest event"));
    }

    #[tokio::test]
    async fn workbench_normalizes_tuple_array_remediation_timestamps() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_document_collection(
            &root.join("abuse/remediation_cases.json"),
            &[(
                "rem_tuple",
                json!({
                    "id": "rem_tuple",
                    "tenant_subject": "tenant:tuple",
                    "opened_by": "operator:abuse",
                    "owner": "operator:incident",
                    "owner_assigned_at": timestamp_tuple(2026, 98, 8, 6, 0),
                    "abuse_case_ids": [],
                    "quarantine_ids": [],
                    "change_request_ids": [],
                    "notify_message_ids": [],
                    "rollback_evidence_refs": ["runbook:tuple-rollback"],
                    "verification_evidence_refs": ["checklist:tuple-verify"],
                    "evidence_state": "ready",
                    "sla_target_seconds": 900,
                    "sla_deadline_at": timestamp_tuple(2026, 98, 8, 20, 0),
                    "sla_state": "at_risk",
                    "escalation_state": "escalated",
                    "escalation_count": 1,
                    "last_escalated_at": timestamp_tuple(2026, 98, 8, 14, 0),
                    "last_escalated_by": "operator:lead",
                    "last_escalation_reason": "handoff to incident commander",
                    "reason": "tuple-backed remediation state",
                    "created_at": timestamp_tuple(2026, 98, 8, 5, 0),
                    "updated_at": timestamp_tuple(2026, 98, 8, 16, 0)
                }),
            )],
        );

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console/workbench")
            .unwrap_or_else(|| panic!("expected console workbench route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let workbench: OperatorWorkbench =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let remediation_case = workbench
            .cases
            .entries
            .iter()
            .find(|entry| entry.id == "rem_tuple")
            .unwrap_or_else(|| panic!("missing tuple remediation case entry"));
        assert_eq!(remediation_case.source, "remediation");
        assert_eq!(remediation_case.status, "escalated");
        assert_eq!(
            remediation_case.updated_at.as_deref(),
            Some("2026-04-08T08:16:00Z")
        );

        let remediation_context = remediation_case
            .context
            .as_deref()
            .unwrap_or_else(|| panic!("missing tuple remediation case context"));
        assert!(remediation_context.contains("tenant tenant:tuple"));
        assert!(remediation_context.contains("owner operator:incident"));
        assert!(remediation_context.contains("owned since 2026-04-08T08:06:00Z"));
        assert!(remediation_context.contains("evidence ready"));
        assert!(remediation_context.contains("SLA target 900s"));
        assert!(remediation_context.contains("SLA at risk by 2026-04-08T08:20:00Z"));
        assert!(remediation_context.contains("last escalation 2026-04-08T08:14:00Z"));
        assert!(remediation_context.contains("last escalated by operator:lead"));
        assert!(remediation_context.contains("escalation reason handoff to incident commander"));

        let response = service
            .response_for(&Method::GET, "/console")
            .unwrap_or_else(|| panic!("expected console route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let body = std::str::from_utf8(&body).unwrap_or_else(|error| panic!("{error}"));

        assert!(body.contains("tuple-backed remediation state"));
        assert!(body.contains("tenant tenant:tuple"));
        assert!(body.contains("owner operator:incident"));
        assert!(body.contains("owned since 2026-04-08T08:06:00Z"));
        assert!(body.contains("evidence ready"));
        assert!(body.contains("SLA at risk by 2026-04-08T08:20:00Z"));
        assert!(body.contains("last escalated by operator:lead"));
        assert!(body.contains("escalation reason handoff to incident commander"));
    }

    #[tokio::test]
    async fn index_route_renders_operator_workbench_sections() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let root = temp.path();
        write_workbench_fixture(root);

        let service = ConsoleService::open(root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .response_for(&Method::GET, "/console")
            .unwrap_or_else(|| panic!("expected console route to match"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let body = std::str::from_utf8(&body).unwrap_or_else(|error| panic!("{error}"));

        assert!(body.contains("Operator workbench"));
        assert!(body.contains("/console/workbench"));
        assert!(body.contains("Derived from billing budgets"));
        assert!(body.contains("Secret reveal grants"));
        assert!(body.contains("Case-linked notifications"));
        assert!(body.contains("Dead letters"));
        assert!(body.contains("workflow trail 2026-04-08T08:05:00Z dry run completed"));
        assert!(body.contains("2026-04-08T08:16:00Z downstream fanout completed: 1 change request and 2 notify messages linked"));
    }

    #[test]
    fn remediation_evidence_counts_drive_attention_even_when_state_is_stale() {
        let summary = RemediationCaseWorkflowSummary {
            owner: Some(String::from("operator:recovery")),
            owner_assigned_at: Some(String::from("2026-04-08T09:05:00Z")),
            rollback_evidence_count: 1,
            verification_evidence_count: 0,
            evidence_state: Some(String::from("ready")),
            sla_state: Some(String::from("within_sla")),
            ..RemediationCaseWorkflowSummary::default()
        };

        assert_eq!(summary.status(None), "verification_missing");
        assert!(summary.needs_attention(None));

        let context = ConsoleService::remediation_case_workflow_context(&summary)
            .unwrap_or_else(|| panic!("missing remediation evidence context"));
        assert!(context.contains("evidence verification missing"));
        assert!(context.contains("1 rollback evidence ref"));
        assert!(context.contains("0 verification evidence refs"));
    }
}
