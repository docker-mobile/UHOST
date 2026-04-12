//! Abuse prevention and trust-safety service.
//!
//! This bounded context owns risk signal ingestion, reputation scoring, case
//! workflows, quarantine/suspension controls, and appeals. It intentionally
//! persists explicit records for every decision so operator actions remain
//! auditable and replayable.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{
    PlatformError, PrincipalKind, RequestContext, Result, canonicalize_hostname, sha256_hex,
    validate_domain_name,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, WorkflowStep, WorkflowStepState};
use uhost_types::{
    AbuseAppealId, AbuseCaseId, AbuseQuarantineId, AbuseSignalId, AuditActor, AuditId,
    ChangeRequestId, EventHeader, EventPayload, NotificationId, OwnershipScope, PlatformEvent,
    ResourceMetadata, ServiceEvent,
};

/// Signal captured by abuse detection pipelines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseSignalRecord {
    /// Stable signal identifier.
    pub id: AbuseSignalId,
    /// Subject domain (`service_identity`, `user`, `tenant`, `project`, `mail_domain`, `ip_address`, `hostname`).
    pub subject_kind: String,
    /// Canonicalized subject key.
    pub subject: String,
    /// Signal class (`signup_abuse`, `spam`, `api_abuse`, etc.).
    pub signal_kind: String,
    /// Signal severity (`low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Confidence in basis points.
    pub confidence_bps: u16,
    /// Source service that emitted this signal.
    pub source_service: String,
    /// Human-readable explanation.
    pub reason: String,
    /// Evidence references (flow IDs, ticket IDs, trace IDs, hashes).
    pub evidence_refs: Vec<String>,
    /// Observation timestamp.
    pub observed_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Reputation profile for one canonical subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationRecord {
    /// Subject domain.
    pub subject_kind: String,
    /// Canonical subject.
    pub subject: String,
    /// Reputation score between `-100` and `100`.
    pub score: i32,
    /// Derived state (`trusted`, `watch`, `restricted`, `blocked`) or operator override.
    pub state: String,
    /// Number of signals processed for this subject.
    pub signal_count: u64,
    /// Timestamp of the last signal update.
    pub last_signal_at: Option<OffsetDateTime>,
    /// Last reason string.
    pub reason: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Abuse case tracked by trust-and-safety responders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseCase {
    /// Case identifier.
    pub id: AbuseCaseId,
    /// Subject domain.
    pub subject_kind: String,
    /// Canonical subject.
    pub subject: String,
    /// Opening reason.
    pub reason: String,
    /// Case status (`open`, `under_review`, `quarantined`, `suspended`, `resolved`, `dismissed`).
    pub status: String,
    /// Priority (`low`, `normal`, `high`, `critical`).
    pub priority: String,
    /// Assignee principal.
    pub assigned_to: Option<String>,
    /// Escalation count.
    pub escalation_count: u32,
    /// Related signal IDs.
    pub signal_ids: Vec<AbuseSignalId>,
    /// Evidence references.
    pub evidence_refs: Vec<String>,
    /// Linked quarantine, if present.
    pub quarantine_id: Option<AbuseQuarantineId>,
    /// Last decision note.
    pub decision_note: Option<String>,
    /// Open timestamp.
    pub opened_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Case closure timestamp.
    pub closed_at: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Quarantine state linked to a subject and optionally to one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Quarantine identifier.
    pub id: AbuseQuarantineId,
    /// Subject domain.
    pub subject_kind: String,
    /// Canonical subject.
    pub subject: String,
    /// Quarantine state (`active` or `released`).
    pub state: String,
    /// Reason for the quarantine.
    pub reason: String,
    /// Related case identifier.
    pub case_id: Option<AbuseCaseId>,
    /// Whether network traffic should be denied.
    pub deny_network: bool,
    /// Whether mail relay should be denied.
    pub deny_mail_relay: bool,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Optional expiration timestamp.
    pub expires_at: Option<OffsetDateTime>,
    /// Optional release timestamp.
    pub released_at: Option<OffsetDateTime>,
    /// Optional release reason.
    pub released_reason: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Appeal submitted against a case or quarantine decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppealRecord {
    /// Appeal identifier.
    pub id: AbuseAppealId,
    /// Target case.
    pub case_id: AbuseCaseId,
    /// Subject domain.
    pub subject_kind: String,
    /// Canonical subject.
    pub subject: String,
    /// Requesting principal.
    pub requested_by: String,
    /// Appeal reason.
    pub reason: String,
    /// Appeal status (`pending`, `accepted`, `rejected`).
    pub status: String,
    /// Reviewer principal.
    pub reviewed_by: Option<String>,
    /// Reviewer note.
    pub review_note: Option<String>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Review timestamp.
    pub reviewed_at: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Operator-facing remediation case linking abuse evidence to approval and notification flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationCaseRecord {
    /// Remediation case identifier.
    pub id: AuditId,
    /// Stable remediation workflow identifier projected from this case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    /// Explicit remediation workflow steps projected into this case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflow_steps: Vec<WorkflowStep>,
    /// Tenant anchor for this operator workflow.
    pub tenant_subject: String,
    /// Operator principal that opened this remediation case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_by: Option<String>,
    /// Current operator owner for this remediation case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Timestamp when the current owner was assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_assigned_at: Option<OffsetDateTime>,
    /// Related abuse case identifiers.
    pub abuse_case_ids: Vec<AbuseCaseId>,
    /// Related quarantine identifiers.
    pub quarantine_ids: Vec<AbuseQuarantineId>,
    /// Related governance change requests.
    pub change_request_ids: Vec<ChangeRequestId>,
    /// Related notify message identifiers.
    pub notify_message_ids: Vec<NotificationId>,
    /// Evidence references describing the rollback path for this remediation workflow.
    #[serde(default)]
    pub rollback_evidence_refs: Vec<String>,
    /// Evidence references describing how operators verify remediation completion.
    #[serde(default)]
    pub verification_evidence_refs: Vec<String>,
    /// Current rollback/verification evidence posture.
    #[serde(default = "default_remediation_evidence_state")]
    pub evidence_state: String,
    /// SLA target in seconds for the next operator action.
    #[serde(default = "default_remediation_sla_target_seconds")]
    pub sla_target_seconds: u32,
    /// Deadline when this remediation case leaves SLA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_deadline_at: Option<OffsetDateTime>,
    /// Current SLA projection (`within_sla`, `at_risk`, `breached`).
    #[serde(default = "default_remediation_sla_state")]
    pub sla_state: String,
    /// Current escalation posture (`none`, `queued`, `escalated`).
    #[serde(default = "default_remediation_escalation_state")]
    pub escalation_state: String,
    /// Number of escalations recorded for this remediation case.
    #[serde(default)]
    pub escalation_count: u32,
    /// Timestamp of the latest escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalated_at: Option<OffsetDateTime>,
    /// Operator that performed the latest escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalated_by: Option<String>,
    /// Reason recorded with the latest escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalation_reason: Option<String>,
    /// Operator reason for opening the remediation case.
    pub reason: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Operator-facing support case linking remediation, governance, and notify work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportCaseRecord {
    /// Support case identifier.
    pub id: AuditId,
    /// Tenant anchor for this support case.
    pub tenant_subject: String,
    /// Operator principal that opened this support case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_by: Option<String>,
    /// Current operator owner for this support case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Timestamp when the current owner was assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_assigned_at: Option<OffsetDateTime>,
    /// Current support lifecycle status.
    #[serde(default = "default_support_case_status")]
    pub status: String,
    /// Current support priority.
    #[serde(default = "default_support_case_priority")]
    pub priority: String,
    /// Related remediation case identifiers.
    #[serde(default)]
    pub remediation_case_ids: Vec<AuditId>,
    /// Related governance change requests.
    #[serde(default)]
    pub change_request_ids: Vec<ChangeRequestId>,
    /// Related notify message identifiers.
    #[serde(default)]
    pub notify_message_ids: Vec<NotificationId>,
    /// Operator reason for opening this support case.
    pub reason: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Generic tally used in summary surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotalByValue {
    pub value: String,
    pub count: usize,
}

/// Read-only abuse summary surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseSummary {
    pub state_root: String,
    pub signals_total: usize,
    pub signals_by_severity: Vec<TotalByValue>,
    pub cases_total: usize,
    pub cases_by_status: Vec<TotalByValue>,
    pub active_cases: usize,
    pub quarantines_total: usize,
    pub active_quarantines: usize,
    pub quarantines_by_state: Vec<TotalByValue>,
    pub appeals_total: usize,
    pub appeals_by_status: Vec<TotalByValue>,
    pub reputations_total: usize,
    pub reputations_by_state: Vec<TotalByValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSignalRequest {
    subject_kind: Option<String>,
    subject: String,
    signal_kind: String,
    severity: String,
    confidence_bps: Option<u16>,
    source_service: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateReputationRequest {
    subject_kind: Option<String>,
    subject: String,
    score: i32,
    state: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateAbuseCaseRequest {
    subject_kind: Option<String>,
    subject: String,
    reason: String,
    priority: Option<String>,
    #[serde(default)]
    signal_ids: Vec<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QuarantinePolicyRequest {
    deny_network: Option<bool>,
    deny_mail_relay: Option<bool>,
    expires_after_seconds: Option<u32>,
}

impl Default for QuarantinePolicyRequest {
    fn default() -> Self {
        Self {
            deny_network: Some(true),
            deny_mail_relay: Some(true),
            expires_after_seconds: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewCaseRequest {
    action: String,
    reviewer: String,
    note: Option<String>,
    assign_to: Option<String>,
    escalate: Option<bool>,
    quarantine: Option<QuarantinePolicyRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateQuarantineRequest {
    subject_kind: Option<String>,
    subject: String,
    reason: String,
    case_id: Option<String>,
    deny_network: Option<bool>,
    deny_mail_relay: Option<bool>,
    expires_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseQuarantineRequest {
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateAppealRequest {
    case_id: String,
    requested_by: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewAppealRequest {
    reviewer: String,
    action: String,
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRiskRequest {
    subject_kind: Option<String>,
    subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRiskResponse {
    subject_kind: String,
    subject: String,
    score: i32,
    state: String,
    signal_count: u64,
    signals_in_last_24h: u32,
    active_case_ids: Vec<String>,
    active_quarantine_id: Option<String>,
    recommended_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSupportCaseRequest {
    tenant_subject: String,
    reason: String,
    owner: Option<String>,
    priority: Option<String>,
    #[serde(default)]
    remediation_case_ids: Vec<String>,
    #[serde(default)]
    change_request_ids: Vec<String>,
    #[serde(default)]
    notify_message_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TransitionSupportCaseRequest {
    reason: String,
    status: Option<String>,
    owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRemediationCaseRequest {
    tenant_subject: String,
    reason: String,
    owner: Option<String>,
    sla_target_seconds: Option<u32>,
    #[serde(default)]
    rollback_evidence_refs: Vec<String>,
    #[serde(default)]
    verification_evidence_refs: Vec<String>,
    #[serde(default)]
    abuse_case_ids: Vec<String>,
    #[serde(default)]
    quarantine_ids: Vec<String>,
    #[serde(default)]
    change_request_ids: Vec<String>,
    #[serde(default)]
    notify_message_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EscalateRemediationCaseRequest {
    reason: String,
    owner: Option<String>,
    #[serde(default)]
    rollback_evidence_refs: Vec<String>,
    #[serde(default)]
    verification_evidence_refs: Vec<String>,
    #[serde(default)]
    change_request_ids: Vec<String>,
    #[serde(default)]
    notify_message_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemediationCaseLinkContext {
    linked_case_priorities: Vec<String>,
    active_quarantine_count: usize,
    requires_attention: bool,
}

/// Abuse service.
#[derive(Debug, Clone)]
pub struct AbuseService {
    signals: DocumentStore<AbuseSignalRecord>,
    reputation: DocumentStore<ReputationRecord>,
    cases: DocumentStore<AbuseCase>,
    quarantines: DocumentStore<QuarantineRecord>,
    appeals: DocumentStore<AppealRecord>,
    support_cases: DocumentStore<SupportCaseRecord>,
    remediation_cases: DocumentStore<RemediationCaseRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl AbuseService {
    /// Open abuse state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("abuse");
        Ok(Self {
            signals: DocumentStore::open(root.join("signals.json")).await?,
            reputation: DocumentStore::open(root.join("reputation.json")).await?,
            cases: DocumentStore::open(root.join("cases.json")).await?,
            quarantines: DocumentStore::open(root.join("quarantines.json")).await?,
            appeals: DocumentStore::open(root.join("appeals.json")).await?,
            support_cases: DocumentStore::open(root.join("support_cases.json")).await?,
            remediation_cases: DocumentStore::open(root.join("remediation_cases.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn create_signal(
        &self,
        request: CreateSignalRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = normalize_subject_kind(request.subject_kind.as_deref())?;
        let subject = normalize_subject(&subject_kind, &request.subject)?;
        let signal_kind = normalize_signal_kind(&request.signal_kind)?;
        let severity = normalize_severity(&request.severity)?;
        let confidence_bps = request.confidence_bps.unwrap_or(8_000).clamp(500, 10_000);
        let reason = request
            .reason
            .unwrap_or_else(|| format!("{} signal observed for {}", signal_kind, subject_kind));
        let source_service = normalize_source_service(request.source_service.as_deref())?;
        let evidence_refs = normalize_evidence_refs(request.evidence_refs)?;

        let id = AbuseSignalId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate abuse signal id")
                .with_detail(error.to_string())
        })?;
        let signal = AbuseSignalRecord {
            id: id.clone(),
            subject_kind: subject_kind.clone(),
            subject: subject.clone(),
            signal_kind: signal_kind.clone(),
            severity: severity.clone(),
            confidence_bps,
            source_service,
            reason: reason.clone(),
            evidence_refs,
            observed_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.signals.create(id.as_str(), signal.clone()).await?;

        let delta = score_delta_for_signal(&signal_kind, &severity, confidence_bps);
        let reputation = self
            .apply_reputation_delta(
                &subject_kind,
                &subject,
                delta,
                Some(reason.clone()),
                true,
                context,
            )
            .await?;
        let quarantine = if reputation.state == "blocked" {
            Some(
                self.ensure_active_quarantine(
                    &subject_kind,
                    &subject,
                    "auto quarantine due to blocked reputation state",
                    None,
                    &QuarantinePolicyRequest::default(),
                    context,
                )
                .await?,
            )
        } else {
            None
        };

        self.append_event(
            "abuse.signal.recorded.v1",
            "abuse_signal",
            id.as_str(),
            "recorded",
            serde_json::json!({
                "subject_kind": subject_kind,
                "subject": subject,
                "signal_kind": signal_kind,
                "severity": severity,
                "confidence_bps": confidence_bps,
                "score_delta": delta,
                "reputation_state": reputation.state,
                "quarantine_id": quarantine.as_ref().map(|entry| entry.id.to_string()),
            }),
            context,
        )
        .await?;

        json_response(
            StatusCode::CREATED,
            &serde_json::json!({
                "signal": signal,
                "reputation": reputation,
                "quarantine": quarantine,
            }),
        )
    }

    async fn upsert_reputation(
        &self,
        request: CreateReputationRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = normalize_subject_kind(request.subject_kind.as_deref())?;
        let subject = normalize_subject(&subject_kind, &request.subject)?;
        let state = normalize_reputation_state(&request.state)?;
        let score = request.score.clamp(-100, 100);
        let key = reputation_key(&subject_kind, &subject);
        let existing = self.reputation.get(&key).await?;
        let record = if let Some(stored) = existing {
            let mut current = stored.value;
            current.score = score;
            current.state = state;
            current.reason = request.reason;
            current.metadata.touch(sha256_hex(key.as_bytes()));
            self.reputation
                .upsert(&key, current.clone(), Some(stored.version))
                .await?;
            current
        } else {
            let created = ReputationRecord {
                subject_kind: subject_kind.clone(),
                subject: subject.clone(),
                score,
                state,
                signal_count: 0,
                last_signal_at: None,
                reason: request.reason,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(key.clone()),
                    sha256_hex(key.as_bytes()),
                ),
            };
            self.reputation.create(&key, created.clone()).await?;
            created
        };
        self.append_event(
            "abuse.reputation.overridden.v1",
            "reputation",
            &key,
            "overridden",
            serde_json::json!({
                "subject_kind": record.subject_kind,
                "subject": record.subject,
                "score": record.score,
                "state": record.state,
                "reason": record.reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_case(
        &self,
        request: CreateAbuseCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = normalize_subject_kind(request.subject_kind.as_deref())?;
        let subject = normalize_subject(&subject_kind, &request.subject)?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let priority = normalize_case_priority(request.priority.as_deref().unwrap_or("normal"))?;
        let mut parsed_signal_ids = Vec::with_capacity(request.signal_ids.len());
        for signal_id in request.signal_ids {
            let id = AbuseSignalId::parse(signal_id).map_err(|error| {
                PlatformError::invalid("invalid signal id").with_detail(error.to_string())
            })?;
            let _ = self
                .signals
                .get(id.as_str())
                .await?
                .ok_or_else(|| PlatformError::not_found("referenced signal does not exist"))?;
            parsed_signal_ids.push(id);
        }

        let id = AbuseCaseId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate abuse case id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let record = AbuseCase {
            id: id.clone(),
            subject_kind: subject_kind.clone(),
            subject: subject.clone(),
            reason: request.reason,
            status: String::from("open"),
            priority,
            assigned_to: None,
            escalation_count: 0,
            signal_ids: parsed_signal_ids,
            evidence_refs: normalize_evidence_refs(request.evidence_refs)?,
            quarantine_id: None,
            decision_note: None,
            opened_at: now,
            updated_at: now,
            closed_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.cases.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "abuse.case.created.v1",
            "abuse_case",
            id.as_str(),
            "created",
            serde_json::json!({
                "subject_kind": subject_kind,
                "subject": subject,
                "priority": record.priority,
                "signal_count": record.signal_ids.len(),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn review_case(
        &self,
        case_id: &str,
        request: ReviewCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let case_id = AbuseCaseId::parse(case_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid case id").with_detail(error.to_string())
        })?;
        let action = normalize_case_action(&request.action)?;
        let reviewer = normalize_principal(&request.reviewer)?;
        let Some(stored) = self.cases.get(case_id.as_str()).await? else {
            return Err(PlatformError::not_found("abuse case does not exist"));
        };
        let mut record = stored.value;
        let next_status = transition_case_status(&record.status, &action)?;
        if let Some(assignee) = request.assign_to {
            record.assigned_to = Some(normalize_principal(&assignee)?);
        }
        if request.escalate.unwrap_or(false) {
            record.escalation_count = record.escalation_count.saturating_add(1);
        }

        let mut linked_quarantine: Option<QuarantineRecord> = None;
        if action == "quarantine" || action == "suspend" {
            let policy = request.quarantine.unwrap_or_default();
            linked_quarantine = Some(
                self.ensure_active_quarantine(
                    &record.subject_kind,
                    &record.subject,
                    request.note.as_deref().unwrap_or(&record.reason),
                    Some(record.id.clone()),
                    &policy,
                    context,
                )
                .await?,
            );
            record.quarantine_id = linked_quarantine.as_ref().map(|value| value.id.clone());
        }
        if action == "resolve" || action == "dismiss" {
            record.closed_at = Some(OffsetDateTime::now_utc());
        }
        if action == "reopen" {
            record.closed_at = None;
        }
        record.status = next_status;
        record.decision_note = request.note;
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.cases
            .upsert(case_id.as_str(), record.clone(), Some(stored.version))
            .await?;

        self.append_event(
            "abuse.case.reviewed.v1",
            "abuse_case",
            case_id.as_str(),
            "reviewed",
            serde_json::json!({
                "action": action,
                "reviewer": reviewer,
                "status": record.status,
                "assigned_to": record.assigned_to,
                "escalation_count": record.escalation_count,
                "quarantine_id": linked_quarantine.as_ref().map(|value| value.id.to_string()),
            }),
            context,
        )
        .await?;

        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "case": record,
                "quarantine": linked_quarantine,
            }),
        )
    }

    async fn create_quarantine(
        &self,
        request: CreateQuarantineRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = normalize_subject_kind(request.subject_kind.as_deref())?;
        let subject = normalize_subject(&subject_kind, &request.subject)?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let case_id = match request.case_id {
            Some(value) => Some(AbuseCaseId::parse(value).map_err(|error| {
                PlatformError::invalid("invalid case_id").with_detail(error.to_string())
            })?),
            None => None,
        };
        if let Some(case_id) = case_id.as_ref() {
            let _ = self.cases.get(case_id.as_str()).await?.ok_or_else(|| {
                PlatformError::not_found("case referenced by case_id does not exist")
            })?;
        }
        let policy = QuarantinePolicyRequest {
            deny_network: request.deny_network,
            deny_mail_relay: request.deny_mail_relay,
            expires_after_seconds: request.expires_after_seconds,
        };
        let record = self
            .ensure_active_quarantine(
                &subject_kind,
                &subject,
                &request.reason,
                case_id.clone(),
                &policy,
                context,
            )
            .await?;

        if let Some(case_id) = case_id {
            self.mark_case_quarantined(&case_id, &record.id).await?;
        }

        json_response(StatusCode::CREATED, &record)
    }

    async fn release_quarantine(
        &self,
        quarantine_id: &str,
        request: ReleaseQuarantineRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let quarantine_id =
            AbuseQuarantineId::parse(quarantine_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid quarantine id").with_detail(error.to_string())
            })?;
        let Some(stored) = self.quarantines.get(quarantine_id.as_str()).await? else {
            return Err(PlatformError::not_found("quarantine does not exist"));
        };
        let mut record = stored.value;
        if record.state != "active" {
            return json_response(StatusCode::OK, &record);
        }
        record.state = String::from("released");
        record.released_reason = Some(request.reason.clone());
        record.released_at = Some(OffsetDateTime::now_utc());
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.quarantines
            .upsert(quarantine_id.as_str(), record.clone(), Some(stored.version))
            .await?;
        if let Some(case_id) = record.case_id.as_ref() {
            self.mark_case_under_review_after_release(case_id, &request.reason)
                .await?;
        }
        self.append_event(
            "abuse.quarantine.released.v1",
            "abuse_quarantine",
            quarantine_id.as_str(),
            "released",
            serde_json::json!({
                "reason": request.reason,
                "subject_kind": record.subject_kind,
                "subject": record.subject,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn create_appeal(
        &self,
        request: CreateAppealRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let case_id = AbuseCaseId::parse(request.case_id).map_err(|error| {
            PlatformError::invalid("invalid case id").with_detail(error.to_string())
        })?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let requested_by = normalize_principal(&request.requested_by)?;
        let case = self
            .cases
            .get(case_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("appeal case does not exist"))?;

        let id = AbuseAppealId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate appeal id")
                .with_detail(error.to_string())
        })?;
        let record = AppealRecord {
            id: id.clone(),
            case_id,
            subject_kind: case.value.subject_kind.clone(),
            subject: case.value.subject.clone(),
            requested_by,
            reason: request.reason,
            status: String::from("pending"),
            reviewed_by: None,
            review_note: None,
            created_at: OffsetDateTime::now_utc(),
            reviewed_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.appeals.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "abuse.appeal.created.v1",
            "abuse_appeal",
            id.as_str(),
            "created",
            serde_json::json!({
                "case_id": record.case_id,
                "subject_kind": record.subject_kind,
                "subject": record.subject,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_support_case(
        &self,
        request: CreateSupportCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "support case management")?;
        let owner_was_explicit = request.owner.is_some();
        let tenant_subject = normalize_tenant_subject(&request.tenant_subject)?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }

        let remediation_case_ids = self
            .resolve_remediation_case_links(request.remediation_case_ids)
            .await?;
        let change_request_ids =
            parse_change_request_links(request.change_request_ids, "change_request_id")?;
        let notify_message_ids =
            parse_notification_links(request.notify_message_ids, "notify_message_id")?;
        if remediation_case_ids.is_empty()
            && change_request_ids.is_empty()
            && notify_message_ids.is_empty()
        {
            return Err(PlatformError::invalid(
                "at least one remediation_case_id, change_request_id, or notify_message_id is required",
            ));
        }

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate support case id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let opened_by = remediation_actor(context)?;
        let owner = request
            .owner
            .as_deref()
            .map(normalize_principal)
            .transpose()?
            .unwrap_or_else(|| opened_by.clone());
        let priority = request
            .priority
            .as_deref()
            .map(normalize_case_priority)
            .transpose()?
            .unwrap_or_else(default_support_case_priority);

        let record = SupportCaseRecord {
            id: id.clone(),
            tenant_subject,
            opened_by: Some(opened_by),
            owner: Some(owner),
            owner_assigned_at: Some(now),
            status: default_support_case_status(),
            priority,
            remediation_case_ids,
            change_request_ids,
            notify_message_ids,
            reason: request.reason,
            created_at: now,
            updated_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.support_cases
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "abuse.support_case.created.v1",
            "abuse_support_case",
            id.as_str(),
            "created",
            support_case_event_details(
                &record,
                serde_json::json!({
                    "owner_source": if owner_was_explicit { "requested" } else { "actor_default" },
                    "link_counts": {
                        "remediation_cases": record.remediation_case_ids.len(),
                        "change_requests": record.change_request_ids.len(),
                        "notify_messages": record.notify_message_ids.len(),
                    },
                }),
            ),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_remediation_case(
        &self,
        request: CreateRemediationCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "remediation case management")?;
        let owner_was_explicit = request.owner.is_some();
        let tenant_subject = normalize_tenant_subject(&request.tenant_subject)?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }

        let abuse_case_ids = self.resolve_case_links(request.abuse_case_ids).await?;
        let quarantine_ids = self
            .resolve_quarantine_links(request.quarantine_ids)
            .await?;
        if abuse_case_ids.is_empty() && quarantine_ids.is_empty() {
            return Err(PlatformError::invalid(
                "at least one abuse_case_id or quarantine_id is required",
            ));
        }
        let change_request_ids =
            parse_change_request_links(request.change_request_ids, "change_request_id")?;
        let notify_message_ids =
            parse_notification_links(request.notify_message_ids, "notify_message_id")?;
        let rollback_evidence_refs = normalize_evidence_refs(request.rollback_evidence_refs)?;
        let verification_evidence_refs =
            normalize_evidence_refs(request.verification_evidence_refs)?;
        ensure_remediation_evidence_requirements(
            &rollback_evidence_refs,
            &verification_evidence_refs,
        )?;

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate remediation case id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let opened_by = remediation_actor(context)?;
        let owner = request
            .owner
            .as_deref()
            .map(normalize_principal)
            .transpose()?
            .unwrap_or_else(|| opened_by.clone());
        let case_records = self.load_case_records(&abuse_case_ids).await?;
        let quarantine_records = self.load_quarantine_records(&quarantine_ids).await?;
        let link_context =
            remediation_link_context_from_records(&case_records, &quarantine_records, now);
        let sla_target_seconds = normalize_remediation_sla_target_seconds(
            request.sla_target_seconds,
            default_remediation_sla_target_seconds_for_links(
                &case_records,
                &quarantine_records,
                now,
            ),
        );
        let mut record = RemediationCaseRecord {
            id: id.clone(),
            workflow_id: None,
            workflow_steps: Vec::new(),
            tenant_subject: tenant_subject.clone(),
            opened_by: Some(opened_by),
            owner: Some(owner),
            owner_assigned_at: Some(now),
            abuse_case_ids: abuse_case_ids.clone(),
            quarantine_ids: quarantine_ids.clone(),
            change_request_ids: change_request_ids.clone(),
            notify_message_ids: notify_message_ids.clone(),
            rollback_evidence_refs: rollback_evidence_refs.clone(),
            verification_evidence_refs: verification_evidence_refs.clone(),
            evidence_state: default_remediation_evidence_state(),
            sla_target_seconds,
            sla_deadline_at: Some(now + Duration::seconds(i64::from(sla_target_seconds))),
            sla_state: default_remediation_sla_state(),
            escalation_state: default_remediation_escalation_state(),
            escalation_count: 0,
            last_escalated_at: None,
            last_escalated_by: None,
            last_escalation_reason: None,
            reason: request.reason,
            created_at: now,
            updated_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        record = materialize_remediation_case(record, &link_context, now);
        self.remediation_cases
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "abuse.remediation_case.created.v1",
            "abuse_remediation_case",
            id.as_str(),
            "created",
            remediation_case_event_details(
                &record,
                &link_context,
                serde_json::json!({
                    "owner_source": if owner_was_explicit { "requested" } else { "actor_default" },
                    "attention_reasons": remediation_attention_reasons(&record, &link_context),
                }),
            ),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn review_appeal(
        &self,
        appeal_id: &str,
        request: ReviewAppealRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let appeal_id = AbuseAppealId::parse(appeal_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid appeal id").with_detail(error.to_string())
        })?;
        let reviewer = normalize_principal(&request.reviewer)?;
        let action = normalize_appeal_action(&request.action)?;
        let Some(stored) = self.appeals.get(appeal_id.as_str()).await? else {
            return Err(PlatformError::not_found("appeal does not exist"));
        };
        let mut record = stored.value;
        if record.status != "pending" {
            return Err(PlatformError::conflict("appeal is already closed"));
        }

        record.status = if action == "accept" {
            String::from("accepted")
        } else {
            String::from("rejected")
        };
        record.reviewed_by = Some(reviewer.clone());
        record.review_note = request.note.clone();
        record.reviewed_at = Some(OffsetDateTime::now_utc());
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.appeals
            .upsert(appeal_id.as_str(), record.clone(), Some(stored.version))
            .await?;

        if action == "accept" {
            self.apply_accepted_appeal(&record, request.note.as_deref(), context)
                .await?;
        }

        self.append_event(
            "abuse.appeal.reviewed.v1",
            "abuse_appeal",
            appeal_id.as_str(),
            "reviewed",
            serde_json::json!({
                "action": action,
                "reviewer": reviewer,
                "case_id": record.case_id,
                "note": record.review_note,
            }),
            context,
        )
        .await?;

        json_response(StatusCode::OK, &record)
    }

    async fn current_support_case(
        &self,
        support_case_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "support case inspection")?;
        let support_case_id = AuditId::parse(support_case_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid support case id").with_detail(error.to_string())
        })?;
        let record = self
            .support_cases
            .get(support_case_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
            .ok_or_else(|| PlatformError::not_found("support case does not exist"))?;
        json_response(StatusCode::OK, &record)
    }

    async fn transition_support_case(
        &self,
        support_case_id: &str,
        request: TransitionSupportCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "support case management")?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        if request.status.is_none() && request.owner.is_none() {
            return Err(PlatformError::invalid(
                "support case transition requires status or owner",
            ));
        }

        let support_case_id = AuditId::parse(support_case_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid support case id").with_detail(error.to_string())
        })?;
        let Some(stored) = self.support_cases.get(support_case_id.as_str()).await? else {
            return Err(PlatformError::not_found("support case does not exist"));
        };
        if stored.deleted {
            return Err(PlatformError::not_found("support case does not exist"));
        }

        let mut record = stored.value;
        let actor = remediation_actor(context)?;
        let requested_status = request
            .status
            .as_deref()
            .map(normalize_support_case_status)
            .transpose()?;
        let requested_owner = request
            .owner
            .as_deref()
            .map(normalize_principal)
            .transpose()?;
        let previous_status = record.status.clone();
        let previous_owner = record.owner.clone();
        let status_changed = requested_status
            .as_deref()
            .is_some_and(|status| status != record.status);
        let owner_changed = requested_owner
            .as_deref()
            .is_some_and(|owner| record.owner.as_deref() != Some(owner));
        if !status_changed && !owner_changed {
            return Err(PlatformError::conflict(
                "support case transition does not change status or owner",
            ));
        }

        let now = OffsetDateTime::now_utc();
        if let Some(status) = requested_status {
            record.status = status;
        }
        if let Some(owner) = requested_owner {
            record.owner = Some(owner);
            record.owner_assigned_at = Some(now);
        }
        if record.opened_by.is_none() {
            record.opened_by = Some(actor.clone());
        }
        record.updated_at = now;
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.support_cases
            .upsert(
                support_case_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;
        self.append_event(
            "abuse.support_case.transitioned.v1",
            "abuse_support_case",
            support_case_id.as_str(),
            "transitioned",
            support_case_event_details(
                &record,
                serde_json::json!({
                    "transition_reason": request.reason.trim(),
                    "transitioned_by": actor,
                    "previous_status": previous_status,
                    "previous_owner": previous_owner,
                    "status_changed": status_changed,
                    "owner_changed": owner_changed,
                }),
            ),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn current_remediation_case(
        &self,
        remediation_case_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "remediation case inspection")?;
        let remediation_case_id =
            AuditId::parse(remediation_case_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid remediation case id").with_detail(error.to_string())
            })?;
        let record = self
            .remediation_cases
            .get(remediation_case_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
            .ok_or_else(|| PlatformError::not_found("remediation case does not exist"))?;
        let record = self
            .project_remediation_case(record, OffsetDateTime::now_utc())
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn escalate_remediation_case(
        &self,
        remediation_case_id: &str,
        request: EscalateRemediationCaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "remediation case management")?;
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let remediation_case_id =
            AuditId::parse(remediation_case_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid remediation case id").with_detail(error.to_string())
            })?;
        let Some(stored) = self
            .remediation_cases
            .get(remediation_case_id.as_str())
            .await?
        else {
            return Err(PlatformError::not_found("remediation case does not exist"));
        };
        if stored.deleted {
            return Err(PlatformError::not_found("remediation case does not exist"));
        }

        let mut record = stored.value;
        let actor = remediation_actor(context)?;
        let reason = request.reason.trim().to_owned();
        let change_request_ids =
            parse_change_request_links(request.change_request_ids, "change_request_id")?;
        let notify_message_ids =
            parse_notification_links(request.notify_message_ids, "notify_message_id")?;
        let rollback_evidence_refs = normalize_evidence_refs(request.rollback_evidence_refs)?;
        let verification_evidence_refs =
            normalize_evidence_refs(request.verification_evidence_refs)?;
        let owner = request
            .owner
            .as_deref()
            .map(normalize_principal)
            .transpose()?
            .or_else(|| record.owner.clone())
            .or_else(|| Some(actor.clone()));
        let previous_owner = record.owner.clone();
        let now = OffsetDateTime::now_utc();

        record.owner = owner;
        if record.owner != previous_owner || record.owner_assigned_at.is_none() {
            record.owner_assigned_at = Some(now);
        }
        if record.opened_by.is_none() {
            record.opened_by = Some(actor.clone());
        }
        let added_rollback_evidence_refs =
            merge_evidence_refs(&mut record.rollback_evidence_refs, rollback_evidence_refs);
        let added_verification_evidence_refs = merge_evidence_refs(
            &mut record.verification_evidence_refs,
            verification_evidence_refs,
        );
        ensure_remediation_evidence_requirements(
            &record.rollback_evidence_refs,
            &record.verification_evidence_refs,
        )?;
        let added_change_request_ids =
            merge_change_request_ids(&mut record.change_request_ids, change_request_ids);
        let added_notify_message_ids =
            merge_notification_ids(&mut record.notify_message_ids, notify_message_ids);
        record.escalation_count = record.escalation_count.saturating_add(1);
        record.last_escalated_at = Some(now);
        record.last_escalated_by = Some(actor.clone());
        record.last_escalation_reason = Some(reason.clone());
        record.updated_at = now;
        let link_context = self
            .remediation_link_context_for_record(&record, now)
            .await?;
        record = materialize_remediation_case(record, &link_context, now);
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.remediation_cases
            .upsert(
                remediation_case_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;
        self.append_event(
            "abuse.remediation_case.escalated.v1",
            "abuse_remediation_case",
            remediation_case_id.as_str(),
            "escalated",
            remediation_case_event_details(
                &record,
                &link_context,
                serde_json::json!({
                    "reason": reason,
                    "added_rollback_evidence_refs": added_rollback_evidence_refs,
                    "added_verification_evidence_refs": added_verification_evidence_refs,
                    "added_change_request_ids": added_change_request_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "added_notify_message_ids": added_notify_message_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "owner_reassigned": previous_owner.as_deref() != record.owner.as_deref(),
                    "attention_reasons": remediation_attention_reasons(&record, &link_context),
                }),
            ),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn evaluate_risk(&self, request: EvaluateRiskRequest) -> Result<Response<ApiBody>> {
        let subject_kind = normalize_subject_kind(request.subject_kind.as_deref())?;
        let subject = normalize_subject(&subject_kind, &request.subject)?;
        let risk = self.evaluate_subject_risk(&subject_kind, &subject).await?;
        json_response(StatusCode::OK, &risk)
    }

    async fn evaluate_subject_risk(
        &self,
        subject_kind: &str,
        subject: &str,
    ) -> Result<EvaluateRiskResponse> {
        let key = reputation_key(subject_kind, subject);
        let reputation = self
            .reputation
            .get(&key)
            .await?
            .filter(|record| !record.deleted)
            .map(|record| record.value);
        let score = reputation.as_ref().map_or(0, |record| record.score);
        let state = reputation
            .as_ref()
            .map_or_else(|| String::from("watch"), |record| record.state.clone());
        let now = OffsetDateTime::now_utc();
        let cutoff = now - Duration::hours(24);

        let (signal_count, signals_in_last_24h) = self
            .signals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.subject_kind == subject_kind && record.subject == subject)
            .fold((0_u64, 0_u32), |(total, recent), record| {
                let total = total.saturating_add(1);
                let recent = if record.observed_at >= cutoff {
                    recent.saturating_add(1)
                } else {
                    recent
                };
                (total, recent)
            });

        let active_case_ids = self
            .cases
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                record.subject_kind == subject_kind
                    && record.subject == subject
                    && is_case_active(&record.status)
            })
            .map(|record| record.id.to_string())
            .collect::<Vec<_>>();

        let active_quarantine = self
            .quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .find(|record| {
                record.subject_kind == subject_kind
                    && record.subject == subject
                    && is_quarantine_active(record, now)
            });

        let recommended_action = if active_quarantine.is_some() {
            String::from("deny_network")
        } else if score <= -50 {
            String::from("open_case")
        } else if score <= -20 {
            String::from("monitor_strictly")
        } else {
            String::from("observe")
        };

        Ok(EvaluateRiskResponse {
            subject_kind: String::from(subject_kind),
            subject: String::from(subject),
            score,
            state,
            signal_count,
            signals_in_last_24h,
            active_case_ids,
            active_quarantine_id: active_quarantine.map(|record| record.id.to_string()),
            recommended_action,
        })
    }

    async fn list_signals(&self, query: &BTreeMap<String, String>) -> Result<Response<ApiBody>> {
        let subject_kind = query
            .get("subject_kind")
            .map(|value| value.to_ascii_lowercase());
        let subject = query.get("subject").map(|value| value.to_ascii_lowercase());
        let signal_kind = query
            .get("signal_kind")
            .map(|value| value.to_ascii_lowercase());
        let severity = query
            .get("severity")
            .map(|value| value.to_ascii_lowercase());
        let mut values = self
            .signals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                subject_kind
                    .as_deref()
                    .is_none_or(|value| value == record.subject_kind)
            })
            .filter(|record| {
                subject
                    .as_deref()
                    .is_none_or(|value| value == record.subject)
            })
            .filter(|record| {
                signal_kind
                    .as_deref()
                    .is_none_or(|value| value == record.signal_kind)
            })
            .filter(|record| {
                severity
                    .as_deref()
                    .is_none_or(|value| value == record.severity)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|record| -record.observed_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn list_cases(&self, query: &BTreeMap<String, String>) -> Result<Response<ApiBody>> {
        let status = query.get("status").map(|value| value.to_ascii_lowercase());
        let subject_kind = query
            .get("subject_kind")
            .map(|value| value.to_ascii_lowercase());
        let subject = query.get("subject").map(|value| value.to_ascii_lowercase());
        let mut values = self
            .cases
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| status.as_deref().is_none_or(|value| value == record.status))
            .filter(|record| {
                subject_kind
                    .as_deref()
                    .is_none_or(|value| value == record.subject_kind)
            })
            .filter(|record| {
                subject
                    .as_deref()
                    .is_none_or(|value| value == record.subject)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|record| -record.updated_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn list_quarantines(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<ApiBody>> {
        let state = query.get("state").map(|value| value.to_ascii_lowercase());
        let subject_kind = query
            .get("subject_kind")
            .map(|value| value.to_ascii_lowercase());
        let subject = query.get("subject").map(|value| value.to_ascii_lowercase());
        let mut values = self
            .quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| state.as_deref().is_none_or(|value| value == record.state))
            .filter(|record| {
                subject_kind
                    .as_deref()
                    .is_none_or(|value| value == record.subject_kind)
            })
            .filter(|record| {
                subject
                    .as_deref()
                    .is_none_or(|value| value == record.subject)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|record| -record.created_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn list_appeals(&self, query: &BTreeMap<String, String>) -> Result<Response<ApiBody>> {
        let status = query.get("status").map(|value| value.to_ascii_lowercase());
        let case_id = query.get("case_id").cloned();
        let mut values = self
            .appeals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| status.as_deref().is_none_or(|value| value == record.status))
            .filter(|record| {
                case_id
                    .as_deref()
                    .is_none_or(|value| value == record.case_id.as_str())
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|record| -record.created_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn list_support_cases(
        &self,
        query: &BTreeMap<String, String>,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "support case inspection")?;
        let tenant_subject = query
            .get("tenant_subject")
            .map(|value| value.to_ascii_lowercase());
        let owner = query.get("owner").map(|value| value.to_ascii_lowercase());
        let status = query.get("status").map(|value| value.to_ascii_lowercase());
        let priority = query
            .get("priority")
            .map(|value| value.to_ascii_lowercase());
        let remediation_case_id = query
            .get("remediation_case_id")
            .map(|value| value.trim().to_owned());
        let change_request_id = query
            .get("change_request_id")
            .map(|value| value.trim().to_owned());
        let notify_message_id = query
            .get("notify_message_id")
            .map(|value| value.trim().to_owned());
        let mut values = self
            .support_cases
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                tenant_subject
                    .as_deref()
                    .is_none_or(|value| value == record.tenant_subject)
            })
            .filter(|record| {
                owner
                    .as_deref()
                    .is_none_or(|value| record.owner.as_deref() == Some(value))
            })
            .filter(|record| status.as_deref().is_none_or(|value| value == record.status))
            .filter(|record| {
                priority
                    .as_deref()
                    .is_none_or(|value| value == record.priority)
            })
            .filter(|record| {
                remediation_case_id.as_deref().is_none_or(|value| {
                    record
                        .remediation_case_ids
                        .iter()
                        .any(|linked_id| linked_id.as_str() == value)
                })
            })
            .filter(|record| {
                change_request_id.as_deref().is_none_or(|value| {
                    record
                        .change_request_ids
                        .iter()
                        .any(|linked_id| linked_id.as_str() == value)
                })
            })
            .filter(|record| {
                notify_message_id.as_deref().is_none_or(|value| {
                    record
                        .notify_message_ids
                        .iter()
                        .any(|linked_id| linked_id.as_str() == value)
                })
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|record| -record.updated_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn list_remediation_cases(
        &self,
        query: &BTreeMap<String, String>,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        require_operator_principal(context, "remediation case inspection")?;
        let tenant_subject = query
            .get("tenant_subject")
            .map(|value| value.to_ascii_lowercase());
        let owner = query.get("owner").map(|value| value.to_ascii_lowercase());
        let evidence_state = query
            .get("evidence_state")
            .map(|value| value.to_ascii_lowercase());
        let sla_state = query
            .get("sla_state")
            .map(|value| value.to_ascii_lowercase());
        let escalation_state = query
            .get("escalation_state")
            .map(|value| value.to_ascii_lowercase());
        let abuse_case_id = query
            .get("abuse_case_id")
            .map(|value| value.trim().to_owned());
        let quarantine_id = query
            .get("quarantine_id")
            .map(|value| value.trim().to_owned());
        let change_request_id = query
            .get("change_request_id")
            .map(|value| value.trim().to_owned());
        let notify_message_id = query
            .get("notify_message_id")
            .map(|value| value.trim().to_owned());
        let now = OffsetDateTime::now_utc();
        let mut values = Vec::new();
        for (_, stored) in self.remediation_cases.list().await? {
            if stored.deleted {
                continue;
            }
            let record = self.project_remediation_case(stored.value, now).await?;
            if tenant_subject
                .as_deref()
                .is_some_and(|value| value != record.tenant_subject)
            {
                continue;
            }
            if owner
                .as_deref()
                .is_some_and(|value| record.owner.as_deref() != Some(value))
            {
                continue;
            }
            if evidence_state
                .as_deref()
                .is_some_and(|value| value != record.evidence_state)
            {
                continue;
            }
            if sla_state
                .as_deref()
                .is_some_and(|value| value != record.sla_state)
            {
                continue;
            }
            if escalation_state
                .as_deref()
                .is_some_and(|value| value != record.escalation_state)
            {
                continue;
            }
            if abuse_case_id
                .as_deref()
                .is_some_and(|value| !record.abuse_case_ids.iter().any(|id| id.as_str() == value))
            {
                continue;
            }
            if quarantine_id
                .as_deref()
                .is_some_and(|value| !record.quarantine_ids.iter().any(|id| id.as_str() == value))
            {
                continue;
            }
            if change_request_id.as_deref().is_some_and(|value| {
                !record
                    .change_request_ids
                    .iter()
                    .any(|id| id.as_str() == value)
            }) {
                continue;
            }
            if notify_message_id.as_deref().is_some_and(|value| {
                !record
                    .notify_message_ids
                    .iter()
                    .any(|id| id.as_str() == value)
            }) {
                continue;
            }
            values.push(record);
        }
        values.sort_by_key(|record| -record.updated_at.unix_timestamp_nanos());
        apply_limit(&mut values, query.get("limit"));
        json_response(StatusCode::OK, &values)
    }

    async fn summary(&self) -> Result<AbuseSummary> {
        let now = OffsetDateTime::now_utc();
        let signals = self
            .signals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut signal_severity = BTreeMap::<String, usize>::new();
        for signal in &signals {
            *signal_severity.entry(signal.severity.clone()).or_default() += 1;
        }

        let cases = self
            .cases
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut case_statuses = BTreeMap::<String, usize>::new();
        for case in &cases {
            *case_statuses.entry(case.status.clone()).or_default() += 1;
        }
        let active_cases = cases
            .iter()
            .filter(|case| is_case_active(&case.status))
            .count();

        let quarantines = self
            .quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut quarantine_states = BTreeMap::<String, usize>::new();
        let mut active_quarantines = 0;
        for quarantine in &quarantines {
            *quarantine_states
                .entry(quarantine.state.clone())
                .or_default() += 1;
            if is_quarantine_active(quarantine, now) {
                active_quarantines += 1;
            }
        }

        let appeals = self
            .appeals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut appeal_statuses = BTreeMap::<String, usize>::new();
        for appeal in &appeals {
            *appeal_statuses.entry(appeal.status.clone()).or_default() += 1;
        }

        let reputations = self
            .reputation
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut reputation_states = BTreeMap::<String, usize>::new();
        for record in &reputations {
            *reputation_states.entry(record.state.clone()).or_default() += 1;
        }

        Ok(AbuseSummary {
            state_root: self.state_root.display().to_string(),
            signals_total: signals.len(),
            signals_by_severity: totals_from_counts(signal_severity),
            cases_total: cases.len(),
            cases_by_status: totals_from_counts(case_statuses),
            active_cases,
            quarantines_total: quarantines.len(),
            active_quarantines,
            quarantines_by_state: totals_from_counts(quarantine_states),
            appeals_total: appeals.len(),
            appeals_by_status: totals_from_counts(appeal_statuses),
            reputations_total: reputations.len(),
            reputations_by_state: totals_from_counts(reputation_states),
        })
    }

    async fn apply_reputation_delta(
        &self,
        subject_kind: &str,
        subject: &str,
        delta: i32,
        reason: Option<String>,
        increment_signal: bool,
        context: &RequestContext,
    ) -> Result<ReputationRecord> {
        let key = reputation_key(subject_kind, subject);
        let stored = self.reputation.get(&key).await?;
        let now = OffsetDateTime::now_utc();
        let record = if let Some(stored) = stored {
            let mut current = stored.value;
            current.score = clamp_score(current.score, delta);
            current.state = derive_reputation_state(current.score);
            if increment_signal {
                current.signal_count = current.signal_count.saturating_add(1);
                current.last_signal_at = Some(now);
            }
            current.reason = reason;
            current.metadata.touch(sha256_hex(key.as_bytes()));
            self.reputation
                .upsert(&key, current.clone(), Some(stored.version))
                .await?;
            current
        } else {
            let score = clamp_score(0, delta);
            let mut created = ReputationRecord {
                subject_kind: String::from(subject_kind),
                subject: String::from(subject),
                score,
                state: derive_reputation_state(score),
                signal_count: u64::from(increment_signal),
                last_signal_at: if increment_signal { Some(now) } else { None },
                reason,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(key.clone()),
                    sha256_hex(key.as_bytes()),
                ),
            };
            if !increment_signal {
                created.signal_count = 0;
            }
            self.reputation.create(&key, created.clone()).await?;
            created
        };
        self.append_event(
            "abuse.reputation.updated.v1",
            "reputation",
            &key,
            "updated",
            serde_json::json!({
                "subject_kind": record.subject_kind,
                "subject": record.subject,
                "score": record.score,
                "state": record.state,
                "signal_count": record.signal_count,
            }),
            context,
        )
        .await?;
        Ok(record)
    }

    async fn ensure_active_quarantine(
        &self,
        subject_kind: &str,
        subject: &str,
        reason: &str,
        case_id: Option<AbuseCaseId>,
        policy: &QuarantinePolicyRequest,
        context: &RequestContext,
    ) -> Result<QuarantineRecord> {
        if reason.trim().is_empty() {
            return Err(PlatformError::invalid("quarantine reason may not be empty"));
        }
        let now = OffsetDateTime::now_utc();
        let existing = self
            .quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .find_map(|(key, stored)| {
                let record = &stored.value;
                if record.subject_kind == subject_kind
                    && record.subject == subject
                    && is_quarantine_active(record, now)
                {
                    Some((key, stored))
                } else {
                    None
                }
            });
        if let Some((key, stored)) = existing {
            let mut record = stored.value;
            if let Some(case_id) = case_id.as_ref() {
                match record.case_id.as_ref() {
                    Some(existing_case_id) if existing_case_id != case_id => {
                        return Err(PlatformError::conflict(
                            "active quarantine is already linked to a different case",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        record.case_id = Some(case_id.clone());
                        record
                            .metadata
                            .touch(sha256_hex(record.id.as_str().as_bytes()));
                        self.quarantines
                            .upsert(&key, record.clone(), Some(stored.version))
                            .await?;
                    }
                }
            }
            return Ok(record);
        }

        let id = AbuseQuarantineId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate abuse quarantine id")
                .with_detail(error.to_string())
        })?;
        let expires_at = policy.expires_after_seconds.map(|seconds| {
            let bounded = seconds.clamp(60, 2_592_000);
            OffsetDateTime::now_utc() + Duration::seconds(i64::from(bounded))
        });
        let record = QuarantineRecord {
            id: id.clone(),
            subject_kind: String::from(subject_kind),
            subject: String::from(subject),
            state: String::from("active"),
            reason: String::from(reason),
            case_id,
            deny_network: policy.deny_network.unwrap_or(true),
            deny_mail_relay: policy.deny_mail_relay.unwrap_or(true),
            created_at: now,
            expires_at,
            released_at: None,
            released_reason: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.quarantines.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "abuse.quarantine.created.v1",
            "abuse_quarantine",
            id.as_str(),
            "created",
            serde_json::json!({
                "subject_kind": subject_kind,
                "subject": subject,
                "deny_network": record.deny_network,
                "deny_mail_relay": record.deny_mail_relay,
                "case_id": record.case_id.as_ref().map(ToString::to_string),
                "expires_at": record.expires_at,
            }),
            context,
        )
        .await?;
        Ok(record)
    }

    async fn mark_case_quarantined(
        &self,
        case_id: &AbuseCaseId,
        quarantine_id: &AbuseQuarantineId,
    ) -> Result<()> {
        let Some(stored) = self.cases.get(case_id.as_str()).await? else {
            return Err(PlatformError::not_found("case does not exist"));
        };
        let mut record = stored.value;
        record.status = String::from("quarantined");
        record.quarantine_id = Some(quarantine_id.clone());
        record.closed_at = None;
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(case_id.as_str().as_bytes()));
        self.cases
            .upsert(case_id.as_str(), record, Some(stored.version))
            .await?;
        Ok(())
    }

    async fn mark_case_under_review_after_release(
        &self,
        case_id: &AbuseCaseId,
        reason: &str,
    ) -> Result<()> {
        let Some(stored) = self.cases.get(case_id.as_str()).await? else {
            return Ok(());
        };
        let mut record = stored.value;
        if !matches!(record.status.as_str(), "quarantined" | "suspended") {
            return Ok(());
        }
        record.status = String::from("under_review");
        record.decision_note = Some(format!("quarantine released: {reason}"));
        record.updated_at = OffsetDateTime::now_utc();
        record.closed_at = None;
        record
            .metadata
            .touch(sha256_hex(case_id.as_str().as_bytes()));
        self.cases
            .upsert(case_id.as_str(), record, Some(stored.version))
            .await?;
        Ok(())
    }

    async fn apply_accepted_appeal(
        &self,
        appeal: &AppealRecord,
        note: Option<&str>,
        context: &RequestContext,
    ) -> Result<()> {
        let Some(stored_case) = self.cases.get(appeal.case_id.as_str()).await? else {
            return Err(PlatformError::not_found("appeal case does not exist"));
        };
        let mut case = stored_case.value;
        if let Some(quarantine_id) = case.quarantine_id.clone() {
            let Some(stored_quarantine) = self.quarantines.get(quarantine_id.as_str()).await?
            else {
                return Err(PlatformError::not_found("case quarantine does not exist"));
            };
            let mut quarantine = stored_quarantine.value;
            if quarantine.state == "active" {
                quarantine.state = String::from("released");
                quarantine.released_reason =
                    Some(format!("appeal accepted for case {}", appeal.case_id));
                quarantine.released_at = Some(OffsetDateTime::now_utc());
                quarantine
                    .metadata
                    .touch(sha256_hex(quarantine.id.as_str().as_bytes()));
                self.quarantines
                    .upsert(
                        quarantine.id.as_str(),
                        quarantine.clone(),
                        Some(stored_quarantine.version),
                    )
                    .await?;
                self.append_event(
                    "abuse.quarantine.released.v1",
                    "abuse_quarantine",
                    quarantine.id.as_str(),
                    "released",
                    serde_json::json!({
                        "reason": quarantine.released_reason,
                        "subject_kind": quarantine.subject_kind,
                        "subject": quarantine.subject,
                    }),
                    context,
                )
                .await?;
            }
        }
        case.status = String::from("under_review");
        case.closed_at = None;
        case.updated_at = OffsetDateTime::now_utc();
        case.decision_note = note.map(ToOwned::to_owned);
        case.metadata.touch(sha256_hex(case.id.as_str().as_bytes()));
        let case_id = case.id.to_string();
        self.cases
            .upsert(&case_id, case, Some(stored_case.version))
            .await
            .map(|_| ())
    }

    async fn load_case_records(&self, ids: &[AbuseCaseId]) -> Result<Vec<AbuseCase>> {
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(stored) = self.cases.get(id.as_str()).await?
                && !stored.deleted
            {
                records.push(stored.value);
            }
        }
        Ok(records)
    }

    async fn load_quarantine_records(
        &self,
        ids: &[AbuseQuarantineId],
    ) -> Result<Vec<QuarantineRecord>> {
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(stored) = self.quarantines.get(id.as_str()).await?
                && !stored.deleted
            {
                records.push(stored.value);
            }
        }
        Ok(records)
    }

    async fn remediation_link_context_for_record(
        &self,
        record: &RemediationCaseRecord,
        now: OffsetDateTime,
    ) -> Result<RemediationCaseLinkContext> {
        let case_records = self.load_case_records(&record.abuse_case_ids).await?;
        let quarantine_records = self.load_quarantine_records(&record.quarantine_ids).await?;
        Ok(remediation_link_context_from_records(
            &case_records,
            &quarantine_records,
            now,
        ))
    }

    async fn project_remediation_case(
        &self,
        record: RemediationCaseRecord,
        now: OffsetDateTime,
    ) -> Result<RemediationCaseRecord> {
        let link_context = self
            .remediation_link_context_for_record(&record, now)
            .await?;
        Ok(materialize_remediation_case(record, &link_context, now))
    }

    async fn resolve_case_links(&self, values: Vec<String>) -> Result<Vec<AbuseCaseId>> {
        let mut unique = BTreeMap::<String, AbuseCaseId>::new();
        for raw in values {
            let id = AbuseCaseId::parse(raw.trim().to_owned()).map_err(|error| {
                PlatformError::invalid("invalid abuse_case_id").with_detail(error.to_string())
            })?;
            if unique.contains_key(id.as_str()) {
                continue;
            }
            let _ = self
                .cases
                .get(id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .ok_or_else(|| PlatformError::not_found("referenced abuse case does not exist"))?;
            let _ = unique.insert(id.to_string(), id);
        }
        Ok(unique.into_values().collect())
    }

    async fn resolve_quarantine_links(
        &self,
        values: Vec<String>,
    ) -> Result<Vec<AbuseQuarantineId>> {
        let mut unique = BTreeMap::<String, AbuseQuarantineId>::new();
        for raw in values {
            let id = AbuseQuarantineId::parse(raw.trim().to_owned()).map_err(|error| {
                PlatformError::invalid("invalid quarantine_id").with_detail(error.to_string())
            })?;
            if unique.contains_key(id.as_str()) {
                continue;
            }
            let _ = self
                .quarantines
                .get(id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .ok_or_else(|| PlatformError::not_found("referenced quarantine does not exist"))?;
            let _ = unique.insert(id.to_string(), id);
        }
        Ok(unique.into_values().collect())
    }

    async fn resolve_remediation_case_links(&self, values: Vec<String>) -> Result<Vec<AuditId>> {
        let mut unique = BTreeMap::<String, AuditId>::new();
        for raw in values {
            let id = AuditId::parse(raw.trim().to_owned()).map_err(|error| {
                PlatformError::invalid("invalid remediation_case_id").with_detail(error.to_string())
            })?;
            if unique.contains_key(id.as_str()) {
                continue;
            }
            let _ = self
                .remediation_cases
                .get(id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .ok_or_else(|| {
                    PlatformError::not_found("referenced remediation case does not exist")
                })?;
            let _ = unique.insert(id.to_string(), id);
        }
        Ok(unique.into_values().collect())
    }

    async fn append_event(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
        context: &RequestContext,
    ) -> Result<()> {
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit event id")
                        .with_detail(error.to_string())
                })?,
                event_type: String::from(event_type),
                schema_version: 1,
                source_service: String::from("abuse"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: context
                        .actor
                        .clone()
                        .unwrap_or_else(|| String::from("system")),
                    actor_type: String::from("principal"),
                    source_ip: None,
                    correlation_id: context.correlation_id.clone(),
                },
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: String::from(resource_kind),
                resource_id: String::from(resource_id),
                action: String::from(action),
                details,
            }),
        };
        self.audit_log.append(&event).await?;
        let idempotency = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("abuse.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for AbuseService {
    fn name(&self) -> &'static str {
        "abuse"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/abuse")];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        context: RequestContext,
    ) -> ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let query = parse_query(request.uri().query());
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["abuse"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "posture": "deny-by-default for blocked/quarantined subjects",
                    }),
                )
                .map(Some),
                (Method::GET, ["abuse", "summary"]) => {
                    let summary = self.summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["abuse", "signals"]) => self.list_signals(&query).await.map(Some),
                (Method::POST, ["abuse", "signals"]) => {
                    let body: CreateSignalRequest = parse_json(request).await?;
                    self.create_signal(body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "reputation"]) => {
                    let mut values = self
                        .reputation
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    values.sort_by_key(|record| record.subject.clone());
                    apply_limit(&mut values, query.get("limit"));
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["abuse", "reputation"]) => {
                    let body: CreateReputationRequest = parse_json(request).await?;
                    self.upsert_reputation(body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "cases"]) => self.list_cases(&query).await.map(Some),
                (Method::POST, ["abuse", "cases"]) => {
                    let body: CreateAbuseCaseRequest = parse_json(request).await?;
                    self.create_case(body, &context).await.map(Some)
                }
                (Method::POST, ["abuse", "cases", case_id, "review"]) => {
                    let body: ReviewCaseRequest = parse_json(request).await?;
                    self.review_case(case_id, body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "quarantines"]) => {
                    self.list_quarantines(&query).await.map(Some)
                }
                (Method::POST, ["abuse", "quarantines"]) => {
                    let body: CreateQuarantineRequest = parse_json(request).await?;
                    self.create_quarantine(body, &context).await.map(Some)
                }
                (Method::POST, ["abuse", "quarantines", quarantine_id, "release"]) => {
                    let body: ReleaseQuarantineRequest = parse_json(request).await?;
                    self.release_quarantine(quarantine_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["abuse", "appeals"]) => self.list_appeals(&query).await.map(Some),
                (Method::POST, ["abuse", "appeals"]) => {
                    let body: CreateAppealRequest = parse_json(request).await?;
                    self.create_appeal(body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "support-cases"]) => {
                    self.list_support_cases(&query, &context).await.map(Some)
                }
                (Method::POST, ["abuse", "support-cases"]) => {
                    let body: CreateSupportCaseRequest = parse_json(request).await?;
                    self.create_support_case(body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "support-cases", support_case_id]) => self
                    .current_support_case(support_case_id, &context)
                    .await
                    .map(Some),
                (Method::POST, ["abuse", "support-cases", support_case_id, "transition"]) => {
                    let body: TransitionSupportCaseRequest = parse_json(request).await?;
                    self.transition_support_case(support_case_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["abuse", "remediation-cases"]) => self
                    .list_remediation_cases(&query, &context)
                    .await
                    .map(Some),
                (Method::POST, ["abuse", "remediation-cases"]) => {
                    let body: CreateRemediationCaseRequest = parse_json(request).await?;
                    self.create_remediation_case(body, &context).await.map(Some)
                }
                (Method::GET, ["abuse", "remediation-cases", remediation_case_id]) => self
                    .current_remediation_case(remediation_case_id, &context)
                    .await
                    .map(Some),
                (
                    Method::POST,
                    [
                        "abuse",
                        "remediation-cases",
                        remediation_case_id,
                        "escalate",
                    ],
                ) => {
                    let body: EscalateRemediationCaseRequest = parse_json(request).await?;
                    self.escalate_remediation_case(remediation_case_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["abuse", "appeals", appeal_id, "review"]) => {
                    let body: ReviewAppealRequest = parse_json(request).await?;
                    self.review_appeal(appeal_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["abuse", "evaluate"]) => {
                    let body: EvaluateRiskRequest = parse_json(request).await?;
                    self.evaluate_risk(body).await.map(Some)
                }
                (Method::GET, ["abuse", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_subject_kind(value: Option<&str>) -> Result<String> {
    let normalized = value
        .unwrap_or("service_identity")
        .trim()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "service_identity" | "user" | "tenant" | "project" | "mail_domain" | "ip_address"
        | "hostname" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "subject_kind must be one of service_identity, user, tenant, project, mail_domain, ip_address, hostname",
        )),
    }
}

fn normalize_subject(subject_kind: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("subject may not be empty"));
    }
    match subject_kind {
        "service_identity" => normalize_service_identity_subject(trimmed),
        "mail_domain" => validate_domain_name(trimmed),
        "hostname" => canonicalize_hostname(trimmed),
        "ip_address" => IpAddr::from_str(trimmed)
            .map(|ip| ip.to_string())
            .map_err(|error| {
                PlatformError::invalid("ip_address subject must be a valid IP")
                    .with_detail(error.to_string())
            }),
        "user" | "tenant" | "project" => normalize_principal(trimmed),
        _ => Ok(trimmed.to_ascii_lowercase()),
    }
}

fn normalize_principal(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("principal may not be empty"));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.' | ':' | '@')
    }) {
        return Err(PlatformError::invalid(
            "principal contains unsupported characters",
        ));
    }
    Ok(normalized)
}

fn normalize_tenant_subject(value: &str) -> Result<String> {
    normalize_principal(value)
}

fn normalize_service_identity_subject(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let Some(subject) = normalized.strip_prefix("svc:") else {
        return Err(PlatformError::invalid(
            "service_identity subject must start with `svc:`",
        ));
    };
    if subject.is_empty() {
        return Err(PlatformError::invalid(
            "service_identity subject must include a name after `svc:`",
        ));
    }
    if !subject.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(PlatformError::invalid(
            "service_identity subject contains unsupported characters",
        ));
    }
    Ok(normalized)
}

fn normalize_signal_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "signup_abuse"
        | "spam"
        | "bot"
        | "api_abuse"
        | "suspicious_activity"
        | "resource_abuse"
        | "crypto_mining"
        | "rate_anomaly"
        | "manual" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "signal_kind must be one of signup_abuse, spam, bot, api_abuse, suspicious_activity, resource_abuse, crypto_mining, rate_anomaly, manual",
        )),
    }
}

fn normalize_severity(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "low" | "medium" | "high" | "critical" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "severity must be one of low, medium, high, critical",
        )),
    }
}

fn normalize_reputation_state(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "trusted" | "watch" | "restricted" | "blocked" | "manual_override" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "state must be one of trusted, watch, restricted, blocked, manual_override",
        )),
    }
}

fn normalize_case_priority(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "low" | "normal" | "high" | "critical" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "priority must be one of low, normal, high, critical",
        )),
    }
}

fn normalize_support_case_status(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "open" | "investigating" | "waiting_on_tenant" | "blocked" | "resolved" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "status must be one of open, investigating, waiting_on_tenant, blocked, resolved",
        )),
    }
}

fn normalize_case_action(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "triage" | "quarantine" | "suspend" | "resolve" | "dismiss" | "reopen" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "action must be one of triage, quarantine, suspend, resolve, dismiss, reopen",
        )),
    }
}

fn normalize_appeal_action(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "accept" | "reject" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "action must be `accept` or `reject`",
        )),
    }
}

fn require_operator_principal(context: &RequestContext, action: &'static str) -> Result<()> {
    if context
        .principal
        .as_ref()
        .is_some_and(|principal| principal.kind == PrincipalKind::Operator)
    {
        return Ok(());
    }

    Err(
        PlatformError::forbidden(format!("{action} requires operator principal"))
            .with_correlation_id(context.correlation_id.clone()),
    )
}

fn remediation_actor(context: &RequestContext) -> Result<String> {
    if let Some(principal) = context.principal.as_ref() {
        return normalize_principal(&principal.subject);
    }
    context
        .actor
        .as_deref()
        .map(normalize_principal)
        .transpose()?
        .ok_or_else(|| {
            PlatformError::forbidden("remediation case management requires operator principal")
                .with_correlation_id(context.correlation_id.clone())
        })
}

fn default_support_case_status() -> String {
    String::from("open")
}

fn default_support_case_priority() -> String {
    String::from("normal")
}

const fn default_remediation_sla_target_seconds() -> u32 {
    14_400
}

const REMEDIATION_DRY_RUN_STEP_NAME: &str = "dry_run";
const REMEDIATION_CHECKPOINT_STEP_NAME: &str = "checkpoint";
const REMEDIATION_ROLLBACK_STEP_NAME: &str = "rollback";
const REMEDIATION_VERIFICATION_STEP_NAME: &str = "verification";
const REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME: &str = "downstream_fanout";

fn default_remediation_sla_state() -> String {
    String::from("within_sla")
}

fn default_remediation_escalation_state() -> String {
    String::from("none")
}

fn default_remediation_evidence_state() -> String {
    String::from("rollback_and_verification_missing")
}

fn remediation_workflow_id(case_id: &AuditId) -> String {
    format!("abuse.remediation.{}", case_id.as_str())
}

fn normalize_remediation_sla_target_seconds(
    requested_target_seconds: Option<u32>,
    default_target_seconds: u32,
) -> u32 {
    requested_target_seconds
        .unwrap_or(default_target_seconds.max(300))
        .clamp(300, 604_800)
}

fn remediation_link_context_from_records(
    case_records: &[AbuseCase],
    quarantine_records: &[QuarantineRecord],
    now: OffsetDateTime,
) -> RemediationCaseLinkContext {
    let mut linked_case_priorities = BTreeSet::new();
    for record in case_records {
        let _ = linked_case_priorities.insert(record.priority.clone());
    }
    let active_quarantine_count = quarantine_records
        .iter()
        .filter(|record| is_quarantine_active(record, now))
        .count();
    let requires_attention =
        active_quarantine_count > 0 || linked_case_priorities.contains("critical");
    RemediationCaseLinkContext {
        linked_case_priorities: linked_case_priorities.into_iter().collect(),
        active_quarantine_count,
        requires_attention,
    }
}

fn default_remediation_sla_target_seconds_for_links(
    case_records: &[AbuseCase],
    quarantine_records: &[QuarantineRecord],
    now: OffsetDateTime,
) -> u32 {
    if quarantine_records
        .iter()
        .any(|record| is_quarantine_active(record, now))
    {
        return 900;
    }
    if case_records
        .iter()
        .any(|record| record.priority == "critical")
    {
        return 1_800;
    }
    if case_records.iter().any(|record| record.priority == "high") {
        return 3_600;
    }
    if case_records
        .iter()
        .any(|record| record.priority == "normal")
    {
        return default_remediation_sla_target_seconds();
    }
    86_400
}

fn derive_remediation_sla_state(
    deadline_at: OffsetDateTime,
    now: OffsetDateTime,
    target_seconds: u32,
) -> String {
    if deadline_at <= now {
        return String::from("breached");
    }
    let remaining_seconds = (deadline_at - now).whole_seconds();
    let at_risk_window_seconds = i64::from((target_seconds / 4).clamp(300, 3_600));
    if remaining_seconds <= at_risk_window_seconds {
        return String::from("at_risk");
    }
    String::from("within_sla")
}

fn derive_remediation_escalation_state(
    owner: Option<&str>,
    sla_state: &str,
    requires_attention: bool,
    escalation_count: u32,
) -> String {
    if escalation_count > 0 {
        return String::from("escalated");
    }
    if owner.is_none() || sla_state == "breached" || requires_attention {
        return String::from("queued");
    }
    String::from("none")
}

fn derive_remediation_evidence_state(
    rollback_evidence_refs: &[String],
    verification_evidence_refs: &[String],
) -> String {
    match (
        rollback_evidence_refs.is_empty(),
        verification_evidence_refs.is_empty(),
    ) {
        (false, false) => String::from("ready"),
        (true, false) => String::from("rollback_missing"),
        (false, true) => String::from("verification_missing"),
        (true, true) => String::from("rollback_and_verification_missing"),
    }
}

fn remediation_workflow_step(
    name: &str,
    index: usize,
    state: WorkflowStepState,
    detail: Option<String>,
    updated_at: OffsetDateTime,
) -> WorkflowStep {
    WorkflowStep {
        name: String::from(name),
        index,
        state,
        detail,
        effect_journal: Vec::new(),
        updated_at,
    }
}

fn remediation_workflow_steps(
    record: &RemediationCaseRecord,
    link_context: &RemediationCaseLinkContext,
) -> Vec<WorkflowStep> {
    let linked_priority_summary = if link_context.linked_case_priorities.is_empty() {
        String::from("no linked abuse priorities")
    } else {
        format!(
            "linked priorities {}",
            link_context.linked_case_priorities.join(", ")
        )
    };
    let active_quarantine_summary = if link_context.active_quarantine_count == 0 {
        String::from("no active quarantines")
    } else {
        format!(
            "{} active quarantine{}",
            link_context.active_quarantine_count,
            if link_context.active_quarantine_count == 1 {
                ""
            } else {
                "s"
            }
        )
    };
    let rollback_ready = !record.rollback_evidence_refs.is_empty();
    let verification_ready = !record.verification_evidence_refs.is_empty();
    let downstream_links_present =
        !record.change_request_ids.is_empty() || !record.notify_message_ids.is_empty();
    let downstream_fanout_required =
        downstream_links_present || link_context.requires_attention || record.escalation_count > 0;
    let rollback_state = if rollback_ready {
        WorkflowStepState::Completed
    } else if record.owner.is_some() {
        WorkflowStepState::Active
    } else {
        WorkflowStepState::Pending
    };
    let verification_state = if verification_ready {
        WorkflowStepState::Completed
    } else if !rollback_ready {
        WorkflowStepState::Pending
    } else if record.owner.is_some() {
        WorkflowStepState::Active
    } else {
        WorkflowStepState::Pending
    };
    let downstream_fanout_state = if downstream_links_present || !downstream_fanout_required {
        WorkflowStepState::Completed
    } else if !rollback_ready || !verification_ready {
        WorkflowStepState::Pending
    } else if record.owner.is_some() {
        WorkflowStepState::Active
    } else {
        WorkflowStepState::Pending
    };

    let downstream_requirement_detail = {
        let mut requirements = Vec::new();
        if record.escalation_count > 0 {
            requirements.push(format!(
                "{} escalation{}",
                record.escalation_count,
                if record.escalation_count == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        if link_context.active_quarantine_count > 0 {
            requirements.push(active_quarantine_summary.clone());
        }
        if link_context
            .linked_case_priorities
            .iter()
            .any(|priority| priority == "critical")
        {
            requirements.push(String::from("critical abuse case"));
        }
        requirements
    };

    vec![
        remediation_workflow_step(
            REMEDIATION_DRY_RUN_STEP_NAME,
            0,
            WorkflowStepState::Completed,
            Some(format!(
                "{}; {}",
                linked_priority_summary, active_quarantine_summary
            )),
            record.created_at,
        ),
        remediation_workflow_step(
            REMEDIATION_CHECKPOINT_STEP_NAME,
            1,
            WorkflowStepState::Completed,
            Some(format!(
                "workflow checkpoint persisted for {} abuse case{} and {} quarantine{}",
                record.abuse_case_ids.len(),
                if record.abuse_case_ids.len() == 1 {
                    ""
                } else {
                    "s"
                },
                record.quarantine_ids.len(),
                if record.quarantine_ids.len() == 1 {
                    ""
                } else {
                    "s"
                }
            )),
            record.updated_at,
        ),
        remediation_workflow_step(
            REMEDIATION_ROLLBACK_STEP_NAME,
            2,
            rollback_state,
            Some(if rollback_ready {
                format!(
                    "{} rollback evidence ref{} ready",
                    record.rollback_evidence_refs.len(),
                    if record.rollback_evidence_refs.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            } else {
                String::from("awaiting rollback evidence refs")
            }),
            record.updated_at,
        ),
        remediation_workflow_step(
            REMEDIATION_VERIFICATION_STEP_NAME,
            3,
            verification_state,
            Some(if verification_ready {
                format!(
                    "{} verification evidence ref{} ready",
                    record.verification_evidence_refs.len(),
                    if record.verification_evidence_refs.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            } else if !rollback_ready {
                String::from("waiting for rollback planning before verification")
            } else {
                String::from("awaiting verification evidence refs")
            }),
            record.updated_at,
        ),
        remediation_workflow_step(
            REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME,
            4,
            downstream_fanout_state,
            Some(if downstream_links_present {
                format!(
                    "{} change request{} and {} notify message{} linked",
                    record.change_request_ids.len(),
                    if record.change_request_ids.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    record.notify_message_ids.len(),
                    if record.notify_message_ids.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            } else if downstream_fanout_required {
                if downstream_requirement_detail.is_empty() {
                    String::from("awaiting downstream fanout targets")
                } else {
                    format!(
                        "awaiting downstream fanout for {}",
                        downstream_requirement_detail.join(", ")
                    )
                }
            } else {
                String::from("no downstream fanout required")
            }),
            record.updated_at,
        ),
    ]
}

fn materialize_remediation_case(
    mut record: RemediationCaseRecord,
    link_context: &RemediationCaseLinkContext,
    now: OffsetDateTime,
) -> RemediationCaseRecord {
    if record.owner.is_none() {
        record.owner = record.opened_by.clone();
    }
    if record.opened_by.is_none() {
        record.opened_by = record.owner.clone();
    }
    if record.owner.is_some() && record.owner_assigned_at.is_none() {
        record.owner_assigned_at = Some(record.created_at);
    }
    record.evidence_state = derive_remediation_evidence_state(
        &record.rollback_evidence_refs,
        &record.verification_evidence_refs,
    );
    record.sla_target_seconds = normalize_remediation_sla_target_seconds(
        (record.sla_target_seconds != 0).then_some(record.sla_target_seconds),
        default_remediation_sla_target_seconds(),
    );
    let deadline_at = record.sla_deadline_at.unwrap_or_else(|| {
        record.created_at + Duration::seconds(i64::from(record.sla_target_seconds))
    });
    record.sla_deadline_at = Some(deadline_at);
    record.sla_state = derive_remediation_sla_state(deadline_at, now, record.sla_target_seconds);
    record.escalation_state = derive_remediation_escalation_state(
        record.owner.as_deref(),
        &record.sla_state,
        link_context.requires_attention,
        record.escalation_count,
    );
    record.workflow_id = Some(remediation_workflow_id(&record.id));
    record.workflow_steps = remediation_workflow_steps(&record, link_context);
    record
}

fn remediation_attention_reasons(
    record: &RemediationCaseRecord,
    link_context: &RemediationCaseLinkContext,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if record.owner.is_none() {
        reasons.push(String::from("unowned"));
    }
    if record.rollback_evidence_refs.is_empty() {
        reasons.push(String::from("rollback_evidence_missing"));
    }
    if record.verification_evidence_refs.is_empty() {
        reasons.push(String::from("verification_evidence_missing"));
    }
    if link_context.active_quarantine_count > 0 {
        reasons.push(String::from("active_quarantine"));
    }
    if link_context
        .linked_case_priorities
        .iter()
        .any(|priority| priority == "critical")
    {
        reasons.push(String::from("critical_abuse_case"));
    }
    if record.sla_state == "breached" {
        reasons.push(String::from("sla_breached"));
    }
    reasons
}

fn support_case_event_details(
    record: &SupportCaseRecord,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut details = serde_json::json!({
        "tenant_subject": record.tenant_subject.clone(),
        "opened_by": record.opened_by.clone(),
        "owner": record.owner.clone(),
        "owner_assigned_at": record.owner_assigned_at,
        "status": record.status.clone(),
        "priority": record.priority.clone(),
        "remediation_case_ids": record.remediation_case_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "change_request_ids": record.change_request_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "notify_message_ids": record.notify_message_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "reason": record.reason.clone(),
    });
    if let Some(details_map) = details.as_object_mut()
        && let Some(extra_map) = extra.as_object()
    {
        for (key, value) in extra_map {
            let _ = details_map.insert(key.clone(), value.clone());
        }
    }
    details
}

fn remediation_case_event_details(
    record: &RemediationCaseRecord,
    link_context: &RemediationCaseLinkContext,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut details = serde_json::json!({
        "tenant_subject": record.tenant_subject.clone(),
        "workflow_id": record.workflow_id.clone(),
        "workflow_steps": record.workflow_steps.clone(),
        "opened_by": record.opened_by.clone(),
        "owner": record.owner.clone(),
        "owner_assigned_at": record.owner_assigned_at,
        "abuse_case_ids": record.abuse_case_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "quarantine_ids": record.quarantine_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "change_request_ids": record.change_request_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "notify_message_ids": record.notify_message_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "rollback_evidence_refs": record.rollback_evidence_refs.clone(),
        "verification_evidence_refs": record.verification_evidence_refs.clone(),
        "rollback_evidence_count": record.rollback_evidence_refs.len(),
        "verification_evidence_count": record.verification_evidence_refs.len(),
        "rollback_evidence_required": true,
        "verification_evidence_required": true,
        "evidence_state": record.evidence_state.clone(),
        "evidence_requirements_met": !record.rollback_evidence_refs.is_empty() && !record.verification_evidence_refs.is_empty(),
        "sla_target_seconds": record.sla_target_seconds,
        "sla_deadline_at": record.sla_deadline_at,
        "sla_state": record.sla_state.clone(),
        "escalation_state": record.escalation_state.clone(),
        "escalation_count": record.escalation_count,
        "last_escalated_at": record.last_escalated_at,
        "last_escalated_by": record.last_escalated_by.clone(),
        "last_escalation_reason": record.last_escalation_reason.clone(),
        "linked_case_priorities": link_context.linked_case_priorities.clone(),
        "active_quarantine_count": link_context.active_quarantine_count,
        "requires_attention": link_context.requires_attention,
    });
    if let Some(details_map) = details.as_object_mut()
        && let Some(extra_map) = extra.as_object()
    {
        for (key, value) in extra_map {
            let _ = details_map.insert(key.clone(), value.clone());
        }
    }
    details
}

fn merge_change_request_ids(
    existing: &mut Vec<ChangeRequestId>,
    additions: Vec<ChangeRequestId>,
) -> Vec<ChangeRequestId> {
    let mut known = existing
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for id in additions {
        if known.insert(id.to_string()) {
            added.push(id.clone());
            existing.push(id);
        }
    }
    added
}

fn merge_notification_ids(
    existing: &mut Vec<NotificationId>,
    additions: Vec<NotificationId>,
) -> Vec<NotificationId> {
    let mut known = existing
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for id in additions {
        if known.insert(id.to_string()) {
            added.push(id.clone());
            existing.push(id);
        }
    }
    added
}

fn merge_evidence_refs(existing: &mut Vec<String>, additions: Vec<String>) -> Vec<String> {
    let mut known = existing.iter().cloned().collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for value in additions {
        if known.insert(value.clone()) {
            added.push(value.clone());
            existing.push(value);
        }
    }
    added
}

fn parse_change_request_links(
    values: Vec<String>,
    field_name: &str,
) -> Result<Vec<ChangeRequestId>> {
    let mut unique = BTreeSet::new();
    let mut parsed = Vec::new();
    for raw in values {
        let id = ChangeRequestId::parse(raw.trim().to_owned()).map_err(|error| {
            PlatformError::invalid(format!("invalid {field_name}")).with_detail(error.to_string())
        })?;
        if unique.insert(id.to_string()) {
            parsed.push(id);
        }
    }
    Ok(parsed)
}

fn parse_notification_links(values: Vec<String>, field_name: &str) -> Result<Vec<NotificationId>> {
    let mut unique = BTreeSet::new();
    let mut parsed = Vec::new();
    for raw in values {
        let id = NotificationId::parse(raw.trim().to_owned()).map_err(|error| {
            PlatformError::invalid(format!("invalid {field_name}")).with_detail(error.to_string())
        })?;
        if unique.insert(id.to_string()) {
            parsed.push(id);
        }
    }
    Ok(parsed)
}

fn normalize_source_service(value: Option<&str>) -> Result<String> {
    let normalized = value.unwrap_or("unknown").trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("source_service may not be empty"));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(PlatformError::invalid(
            "source_service contains unsupported characters",
        ));
    }
    Ok(normalized)
}

fn normalize_evidence_refs(values: Vec<String>) -> Result<Vec<String>> {
    if values.len() > 64 {
        return Err(PlatformError::invalid(
            "evidence_refs may not contain more than 64 entries",
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > 256 {
            return Err(PlatformError::invalid(
                "each evidence reference must be 256 chars or less",
            ));
        }
        if normalized.iter().any(|existing| existing == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_owned());
    }
    Ok(normalized)
}

fn ensure_remediation_evidence_requirements(
    rollback_evidence_refs: &[String],
    verification_evidence_refs: &[String],
) -> Result<()> {
    if rollback_evidence_refs.is_empty() {
        return Err(PlatformError::invalid(
            "rollback_evidence_refs must include at least one evidence reference",
        ));
    }
    if verification_evidence_refs.is_empty() {
        return Err(PlatformError::invalid(
            "verification_evidence_refs must include at least one evidence reference",
        ));
    }
    Ok(())
}

fn transition_case_status(current: &str, action: &str) -> Result<String> {
    let next = match action {
        "triage" => String::from("under_review"),
        "quarantine" => String::from("quarantined"),
        "suspend" => String::from("suspended"),
        "resolve" => String::from("resolved"),
        "dismiss" => String::from("dismissed"),
        "reopen" => String::from("open"),
        _ => return Err(PlatformError::invalid("unsupported case transition action")),
    };
    match (current, action) {
        ("resolved" | "dismissed", "reopen") => Ok(next),
        ("resolved" | "dismissed", _) => Err(PlatformError::conflict(
            "closed case must be reopened before further actions",
        )),
        ("open" | "under_review" | "quarantined" | "suspended", _) => Ok(next),
        _ => Err(PlatformError::conflict(
            "unsupported case status transition",
        )),
    }
}

fn score_delta_for_signal(signal_kind: &str, severity: &str, confidence_bps: u16) -> i32 {
    let severity_weight = match severity {
        "low" => -5,
        "medium" => -15,
        "high" => -35,
        "critical" => -55,
        _ => -10,
    };
    let kind_weight = match signal_kind {
        "signup_abuse" => -8,
        "spam" => -12,
        "bot" => -10,
        "api_abuse" => -20,
        "suspicious_activity" => -18,
        "resource_abuse" => -20,
        "crypto_mining" => -30,
        "rate_anomaly" => -8,
        "manual" => -5,
        _ => -5,
    };
    let raw = severity_weight + kind_weight;
    let scaled = scale_signed_bps(raw, confidence_bps);
    if scaled == 0 {
        if raw < 0 {
            -1
        } else if raw > 0 {
            1
        } else {
            0
        }
    } else {
        scaled
    }
}

fn scale_signed_bps(value: i32, confidence_bps: u16) -> i32 {
    let numerator = value.saturating_mul(i32::from(confidence_bps));
    if numerator >= 0 {
        numerator / 10_000
    } else {
        -((-numerator + 9_999) / 10_000)
    }
}

fn clamp_score(current: i32, delta: i32) -> i32 {
    (current.saturating_add(delta)).clamp(-100, 100)
}

fn derive_reputation_state(score: i32) -> String {
    if score >= 40 {
        return String::from("trusted");
    }
    if score >= 0 {
        return String::from("watch");
    }
    if score >= -40 {
        return String::from("restricted");
    }
    String::from("blocked")
}

fn reputation_key(subject_kind: &str, subject: &str) -> String {
    sha256_hex(format!("{subject_kind}:{subject}").as_bytes())
}

fn is_quarantine_active(record: &QuarantineRecord, now: OffsetDateTime) -> bool {
    if record.state != "active" {
        return false;
    }
    if let Some(expires_at) = record.expires_at {
        return expires_at > now;
    }
    true
}

fn is_case_active(status: &str) -> bool {
    matches!(
        status,
        "open" | "under_review" | "quarantined" | "suspended"
    )
}

fn apply_limit<T>(values: &mut Vec<T>, limit: Option<&String>) {
    if let Some(limit) = limit.and_then(|value| value.parse::<usize>().ok()) {
        let bounded = limit.clamp(1, 1_000);
        if values.len() > bounded {
            values.truncate(bounded);
        }
    }
}

fn totals_from_counts(counts: BTreeMap<String, usize>) -> Vec<TotalByValue> {
    counts
        .into_iter()
        .map(|(value, count)| TotalByValue { value, count })
        .collect()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Request;
    use http_body_util::{BodyExt, Full};
    use proptest::prelude::*;
    use serde::de::DeserializeOwned;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    use super::{
        AbuseCase, AbuseService, AppealRecord, CreateAbuseCaseRequest, CreateAppealRequest,
        CreateQuarantineRequest, CreateRemediationCaseRequest, CreateReputationRequest,
        CreateSignalRequest, CreateSupportCaseRequest, EscalateRemediationCaseRequest,
        EvaluateRiskRequest, ReleaseQuarantineRequest, RemediationCaseRecord, ReviewAppealRequest,
        ReviewCaseRequest, SupportCaseRecord, TotalByValue,
    };
    use uhost_api::ApiBody;
    use uhost_core::PrincipalIdentity;
    use uhost_core::RequestContext;
    use uhost_runtime::HttpService;
    use uhost_store::WorkflowStepState;
    use uhost_types::{ChangeRequestId, EventPayload, NotificationId, PrincipalKind};

    async fn read_json<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let collected: http_body_util::Collected<Bytes> = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        serde_json::from_slice(&collected.to_bytes()).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn extract_case_id(response: http::Response<ApiBody>) -> String {
        let record: AbuseCase = read_json(response).await;
        record.id.to_string()
    }

    fn remediation_workflow_step<'a>(
        record: &'a RemediationCaseRecord,
        name: &str,
    ) -> &'a super::WorkflowStep {
        record
            .workflow_steps
            .iter()
            .find(|step| step.name == name)
            .unwrap_or_else(|| panic!("missing remediation workflow step `{name}`"))
    }

    fn count_for(entries: &[TotalByValue], value: &str) -> usize {
        entries
            .iter()
            .find(|entry| entry.value == value)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    fn operator_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::Operator,
                "operator:abuse",
            ))
    }

    fn user_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::User,
                "user:abuse-viewer",
            ))
    }

    fn service_request(
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> Request<uhost_runtime::RequestBody> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(uhost_runtime::RequestBody::Right(Full::new(Bytes::from(
                body.unwrap_or_default().to_owned(),
            ))))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn seed_remediation_case(
        service: &AbuseService,
        context: &RequestContext,
        service_subject: &str,
        tenant_subject: &str,
    ) -> RemediationCaseRecord {
        let case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from(service_subject),
                        reason: String::from("support workflow seed"),
                        priority: Some(String::from("high")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let quarantine: super::QuarantineRecord = read_json(
            service
                .create_quarantine(
                    CreateQuarantineRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from(service_subject),
                        reason: String::from("support workflow containment"),
                        case_id: Some(case_id.clone()),
                        deny_network: Some(true),
                        deny_mail_relay: Some(false),
                        expires_after_seconds: None,
                    },
                    context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from(tenant_subject),
                        reason: String::from("support remediation seed"),
                        owner: None,
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:support-seed")],
                        verification_evidence_refs: vec![String::from("checklist:support-seed")],
                        abuse_case_ids: vec![case_id],
                        quarantine_ids: vec![quarantine.id.to_string()],
                        change_request_ids: Vec::new(),
                        notify_message_ids: Vec::new(),
                    },
                    context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
    }

    async fn seed_support_case(
        service: &AbuseService,
        context: &RequestContext,
        service_subject: &str,
        tenant_subject: &str,
    ) -> SupportCaseRecord {
        let remediation_case =
            seed_remediation_case(service, context, service_subject, tenant_subject).await;
        read_json(
            service
                .create_support_case(
                    CreateSupportCaseRequest {
                        tenant_subject: String::from(tenant_subject),
                        reason: String::from("support case seed"),
                        owner: None,
                        priority: None,
                        remediation_case_ids: vec![remediation_case.id.to_string()],
                        change_request_ids: Vec::new(),
                        notify_message_ids: Vec::new(),
                    },
                    context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
    }

    #[tokio::test]
    async fn critical_signal_updates_reputation_and_triggers_quarantine() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_signal(
                CreateSignalRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:miner"),
                    signal_kind: String::from("crypto_mining"),
                    severity: String::from("critical"),
                    confidence_bps: Some(10_000),
                    source_service: Some(String::from("node")),
                    reason: Some(String::from("unexpected cpu profile")),
                    evidence_refs: vec![String::from("trace:abc123"), String::from("trace:abc123")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let reputation = service
            .reputation
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reputation.len(), 1);
        assert!(reputation[0].1.value.score <= -40);
        assert_eq!(reputation[0].1.value.state, "blocked");
        assert_eq!(
            service
                .signals
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .into_iter()
                .find(|(_, stored)| stored.value.subject == "svc:miner")
                .unwrap_or_else(|| panic!("missing signal"))
                .1
                .value
                .evidence_refs,
            vec![String::from("trace:abc123")]
        );

        let quarantines = service
            .quarantines
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(quarantines.len(), 1);
        assert_eq!(quarantines[0].1.value.state, "active");
        assert_eq!(quarantines[0].1.value.subject, "svc:miner");

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!outbox.is_empty());
    }

    #[tokio::test]
    async fn reused_quarantine_is_linked_to_case_and_release_updates_case() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_signal(
                CreateSignalRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:shared"),
                    signal_kind: String::from("crypto_mining"),
                    severity: String::from("critical"),
                    confidence_bps: Some(10_000),
                    source_service: Some(String::from("node")),
                    reason: Some(String::from("unexpected cpu profile")),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cases = service
            .cases
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cases.is_empty());

        let _ = service
            .create_case(
                CreateAbuseCaseRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:shared"),
                    reason: String::from("repeated abuse signal"),
                    priority: Some(String::from("high")),
                    signal_ids: Vec::new(),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cases = service
            .cases
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let case_id = cases[0].1.value.id.clone();

        let _ = service
            .review_case(
                case_id.as_str(),
                ReviewCaseRequest {
                    action: String::from("quarantine"),
                    reviewer: String::from("ops.review"),
                    note: Some(String::from("contain while investigating")),
                    assign_to: None,
                    escalate: None,
                    quarantine: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let quarantines = service
            .quarantines
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(quarantines.len(), 1);
        let quarantine_id = quarantines[0].1.value.id.clone();
        assert_eq!(quarantines[0].1.value.case_id.as_ref(), Some(&case_id));

        let _ = service
            .release_quarantine(
                quarantine_id.as_str(),
                ReleaseQuarantineRequest {
                    reason: String::from("manual containment rollback"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let case = service
            .cases
            .get(case_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing case after quarantine release"));
        assert_eq!(case.value.status, "under_review");
    }

    #[tokio::test]
    async fn case_quarantine_then_accepted_appeal_releases_quarantine() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_case(
                CreateAbuseCaseRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:api"),
                    reason: String::from("suspicious burst behavior"),
                    priority: Some(String::from("high")),
                    signal_ids: Vec::new(),
                    evidence_refs: vec![String::from("flow:123")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cases = service
            .cases
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let case_id = cases[0].1.value.id.to_string();

        let _ = service
            .review_case(
                &case_id,
                ReviewCaseRequest {
                    action: String::from("quarantine"),
                    reviewer: String::from("ops.review"),
                    note: Some(String::from("contain while investigating")),
                    assign_to: Some(String::from("sec.lead")),
                    escalate: Some(true),
                    quarantine: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let active_quarantine = service
            .quarantines
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(active_quarantine.len(), 1);
        assert_eq!(active_quarantine[0].1.value.state, "active");

        let _ = service
            .create_appeal(
                CreateAppealRequest {
                    case_id: case_id.clone(),
                    requested_by: String::from("tenant.owner"),
                    reason: String::from("false positive after incident drill"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let appeals = service
            .appeals
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let appeal_id = appeals[0].1.value.id.to_string();
        let _ = service
            .review_appeal(
                &appeal_id,
                ReviewAppealRequest {
                    reviewer: String::from("sec.manager"),
                    action: String::from("accept"),
                    note: Some(String::from("restoring service while continuing review")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let quarantine = service
            .quarantines
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(quarantine[0].1.value.state, "released");
        let case = service
            .cases
            .get(&case_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing case after appeal"));
        assert_eq!(case.value.status, "under_review");
    }

    #[tokio::test]
    async fn remediation_case_persists_linked_abuse_and_external_ids() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:tenant-remediation"),
                        reason: String::from("tenant workload needs containment"),
                        priority: Some(String::from("high")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let quarantine: super::QuarantineRecord = read_json(
            service
                .create_quarantine(
                    CreateQuarantineRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:tenant-remediation"),
                        reason: String::from("manual containment"),
                        case_id: Some(case_id.clone()),
                        deny_network: Some(true),
                        deny_mail_relay: Some(false),
                        expires_after_seconds: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));

        let remediation_case: RemediationCaseRecord = read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from("tenant.ops"),
                        reason: String::from("coordinate tenant rollback and communication"),
                        owner: None,
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:tenant-rollback")],
                        verification_evidence_refs: vec![String::from(
                            "checklist:tenant-verification",
                        )],
                        abuse_case_ids: vec![case_id.clone()],
                        quarantine_ids: vec![quarantine.id.to_string()],
                        change_request_ids: vec![change_request_id.to_string()],
                        notify_message_ids: vec![notify_message_id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(remediation_case.tenant_subject, "tenant.ops");
        assert_eq!(remediation_case.abuse_case_ids.len(), 1);
        assert_eq!(remediation_case.quarantine_ids.len(), 1);
        assert_eq!(remediation_case.change_request_ids, vec![change_request_id]);
        assert_eq!(remediation_case.notify_message_ids, vec![notify_message_id]);
        assert_eq!(
            remediation_case.opened_by.as_deref(),
            Some("operator:abuse")
        );
        assert_eq!(remediation_case.owner.as_deref(), Some("operator:abuse"));
        assert_eq!(
            remediation_case.rollback_evidence_refs,
            vec![String::from("runbook:tenant-rollback")]
        );
        assert_eq!(
            remediation_case.verification_evidence_refs,
            vec![String::from("checklist:tenant-verification")]
        );
        assert_eq!(remediation_case.evidence_state, "ready");
        assert_eq!(remediation_case.sla_target_seconds, 900);
        assert!(remediation_case.sla_deadline_at.is_some());
        assert_eq!(remediation_case.sla_state, "within_sla");
        assert_eq!(remediation_case.escalation_state, "queued");
        assert_eq!(remediation_case.escalation_count, 0);
        assert_eq!(
            remediation_case.workflow_id.as_deref(),
            Some(format!("abuse.remediation.{}", remediation_case.id).as_str())
        );
        assert_eq!(remediation_case.workflow_steps.len(), 5);
        assert_eq!(
            remediation_workflow_step(&remediation_case, super::REMEDIATION_DRY_RUN_STEP_NAME)
                .state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&remediation_case, super::REMEDIATION_CHECKPOINT_STEP_NAME)
                .state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&remediation_case, super::REMEDIATION_ROLLBACK_STEP_NAME)
                .state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&remediation_case, super::REMEDIATION_VERIFICATION_STEP_NAME)
                .state,
            WorkflowStepState::Completed
        );
        let downstream_fanout_step = remediation_workflow_step(
            &remediation_case,
            super::REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME,
        );
        assert_eq!(downstream_fanout_step.state, WorkflowStepState::Completed);
        assert_eq!(
            downstream_fanout_step.detail.as_deref(),
            Some("1 change request and 1 notify message linked")
        );

        let stored = service
            .remediation_cases
            .get(remediation_case.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing remediation case"));
        assert_eq!(stored.value, remediation_case);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created = outbox
            .iter()
            .find(|message| {
                message.payload.header.event_type == "abuse.remediation_case.created.v1"
            })
            .unwrap_or_else(|| panic!("missing remediation case create event"));
        match &created.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(event.resource_kind, "abuse_remediation_case");
                assert_eq!(event.action, "created");
                assert_eq!(event.details["owner"], serde_json::json!("operator:abuse"));
                assert_eq!(event.details["evidence_state"], serde_json::json!("ready"));
                assert_eq!(
                    event.details["rollback_evidence_count"],
                    serde_json::json!(1)
                );
                assert_eq!(
                    event.details["verification_evidence_count"],
                    serde_json::json!(1)
                );
                assert_eq!(event.details["sla_target_seconds"], serde_json::json!(900));
                assert_eq!(
                    event.details["escalation_state"],
                    serde_json::json!("queued")
                );
                assert_eq!(
                    event.details["active_quarantine_count"],
                    serde_json::json!(1)
                );
                assert_eq!(
                    event.details["attention_reasons"],
                    serde_json::json!(["active_quarantine"])
                );
                assert_eq!(
                    event.details["workflow_id"],
                    serde_json::json!(format!("abuse.remediation.{}", remediation_case.id))
                );
                assert_eq!(
                    event.details["workflow_steps"][0]["name"],
                    serde_json::json!(super::REMEDIATION_DRY_RUN_STEP_NAME)
                );
                assert_eq!(
                    event.details["workflow_steps"][4]["state"],
                    serde_json::json!("completed")
                );
            }
            other => panic!("unexpected event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn remediation_case_list_filters_by_tenant_and_related_ids() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let first_case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:first"),
                        reason: String::from("first remediation anchor"),
                        priority: Some(String::from("normal")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let second_case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:second"),
                        reason: String::from("second remediation anchor"),
                        priority: Some(String::from("normal")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let first_quarantine: super::QuarantineRecord = read_json(
            service
                .create_quarantine(
                    CreateQuarantineRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:first"),
                        reason: String::from("tenant rollback still quarantined"),
                        case_id: Some(first_case_id.clone()),
                        deny_network: Some(true),
                        deny_mail_relay: Some(true),
                        expires_after_seconds: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let first: RemediationCaseRecord = read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from("tenant.alpha"),
                        reason: String::from("first tenant rollback"),
                        owner: None,
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:first-rollback")],
                        verification_evidence_refs: vec![String::from("checklist:first-verify")],
                        abuse_case_ids: vec![first_case_id.clone()],
                        quarantine_ids: vec![first_quarantine.id.to_string()],
                        change_request_ids: vec![change_request_id.to_string()],
                        notify_message_ids: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let second: RemediationCaseRecord = read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from("tenant.beta"),
                        reason: String::from("second tenant rollback"),
                        owner: Some(String::from("operator:secondary")),
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:second-rollback")],
                        verification_evidence_refs: vec![String::from("checklist:second-verify")],
                        abuse_case_ids: vec![second_case_id.clone()],
                        quarantine_ids: Vec::new(),
                        change_request_ids: Vec::new(),
                        notify_message_ids: vec![notify_message_id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let stored_second = service
            .remediation_cases
            .get(second.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second remediation case"));
        let mut breached_second = stored_second.value;
        breached_second.verification_evidence_refs.clear();
        breached_second.sla_deadline_at =
            Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(60));
        breached_second.updated_at = time::OffsetDateTime::now_utc();
        breached_second.metadata.touch(uhost_core::sha256_hex(
            breached_second.id.as_str().as_bytes(),
        ));
        service
            .remediation_cases
            .upsert(
                second.id.as_str(),
                breached_second,
                Some(stored_second.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let by_tenant: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(
                        String::from("tenant_subject"),
                        String::from("tenant.alpha"),
                    )]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(by_tenant.len(), 1);
        assert_eq!(by_tenant[0].tenant_subject, "tenant.alpha");
        assert_eq!(
            remediation_workflow_step(
                &by_tenant[0],
                super::REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME
            )
            .state,
            WorkflowStepState::Completed
        );

        let by_change_request: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(
                        String::from("change_request_id"),
                        change_request_id.to_string(),
                    )]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(by_change_request.len(), 1);
        assert_eq!(by_change_request[0].tenant_subject, "tenant.alpha");

        let by_notify: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(
                        String::from("notify_message_id"),
                        notify_message_id.to_string(),
                    )]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(by_notify.len(), 1);
        assert_eq!(by_notify[0].tenant_subject, "tenant.beta");

        let by_owner: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(String::from("owner"), String::from("operator:secondary"))]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(by_owner.len(), 1);
        assert_eq!(by_owner[0].id, second.id);

        let missing_verification: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(
                        String::from("evidence_state"),
                        String::from("verification_missing"),
                    )]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(missing_verification.len(), 1);
        assert_eq!(missing_verification[0].id, second.id);
        assert_eq!(
            remediation_workflow_step(
                &missing_verification[0],
                super::REMEDIATION_VERIFICATION_STEP_NAME
            )
            .state,
            WorkflowStepState::Active
        );
        assert_eq!(
            remediation_workflow_step(
                &missing_verification[0],
                super::REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME
            )
            .state,
            WorkflowStepState::Completed
        );

        let queued: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([
                        (String::from("escalation_state"), String::from("queued")),
                        (String::from("tenant_subject"), String::from("tenant.alpha")),
                    ]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].id, first.id);

        let breached: Vec<RemediationCaseRecord> = read_json(
            service
                .list_remediation_cases(
                    &BTreeMap::from([(String::from("sla_state"), String::from("breached"))]),
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(breached.len(), 1);
        assert_eq!(breached[0].id, second.id);
    }

    #[tokio::test]
    async fn support_case_persists_linked_remediation_and_external_ids() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let remediation_case = seed_remediation_case(
            &service,
            &context,
            "svc:support-case-seed",
            "tenant.support",
        )
        .await;
        let change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));

        let support_case: SupportCaseRecord = read_json(
            service
                .create_support_case(
                    CreateSupportCaseRequest {
                        tenant_subject: String::from("tenant.support"),
                        reason: String::from("coordinate guided recovery with operators"),
                        owner: Some(String::from("ops.support")),
                        priority: Some(String::from("high")),
                        remediation_case_ids: vec![remediation_case.id.to_string()],
                        change_request_ids: vec![change_request_id.to_string()],
                        notify_message_ids: vec![notify_message_id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(support_case.tenant_subject, "tenant.support");
        assert_eq!(support_case.opened_by.as_deref(), Some("operator:abuse"));
        assert_eq!(support_case.owner.as_deref(), Some("ops.support"));
        assert_eq!(support_case.status, "open");
        assert_eq!(support_case.priority, "high");
        assert_eq!(
            support_case.remediation_case_ids,
            vec![remediation_case.id.clone()]
        );
        assert_eq!(
            support_case.change_request_ids,
            vec![change_request_id.clone()]
        );
        assert_eq!(
            support_case.notify_message_ids,
            vec![notify_message_id.clone()]
        );

        let stored = service
            .support_cases
            .get(support_case.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing support case"));
        assert_eq!(stored.value, support_case);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created = outbox
            .iter()
            .find(|message| message.payload.header.event_type == "abuse.support_case.created.v1")
            .unwrap_or_else(|| panic!("missing support case create event"));
        match &created.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(event.resource_kind, "abuse_support_case");
                assert_eq!(event.action, "created");
                assert_eq!(event.details["owner"], serde_json::json!("ops.support"));
                assert_eq!(event.details["priority"], serde_json::json!("high"));
                assert_eq!(event.details["status"], serde_json::json!("open"));
                assert_eq!(
                    event.details["remediation_case_ids"],
                    serde_json::json!([remediation_case.id.to_string()])
                );
                assert_eq!(
                    event.details["change_request_ids"],
                    serde_json::json!([change_request_id.to_string()])
                );
                assert_eq!(
                    event.details["notify_message_ids"],
                    serde_json::json!([notify_message_id.to_string()])
                );
            }
            payload => panic!("expected service event, got {payload:?}"),
        }
    }

    #[tokio::test]
    async fn support_case_routes_list_and_detail_by_link_filters() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let first_remediation = seed_remediation_case(
            &service,
            &context,
            "svc:support-list-a",
            "tenant.support.one",
        )
        .await;
        let second_remediation = seed_remediation_case(
            &service,
            &context,
            "svc:support-list-b",
            "tenant.support.two",
        )
        .await;
        let first_change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let first_notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second_change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second_notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));

        let first: SupportCaseRecord = read_json(
            service
                .create_support_case(
                    CreateSupportCaseRequest {
                        tenant_subject: String::from("tenant.support.one"),
                        reason: String::from("first support lane"),
                        owner: Some(String::from("ops.support")),
                        priority: Some(String::from("high")),
                        remediation_case_ids: vec![first_remediation.id.to_string()],
                        change_request_ids: vec![first_change_request_id.to_string()],
                        notify_message_ids: vec![first_notify_message_id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _second: SupportCaseRecord = read_json(
            service
                .create_support_case(
                    CreateSupportCaseRequest {
                        tenant_subject: String::from("tenant.support.two"),
                        reason: String::from("second support lane"),
                        owner: Some(String::from("ops.incident")),
                        priority: Some(String::from("low")),
                        remediation_case_ids: vec![second_remediation.id.to_string()],
                        change_request_ids: vec![second_change_request_id.to_string()],
                        notify_message_ids: vec![second_notify_message_id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let list_uri = format!(
            "/abuse/support-cases?tenant_subject=tenant.support.one&owner=ops.support&status=open&priority=high&remediation_case_id={}&change_request_id={}&notify_message_id={}&limit=1",
            first_remediation.id, first_change_request_id, first_notify_message_id,
        );
        let listed: Vec<SupportCaseRecord> = read_json(
            service
                .handle(service_request("GET", &list_uri, None), operator_context())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected support case list response")),
        )
        .await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, first.id);

        let detail_uri = format!("/abuse/support-cases/{}", first.id);
        let detail: SupportCaseRecord = read_json(
            service
                .handle(
                    service_request("GET", &detail_uri, None),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected support case detail response")),
        )
        .await;
        assert_eq!(detail, first);
    }

    #[tokio::test]
    async fn support_case_transition_updates_status_and_owner_and_emits_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let support_case = seed_support_case(
            &service,
            &context,
            "svc:support-transition",
            "tenant.support.transition",
        )
        .await;

        let transition_uri = format!("/abuse/support-cases/{}/transition", support_case.id);
        let transition_body = serde_json::json!({
            "reason": "waiting on tenant rollback confirmation",
            "status": "waiting_on_tenant",
            "owner": "operator:support-tier2",
        })
        .to_string();
        let transitioned: SupportCaseRecord = read_json(
            service
                .handle(
                    service_request("POST", &transition_uri, Some(&transition_body)),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected support case transition response")),
        )
        .await;
        assert_eq!(transitioned.id, support_case.id);
        assert_eq!(transitioned.status, "waiting_on_tenant");
        assert_eq!(
            transitioned.owner.as_deref(),
            Some("operator:support-tier2")
        );
        assert_eq!(transitioned.priority, support_case.priority);
        assert_eq!(
            transitioned.remediation_case_ids,
            support_case.remediation_case_ids
        );

        let stored = service
            .support_cases
            .get(transitioned.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing transitioned support case"));
        assert_eq!(stored.value, transitioned);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let transitioned_event = outbox
            .iter()
            .find(|message| {
                message.payload.header.event_type == "abuse.support_case.transitioned.v1"
            })
            .unwrap_or_else(|| panic!("missing support case transition event"));
        match &transitioned_event.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(event.resource_kind, "abuse_support_case");
                assert_eq!(event.action, "transitioned");
                assert_eq!(
                    event.details["status"],
                    serde_json::json!("waiting_on_tenant")
                );
                assert_eq!(
                    event.details["owner"],
                    serde_json::json!("operator:support-tier2")
                );
                assert_eq!(event.details["previous_status"], serde_json::json!("open"));
                assert_eq!(
                    event.details["previous_owner"],
                    serde_json::json!("operator:abuse")
                );
                assert_eq!(
                    event.details["transition_reason"],
                    serde_json::json!("waiting on tenant rollback confirmation")
                );
                assert_eq!(event.details["status_changed"], serde_json::json!(true));
                assert_eq!(event.details["owner_changed"], serde_json::json!(true));
            }
            payload => panic!("expected service event, got {payload:?}"),
        }
    }

    #[tokio::test]
    async fn support_case_transition_rejects_missing_or_noop_changes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let support_case = seed_support_case(
            &service,
            &context,
            "svc:support-transition-validation",
            "tenant.support.transition.validation",
        )
        .await;

        let transition_uri = format!("/abuse/support-cases/{}/transition", support_case.id);
        let missing_change_body = serde_json::json!({
            "reason": "reason only",
        })
        .to_string();
        let missing_change_error = service
            .handle(
                service_request("POST", &transition_uri, Some(&missing_change_body)),
                operator_context(),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected missing change rejection"));
        assert_eq!(
            missing_change_error.code,
            uhost_core::ErrorCode::InvalidInput
        );
        assert_eq!(
            missing_change_error.message,
            "support case transition requires status or owner"
        );

        let noop_body = serde_json::json!({
            "reason": "no effective update",
            "status": "open",
            "owner": "operator:abuse",
        })
        .to_string();
        let noop_error = service
            .handle(
                service_request("POST", &transition_uri, Some(&noop_body)),
                operator_context(),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected no-op transition rejection"));
        assert_eq!(noop_error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            noop_error.message,
            "support case transition does not change status or owner"
        );
    }

    #[tokio::test]
    async fn support_case_routes_require_operator_principal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let operator_request_context = operator_context();

        let remediation_case = seed_remediation_case(
            &service,
            &operator_request_context,
            "svc:support-operator-gated",
            "tenant.support.route",
        )
        .await;

        let list_context = user_context();
        let list_correlation_id = list_context.correlation_id.clone();
        let list_error = service
            .handle(
                service_request("GET", "/abuse/support-cases", None),
                list_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator list rejection"));
        assert_eq!(list_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            list_error.message,
            "support case inspection requires operator principal"
        );
        assert_eq!(
            list_error.correlation_id.as_deref(),
            Some(list_correlation_id.as_str())
        );

        let create_body = serde_json::json!({
            "tenant_subject": "tenant.support.route",
            "reason": "unauthorized attempt",
            "remediation_case_ids": [remediation_case.id.to_string()],
        })
        .to_string();
        let create_context = user_context();
        let create_correlation_id = create_context.correlation_id.clone();
        let create_error = service
            .handle(
                service_request("POST", "/abuse/support-cases", Some(&create_body)),
                create_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator create rejection"));
        assert_eq!(create_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            create_error.message,
            "support case management requires operator principal"
        );
        assert_eq!(
            create_error.correlation_id.as_deref(),
            Some(create_correlation_id.as_str())
        );

        let created: SupportCaseRecord = read_json(
            service
                .handle(
                    service_request("POST", "/abuse/support-cases", Some(&create_body)),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected support case create response")),
        )
        .await;

        let detail_uri = format!("/abuse/support-cases/{}", created.id);
        let detail_context = user_context();
        let detail_error = service
            .handle(service_request("GET", &detail_uri, None), detail_context)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator detail rejection"));
        assert_eq!(detail_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            detail_error.message,
            "support case inspection requires operator principal"
        );

        let transition_uri = format!("{detail_uri}/transition");
        let transition_body = serde_json::json!({
            "reason": "handoff to another operator",
            "status": "investigating",
            "owner": "operator:support-tier2",
        })
        .to_string();
        let transition_context = user_context();
        let transition_correlation_id = transition_context.correlation_id.clone();
        let transition_error = service
            .handle(
                service_request("POST", &transition_uri, Some(&transition_body)),
                transition_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator transition rejection"));
        assert_eq!(transition_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            transition_error.message,
            "support case management requires operator principal"
        );
        assert_eq!(
            transition_error.correlation_id.as_deref(),
            Some(transition_correlation_id.as_str())
        );

        let detail: SupportCaseRecord = read_json(
            service
                .handle(
                    service_request("GET", &detail_uri, None),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected support case detail response")),
        )
        .await;
        assert_eq!(detail.id, created.id);
    }

    #[tokio::test]
    async fn remediation_case_routes_require_operator_principal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let operator_request_context = operator_context();

        let case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:operator-gated"),
                        reason: String::from("operator-only queue seed"),
                        priority: Some(String::from("high")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &operator_request_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let remediation_case: RemediationCaseRecord = read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from("tenant.operator"),
                        reason: String::from("contain and notify"),
                        owner: None,
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:operator-rollback")],
                        verification_evidence_refs: vec![String::from("checklist:operator-verify")],
                        abuse_case_ids: vec![case_id.clone()],
                        quarantine_ids: Vec::new(),
                        change_request_ids: Vec::new(),
                        notify_message_ids: Vec::new(),
                    },
                    &operator_request_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let list_context = user_context();
        let list_correlation_id = list_context.correlation_id.clone();
        let list_error = service
            .handle(
                service_request("GET", "/abuse/remediation-cases", None),
                list_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator list rejection"));
        assert_eq!(list_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            list_error.message,
            "remediation case inspection requires operator principal"
        );
        assert_eq!(
            list_error.correlation_id.as_deref(),
            Some(list_correlation_id.as_str())
        );

        let detail_uri = format!("/abuse/remediation-cases/{}", remediation_case.id);
        let detail_context = user_context();
        let detail_error = service
            .handle(service_request("GET", &detail_uri, None), detail_context)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator detail rejection"));
        assert_eq!(detail_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            detail_error.message,
            "remediation case inspection requires operator principal"
        );

        let create_body = serde_json::json!({
            "tenant_subject": "tenant.operator",
            "reason": "unauthorized attempt",
            "abuse_case_ids": [case_id],
        })
        .to_string();
        let create_context = user_context();
        let create_correlation_id = create_context.correlation_id.clone();
        let create_error = service
            .handle(
                service_request("POST", "/abuse/remediation-cases", Some(&create_body)),
                create_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator create rejection"));
        assert_eq!(create_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            create_error.message,
            "remediation case management requires operator principal"
        );
        assert_eq!(
            create_error.correlation_id.as_deref(),
            Some(create_correlation_id.as_str())
        );

        let escalation_change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        let escalation_notify_message_id =
            NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let escalate_uri = format!("{detail_uri}/escalate");
        let escalate_body = serde_json::json!({
            "reason": "handoff to incident commander",
            "owner": "operator:incident",
            "change_request_ids": [escalation_change_request_id.to_string()],
            "notify_message_ids": [escalation_notify_message_id.to_string()],
        })
        .to_string();
        let escalate_context = user_context();
        let escalate_correlation_id = escalate_context.correlation_id.clone();
        let escalate_error = service
            .handle(
                service_request("POST", &escalate_uri, Some(&escalate_body)),
                escalate_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-operator escalate rejection"));
        assert_eq!(escalate_error.code, uhost_core::ErrorCode::Forbidden);
        assert_eq!(
            escalate_error.message,
            "remediation case management requires operator principal"
        );
        assert_eq!(
            escalate_error.correlation_id.as_deref(),
            Some(escalate_correlation_id.as_str())
        );

        let escalated: RemediationCaseRecord = read_json(
            service
                .handle(
                    service_request("POST", &escalate_uri, Some(&escalate_body)),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected remediation escalation response")),
        )
        .await;
        assert_eq!(escalated.owner.as_deref(), Some("operator:incident"));
        assert_eq!(escalated.escalation_state, "escalated");
        assert_eq!(escalated.escalation_count, 1);
        assert_eq!(
            escalated.last_escalation_reason.as_deref(),
            Some("handoff to incident commander")
        );
        assert_eq!(
            escalated.workflow_id.as_deref(),
            Some(format!("abuse.remediation.{}", escalated.id).as_str())
        );
        assert_eq!(
            escalated.change_request_ids,
            vec![escalation_change_request_id.clone()]
        );
        assert_eq!(
            escalated.notify_message_ids,
            vec![escalation_notify_message_id.clone()]
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_ROLLBACK_STEP_NAME).state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_VERIFICATION_STEP_NAME).state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME)
                .state,
            WorkflowStepState::Completed
        );

        let listed: Vec<RemediationCaseRecord> = read_json(
            service
                .handle(
                    service_request("GET", "/abuse/remediation-cases", None),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected remediation list response")),
        )
        .await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, remediation_case.id);
        assert_eq!(listed[0], escalated);

        let detail: RemediationCaseRecord = read_json(
            service
                .handle(
                    service_request("GET", &detail_uri, None),
                    operator_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("expected remediation detail response")),
        )
        .await;
        assert_eq!(detail, escalated);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let escalated_event = outbox
            .iter()
            .find(|message| {
                message.payload.header.event_type == "abuse.remediation_case.escalated.v1"
            })
            .unwrap_or_else(|| panic!("missing remediation escalation event"));
        match &escalated_event.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(event.action, "escalated");
                assert_eq!(
                    event.details["owner"],
                    serde_json::json!("operator:incident")
                );
                assert_eq!(event.details["escalation_count"], serde_json::json!(1));
                assert_eq!(
                    event.details["added_change_request_ids"],
                    serde_json::json!([escalation_change_request_id.to_string()])
                );
                assert_eq!(
                    event.details["added_notify_message_ids"],
                    serde_json::json!([escalation_notify_message_id.to_string()])
                );
                assert_eq!(event.details["owner_reassigned"], serde_json::json!(true));
                assert_eq!(
                    event.details["reason"],
                    serde_json::json!("handoff to incident commander")
                );
                assert_eq!(event.details["evidence_state"], serde_json::json!("ready"));
                assert_eq!(
                    event.details["rollback_evidence_count"],
                    serde_json::json!(1)
                );
                assert_eq!(
                    event.details["verification_evidence_count"],
                    serde_json::json!(1)
                );
                assert_eq!(
                    event.details["workflow_steps"][4]["state"],
                    serde_json::json!("completed")
                );
            }
            other => panic!("unexpected event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn remediation_case_requires_rollback_and_verification_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:evidence-gated"),
                        reason: String::from("evidence-gated remediation"),
                        priority: Some(String::from("normal")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let missing_rollback = service
            .create_remediation_case(
                CreateRemediationCaseRequest {
                    tenant_subject: String::from("tenant.gamma"),
                    reason: String::from("missing rollback evidence"),
                    owner: None,
                    sla_target_seconds: None,
                    rollback_evidence_refs: Vec::new(),
                    verification_evidence_refs: vec![String::from("checklist:verify")],
                    abuse_case_ids: vec![case_id.clone()],
                    quarantine_ids: Vec::new(),
                    change_request_ids: Vec::new(),
                    notify_message_ids: Vec::new(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected rollback evidence validation failure"));
        assert_eq!(missing_rollback.code, uhost_core::ErrorCode::InvalidInput);
        assert_eq!(
            missing_rollback.message,
            "rollback_evidence_refs must include at least one evidence reference"
        );

        let missing_verification = service
            .create_remediation_case(
                CreateRemediationCaseRequest {
                    tenant_subject: String::from("tenant.gamma"),
                    reason: String::from("missing verification evidence"),
                    owner: None,
                    sla_target_seconds: None,
                    rollback_evidence_refs: vec![String::from("runbook:rollback")],
                    verification_evidence_refs: Vec::new(),
                    abuse_case_ids: vec![case_id],
                    quarantine_ids: Vec::new(),
                    change_request_ids: Vec::new(),
                    notify_message_ids: Vec::new(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected verification evidence validation failure"));
        assert_eq!(
            missing_verification.code,
            uhost_core::ErrorCode::InvalidInput
        );
        assert_eq!(
            missing_verification.message,
            "verification_evidence_refs must include at least one evidence reference"
        );
    }

    #[tokio::test]
    async fn remediation_case_escalation_requires_missing_evidence_backfill() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let case_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:legacy-remediation"),
                        reason: String::from("legacy remediation seed"),
                        priority: Some(String::from("high")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let remediation_case: RemediationCaseRecord = read_json(
            service
                .create_remediation_case(
                    CreateRemediationCaseRequest {
                        tenant_subject: String::from("tenant.legacy"),
                        reason: String::from("legacy workflow migration"),
                        owner: None,
                        sla_target_seconds: None,
                        rollback_evidence_refs: vec![String::from("runbook:legacy-rollback")],
                        verification_evidence_refs: vec![String::from("checklist:legacy-verify")],
                        abuse_case_ids: vec![case_id],
                        quarantine_ids: Vec::new(),
                        change_request_ids: Vec::new(),
                        notify_message_ids: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let stored = service
            .remediation_cases
            .get(remediation_case.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing remediation case"));
        let mut legacy_record = stored.value;
        legacy_record.rollback_evidence_refs.clear();
        legacy_record.verification_evidence_refs.clear();
        legacy_record.updated_at = time::OffsetDateTime::now_utc();
        legacy_record
            .metadata
            .touch(uhost_core::sha256_hex(legacy_record.id.as_str().as_bytes()));
        service
            .remediation_cases
            .upsert(
                remediation_case.id.as_str(),
                legacy_record,
                Some(stored.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let missing_backfill_error = service
            .escalate_remediation_case(
                remediation_case.id.as_str(),
                EscalateRemediationCaseRequest {
                    reason: String::from("handoff without evidence backfill"),
                    owner: Some(String::from("operator:incident")),
                    rollback_evidence_refs: Vec::new(),
                    verification_evidence_refs: Vec::new(),
                    change_request_ids: Vec::new(),
                    notify_message_ids: Vec::new(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected escalation evidence validation failure"));
        assert_eq!(
            missing_backfill_error.message,
            "rollback_evidence_refs must include at least one evidence reference"
        );

        let escalated: RemediationCaseRecord = read_json(
            service
                .escalate_remediation_case(
                    remediation_case.id.as_str(),
                    EscalateRemediationCaseRequest {
                        reason: String::from("handoff with evidence backfill"),
                        owner: Some(String::from("operator:incident")),
                        rollback_evidence_refs: vec![String::from("runbook:legacy-rollback-v2")],
                        verification_evidence_refs: vec![String::from(
                            "checklist:legacy-verify-v2",
                        )],
                        change_request_ids: Vec::new(),
                        notify_message_ids: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(escalated.owner.as_deref(), Some("operator:incident"));
        assert_eq!(escalated.evidence_state, "ready");
        assert_eq!(
            escalated.rollback_evidence_refs,
            vec![String::from("runbook:legacy-rollback-v2")]
        );
        assert_eq!(
            escalated.verification_evidence_refs,
            vec![String::from("checklist:legacy-verify-v2")]
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_ROLLBACK_STEP_NAME).state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_VERIFICATION_STEP_NAME).state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            remediation_workflow_step(&escalated, super::REMEDIATION_DOWNSTREAM_FANOUT_STEP_NAME)
                .state,
            WorkflowStepState::Active
        );

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let escalated_event = outbox
            .iter()
            .rev()
            .find(|message| {
                message.payload.header.event_type == "abuse.remediation_case.escalated.v1"
            })
            .unwrap_or_else(|| panic!("missing remediation escalation event"));
        match &escalated_event.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(
                    event.details["added_rollback_evidence_refs"],
                    serde_json::json!(["runbook:legacy-rollback-v2"])
                );
                assert_eq!(
                    event.details["added_verification_evidence_refs"],
                    serde_json::json!(["checklist:legacy-verify-v2"])
                );
                assert_eq!(event.details["evidence_state"], serde_json::json!("ready"));
                assert_eq!(
                    event.details["workflow_steps"][4]["state"],
                    serde_json::json!("active")
                );
            }
            other => panic!("unexpected event payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn remediation_case_requires_abuse_case_or_quarantine_link() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let error = service
            .create_remediation_case(
                CreateRemediationCaseRequest {
                    tenant_subject: String::from("tenant.gamma"),
                    reason: String::from("missing abuse links"),
                    owner: None,
                    sla_target_seconds: None,
                    rollback_evidence_refs: Vec::new(),
                    verification_evidence_refs: Vec::new(),
                    abuse_case_ids: Vec::new(),
                    quarantine_ids: Vec::new(),
                    change_request_ids: Vec::new(),
                    notify_message_ids: Vec::new(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected remediation link validation failure"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn summary_reports_state_counts() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_signal(
                CreateSignalRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:summary-signal"),
                    signal_kind: String::from("manual"),
                    severity: String::from("low"),
                    confidence_bps: Some(8_000),
                    source_service: Some(String::from("node")),
                    reason: Some(String::from("summary seed")),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_case(
                CreateAbuseCaseRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:summary-open"),
                    reason: String::from("baseline open case"),
                    priority: Some(String::from("normal")),
                    signal_ids: Vec::new(),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let case_quarantined_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:summary-quarantine"),
                        reason: String::from("contain risk"),
                        priority: Some(String::from("high")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let case_resolved_id = extract_case_id(
            service
                .create_case(
                    CreateAbuseCaseRequest {
                        subject_kind: Some(String::from("service_identity")),
                        subject: String::from("svc:summary-resolved"),
                        reason: String::from("finish review"),
                        priority: Some(String::from("normal")),
                        signal_ids: Vec::new(),
                        evidence_refs: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        service
            .review_case(
                &case_resolved_id,
                ReviewCaseRequest {
                    action: String::from("resolve"),
                    reviewer: String::from("ops.resolver"),
                    note: None,
                    assign_to: None,
                    escalate: None,
                    quarantine: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_quarantine(
                CreateQuarantineRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:summary-quarantine"),
                    reason: String::from("issue review"),
                    case_id: Some(case_quarantined_id.clone()),
                    deny_network: Some(true),
                    deny_mail_relay: Some(true),
                    expires_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _pending_appeal = read_json::<AppealRecord>(
            service
                .create_appeal(
                    CreateAppealRequest {
                        case_id: case_quarantined_id.clone(),
                        requested_by: String::from("tenant.owner"),
                        reason: String::from("please review"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _ = service
            .upsert_reputation(
                CreateReputationRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:summary-blocked"),
                    score: -90,
                    state: String::from("blocked"),
                    reason: Some(String::from("test signal")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .upsert_reputation(
                CreateReputationRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:summary-trusted"),
                    score: 70,
                    state: String::from("trusted"),
                    reason: Some(String::from("whitelisted")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.signals_total, 1);
        assert_eq!(count_for(&summary.signals_by_severity, "low"), 1);
        assert_eq!(summary.cases_total, 3);
        assert_eq!(count_for(&summary.cases_by_status, "open"), 1);
        assert_eq!(count_for(&summary.cases_by_status, "quarantined"), 1);
        assert_eq!(count_for(&summary.cases_by_status, "resolved"), 1);
        assert_eq!(summary.active_cases, 2);
        assert_eq!(summary.quarantines_total, 1);
        assert_eq!(summary.active_quarantines, 1);
        assert_eq!(count_for(&summary.quarantines_by_state, "active"), 1);
        assert_eq!(summary.appeals_total, 1);
        assert_eq!(count_for(&summary.appeals_by_status, "pending"), 1);
        assert_eq!(summary.reputations_total, 3);
        assert_eq!(count_for(&summary.reputations_by_state, "blocked"), 1);
        assert_eq!(count_for(&summary.reputations_by_state, "trusted"), 1);
        assert_eq!(count_for(&summary.reputations_by_state, "restricted"), 1);
    }

    #[tokio::test]
    async fn evaluate_risk_reports_active_case_and_recent_signals() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_signal(
                CreateSignalRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:web"),
                    signal_kind: String::from("api_abuse"),
                    severity: String::from("medium"),
                    confidence_bps: Some(9_000),
                    source_service: Some(String::from("ingress")),
                    reason: Some(String::from("rate anomaly")),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_case(
                CreateAbuseCaseRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:web"),
                    reason: String::from("triage suspicious traffic"),
                    priority: None,
                    signal_ids: Vec::new(),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .evaluate_risk(EvaluateRiskRequest {
                subject_kind: Some(String::from("service_identity")),
                subject: String::from("svc:web"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let risk = service
            .evaluate_subject_risk("service_identity", "svc:web")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(risk.subject, "svc:web");
        assert_eq!(risk.signals_in_last_24h, 1);
        assert_eq!(risk.active_case_ids.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_risk_uses_signal_history_when_reputation_is_missing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = AbuseService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_signal(
                CreateSignalRequest {
                    subject_kind: Some(String::from("service_identity")),
                    subject: String::from("svc:history"),
                    signal_kind: String::from("spam"),
                    severity: String::from("medium"),
                    confidence_bps: Some(9_000),
                    source_service: Some(String::from("mail")),
                    reason: Some(String::from("suspicious burst")),
                    evidence_refs: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let key = super::reputation_key("service_identity", "svc:history");
        service
            .reputation
            .soft_delete(&key, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let risk = service
            .evaluate_subject_risk("service_identity", "svc:history")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(risk.score, 0);
        assert_eq!(risk.state, "watch");
        assert_eq!(risk.signal_count, 1);
        assert_eq!(risk.signals_in_last_24h, 1);
    }

    proptest! {
        #[test]
        fn score_clamp_is_bounded(current in -2000_i32..=2000_i32, delta in -2000_i32..=2000_i32) {
            let value = super::clamp_score(current, delta);
            prop_assert!((-100..=100).contains(&value));
        }
    }
}
