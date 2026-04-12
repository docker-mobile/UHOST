//! Governance, compliance, and approval workflows service.
//!
//! This service owns legal hold state, retention and residency policies,
//! change approvals with separation-of-duties checks, and tamper-evident audit
//! checkpoints chained by hash.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use http::{Method, Request, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::{fs, sync::Mutex};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{ErrorCode, PlatformError, RequestContext, Result, sha256_hex, validate_slug};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentCollection, DocumentStore, DurableOutbox};
use uhost_types::{
    AuditActor, AuditCheckpointId, AuditId, ChangeRequestId, EdgeExposureIntent, EdgePublication,
    EventHeader, EventPayload, GovernanceRequestProvenance, LegalHoldId, OwnershipScope,
    PlatformEvent, PrincipalKind, ResourceMetadata, RetentionPolicyId, ServiceEvent,
};

/// Legal hold for retention override and investigation support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldRecord {
    /// Legal hold identifier.
    pub id: LegalHoldId,
    /// Subject kind such as `tenant`, `project`, or `bucket`.
    pub subject_kind: String,
    /// Subject identifier.
    pub subject_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Whether the hold is currently active.
    pub active: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Retention and deletion policy definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicyRecord {
    /// Retention policy identifier.
    pub id: RetentionPolicyId,
    /// Policy name.
    pub name: String,
    /// Resource kind targeted by this policy.
    pub resource_kind: String,
    /// Minimum retention period.
    pub retain_days: u32,
    /// Hard-delete window after retention expiry.
    pub hard_delete_after_days: u32,
    /// Residency tags such as `eu`, `us`, `ca`.
    pub residency_tags: Vec<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Lifecycle state for a change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestState {
    /// Created and waiting for approval.
    Pending,
    /// Approved by a different operator.
    Approved,
    /// Rejected by approver.
    Rejected,
    /// Executed and complete.
    Applied,
}

/// Change-management request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRequestRecord {
    /// Change request identifier.
    pub id: ChangeRequestId,
    /// Short title.
    pub title: String,
    /// Change type such as `deploy`, `schema_migration`, `policy_change`.
    pub change_type: String,
    /// Requesting operator subject.
    pub requested_by: String,
    /// Approver subject if approved or rejected.
    pub approved_by: Option<String>,
    /// Optional reviewer note.
    pub reviewer_comment: Option<String>,
    /// Number of unique approvals required before the change can be applied.
    #[serde(default = "default_required_approvals")]
    pub required_approvals: u8,
    /// Current state.
    pub state: ChangeRequestState,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Immutable approval evidence for one reviewer action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeApprovalRecord {
    /// Approval identifier.
    pub id: AuditId,
    /// Change request identifier.
    pub change_request_id: ChangeRequestId,
    /// Approver principal.
    pub approver: String,
    /// Optional reviewer comment.
    pub comment: Option<String>,
    /// Timestamp of approval action.
    pub approved_at: OffsetDateTime,
    /// Authenticated request provenance bound to the approval action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<GovernanceRequestProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChangeApprovalView {
    id: AuditId,
    change_request_id: ChangeRequestId,
    approver: String,
    comment: Option<String>,
    approved_at: OffsetDateTime,
}

impl From<ChangeApprovalRecord> for ChangeApprovalView {
    fn from(value: ChangeApprovalRecord) -> Self {
        Self {
            id: value.id,
            change_request_id: value.change_request_id,
            approver: value.approver,
            comment: value.comment,
            approved_at: value.approved_at,
        }
    }
}

/// One checkpoint in the append-only audit hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpointRecord {
    /// Checkpoint identifier.
    pub id: AuditCheckpointId,
    /// Previous chain head (or `genesis` for first record).
    pub previous_hash: String,
    /// New chain head.
    pub current_hash: String,
    /// Checkpoint summary.
    pub summary: String,
    /// Checkpoint timestamp.
    pub recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChainHeadRecord {
    current_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExposureOverrideState {
    Pending,
    Active,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureOverrideRecord {
    id: AuditId,
    surface: String,
    target_kind: String,
    target_id: String,
    override_kind: String,
    reason: String,
    change_request_id: ChangeRequestId,
    requested_by: String,
    activated_by: Option<String>,
    reverted_by: Option<String>,
    revert_reason: Option<String>,
    state: ExposureOverrideState,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    reverted_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
    metadata: ResourceMetadata,
}

#[derive(Debug, Serialize)]
struct GovernanceSummary {
    state_root: String,
    audit_chain_head: String,
    change_requests: ChangeRequestTotals,
    approvals: ApprovalTotals,
    legal_holds: LegalHoldTotals,
    overrides: ExposureOverrideTotals,
    audit: AuditTotals,
}

#[derive(Debug, Serialize)]
struct ChangeRequestTotals {
    total: u64,
    pending: u64,
    approved: u64,
    rejected: u64,
    applied: u64,
}

#[derive(Debug, Serialize)]
struct ApprovalTotals {
    total: u64,
}

#[derive(Debug, Serialize)]
struct LegalHoldTotals {
    total: u64,
    active: u64,
}

#[derive(Debug, Serialize)]
struct ExposureOverrideTotals {
    total: u64,
    pending: u64,
    active: u64,
    reverted: u64,
}

#[derive(Debug, Serialize)]
struct AuditTotals {
    total_checkpoints: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_checkpoint_at: Option<OffsetDateTime>,
    recent: Vec<AuditCheckpointSummary>,
}

#[derive(Debug, Serialize)]
struct AuditCheckpointSummary {
    id: AuditCheckpointId,
    summary: String,
    recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReportCounter {
    key: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureOverrideReport {
    total: usize,
    pending: usize,
    active: usize,
    effective_active: usize,
    reverted: usize,
    active_publishability: usize,
    active_readiness: usize,
    active_by_surface: Vec<ReportCounter>,
    active_entries: Vec<ExposureOverrideRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IngressExposureReadiness {
    total_routes: usize,
    public_routes: usize,
    private_routes: usize,
    routes_with_dns_binding: usize,
    routes_with_security_policy: usize,
    routes_without_active_publication_targets: usize,
    publishable: bool,
    effective_publishable: bool,
    active_publishability_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsExposureReadiness {
    total_zones: usize,
    verified_zones: usize,
    unverified_zones: usize,
    total_provider_tasks: usize,
    pending_provider_tasks: usize,
    failed_provider_tasks: usize,
    publishable: bool,
    effective_publishable: bool,
    active_publishability_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailExposureReadiness {
    total_domains: usize,
    verified_domains: usize,
    unverified_domains: usize,
    suspended_relay_domains: usize,
    active_delivery_quarantines: usize,
    total_provider_tasks: usize,
    pending_provider_tasks: usize,
    failed_provider_tasks: usize,
    publishable: bool,
    effective_publishable: bool,
    active_publishability_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetsecExposureReadiness {
    total_policies: usize,
    total_private_networks: usize,
    deny_flow_audits: usize,
    active_network_quarantines: usize,
    ready: bool,
    effective_ready: bool,
    active_readiness_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyExposureReadiness {
    total_policies: usize,
    total_approvals: usize,
    pending_approvals: usize,
    ready: bool,
    effective_ready: bool,
    active_readiness_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceExposureReadiness {
    total_change_requests: usize,
    pending_change_requests: usize,
    approved_change_requests: usize,
    ready: bool,
    effective_ready: bool,
    active_readiness_overrides: usize,
    blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureReadinessReport {
    generated_at: OffsetDateTime,
    raw_publishable: bool,
    effective_publishable: bool,
    raw_ready: bool,
    effective_ready: bool,
    blockers: Vec<String>,
    overrides: ExposureOverrideReport,
    ingress: IngressExposureReadiness,
    dns: DnsExposureReadiness,
    mail: MailExposureReadiness,
    netsec: NetsecExposureReadiness,
    policy: PolicyExposureReadiness,
    governance: GovernanceExposureReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateLegalHoldRequest {
    subject_kind: String,
    subject_id: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRetentionPolicyRequest {
    name: String,
    resource_kind: String,
    retain_days: u32,
    hard_delete_after_days: u32,
    residency_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateChangeRequestRequest {
    title: String,
    change_type: String,
    requested_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewChangeRequest {
    approver: String,
    comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApplyChangeRequest {
    executor: String,
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateExposureOverrideRequest {
    surface: String,
    target_kind: String,
    target_id: String,
    override_kind: String,
    reason: String,
    change_request_id: String,
    requested_by: String,
    expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ActivateExposureOverrideRequest {
    activated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevertExposureOverrideRequest {
    reverted_by: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManualCheckpointRequest {
    summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRetentionRequest {
    subject_kind: String,
    subject_id: String,
    resource_kind: String,
    residency_tag: Option<String>,
    age_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRetentionResponse {
    can_delete: bool,
    reason: String,
    matched_policy_id: Option<String>,
    required_retain_days: Option<u32>,
    hard_delete_after_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditIntegrityReport {
    valid: bool,
    checkpoints_checked: usize,
    head_hash: String,
    expected_head_hash: String,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureIngressRouteHook {
    #[serde(default)]
    publication: EdgePublication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureZoneHook {
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureProviderTaskHook {
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureMailDomainHook {
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureMailReputationHook {
    suspended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureMailQuarantineHook {
    #[serde(default)]
    state: String,
    #[serde(default)]
    deny_mail_relay: bool,
    expires_at: Option<OffsetDateTime>,
    released_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureNetsecPolicyHook {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposurePrivateNetworkHook {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureNetsecFlowAuditHook {
    verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposureNetsecQuarantineHook {
    #[serde(default)]
    state: String,
    #[serde(default)]
    deny_network: bool,
    expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposurePolicyRecordHook {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExposurePolicyApprovalHook {
    approved: bool,
}

/// Governance service implementation.
#[derive(Debug, Clone)]
pub struct GovernanceService {
    legal_holds: DocumentStore<LegalHoldRecord>,
    retention_policies: DocumentStore<RetentionPolicyRecord>,
    change_requests: DocumentStore<ChangeRequestRecord>,
    change_approvals: DocumentStore<ChangeApprovalRecord>,
    exposure_overrides: DocumentStore<ExposureOverrideRecord>,
    audit_checkpoints: DocumentStore<AuditCheckpointRecord>,
    chain_head: DocumentStore<ChainHeadRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    audit_chain_guard: Arc<Mutex<()>>,
    state_root: PathBuf,
}

impl GovernanceService {
    /// Open governance service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("governance");
        let audit_chain_guard = shared_audit_chain_guard(&root.join("audit_chain_head.json"));
        Ok(Self {
            legal_holds: DocumentStore::open(root.join("legal_holds.json")).await?,
            retention_policies: DocumentStore::open(root.join("retention_policies.json")).await?,
            change_requests: DocumentStore::open(root.join("change_requests.json")).await?,
            change_approvals: DocumentStore::open(root.join("change_approvals.json")).await?,
            exposure_overrides: DocumentStore::open(root.join("exposure_overrides.json")).await?,
            audit_checkpoints: DocumentStore::open(root.join("audit_checkpoints.json")).await?,
            chain_head: DocumentStore::open(root.join("audit_chain_head.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            audit_chain_guard,
            state_root: root,
        })
    }

    async fn create_legal_hold(
        &self,
        request: CreateLegalHoldRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = request.subject_kind.trim();
        let subject_id = request.subject_id.trim();
        let reason = request.reason.trim();
        if subject_kind.is_empty() || subject_id.is_empty() {
            return Err(PlatformError::invalid(
                "subject_kind and subject_id may not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }

        let id = LegalHoldId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate legal hold id")
                .with_detail(error.to_string())
        })?;
        let record = LegalHoldRecord {
            id: id.clone(),
            subject_kind: subject_kind.to_owned(),
            subject_id: subject_id.to_owned(),
            reason: reason.to_owned(),
            active: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.legal_holds.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "governance.legal_hold.created.v1",
            "legal_hold",
            id.as_str(),
            "created",
            serde_json::json!({
                "subject_kind": record.subject_kind,
                "subject_id": record.subject_id,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn release_legal_hold(
        &self,
        hold_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let stored = self
            .legal_holds
            .get(hold_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("legal hold does not exist"))?;
        let mut record = stored.value;
        record.active = false;
        record.metadata.touch(sha256_hex(hold_id.as_bytes()));
        self.legal_holds
            .upsert(hold_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.legal_hold.released.v1",
            "legal_hold",
            hold_id,
            "released",
            serde_json::json!({}),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn create_retention_policy(
        &self,
        request: CreateRetentionPolicyRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let name = request.name.trim();
        let resource_kind = request.resource_kind.trim();
        if name.is_empty() || resource_kind.is_empty() {
            return Err(PlatformError::invalid(
                "name and resource_kind may not be empty",
            ));
        }
        if request.hard_delete_after_days < request.retain_days {
            return Err(PlatformError::invalid(
                "hard_delete_after_days must be >= retain_days",
            ));
        }

        let id = RetentionPolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate retention policy id")
                .with_detail(error.to_string())
        })?;
        let record = RetentionPolicyRecord {
            id: id.clone(),
            name: name.to_owned(),
            resource_kind: resource_kind.to_owned(),
            retain_days: request.retain_days,
            hard_delete_after_days: request.hard_delete_after_days,
            residency_tags: normalize_residency_tags(request.residency_tags),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.retention_policies
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "governance.retention_policy.created.v1",
            "retention_policy",
            id.as_str(),
            "created",
            serde_json::json!({
                "resource_kind": record.resource_kind,
                "retain_days": record.retain_days,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_change_request(
        &self,
        request: CreateChangeRequestRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let title = request.title.trim();
        let change_type = request.change_type.trim();
        if title.is_empty() || change_type.is_empty() {
            return Err(PlatformError::invalid(
                "title and change_type may not be empty",
            ));
        }
        let requested_by =
            bind_authenticated_change_actor(context, &request.requested_by, "requested_by")?;

        let id = ChangeRequestId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate change request id")
                .with_detail(error.to_string())
        })?;
        let required_approvals = required_approvals_for_change_type(change_type);
        let record = ChangeRequestRecord {
            id: id.clone(),
            title: title.to_owned(),
            change_type: change_type.to_owned(),
            requested_by,
            approved_by: None,
            reviewer_comment: None,
            required_approvals,
            state: ChangeRequestState::Pending,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.change_requests
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "governance.change_request.created.v1",
            "change_request",
            id.as_str(),
            "created",
            serde_json::json!({
                "change_type": record.change_type,
                "requested_by": record.requested_by,
                "required_approvals": record.required_approvals,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn approve_change_request(
        &self,
        request_id: &str,
        review: ReviewChangeRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let approver = bind_authenticated_change_actor(context, &review.approver, "approver")?;
        let comment = normalize_optional_comment(review.comment);
        let provenance = Some(change_approval_provenance(context)?);
        let stored = self
            .change_requests
            .get(request_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("change request does not exist"))?;
        let mut record = stored.value;
        if record.state != ChangeRequestState::Pending {
            return Err(PlatformError::conflict(
                "change request is already finalized and cannot be approved",
            ));
        }
        enforce_reviewer_separation(&record, &approver)?;
        let approval_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate change approval id")
                .with_detail(error.to_string())
        })?;
        let approval_key = change_approval_key(&record.id, &approver);
        let approval = ChangeApprovalRecord {
            id: approval_id,
            change_request_id: record.id.clone(),
            approver: approver.clone(),
            comment: comment.clone(),
            approved_at: OffsetDateTime::now_utc(),
            provenance,
        };
        self.change_approvals
            .create(&approval_key, approval)
            .await?;

        let unique_approvers = self
            .change_approvals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|approval| approval.change_request_id == record.id)
            .map(|approval| approval.approver)
            .collect::<BTreeSet<_>>();

        let required = record.required_approvals.max(1);
        record.approved_by = Some(approver);
        record.reviewer_comment = comment;
        record.state = if unique_approvers.len() >= usize::from(required) {
            ChangeRequestState::Approved
        } else {
            ChangeRequestState::Pending
        };
        record.metadata.touch(sha256_hex(request_id.as_bytes()));
        self.change_requests
            .upsert(request_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.approval.approved.v1",
            "change_request",
            request_id,
            "approved",
            serde_json::json!({
                "approved_by": record.approved_by,
                "approval_count": unique_approvers.len(),
                "required_approvals": required,
                "state": record.state,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn reject_change_request(
        &self,
        request_id: &str,
        review: ReviewChangeRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let approver = bind_authenticated_change_actor(context, &review.approver, "approver")?;
        let comment = normalize_optional_comment(review.comment);
        let stored = self
            .change_requests
            .get(request_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("change request does not exist"))?;
        let mut record = stored.value;
        if record.state != ChangeRequestState::Pending {
            return Err(PlatformError::conflict(
                "change request is already finalized and cannot be rejected",
            ));
        }
        enforce_reviewer_separation(&record, &approver)?;
        record.approved_by = Some(approver);
        record.reviewer_comment = comment;
        record.state = ChangeRequestState::Rejected;
        record.metadata.touch(sha256_hex(request_id.as_bytes()));
        self.change_requests
            .upsert(request_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.approval.rejected.v1",
            "change_request",
            request_id,
            "rejected",
            serde_json::json!({ "approved_by": record.approved_by }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn apply_change_request(
        &self,
        request_id: &str,
        apply: ApplyChangeRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let executor = bind_authenticated_change_actor(context, &apply.executor, "executor")?;
        let note = normalize_optional_comment(apply.note);
        let stored = self
            .change_requests
            .get(request_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("change request does not exist"))?;
        let mut record = stored.value;
        if record.state != ChangeRequestState::Approved {
            return Err(PlatformError::conflict(
                "change request must be approved before apply",
            ));
        }
        if executor == record.requested_by {
            return Err(PlatformError::forbidden(
                "executor must be different from requester",
            ));
        }
        record.state = ChangeRequestState::Applied;
        record.metadata.touch(sha256_hex(request_id.as_bytes()));
        self.change_requests
            .upsert(request_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.change_request.applied.v1",
            "change_request",
            request_id,
            "applied",
            serde_json::json!({
                "executor": executor,
                "note": note,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn list_exposure_overrides(&self) -> Result<Response<ApiBody>> {
        let mut values = self
            .exposure_overrides
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });
        json_response(StatusCode::OK, &values)
    }

    async fn create_exposure_override(
        &self,
        request: CreateExposureOverrideRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let requested_by =
            bind_authenticated_change_actor(context, &request.requested_by, "requested_by")?;
        let surface = normalize_exposure_surface(&request.surface)?;
        let target_kind =
            validate_slug(&request.target_kind.trim().to_ascii_lowercase()).map_err(|error| {
                PlatformError::invalid("invalid target_kind").with_detail(error.to_string())
            })?;
        let target_id = normalize_required_text("target_id", &request.target_id)?;
        let override_kind = normalize_exposure_override_kind(&request.override_kind)?;
        let reason = normalize_required_text("reason", &request.reason)?;
        if let Some(expires_at) = request.expires_at
            && expires_at <= OffsetDateTime::now_utc()
        {
            return Err(PlatformError::invalid("expires_at must be in the future"));
        }

        let change_request_id = ChangeRequestId::parse(request.change_request_id.trim().to_owned())
            .map_err(|error| {
                PlatformError::invalid("invalid change_request_id").with_detail(error.to_string())
            })?;
        let stored_change = self
            .change_requests
            .get(change_request_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("referenced change request does not exist"))?;
        if stored_change.deleted {
            return Err(PlatformError::not_found(
                "referenced change request does not exist",
            ));
        }
        if stored_change.value.requested_by != requested_by {
            return Err(PlatformError::conflict(
                "override requester must match referenced change request requester",
            ));
        }
        if stored_change.value.state == ChangeRequestState::Rejected {
            return Err(PlatformError::conflict(
                "referenced change request is rejected",
            ));
        }

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate exposure override id")
                .with_detail(error.to_string())
        })?;
        let record = ExposureOverrideRecord {
            id: id.clone(),
            surface,
            target_kind,
            target_id,
            override_kind,
            reason: reason.clone(),
            change_request_id: change_request_id.clone(),
            requested_by,
            activated_by: None,
            reverted_by: None,
            revert_reason: None,
            state: ExposureOverrideState::Pending,
            created_at: OffsetDateTime::now_utc(),
            activated_at: None,
            reverted_at: None,
            expires_at: request.expires_at,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.exposure_overrides
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "governance.exposure_override.created.v1",
            "exposure_override",
            id.as_str(),
            "created",
            serde_json::json!({
                "surface": record.surface,
                "target_kind": record.target_kind,
                "target_id": record.target_id,
                "override_kind": record.override_kind,
                "change_request_id": record.change_request_id,
                "reason": reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn activate_exposure_override(
        &self,
        override_id: &str,
        request: ActivateExposureOverrideRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let activated_by =
            bind_authenticated_change_actor(context, &request.activated_by, "activated_by")?;
        let stored = self
            .exposure_overrides
            .get(override_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("exposure override does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("exposure override does not exist"));
        }
        let mut record = stored.value;
        if record.state != ExposureOverrideState::Pending {
            return Err(PlatformError::conflict(
                "exposure override is already finalized",
            ));
        }
        if activated_by == record.requested_by {
            return Err(PlatformError::forbidden(
                "activator must be different from requester",
            ));
        }
        let stored_change = self
            .change_requests
            .get(record.change_request_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("referenced change request does not exist"))?;
        if stored_change.deleted {
            return Err(PlatformError::not_found(
                "referenced change request does not exist",
            ));
        }
        if !matches!(
            stored_change.value.state,
            ChangeRequestState::Approved | ChangeRequestState::Applied
        ) {
            return Err(PlatformError::conflict(
                "referenced change request must be approved before override activation",
            ));
        }

        record.state = ExposureOverrideState::Active;
        record.activated_by = Some(activated_by.clone());
        record.activated_at = Some(OffsetDateTime::now_utc());
        record.metadata.touch(sha256_hex(override_id.as_bytes()));
        self.exposure_overrides
            .upsert(override_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.exposure_override.activated.v1",
            "exposure_override",
            override_id,
            "activated",
            serde_json::json!({
                "surface": record.surface,
                "override_kind": record.override_kind,
                "activated_by": activated_by,
                "change_request_id": record.change_request_id,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn revert_exposure_override(
        &self,
        override_id: &str,
        request: RevertExposureOverrideRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let reverted_by =
            bind_authenticated_change_actor(context, &request.reverted_by, "reverted_by")?;
        let revert_reason =
            normalize_required_text("reason", request.reason.as_deref().unwrap_or_default())?;
        let stored = self
            .exposure_overrides
            .get(override_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("exposure override does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("exposure override does not exist"));
        }
        let mut record = stored.value;
        if record.state != ExposureOverrideState::Active {
            return Err(PlatformError::conflict(
                "exposure override must be active before revert",
            ));
        }

        record.state = ExposureOverrideState::Reverted;
        record.reverted_by = Some(reverted_by.clone());
        record.revert_reason = Some(revert_reason.clone());
        record.reverted_at = Some(OffsetDateTime::now_utc());
        record.metadata.touch(sha256_hex(override_id.as_bytes()));
        self.exposure_overrides
            .upsert(override_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "governance.exposure_override.reverted.v1",
            "exposure_override",
            override_id,
            "reverted",
            serde_json::json!({
                "surface": record.surface,
                "override_kind": record.override_kind,
                "reverted_by": reverted_by,
                "reason": revert_reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn create_manual_checkpoint(
        &self,
        request: ManualCheckpointRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let summary = request.summary.trim();
        if summary.is_empty() {
            return Err(PlatformError::invalid("summary may not be empty"));
        }
        self.append_event(
            "governance.audit.checkpointed.v1",
            "audit_chain",
            "manual",
            "checkpointed",
            serde_json::json!({ "summary": summary }),
            context,
        )
        .await?;

        let checkpoint = latest_checkpoint(&self.audit_checkpoints).await?;
        json_response(StatusCode::CREATED, &checkpoint)
    }

    async fn evaluate_retention(
        &self,
        request: EvaluateRetentionRequest,
    ) -> Result<Response<ApiBody>> {
        let subject_kind = request.subject_kind.trim();
        let subject_id = request.subject_id.trim();
        let resource_kind = request.resource_kind.trim();
        if subject_kind.is_empty() || subject_id.is_empty() || resource_kind.is_empty() {
            return Err(PlatformError::invalid(
                "subject_kind, subject_id, and resource_kind may not be empty",
            ));
        }
        let active_hold = self
            .legal_holds
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .any(|hold| {
                hold.active && hold.subject_kind == subject_kind && hold.subject_id == subject_id
            });
        if active_hold {
            let response = EvaluateRetentionResponse {
                can_delete: false,
                reason: String::from("active legal hold prevents deletion"),
                matched_policy_id: None,
                required_retain_days: None,
                hard_delete_after_days: None,
            };
            return json_response(StatusCode::OK, &response);
        }

        let residency_tag = request
            .residency_tag
            .as_ref()
            .map(|tag| tag.trim().to_ascii_lowercase());
        let mut policies = self
            .retention_policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|policy| policy.resource_kind == resource_kind)
            .filter(|policy| {
                residency_tag.as_ref().is_none_or(|tag| {
                    policy.residency_tags.is_empty() || policy.residency_tags.contains(tag)
                })
            })
            .collect::<Vec<_>>();
        if policies.is_empty() {
            let response = EvaluateRetentionResponse {
                can_delete: false,
                reason: String::from("no retention policy matched resource/residency"),
                matched_policy_id: None,
                required_retain_days: None,
                hard_delete_after_days: None,
            };
            return json_response(StatusCode::OK, &response);
        }
        policies.sort_by_key(|policy| {
            (
                policy.hard_delete_after_days,
                policy.retain_days,
                policy.id.to_string(),
            )
        });
        let selected = policies
            .into_iter()
            .next_back()
            .ok_or_else(|| PlatformError::unavailable("retention policy selection failed"))?;
        let can_delete = request.age_days >= selected.hard_delete_after_days;
        let response = EvaluateRetentionResponse {
            can_delete,
            reason: if can_delete {
                String::from("age meets hard-delete threshold")
            } else {
                String::from("age is below hard-delete threshold")
            },
            matched_policy_id: Some(selected.id.to_string()),
            required_retain_days: Some(selected.retain_days),
            hard_delete_after_days: Some(selected.hard_delete_after_days),
        };
        json_response(StatusCode::OK, &response)
    }

    async fn verify_audit_integrity(&self) -> Result<Response<ApiBody>> {
        let head_hash = self
            .chain_head
            .get("head")
            .await?
            .map(|record| record.value.current_hash)
            .unwrap_or_else(|| String::from("genesis"));
        let mut checkpoints = self
            .audit_checkpoints
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        checkpoints.sort_by(|left, right| {
            left.recorded_at
                .cmp(&right.recorded_at)
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });
        if checkpoints.is_empty() {
            let report = AuditIntegrityReport {
                valid: head_hash == "genesis",
                checkpoints_checked: 0,
                head_hash: head_hash.clone(),
                expected_head_hash: String::from("genesis"),
                error: (head_hash != "genesis").then_some(String::from(
                    "chain head must be genesis with zero checkpoints",
                )),
            };
            return json_response(StatusCode::OK, &report);
        }
        let mut previous = String::from("genesis");
        for checkpoint in &checkpoints {
            if checkpoint.previous_hash != previous {
                let report = AuditIntegrityReport {
                    valid: false,
                    checkpoints_checked: checkpoints.len(),
                    head_hash,
                    expected_head_hash: checkpoints
                        .last()
                        .map(|item| item.current_hash.clone())
                        .unwrap_or_else(|| String::from("genesis")),
                    error: Some(format!(
                        "checkpoint {} expected previous_hash={} but found {}",
                        checkpoint.id, previous, checkpoint.previous_hash
                    )),
                };
                return json_response(StatusCode::OK, &report);
            }
            previous = checkpoint.current_hash.clone();
        }
        let expected_head_hash = checkpoints
            .last()
            .map(|item| item.current_hash.clone())
            .unwrap_or_else(|| String::from("genesis"));
        let valid = head_hash == expected_head_hash;
        let report = AuditIntegrityReport {
            valid,
            checkpoints_checked: checkpoints.len(),
            head_hash: head_hash.clone(),
            expected_head_hash: expected_head_hash.clone(),
            error: (!valid).then_some(format!(
                "chain head mismatch: expected {expected_head_hash} got {head_hash}"
            )),
        };
        json_response(StatusCode::OK, &report)
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
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("governance"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: context
                        .actor
                        .clone()
                        .unwrap_or_else(|| String::from("system")),
                    actor_type: context
                        .principal
                        .as_ref()
                        .map(|principal| principal.kind.as_str().to_owned())
                        .unwrap_or_else(|| String::from("principal")),
                    source_ip: None,
                    correlation_id: context.correlation_id.clone(),
                },
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
                action: action.to_owned(),
                details,
            }),
        };
        let _audit_chain_guard = self.audit_chain_guard.lock().await;
        self.audit_log.append(&event).await?;

        let event_hash = sha256_hex(
            serde_json::to_vec(&event)
                .map_err(|error| {
                    PlatformError::unavailable("failed to encode event for hash chain")
                        .with_detail(error.to_string())
                })?
                .as_slice(),
        );
        let head = self.chain_head.get("head").await?;
        let previous = head
            .as_ref()
            .map(|record| record.value.current_hash.clone())
            .unwrap_or_else(|| String::from("genesis"));
        let current = sha256_hex(format!("{previous}:{event_hash}").as_bytes());
        let checkpoint = AuditCheckpointRecord {
            id: AuditCheckpointId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate checkpoint id")
                    .with_detail(error.to_string())
            })?,
            previous_hash: previous,
            current_hash: current.clone(),
            summary: format!("{resource_kind}:{action}"),
            recorded_at: OffsetDateTime::now_utc(),
        };
        let checkpoint_key = checkpoint.id.to_string();
        self.audit_checkpoints
            .create(&checkpoint_key, checkpoint)
            .await?;
        self.chain_head
            .upsert(
                "head",
                ChainHeadRecord {
                    current_hash: current,
                },
                head.as_ref().map(|record| record.version),
            )
            .await?;

        let idempotency = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("governance.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }

    async fn governance_summary(&self) -> Result<GovernanceSummary> {
        let change_req_values = self
            .change_requests
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let mut change_totals = ChangeRequestTotals {
            total: 0,
            pending: 0,
            approved: 0,
            rejected: 0,
            applied: 0,
        };
        for change in &change_req_values {
            change_totals.total += 1;
            match change.state {
                ChangeRequestState::Pending => change_totals.pending += 1,
                ChangeRequestState::Approved => change_totals.approved += 1,
                ChangeRequestState::Rejected => change_totals.rejected += 1,
                ChangeRequestState::Applied => change_totals.applied += 1,
            }
        }

        let approval_total = self
            .change_approvals
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .count() as u64;

        let legal_hold_values = self
            .legal_holds
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let legal_totals = LegalHoldTotals {
            total: legal_hold_values.len() as u64,
            active: legal_hold_values.iter().filter(|hold| hold.active).count() as u64,
        };

        let mut override_totals = ExposureOverrideTotals {
            total: 0,
            pending: 0,
            active: 0,
            reverted: 0,
        };
        for record in self
            .exposure_overrides
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
        {
            override_totals.total += 1;
            match record.state {
                ExposureOverrideState::Pending => override_totals.pending += 1,
                ExposureOverrideState::Active => override_totals.active += 1,
                ExposureOverrideState::Reverted => override_totals.reverted += 1,
            }
        }

        let mut checkpoints = self
            .audit_checkpoints
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        checkpoints.sort_by(|left, right| {
            right
                .recorded_at
                .cmp(&left.recorded_at)
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });
        let latest_checkpoint_at = checkpoints.first().map(|checkpoint| checkpoint.recorded_at);
        let recent = checkpoints
            .iter()
            .take(5)
            .map(|checkpoint| AuditCheckpointSummary {
                id: checkpoint.id.clone(),
                summary: checkpoint.summary.clone(),
                recorded_at: checkpoint.recorded_at,
            })
            .collect::<Vec<_>>();
        let audit_totals = AuditTotals {
            total_checkpoints: checkpoints.len() as u64,
            latest_checkpoint_at,
            recent,
        };

        let chain_head = self
            .chain_head
            .get("head")
            .await?
            .map(|record| record.value.current_hash)
            .unwrap_or_else(|| String::from("genesis"));

        Ok(GovernanceSummary {
            state_root: self.state_root.display().to_string(),
            audit_chain_head: chain_head,
            change_requests: change_totals,
            approvals: ApprovalTotals {
                total: approval_total,
            },
            legal_holds: legal_totals,
            overrides: override_totals,
            audit: audit_totals,
        })
    }

    async fn exposure_readiness_report(&self) -> Result<Response<ApiBody>> {
        let platform_state_root = self.state_root.parent().ok_or_else(|| {
            PlatformError::unavailable("governance state root is missing platform parent")
        })?;
        let now = OffsetDateTime::now_utc();

        let ingress_routes = load_active_values_from_path::<ExposureIngressRouteHook>(
            &platform_state_root.join("ingress").join("routes.json"),
        )
        .await?;
        let dns_zones = load_active_values_from_path::<ExposureZoneHook>(
            &platform_state_root.join("dns").join("zones.json"),
        )
        .await?;
        let dns_provider_tasks = load_active_values_from_path::<ExposureProviderTaskHook>(
            &platform_state_root.join("dns").join("provider_tasks.json"),
        )
        .await?;
        let mail_domains = load_active_values_from_path::<ExposureMailDomainHook>(
            &platform_state_root.join("mail").join("domains.json"),
        )
        .await?;
        let mail_reputation = load_active_values_from_path::<ExposureMailReputationHook>(
            &platform_state_root.join("mail").join("reputation.json"),
        )
        .await?;
        let mail_provider_tasks = load_active_values_from_path::<ExposureProviderTaskHook>(
            &platform_state_root
                .join("mail")
                .join("dns_provider_tasks.json"),
        )
        .await?;
        let mail_quarantines = load_active_values_from_path::<ExposureMailQuarantineHook>(
            &platform_state_root
                .join("mail")
                .join("abuse_quarantines.json"),
        )
        .await?;
        let netsec_policies = load_active_values_from_path::<ExposureNetsecPolicyHook>(
            &platform_state_root.join("netsec").join("policies.json"),
        )
        .await?;
        let netsec_private_networks = load_active_values_from_path::<ExposurePrivateNetworkHook>(
            &platform_state_root
                .join("netsec")
                .join("private_networks.json"),
        )
        .await?;
        let netsec_flow_audit = load_active_values_from_path::<ExposureNetsecFlowAuditHook>(
            &platform_state_root.join("netsec").join("flow_audit.json"),
        )
        .await?;
        let netsec_quarantines = load_active_values_from_path::<ExposureNetsecQuarantineHook>(
            &platform_state_root.join("abuse").join("quarantines.json"),
        )
        .await?;
        let policy_records = load_active_values_from_path::<ExposurePolicyRecordHook>(
            &platform_state_root.join("policy").join("policies.json"),
        )
        .await?;
        let policy_approvals = load_active_values_from_path::<ExposurePolicyApprovalHook>(
            &platform_state_root.join("policy").join("approvals.json"),
        )
        .await?;

        let change_requests = self
            .change_requests
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let overrides = self
            .exposure_overrides
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();

        let pending_override_count = overrides
            .iter()
            .filter(|record| record.state == ExposureOverrideState::Pending)
            .count();
        let active_override_count = overrides
            .iter()
            .filter(|record| record.state == ExposureOverrideState::Active)
            .count();
        let reverted_override_count = overrides
            .iter()
            .filter(|record| record.state == ExposureOverrideState::Reverted)
            .count();
        let mut effective_active_overrides = overrides
            .iter()
            .filter(|record| exposure_override_is_effective(record, now))
            .cloned()
            .collect::<Vec<_>>();
        effective_active_overrides.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });
        let mut active_by_surface = BTreeMap::<String, usize>::new();
        for record in &effective_active_overrides {
            let entry = active_by_surface.entry(record.surface.clone()).or_insert(0);
            *entry += 1;
        }
        let overrides_report = ExposureOverrideReport {
            total: overrides.len(),
            pending: pending_override_count,
            active: active_override_count,
            effective_active: effective_active_overrides.len(),
            reverted: reverted_override_count,
            active_publishability: effective_active_overrides
                .iter()
                .filter(|record| record.override_kind == "publishability")
                .count(),
            active_readiness: effective_active_overrides
                .iter()
                .filter(|record| record.override_kind == "readiness")
                .count(),
            active_by_surface: map_report_counters(active_by_surface),
            active_entries: effective_active_overrides.clone(),
        };

        let public_routes = ingress_routes
            .iter()
            .filter(|record| record.publication.exposure == EdgeExposureIntent::Public)
            .count();
        let private_routes = ingress_routes
            .iter()
            .filter(|record| record.publication.exposure == EdgeExposureIntent::Private)
            .count();
        let routes_with_dns_binding = ingress_routes
            .iter()
            .filter(|record| record.publication.dns_binding.is_some())
            .count();
        let routes_with_security_policy = ingress_routes
            .iter()
            .filter(|record| record.publication.security_policy.is_some())
            .count();
        let routes_without_active_publication_targets = ingress_routes
            .iter()
            .filter(|record| {
                !record.publication.targets.is_empty()
                    && record.publication.targets.iter().all(|target| target.drain)
            })
            .count();
        let ingress_publishability_overrides =
            effective_override_count(&effective_active_overrides, "ingress", "publishability");
        let mut ingress_blockers = Vec::new();
        if routes_without_active_publication_targets > 0 {
            ingress_blockers.push(format!(
                "{routes_without_active_publication_targets} routes have only draining publication targets"
            ));
        }
        let ingress = IngressExposureReadiness {
            total_routes: ingress_routes.len(),
            public_routes,
            private_routes,
            routes_with_dns_binding,
            routes_with_security_policy,
            routes_without_active_publication_targets,
            publishable: ingress_blockers.is_empty(),
            effective_publishable: ingress_blockers.is_empty()
                || ingress_publishability_overrides > 0,
            active_publishability_overrides: ingress_publishability_overrides,
            blockers: ingress_blockers,
        };

        let verified_zones = dns_zones.iter().filter(|zone| zone.verified).count();
        let pending_dns_provider_tasks = dns_provider_tasks
            .iter()
            .filter(|task| provider_task_is_pending(&task.status))
            .count();
        let failed_dns_provider_tasks = dns_provider_tasks
            .iter()
            .filter(|task| provider_task_is_failed(&task.status))
            .count();
        let dns_publishability_overrides =
            effective_override_count(&effective_active_overrides, "dns", "publishability");
        let mut dns_blockers = Vec::new();
        let unverified_zones = dns_zones.len().saturating_sub(verified_zones);
        if unverified_zones > 0 {
            dns_blockers.push(format!("{unverified_zones} zones are not verified"));
        }
        if pending_dns_provider_tasks > 0 {
            dns_blockers.push(format!(
                "{pending_dns_provider_tasks} provider sync tasks are still pending"
            ));
        }
        if failed_dns_provider_tasks > 0 {
            dns_blockers.push(format!(
                "{failed_dns_provider_tasks} provider sync tasks are failed"
            ));
        }
        let dns = DnsExposureReadiness {
            total_zones: dns_zones.len(),
            verified_zones,
            unverified_zones,
            total_provider_tasks: dns_provider_tasks.len(),
            pending_provider_tasks: pending_dns_provider_tasks,
            failed_provider_tasks: failed_dns_provider_tasks,
            publishable: dns_blockers.is_empty(),
            effective_publishable: dns_blockers.is_empty() || dns_publishability_overrides > 0,
            active_publishability_overrides: dns_publishability_overrides,
            blockers: dns_blockers,
        };

        let verified_domains = mail_domains.iter().filter(|domain| domain.verified).count();
        let suspended_relay_domains = mail_reputation
            .iter()
            .filter(|record| record.suspended)
            .count();
        let active_delivery_quarantines = mail_quarantines
            .iter()
            .filter(|record| mail_quarantine_is_active(record, now))
            .count();
        let pending_mail_provider_tasks = mail_provider_tasks
            .iter()
            .filter(|task| provider_task_is_pending(&task.status))
            .count();
        let failed_mail_provider_tasks = mail_provider_tasks
            .iter()
            .filter(|task| provider_task_is_failed(&task.status))
            .count();
        let mail_publishability_overrides =
            effective_override_count(&effective_active_overrides, "mail", "publishability");
        let unverified_domains = mail_domains.len().saturating_sub(verified_domains);
        let mut mail_blockers = Vec::new();
        if unverified_domains > 0 {
            mail_blockers.push(format!(
                "{unverified_domains} mail domains are not verified"
            ));
        }
        if suspended_relay_domains > 0 {
            mail_blockers.push(format!(
                "{suspended_relay_domains} mail domains have relay suspension"
            ));
        }
        if active_delivery_quarantines > 0 {
            mail_blockers.push(format!(
                "{active_delivery_quarantines} abuse quarantines still deny mail relay"
            ));
        }
        if pending_mail_provider_tasks > 0 {
            mail_blockers.push(format!(
                "{pending_mail_provider_tasks} mail DNS provider tasks are still pending"
            ));
        }
        if failed_mail_provider_tasks > 0 {
            mail_blockers.push(format!(
                "{failed_mail_provider_tasks} mail DNS provider tasks are failed"
            ));
        }
        let mail = MailExposureReadiness {
            total_domains: mail_domains.len(),
            verified_domains,
            unverified_domains,
            suspended_relay_domains,
            active_delivery_quarantines,
            total_provider_tasks: mail_provider_tasks.len(),
            pending_provider_tasks: pending_mail_provider_tasks,
            failed_provider_tasks: failed_mail_provider_tasks,
            publishable: mail_blockers.is_empty(),
            effective_publishable: mail_blockers.is_empty() || mail_publishability_overrides > 0,
            active_publishability_overrides: mail_publishability_overrides,
            blockers: mail_blockers,
        };

        let deny_flow_audits = netsec_flow_audit
            .iter()
            .filter(|record| record.verdict.eq_ignore_ascii_case("deny"))
            .count();
        let active_network_quarantines = netsec_quarantines
            .iter()
            .filter(|record| netsec_quarantine_is_active(record, now))
            .count();
        let netsec_readiness_overrides =
            effective_override_count(&effective_active_overrides, "netsec", "readiness");
        let mut netsec_blockers = Vec::new();
        if active_network_quarantines > 0 {
            netsec_blockers.push(format!(
                "{active_network_quarantines} quarantines still deny network activity"
            ));
        }
        let netsec = NetsecExposureReadiness {
            total_policies: netsec_policies.len(),
            total_private_networks: netsec_private_networks.len(),
            deny_flow_audits,
            active_network_quarantines,
            ready: netsec_blockers.is_empty(),
            effective_ready: netsec_blockers.is_empty() || netsec_readiness_overrides > 0,
            active_readiness_overrides: netsec_readiness_overrides,
            blockers: netsec_blockers,
        };

        let pending_policy_approvals = policy_approvals
            .iter()
            .filter(|record| !record.approved)
            .count();
        let policy_readiness_overrides =
            effective_override_count(&effective_active_overrides, "policy", "readiness");
        let mut policy_blockers = Vec::new();
        if pending_policy_approvals > 0 {
            policy_blockers.push(format!(
                "{pending_policy_approvals} policy approvals are still pending"
            ));
        }
        let policy = PolicyExposureReadiness {
            total_policies: policy_records.len(),
            total_approvals: policy_approvals.len(),
            pending_approvals: pending_policy_approvals,
            ready: policy_blockers.is_empty(),
            effective_ready: policy_blockers.is_empty() || policy_readiness_overrides > 0,
            active_readiness_overrides: policy_readiness_overrides,
            blockers: policy_blockers,
        };

        let pending_change_requests = change_requests
            .iter()
            .filter(|record| record.state == ChangeRequestState::Pending)
            .count();
        let approved_change_requests = change_requests
            .iter()
            .filter(|record| record.state == ChangeRequestState::Approved)
            .count();
        let governance_readiness_overrides =
            effective_override_count(&effective_active_overrides, "governance", "readiness");
        let mut governance_blockers = Vec::new();
        if pending_change_requests > 0 {
            governance_blockers.push(format!(
                "{pending_change_requests} change requests are still pending review"
            ));
        }
        if approved_change_requests > 0 {
            governance_blockers.push(format!(
                "{approved_change_requests} approved change requests still await execution"
            ));
        }
        let governance = GovernanceExposureReadiness {
            total_change_requests: change_requests.len(),
            pending_change_requests,
            approved_change_requests,
            ready: governance_blockers.is_empty(),
            effective_ready: governance_blockers.is_empty() || governance_readiness_overrides > 0,
            active_readiness_overrides: governance_readiness_overrides,
            blockers: governance_blockers,
        };

        let mut blockers = Vec::new();
        append_surface_blockers(&mut blockers, "ingress", &ingress.blockers);
        append_surface_blockers(&mut blockers, "dns", &dns.blockers);
        append_surface_blockers(&mut blockers, "mail", &mail.blockers);
        append_surface_blockers(&mut blockers, "netsec", &netsec.blockers);
        append_surface_blockers(&mut blockers, "policy", &policy.blockers);
        append_surface_blockers(&mut blockers, "governance", &governance.blockers);

        let report = ExposureReadinessReport {
            generated_at: now,
            raw_publishable: ingress.publishable && dns.publishable && mail.publishable,
            effective_publishable: ingress.effective_publishable
                && dns.effective_publishable
                && mail.effective_publishable,
            raw_ready: ingress.publishable
                && dns.publishable
                && mail.publishable
                && netsec.ready
                && policy.ready
                && governance.ready,
            effective_ready: ingress.effective_publishable
                && dns.effective_publishable
                && mail.effective_publishable
                && netsec.effective_ready
                && policy.effective_ready
                && governance.effective_ready,
            blockers,
            overrides: overrides_report,
            ingress,
            dns,
            mail,
            netsec,
            policy,
            governance,
        };
        json_response(StatusCode::OK, &report)
    }
}

impl HttpService for GovernanceService {
    fn name(&self) -> &'static str {
        "governance"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/governance")];
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
            let segments = path_segments(&path);

            if !governance_endpoint_allows_non_operator_principal(&method, segments.as_slice()) {
                require_non_workload_principal_or_local_dev(&context, "governance control plane")?;
            }

            match (method, segments.as_slice()) {
                (Method::GET, ["governance"]) => {
                    let chain_head = self
                        .chain_head
                        .get("head")
                        .await?
                        .map(|record| record.value.current_hash)
                        .unwrap_or_else(|| String::from("genesis"));
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "service": self.name(),
                            "state_root": self.state_root,
                            "audit_chain_head": chain_head,
                        }),
                    )
                    .map(Some)
                }
                (Method::GET, ["governance", "summary"]) => {
                    let summary = self.governance_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["governance", "legal-holds"]) => {
                    let values = self
                        .legal_holds
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["governance", "legal-holds"]) => {
                    let body: CreateLegalHoldRequest = parse_json(request).await?;
                    self.create_legal_hold(body, &context).await.map(Some)
                }
                (Method::POST, ["governance", "legal-holds", hold_id, "release"]) => {
                    self.release_legal_hold(hold_id, &context).await.map(Some)
                }
                (Method::GET, ["governance", "retention-policies"]) => {
                    let values = self
                        .retention_policies
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["governance", "retention-policies"]) => {
                    let body: CreateRetentionPolicyRequest = parse_json(request).await?;
                    self.create_retention_policy(body, &context).await.map(Some)
                }
                (Method::GET, ["governance", "change-requests"]) => {
                    let values = self
                        .change_requests
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["governance", "change-requests"]) => {
                    let body: CreateChangeRequestRequest = parse_json(request).await?;
                    self.create_change_request(body, &context).await.map(Some)
                }
                (Method::POST, ["governance", "change-requests", change_id, "approve"]) => {
                    let body: ReviewChangeRequest = parse_json(request).await?;
                    self.approve_change_request(change_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["governance", "change-requests", change_id, "reject"]) => {
                    let body: ReviewChangeRequest = parse_json(request).await?;
                    self.reject_change_request(change_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["governance", "change-requests", change_id, "approvals"]) => {
                    let change_id =
                        ChangeRequestId::parse(change_id.to_owned()).map_err(|error| {
                            PlatformError::invalid("invalid change request id")
                                .with_detail(error.to_string())
                        })?;
                    let mut values = self
                        .change_approvals
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .filter(|approval| approval.change_request_id == change_id)
                        .collect::<Vec<_>>();
                    values.sort_by(|left, right| {
                        left.approved_at
                            .cmp(&right.approved_at)
                            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
                    });
                    let values = values
                        .into_iter()
                        .map(ChangeApprovalView::from)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["governance", "change-requests", change_id, "apply"]) => {
                    let body: ApplyChangeRequest = parse_json(request).await?;
                    self.apply_change_request(change_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["governance", "exposure-overrides"]) => {
                    self.list_exposure_overrides().await.map(Some)
                }
                (Method::POST, ["governance", "exposure-overrides"]) => {
                    let body: CreateExposureOverrideRequest = parse_json(request).await?;
                    self.create_exposure_override(body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["governance", "exposure-overrides", override_id, "activate"]) => {
                    let body: ActivateExposureOverrideRequest = parse_json(request).await?;
                    self.activate_exposure_override(override_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["governance", "exposure-overrides", override_id, "revert"]) => {
                    let body: RevertExposureOverrideRequest = parse_json(request).await?;
                    self.revert_exposure_override(override_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["governance", "exposure-readiness"]) => {
                    self.exposure_readiness_report().await.map(Some)
                }
                (Method::GET, ["governance", "audit-checkpoints"]) => {
                    let mut values = self
                        .audit_checkpoints
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    values.sort_by(|left, right| {
                        left.recorded_at
                            .cmp(&right.recorded_at)
                            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
                    });
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["governance", "audit-checkpoints"]) => {
                    let body: ManualCheckpointRequest = parse_json(request).await?;
                    self.create_manual_checkpoint(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["governance", "audit-integrity"]) => {
                    self.verify_audit_integrity().await.map(Some)
                }
                (Method::POST, ["governance", "retention-evaluate"]) => {
                    let body: EvaluateRetentionRequest = parse_json(request).await?;
                    self.evaluate_retention(body).await.map(Some)
                }
                (Method::GET, ["governance", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn governance_endpoint_allows_non_operator_principal(method: &Method, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        (&Method::POST, ["governance", "retention-evaluate"])
    )
}

fn require_non_workload_principal_or_local_dev(
    context: &RequestContext,
    capability: &str,
) -> Result<()> {
    if let Some(principal) = context.principal.as_ref()
        && principal.kind == PrincipalKind::Workload
    {
        return Err(PlatformError::forbidden(format!(
            "{capability} requires an authenticated non-workload principal"
        ))
        .with_correlation_id(context.correlation_id.clone()));
    }
    Ok(())
}

fn enforce_reviewer_separation(record: &ChangeRequestRecord, approver: &str) -> Result<()> {
    if approver.trim().is_empty() {
        return Err(PlatformError::invalid("approver may not be empty"));
    }
    if approver == record.requested_by {
        return Err(PlatformError::forbidden(
            "approver must be different from requester",
        ));
    }
    Ok(())
}

fn bind_authenticated_change_actor(
    context: &RequestContext,
    claimed: &str,
    field: &'static str,
) -> Result<String> {
    let claimed = claimed.trim();
    if claimed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty"))
            .with_correlation_id(context.correlation_id.clone()));
    }

    let authenticated = authenticated_change_actor(context)?;

    if authenticated != claimed {
        return Err(
            PlatformError::forbidden(format!("{field} must match authenticated actor"))
                .with_correlation_id(context.correlation_id.clone()),
        );
    }

    Ok(authenticated.to_owned())
}

fn authenticated_change_actor(context: &RequestContext) -> Result<&str> {
    context.actor.as_deref().ok_or_else(|| {
        PlatformError::new(
            ErrorCode::Unauthorized,
            "governance change workflow requires an authenticated actor",
        )
        .with_correlation_id(context.correlation_id.clone())
    })
}

fn change_approval_provenance(context: &RequestContext) -> Result<GovernanceRequestProvenance> {
    Ok(GovernanceRequestProvenance {
        authenticated_actor: authenticated_change_actor(context)?.to_owned(),
        principal: context.principal.clone(),
        correlation_id: context.correlation_id.clone(),
        request_id: context.request_id.clone(),
    })
}

fn shared_audit_chain_guard(path: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn default_required_approvals() -> u8 {
    1
}

fn required_approvals_for_change_type(change_type: &str) -> u8 {
    match change_type.trim().to_ascii_lowercase().as_str() {
        "security_change" | "access_change" | "policy_change" => 2,
        _ => 1,
    }
}

fn normalize_residency_tags(tags: Vec<String>) -> Vec<String> {
    let mut normalized = BTreeSet::new();
    for tag in tags {
        let tag = tag.trim().to_ascii_lowercase();
        if !tag.is_empty() {
            normalized.insert(tag);
        }
    }
    normalized.into_iter().collect()
}

fn normalize_optional_comment(comment: Option<String>) -> Option<String> {
    comment.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn normalize_required_text(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    Ok(value.to_owned())
}

fn normalize_exposure_surface(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "ingress" | "dns" | "mail" | "netsec" | "policy" | "governance" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "surface must be one of ingress, dns, mail, netsec, policy, or governance",
        )),
    }
}

fn normalize_exposure_override_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "publishability" | "readiness" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "override_kind must be one of publishability or readiness",
        )),
    }
}

fn exposure_override_is_effective(record: &ExposureOverrideRecord, now: OffsetDateTime) -> bool {
    record.state == ExposureOverrideState::Active
        && record.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn effective_override_count(
    overrides: &[ExposureOverrideRecord],
    surface: &str,
    override_kind: &str,
) -> usize {
    overrides
        .iter()
        .filter(|record| record.surface == surface && record.override_kind == override_kind)
        .count()
}

fn map_report_counters(counters: BTreeMap<String, usize>) -> Vec<ReportCounter> {
    counters
        .into_iter()
        .map(|(key, count)| ReportCounter { key, count })
        .collect()
}

fn append_surface_blockers(aggregate: &mut Vec<String>, surface: &str, blockers: &[String]) {
    aggregate.extend(
        blockers
            .iter()
            .map(|blocker| format!("{surface}: {blocker}")),
    );
}

fn provider_task_is_pending(status: &str) -> bool {
    status.trim().eq_ignore_ascii_case("pending")
}

fn provider_task_is_failed(status: &str) -> bool {
    status.trim().eq_ignore_ascii_case("failed")
}

fn mail_quarantine_is_active(record: &ExposureMailQuarantineHook, now: OffsetDateTime) -> bool {
    record.deny_mail_relay
        && !record.state.eq_ignore_ascii_case("released")
        && record.released_at.is_none()
        && record.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn netsec_quarantine_is_active(record: &ExposureNetsecQuarantineHook, now: OffsetDateTime) -> bool {
    record.deny_network
        && !record.state.eq_ignore_ascii_case("released")
        && record.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn change_approval_key(change_request_id: &ChangeRequestId, approver: &str) -> String {
    format!("{}:{approver}", change_request_id.as_str())
}

async fn load_active_values_from_path<T>(path: &Path) -> Result<Vec<T>>
where
    T: Clone + DeserializeOwned,
{
    if fs::metadata(path).await.is_err() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).await.map_err(|error| {
        PlatformError::unavailable("failed to read document collection")
            .with_detail(error.to_string())
    })?;
    let collection = serde_json::from_slice::<DocumentCollection<T>>(&bytes).map_err(|error| {
        PlatformError::unavailable("failed to decode document collection")
            .with_detail(error.to_string())
    })?;
    Ok(collection
        .records
        .into_values()
        .filter(|record| !record.deleted)
        .map(|record| record.value)
        .collect())
}

async fn latest_checkpoint(
    checkpoints: &DocumentStore<AuditCheckpointRecord>,
) -> Result<AuditCheckpointRecord> {
    let mut values = checkpoints
        .list()
        .await?
        .into_iter()
        .filter(|(_, stored)| !stored.deleted)
        .map(|(_, record)| record.value)
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
    });
    values
        .into_iter()
        .next_back()
        .ok_or_else(|| PlatformError::not_found("no audit checkpoint exists"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use http_body_util::BodyExt;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::Value;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    use super::{
        ActivateExposureOverrideRequest, ApplyChangeRequest, AuditCheckpointId,
        AuditCheckpointRecord, ChainHeadRecord, ChangeRequestState, CreateChangeRequestRequest,
        CreateExposureOverrideRequest, CreateLegalHoldRequest, CreateRetentionPolicyRequest,
        EvaluateRetentionRequest, ExposureIngressRouteHook, ExposureMailDomainHook,
        ExposureMailQuarantineHook, ExposureMailReputationHook, ExposureNetsecFlowAuditHook,
        ExposureNetsecPolicyHook, ExposureNetsecQuarantineHook, ExposurePolicyApprovalHook,
        ExposurePolicyRecordHook, ExposurePrivateNetworkHook, ExposureProviderTaskHook,
        ExposureZoneHook, GovernanceService, RevertExposureOverrideRequest, ReviewChangeRequest,
        latest_checkpoint,
    };
    use uhost_core::{ErrorCode, PrincipalIdentity, PrincipalKind, RequestContext};
    use uhost_store::DocumentStore;
    use uhost_types::{
        EdgeExposureIntent, EdgePublication, EdgePublicationTarget, EdgePublicationTargetId,
    };

    fn actor_context(actor: &str) -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor(actor)
    }

    fn actor_context_with_principal(
        actor: &str,
        principal_subject: &str,
        credential_id: &str,
    ) -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor(actor)
            .with_principal(
                PrincipalIdentity::new(PrincipalKind::Operator, principal_subject)
                    .with_credential_id(credential_id),
            )
    }

    async fn response_json(response: http::Response<uhost_api::ApiBody>) -> Value {
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        serde_json::from_slice(&body.to_bytes()).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn seed_document<T>(root: &Path, relative_path: &str, key: &str, value: T)
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let store = DocumentStore::open(root.join(relative_path))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .create(key, value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn change_approval_enforces_separation_of_duties_and_multi_approver_threshold() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let requester_context = actor_context("alice");
        let bob_context = actor_context("bob");
        let carol_context = actor_context("carol");
        let dave_context = actor_context("dave");
        let erin_context = actor_context("erin");

        let created = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Rotate signing key"),
                    change_type: String::from("security_change"),
                    requested_by: String::from("alice"),
                },
                &requester_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);

        let records = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let id = records[0].1.value.id.to_string();

        let forbidden = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("alice"),
                    comment: None,
                },
                &requester_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected separation-of-duties rejection"));
        assert_eq!(forbidden.code, ErrorCode::Forbidden);

        let spoofed = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("mallory"),
                    comment: Some(String::from("spoofed")),
                },
                &bob_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected actor-binding rejection"));
        assert_eq!(spoofed.code, ErrorCode::Forbidden);

        let accepted = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("approved")),
                },
                &bob_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(accepted.status(), http::StatusCode::OK);
        let first_update = service
            .change_requests
            .get(&id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing change request"));
        assert_eq!(first_update.value.state, ChangeRequestState::Pending);

        let duplicate = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("duplicate")),
                },
                &bob_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate-approval rejection"));
        assert_eq!(duplicate.code, ErrorCode::Conflict);

        let _ = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("carol"),
                    comment: Some(String::from("approved")),
                },
                &carol_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let updated = service
            .change_requests
            .get(&id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing change request"));
        assert_eq!(updated.value.state, ChangeRequestState::Approved);

        let late_approval = service
            .approve_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("dave"),
                    comment: Some(String::from("too late")),
                },
                &dave_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected finalized approval rejection"));
        assert_eq!(late_approval.code, ErrorCode::Conflict);

        let late_rejection = service
            .reject_change_request(
                &id,
                ReviewChangeRequest {
                    approver: String::from("erin"),
                    comment: Some(String::from("too late")),
                },
                &erin_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected finalized rejection rejection"));
        assert_eq!(late_rejection.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn change_request_identity_claims_require_authenticated_matching_actor() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let unauthenticated = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let unauthenticated_error = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Deploy API"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &unauthenticated,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected authenticated actor requirement"));
        assert_eq!(unauthenticated_error.code, ErrorCode::Unauthorized);

        let spoofed_context = actor_context("bob");
        let spoofed_error = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Deploy API"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &spoofed_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected requester spoof rejection"));
        assert_eq!(spoofed_error.code, ErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn approved_change_can_be_applied_by_different_executor() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let requester_context = actor_context("alice");
        let approver_context = actor_context("bob");
        let executor_context = actor_context("carol");

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Deploy API"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &requester_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let change_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();
        let _ = service
            .approve_change_request(
                &change_id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("approved")),
                },
                &approver_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let forbidden = service
            .apply_change_request(
                &change_id,
                ApplyChangeRequest {
                    executor: String::from("alice"),
                    note: None,
                },
                &requester_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected apply separation-of-duties rejection"));
        assert_eq!(forbidden.code, ErrorCode::Forbidden);

        let applied = service
            .apply_change_request(
                &change_id,
                ApplyChangeRequest {
                    executor: String::from("carol"),
                    note: Some(String::from("maintenance window")),
                },
                &executor_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(applied.status(), http::StatusCode::OK);
        let updated = service
            .change_requests
            .get(&change_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing change request"));
        assert_eq!(updated.value.state, ChangeRequestState::Applied);
    }

    #[tokio::test]
    async fn change_approval_persists_authenticated_request_provenance() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let requester_context = actor_context("alice");
        let approver_context =
            actor_context_with_principal("bob", "operator:bob", "cred_operator_bob");

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Deploy API"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &requester_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let change_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .approve_change_request(
                &change_id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("approved")),
                },
                &approver_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let approvals = service
            .change_approvals
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(approvals.len(), 1);
        let approval = &approvals[0].1.value;
        let provenance = approval
            .provenance
            .as_ref()
            .unwrap_or_else(|| panic!("missing approval provenance"));
        assert_eq!(approval.approver, "bob");
        assert_eq!(provenance.authenticated_actor, "bob");
        assert_eq!(provenance.correlation_id, approver_context.correlation_id);
        assert_eq!(provenance.request_id, approver_context.request_id);
        let principal = provenance
            .principal
            .as_ref()
            .unwrap_or_else(|| panic!("missing principal provenance"));
        assert_eq!(principal.kind, PrincipalKind::Operator);
        assert_eq!(principal.subject, "operator:bob");
        assert_eq!(
            principal.credential_id.as_deref(),
            Some("cred_operator_bob")
        );
    }

    #[tokio::test]
    async fn exposure_override_workflow_requires_approved_change_and_supports_revert() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let requester_context = actor_context("alice");
        let approver_context = actor_context("bob");
        let activator_context = actor_context("carol");
        let reverter_context = actor_context("dave");

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Temporary DNS publish override"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &requester_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let change_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let created = service
            .create_exposure_override(
                CreateExposureOverrideRequest {
                    surface: String::from("dns"),
                    target_kind: String::from("zone"),
                    target_id: String::from("zone-public-a"),
                    override_kind: String::from("publishability"),
                    reason: String::from("maintenance window"),
                    change_request_id: change_id.clone(),
                    requested_by: String::from("alice"),
                    expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
                },
                &requester_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);
        let override_id = service
            .exposure_overrides
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let approval_gate = service
            .activate_exposure_override(
                &override_id,
                ActivateExposureOverrideRequest {
                    activated_by: String::from("carol"),
                },
                &activator_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected approval gate before activation"));
        assert_eq!(approval_gate.code, ErrorCode::Conflict);

        let _ = service
            .approve_change_request(
                &change_id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("approved")),
                },
                &approver_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let same_actor = service
            .activate_exposure_override(
                &override_id,
                ActivateExposureOverrideRequest {
                    activated_by: String::from("alice"),
                },
                &requester_context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected activator separation-of-duties rejection"));
        assert_eq!(same_actor.code, ErrorCode::Forbidden);

        let activated = service
            .activate_exposure_override(
                &override_id,
                ActivateExposureOverrideRequest {
                    activated_by: String::from("carol"),
                },
                &activator_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(activated.status(), http::StatusCode::OK);

        let reverted = service
            .revert_exposure_override(
                &override_id,
                RevertExposureOverrideRequest {
                    reverted_by: String::from("dave"),
                    reason: Some(String::from("incident closed")),
                },
                &reverter_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reverted.status(), http::StatusCode::OK);

        let stored = service
            .exposure_overrides
            .get(&override_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing exposure override"));
        assert_eq!(stored.value.state, super::ExposureOverrideState::Reverted);
        assert_eq!(stored.value.reverted_by.as_deref(), Some("dave"));
        assert_eq!(
            stored.value.revert_reason.as_deref(),
            Some("incident closed")
        );
    }

    #[tokio::test]
    async fn exposure_readiness_report_spans_surfaces_and_accounts_for_overrides() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let alice_context = actor_context("alice");
        let bob_context = actor_context("bob");
        let carol_context = actor_context("carol");
        let dave_context = actor_context("dave");
        let erin_context = actor_context("erin");
        let frank_context = actor_context("frank");

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("DNS override"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dns_change_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();
        let _ = service
            .approve_change_request(
                &dns_change_id,
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: Some(String::from("approved")),
                },
                &bob_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_exposure_override(
                CreateExposureOverrideRequest {
                    surface: String::from("dns"),
                    target_kind: String::from("zone"),
                    target_id: String::from("zone-pending"),
                    override_kind: String::from("publishability"),
                    reason: String::from("provider outage"),
                    change_request_id: dns_change_id,
                    requested_by: String::from("alice"),
                    expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dns_override_id = service
            .exposure_overrides
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| stored.value.surface == "dns")
            .unwrap_or_else(|| panic!("missing dns override"))
            .1
            .value
            .id
            .to_string();
        let _ = service
            .activate_exposure_override(
                &dns_override_id,
                ActivateExposureOverrideRequest {
                    activated_by: String::from("carol"),
                },
                &carol_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Netsec override"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("dave"),
                },
                &dave_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let netsec_change_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| stored.value.requested_by == "dave")
            .unwrap_or_else(|| panic!("missing netsec change request"))
            .1
            .value
            .id
            .to_string();
        let _ = service
            .approve_change_request(
                &netsec_change_id,
                ReviewChangeRequest {
                    approver: String::from("erin"),
                    comment: Some(String::from("approved")),
                },
                &erin_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_exposure_override(
                CreateExposureOverrideRequest {
                    surface: String::from("netsec"),
                    target_kind: String::from("quarantine"),
                    target_id: String::from("tenant-1"),
                    override_kind: String::from("readiness"),
                    reason: String::from("emergency containment exception"),
                    change_request_id: netsec_change_id,
                    requested_by: String::from("dave"),
                    expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
                },
                &dave_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let netsec_override_id = service
            .exposure_overrides
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| stored.value.surface == "netsec")
            .unwrap_or_else(|| panic!("missing netsec override"))
            .1
            .value
            .id
            .to_string();
        let _ = service
            .activate_exposure_override(
                &netsec_override_id,
                ActivateExposureOverrideRequest {
                    activated_by: String::from("frank"),
                },
                &frank_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("Pending governance review"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let draining_target_id =
            EdgePublicationTargetId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_document(
            temp.path(),
            "ingress/routes.json",
            "route-public-a",
            ExposureIngressRouteHook {
                publication: EdgePublication {
                    exposure: EdgeExposureIntent::Public,
                    dns_binding: None,
                    security_policy: None,
                    private_network: None,
                    targets: vec![EdgePublicationTarget {
                        id: draining_target_id,
                        cell: String::from("use1-edge-a"),
                        region: String::from("us-east-1"),
                        failover_group: None,
                        drain: true,
                        tls_owner: String::from("platform-edge"),
                    }],
                },
            },
        )
        .await;
        seed_document(
            temp.path(),
            "dns/zones.json",
            "zone-pending",
            ExposureZoneHook { verified: false },
        )
        .await;
        seed_document(
            temp.path(),
            "dns/provider_tasks.json",
            "dns-task-pending",
            ExposureProviderTaskHook {
                status: String::from("pending"),
            },
        )
        .await;
        seed_document(
            temp.path(),
            "mail/domains.json",
            "mail-domain-1",
            ExposureMailDomainHook { verified: false },
        )
        .await;
        seed_document(
            temp.path(),
            "mail/reputation.json",
            "mail-domain-1",
            ExposureMailReputationHook { suspended: true },
        )
        .await;
        seed_document(
            temp.path(),
            "mail/dns_provider_tasks.json",
            "mail-task-pending",
            ExposureProviderTaskHook {
                status: String::from("pending"),
            },
        )
        .await;
        seed_document(
            temp.path(),
            "mail/abuse_quarantines.json",
            "mail-quarantine-1",
            ExposureMailQuarantineHook {
                state: String::from("active"),
                deny_mail_relay: true,
                expires_at: None,
                released_at: None,
            },
        )
        .await;
        seed_document(
            temp.path(),
            "netsec/policies.json",
            "net-policy-1",
            ExposureNetsecPolicyHook {},
        )
        .await;
        seed_document(
            temp.path(),
            "netsec/private_networks.json",
            "private-network-1",
            ExposurePrivateNetworkHook {},
        )
        .await;
        seed_document(
            temp.path(),
            "netsec/flow_audit.json",
            "flow-audit-1",
            ExposureNetsecFlowAuditHook {
                verdict: String::from("deny"),
            },
        )
        .await;
        seed_document(
            temp.path(),
            "abuse/quarantines.json",
            "network-quarantine-1",
            ExposureNetsecQuarantineHook {
                state: String::from("active"),
                deny_network: true,
                expires_at: None,
            },
        )
        .await;
        seed_document(
            temp.path(),
            "policy/policies.json",
            "policy-1",
            ExposurePolicyRecordHook {},
        )
        .await;
        seed_document(
            temp.path(),
            "policy/approvals.json",
            "approval-1",
            ExposurePolicyApprovalHook { approved: false },
        )
        .await;

        let payload = response_json(
            service
                .exposure_readiness_report()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        assert!(
            !payload["ingress"]["publishable"]
                .as_bool()
                .unwrap_or_default()
        );
        assert!(!payload["dns"]["publishable"].as_bool().unwrap_or_default());
        assert!(
            payload["dns"]["effective_publishable"]
                .as_bool()
                .unwrap_or_default()
        );
        assert!(!payload["mail"]["publishable"].as_bool().unwrap_or_default());
        assert!(!payload["netsec"]["ready"].as_bool().unwrap_or_default());
        assert!(
            payload["netsec"]["effective_ready"]
                .as_bool()
                .unwrap_or_default()
        );
        assert!(!payload["policy"]["ready"].as_bool().unwrap_or_default());
        assert!(!payload["governance"]["ready"].as_bool().unwrap_or_default());
        assert_eq!(
            payload["overrides"]["effective_active"]
                .as_u64()
                .unwrap_or_default(),
            2
        );
        assert!(!payload["raw_publishable"].as_bool().unwrap_or_default());
        assert!(
            !payload["effective_publishable"]
                .as_bool()
                .unwrap_or_default()
        );
        assert!(!payload["raw_ready"].as_bool().unwrap_or_default());
        assert!(!payload["effective_ready"].as_bool().unwrap_or_default());
    }

    #[tokio::test]
    async fn retention_evaluation_respects_legal_holds_and_age_thresholds() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_retention_policy(
                CreateRetentionPolicyRequest {
                    name: String::from("object-us"),
                    resource_kind: String::from("object"),
                    retain_days: 7,
                    hard_delete_after_days: 30,
                    residency_tags: vec![String::from("us")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let too_early = service
            .evaluate_retention(EvaluateRetentionRequest {
                subject_kind: String::from("tenant"),
                subject_id: String::from("tnt_demo"),
                resource_kind: String::from("object"),
                residency_tag: Some(String::from("us")),
                age_days: 10,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(too_early.status(), http::StatusCode::OK);

        let old_enough = service
            .evaluate_retention(EvaluateRetentionRequest {
                subject_kind: String::from("tenant"),
                subject_id: String::from("tnt_demo"),
                resource_kind: String::from("object"),
                residency_tag: Some(String::from("us")),
                age_days: 45,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(old_enough.status(), http::StatusCode::OK);

        let _ = service
            .create_legal_hold(
                CreateLegalHoldRequest {
                    subject_kind: String::from("tenant"),
                    subject_id: String::from("tnt_demo"),
                    reason: String::from("investigation"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let blocked = service
            .evaluate_retention(EvaluateRetentionRequest {
                subject_kind: String::from("tenant"),
                subject_id: String::from("tnt_demo"),
                resource_kind: String::from("object"),
                residency_tag: Some(String::from("us")),
                age_days: 365,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(blocked.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn retention_policy_residency_tags_are_deduped_and_normalized() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_retention_policy(
                CreateRetentionPolicyRequest {
                    name: String::from("object-global"),
                    resource_kind: String::from("object"),
                    retain_days: 7,
                    hard_delete_after_days: 14,
                    residency_tags: vec![
                        String::from("US"),
                        String::from(" us "),
                        String::from("eu"),
                        String::from("EU"),
                        String::from(""),
                    ],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);

        let stored = service
            .retention_policies
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].1.value.residency_tags,
            vec![String::from("eu"), String::from("us")]
        );
    }

    #[tokio::test]
    async fn audit_checkpoint_reads_ignore_soft_deleted_entries() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let active_id = AuditCheckpointId::generate().unwrap_or_else(|error| panic!("{error}"));
        let deleted_id = AuditCheckpointId::generate().unwrap_or_else(|error| panic!("{error}"));
        let recorded_at = OffsetDateTime::now_utc();
        let active = AuditCheckpointRecord {
            id: active_id.clone(),
            previous_hash: String::from("genesis"),
            current_hash: String::from("hash-1"),
            summary: String::from("active"),
            recorded_at,
        };
        let deleted = AuditCheckpointRecord {
            id: deleted_id.clone(),
            previous_hash: String::from("hash-1"),
            current_hash: String::from("hash-2"),
            summary: String::from("deleted"),
            recorded_at: recorded_at + Duration::seconds(1),
        };

        service
            .audit_checkpoints
            .create(active_id.as_str(), active.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .audit_checkpoints
            .create(deleted_id.as_str(), deleted)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .audit_checkpoints
            .soft_delete(deleted_id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .chain_head
            .upsert(
                "head",
                ChainHeadRecord {
                    current_hash: active.current_hash.clone(),
                },
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let latest = latest_checkpoint(&service.audit_checkpoints)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(latest.id, active_id);

        let report = service
            .verify_audit_integrity()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_integrity_report_is_valid_after_mutation_chain() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_legal_hold(
                CreateLegalHoldRequest {
                    subject_kind: String::from("tenant"),
                    subject_id: String::from("tnt_abc"),
                    reason: String::from("incident triage"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let report = service
            .verify_audit_integrity()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn concurrent_mutations_preserve_audit_chain_integrity_across_service_handles() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service_a = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let service_b = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let expected_events = 12_u64;
        let mut handles = Vec::new();
        for index in 0..expected_events {
            let service = if index % 2 == 0 {
                service_a.clone()
            } else {
                service_b.clone()
            };
            handles.push(tokio::spawn(async move {
                let context = RequestContext::new()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .with_actor(format!("actor-{index}"));
                service
                    .create_legal_hold(
                        CreateLegalHoldRequest {
                            subject_kind: String::from("tenant"),
                            subject_id: format!("tnt-{index}"),
                            reason: format!("reason-{index}"),
                        },
                        &context,
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
            }));
        }

        for handle in handles {
            handle.await.unwrap_or_else(|error| panic!("{error}"));
        }

        let verifier = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = verifier
            .verify_audit_integrity()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let bytes = body.to_bytes();
        let payload: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));

        assert!(payload["valid"].as_bool().unwrap_or(false));
        assert_eq!(
            payload["checkpoints_checked"].as_u64().unwrap_or_default(),
            expected_events,
        );
    }

    #[tokio::test]
    async fn governance_summary_route_aggregates_counts() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = GovernanceService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let alice_context = actor_context("alice");
        let bob_context = actor_context("bob");
        let carol_context = actor_context("carol");
        let dave_context = actor_context("dave");

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("deploy"),
                    change_type: String::from("deploy"),
                    requested_by: String::from("alice"),
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_id = service
            .change_requests
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .approve_change_request(
                first_id.as_str(),
                ReviewChangeRequest {
                    approver: String::from("bob"),
                    comment: None,
                },
                &bob_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .apply_change_request(
                first_id.as_str(),
                ApplyChangeRequest {
                    executor: String::from("carol"),
                    note: Some(String::from("done")),
                },
                &carol_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_change_request(
                CreateChangeRequestRequest {
                    title: String::from("policy"),
                    change_type: String::from("policy"),
                    requested_by: String::from("dave"),
                },
                &dave_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_exposure_override(
                CreateExposureOverrideRequest {
                    surface: String::from("dns"),
                    target_kind: String::from("zone"),
                    target_id: String::from("zone-pending"),
                    override_kind: String::from("publishability"),
                    reason: String::from("manual holdback"),
                    change_request_id: first_id.clone(),
                    requested_by: String::from("alice"),
                    expires_at: None,
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_legal_hold(
                CreateLegalHoldRequest {
                    subject_kind: String::from("tenant"),
                    subject_id: String::from("tnt"),
                    reason: String::from("legal hold"),
                },
                &alice_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let checkpoint_id = AuditCheckpointId::generate().unwrap_or_else(|error| panic!("{error}"));
        let checkpoint = AuditCheckpointRecord {
            id: checkpoint_id.clone(),
            previous_hash: String::from("genesis"),
            current_hash: String::from("hash-1"),
            summary: String::from("summary"),
            recorded_at: OffsetDateTime::now_utc(),
        };
        service
            .audit_checkpoints
            .create(checkpoint_id.as_str(), checkpoint.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .chain_head
            .upsert(
                "head",
                ChainHeadRecord {
                    current_hash: checkpoint.current_hash.clone(),
                },
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .governance_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            summary.audit.latest_checkpoint_at,
            Some(checkpoint.recorded_at)
        );
        let summary_value: Value =
            serde_json::to_value(&summary).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            summary_value["change_requests"]["total"]
                .as_u64()
                .unwrap_or_default(),
            2
        );
        assert_eq!(
            summary_value["change_requests"]["applied"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["change_requests"]["pending"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["approvals"]["total"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["legal_holds"]["total"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["legal_holds"]["active"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["overrides"]["total"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["overrides"]["pending"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary_value["overrides"]["active"]
                .as_u64()
                .unwrap_or_default(),
            0
        );
        assert!(
            summary_value["audit"]["total_checkpoints"]
                .as_u64()
                .unwrap_or_default()
                >= 1
        );
        assert_eq!(
            summary_value["state_root"]
                .as_str()
                .unwrap_or_else(|| panic!("missing state root")),
            service.state_root.display().to_string()
        );
    }
}
