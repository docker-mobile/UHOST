//! UVM control-plane service.
//!
//! This bounded context owns UVM instance lifecycle operations and the
//! user-facing VM contracts:
//! - templates
//! - instances
//! - lifecycle transitions (start/stop/reboot)
//! - migration requests
//! - snapshot and restore requests
//!
//! The implementation is intentionally explicit and file-backed so the same
//! contracts can run in all-in-one mode with low ops while preserving clear
//! seams for future distributed adapters.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use http::header::{HeaderMap, HeaderName, HeaderValue, IF_MATCH};
use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use tokio::fs;
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments, with_etag};
use uhost_core::{
    ErrorCode, PlatformError, RequestContext, Result, base64url_decode, base64url_encode,
    sha256_hex,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    AuditLog, DocumentCollection, DocumentStore, DurableOutbox, StoredDocument, WorkflowCollection,
    WorkflowInstance, WorkflowPhase, WorkflowStep, WorkflowStepState,
};
use uhost_types::contracts::ListRequestError;
use uhost_types::{
    AuditActor, AuditId, ConcurrencyToken, EventHeader, EventPayload, ListRequest, NodeId,
    OwnershipScope, Page, PageCursor, PlatformEvent, ProjectId, ResourceLifecycleState,
    ResourceMetadata, ServiceEvent, UvmCheckpointId, UvmClaimDecisionId, UvmHostEvidenceId,
    UvmImageId, UvmInstanceId, UvmMigrationId, UvmNodeCapabilityId, UvmPerfAttestationId,
    UvmRuntimeSessionId, UvmSnapshotId, UvmTemplateId,
};
use uhost_uvm::{
    BootDevice, ClaimTier, GuestArchitecture, GuestProfile, HypervisorBackend, MachineFamily,
    MigrationPolicy, MigrationPolicyTier, MigrationStrategy, RestorePolicyTier,
    UvmCompatibilityRequirement, UvmExecutionIntent, UvmPortabilityAssessment,
    UvmPortabilityAssessmentSource, UvmPortabilityAssessmentUnavailableReason,
};

/// UVM instance runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmInstanceState {
    /// Provisioning metadata and admission checks are still in progress.
    Provisioning,
    /// The VM is stopped and can be started.
    Stopped,
    /// The VM is running.
    Running,
    /// The VM is in a migration transition.
    Migrating,
    /// The VM failed and needs operator intervention.
    Failed,
}

/// UVM template with reusable sizing and firmware defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmTemplateRecord {
    /// Template identifier.
    pub id: UvmTemplateId,
    /// Human-readable template name.
    pub name: String,
    /// Guest architecture.
    pub architecture: String,
    /// Default virtual CPU count.
    pub vcpu: u16,
    /// Default memory in MiB.
    pub memory_mb: u64,
    /// CPU topology profile.
    pub cpu_topology: String,
    /// NUMA placement policy.
    pub numa_policy: String,
    /// Firmware profile (`uefi_secure`, `uefi_standard`, `bios`).
    pub firmware_profile: String,
    /// Preferred initial boot device for instances derived from this template.
    #[serde(default = "default_boot_device_key")]
    pub boot_device: String,
    /// Device profile key owned by `uvm-node`.
    pub device_profile: String,
    /// Migration policy (`cold_only`, `best_effort_live`, `strict_live`).
    pub migration_policy: String,
    /// Machine family derived for execution planning.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile derived for compatibility planning.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Evidence-gated claim tier attached to this template.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Execution intent independent of the concrete runtime backend.
    #[serde(
        default = "default_execution_intent",
        deserialize_with = "deserialize_execution_intent"
    )]
    pub execution_intent: UvmExecutionIntent,
    /// Control-plane policy for the highest allowed claim tier.
    #[serde(default = "default_claim_tier_policy")]
    pub claim_tier_policy: ClaimTier,
    /// Restore policy tier for lifecycle workflows.
    #[serde(default = "default_restore_policy_tier")]
    pub restore_policy_tier: RestorePolicyTier,
    /// Migration policy tier independent of concrete node-plane strategy.
    #[serde(default = "default_migration_policy_tier")]
    pub migration_policy_tier: MigrationPolicyTier,
    /// Whether template is explicitly approved for Apple guest workloads.
    pub apple_guest_allowed: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// One managed UVM instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmInstanceRecord {
    /// Instance identifier.
    pub id: UvmInstanceId,
    /// Owning project identifier.
    pub project_id: ProjectId,
    /// Instance name.
    pub name: String,
    /// Source template identifier, when used.
    pub template_id: Option<UvmTemplateId>,
    /// Boot image identifier.
    pub boot_image_id: UvmImageId,
    /// Guest architecture.
    pub architecture: String,
    /// Guest OS family hint.
    pub guest_os: String,
    /// vCPU count.
    pub vcpu: u16,
    /// Memory in MiB.
    pub memory_mb: u64,
    /// CPU topology profile.
    pub cpu_topology: String,
    /// NUMA placement policy.
    pub numa_policy: String,
    /// Firmware profile.
    pub firmware_profile: String,
    /// Initial boot device used for the instance launch contract.
    #[serde(default = "default_boot_device_key")]
    pub boot_device: String,
    /// Device profile key.
    pub device_profile: String,
    /// Optional install-media image attached for provisioning workflows.
    #[serde(default)]
    pub install_media_image_id: Option<UvmImageId>,
    /// Migration policy.
    pub migration_policy: String,
    /// Machine family derived for execution planning.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile derived for compatibility planning.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Evidence-gated claim tier attached to this instance.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Execution intent independent of the concrete runtime backend.
    #[serde(
        default = "default_execution_intent",
        deserialize_with = "deserialize_execution_intent"
    )]
    pub execution_intent: UvmExecutionIntent,
    /// Control-plane policy for the highest allowed claim tier.
    #[serde(default = "default_claim_tier_policy")]
    pub claim_tier_policy: ClaimTier,
    /// Restore policy tier for lifecycle workflows.
    #[serde(default = "default_restore_policy_tier")]
    pub restore_policy_tier: RestorePolicyTier,
    /// Migration policy tier independent of concrete node-plane strategy.
    #[serde(default = "default_migration_policy_tier")]
    pub migration_policy_tier: MigrationPolicyTier,
    /// Legal-policy flag indicating Apple guest approval was provided.
    pub apple_guest_approved: bool,
    /// Last known host node.
    pub host_node_id: Option<NodeId>,
    /// Runtime state.
    pub state: UvmInstanceState,
    /// Last lifecycle transition timestamp.
    pub last_transition_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// VM snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmSnapshotRecord {
    /// Snapshot identifier.
    pub id: UvmSnapshotId,
    /// Owning instance.
    pub instance_id: UvmInstanceId,
    /// Snapshot name.
    pub name: String,
    /// Whether the snapshot is crash-consistent.
    pub crash_consistent: bool,
    /// Snapshot state.
    pub state: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Migration operation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmMigrationRecord {
    /// Migration identifier.
    pub id: UvmMigrationId,
    /// Migrating instance.
    pub instance_id: UvmInstanceId,
    /// Source node (when known).
    pub from_node_id: Option<NodeId>,
    /// Destination node.
    pub to_node_id: NodeId,
    /// Operator reason.
    pub reason: String,
    /// Requested target capability attached to the workflow, when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_capability_id: Option<String>,
    /// Checkpoint reference carried by the durable migration workflow.
    #[serde(default = "default_migration_checkpoint_reference")]
    pub checkpoint_reference: String,
    /// Checkpoint kind carried by the durable migration workflow.
    #[serde(default = "default_migration_checkpoint_kind")]
    pub checkpoint_kind: String,
    /// Maximum tolerated downtime budget in milliseconds when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_max_downtime_ms: Option<u32>,
    /// Optional portability assessment linked to the migration request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portability_assessment: Option<UvmPortabilityAssessment>,
    /// Provenance for the linked portability assessment.
    #[serde(default)]
    pub portability_assessment_source: UvmPortabilityAssessmentSource,
    /// Stable reason when portability evidence was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portability_assessment_unavailable_reason:
        Option<UvmPortabilityAssessmentUnavailableReason>,
    /// Durable workflow family backing this migration.
    #[serde(default = "default_migration_workflow_kind")]
    pub workflow_kind: String,
    /// Migration state.
    pub state: String,
    /// Start timestamp.
    pub started_at: OffsetDateTime,
    /// Completion timestamp when complete.
    pub completed_at: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

const UVM_MIGRATION_WORKFLOW_KIND: &str = "uvm.control.migration";
const UVM_MIGRATION_WORKFLOW_SUBJECT_KIND: &str = "uvm_instance";
const UVM_MIGRATION_FINAL_STEP_INDEX: usize = 2;

type UvmMigrationWorkflow = WorkflowInstance<UvmMigrationRecord>;

/// Reconciliation issue discovered between UVM control-plane and node-plane state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmReconciliationIssue {
    /// Severity classification.
    pub severity: String,
    /// Stable issue code.
    pub code: String,
    /// Target control-plane instance when applicable.
    pub instance_id: Option<UvmInstanceId>,
    /// Target runtime session identifier when applicable.
    pub runtime_session_id: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

/// Persisted reconciliation report over UVM control and node runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmReconciliationReport {
    /// Report identifier.
    pub id: AuditId,
    /// Creation timestamp.
    pub generated_at: OffsetDateTime,
    /// Total control-plane instances evaluated.
    pub total_instances: usize,
    /// Total runtime sessions observed from node state.
    pub total_runtime_sessions: usize,
    /// Report status (`clean`, `drift_detected`).
    pub status: String,
    /// Enumerated issues.
    pub issues: Vec<UvmReconciliationIssue>,
}

/// Read-only persisted summary for UVM control-plane resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmControlSummary {
    /// Number of active templates.
    pub template_count: usize,
    /// Number of active instances.
    pub instance_count: usize,
    /// Active instance counts by lifecycle state.
    pub instance_state_totals: BTreeMap<String, usize>,
    /// Active template counts by claim tier.
    pub template_claim_tier_totals: BTreeMap<String, usize>,
    /// Active instance counts by claim tier.
    pub instance_claim_tier_totals: BTreeMap<String, usize>,
    /// Active template counts by preferred backend intent.
    pub template_preferred_backend_totals: BTreeMap<String, usize>,
    /// Active instance counts by preferred backend intent.
    pub instance_preferred_backend_totals: BTreeMap<String, usize>,
    /// Latest persisted effective claim publication state from UVM observe.
    pub effective_claim_publication_state: Option<String>,
    /// Workload classes failing the latest persisted claim publication decision.
    pub failing_workload_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmNodeRuntimeSessionSnapshot {
    #[serde(alias = "id")]
    runtime_session_id: String,
    instance_id: String,
    node_id: String,
    state: String,
    #[serde(default)]
    migration_in_progress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmObserveClaimDecisionSnapshot {
    id: String,
    claim_status: String,
    #[serde(default)]
    failing_workload_classes: Vec<String>,
    decided_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmImageContractSnapshot {
    id: UvmImageId,
    #[serde(default)]
    guest_profile: String,
    #[serde(default)]
    machine_family: String,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    preferred_boot_device: String,
    #[serde(default)]
    install_media: bool,
    #[serde(default = "default_execution_intent")]
    execution_intent: UvmExecutionIntent,
    #[serde(default)]
    compatibility_requirement: Option<UvmCompatibilityRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeSessionContractSnapshot {
    id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    node_id: NodeId,
    capability_id: UvmNodeCapabilityId,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    accelerator_backend: String,
    state: String,
    #[serde(default)]
    migration_in_progress: bool,
    created_at: OffsetDateTime,
    last_transition_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeNetworkAccessContractSnapshot {
    #[serde(default = "default_runtime_network_mode_key")]
    network_mode: String,
    #[serde(default)]
    internet_nat: bool,
    #[serde(default)]
    ssh_available: bool,
    #[serde(default)]
    guest_exec_route_available: bool,
    #[serde(default)]
    ingress_http_ready: bool,
    #[serde(default)]
    ingress_tcp_ready: bool,
    #[serde(default)]
    ingress_udp_ready: bool,
    #[serde(default)]
    egress_transport: Option<String>,
    #[serde(default)]
    ingress_transport: Option<String>,
    #[serde(default)]
    ingress_http_bind: Option<String>,
    #[serde(default)]
    ingress_http_url: Option<String>,
    #[serde(default)]
    ingress_tcp_bind: Option<String>,
    #[serde(default)]
    ingress_tcp_service: Option<String>,
    #[serde(default)]
    ingress_udp_bind: Option<String>,
    #[serde(default)]
    ingress_udp_service: Option<String>,
    #[serde(default)]
    guest_web_root: Option<String>,
    #[serde(default)]
    supported_guest_commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRunnerSupervisionContractSnapshot {
    runtime_session_id: UvmRuntimeSessionId,
    runtime_incarnation: u32,
    state: String,
    #[serde(default)]
    network_access: Option<UvmRuntimeNetworkAccessContractSnapshot>,
    last_event_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeSessionReadRecord {
    id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    node_id: NodeId,
    capability_id: UvmNodeCapabilityId,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    #[serde(default)]
    accelerator_backend: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    migration_in_progress: bool,
    #[serde(default)]
    last_checkpoint_id: Option<UvmCheckpointId>,
    #[serde(default)]
    restored_from_checkpoint_id: Option<UvmCheckpointId>,
    #[serde(default)]
    last_error: Option<String>,
    created_at: OffsetDateTime,
    last_transition_at: OffsetDateTime,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeCheckpointReadRecord {
    id: UvmCheckpointId,
    runtime_session_id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    source_node_id: NodeId,
    target_node_id: NodeId,
    kind: String,
    checkpoint_uri: String,
    memory_bitmap_hash: String,
    disk_generation: u64,
    envelope_digest: String,
    #[serde(default)]
    provenance: serde_json::Value,
    created_at: OffsetDateTime,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeSessionIntentContractSnapshot {
    runtime_session_id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    #[serde(default = "default_execution_intent")]
    execution_intent: UvmExecutionIntent,
    #[serde(default)]
    first_placement_portability_assessment: Option<UvmPortabilityAssessment>,
    #[serde(default)]
    last_portability_preflight_id: Option<AuditId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimePreflightContractSnapshot {
    id: AuditId,
    #[serde(default)]
    selected_backend: Option<String>,
    #[serde(default)]
    blockers: Vec<String>,
    #[serde(default)]
    portability_assessment: Option<UvmPortabilityAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmObserveClaimDecisionContractSnapshot {
    id: UvmClaimDecisionId,
    #[serde(default)]
    host_evidence_id: Option<UvmHostEvidenceId>,
    #[serde(default)]
    runtime_session_id: Option<UvmRuntimeSessionId>,
    #[serde(default)]
    runtime_preflight_id: Option<AuditId>,
    #[serde(default = "default_claim_tier_key")]
    highest_claim_tier: String,
    claim_status: String,
    #[serde(default)]
    native_indistinguishable_status: bool,
    #[serde(default)]
    prohibited_claim_count: u32,
    #[serde(default)]
    missing_required_workload_classes: Vec<String>,
    #[serde(default)]
    failing_workload_classes: Vec<String>,
    #[serde(default)]
    portability_assessment: Option<UvmPortabilityAssessment>,
    #[serde(default)]
    portability_assessment_source: UvmPortabilityAssessmentSource,
    #[serde(default)]
    portability_assessment_unavailable_reason: Option<UvmPortabilityAssessmentUnavailableReason>,
    decided_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmObserveHostEvidenceContractSnapshot {
    id: UvmHostEvidenceId,
    evidence_mode: String,
    host_platform: String,
    execution_environment: String,
    hardware_virtualization: bool,
    nested_virtualization: bool,
    qemu_available: bool,
    collected_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmObservePerfAttestationContractSnapshot {
    id: UvmPerfAttestationId,
    instance_id: UvmInstanceId,
    workload_class: String,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    #[serde(default)]
    claim_evidence_mode: String,
    #[serde(default)]
    native_indistinguishable: bool,
    measured_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmResolvedContractView {
    instance: UvmInstanceRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    template: Option<UvmTemplateRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_image: Option<UvmImageContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install_media_image: Option<UvmImageContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_session: Option<UvmRuntimeSessionContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_access: Option<UvmRuntimeNetworkAccessContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_execution_intent: Option<UvmExecutionIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_preflight: Option<UvmRuntimePreflightContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim_decision: Option<UvmObserveClaimDecisionContractSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_evidence: Option<UvmObserveHostEvidenceContractSnapshot>,
    #[serde(default)]
    latest_perf_attestations: Vec<UvmObservePerfAttestationContractSnapshot>,
    effective_execution_intent: UvmExecutionIntent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_portability_assessment: Option<UvmPortabilityAssessment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    portability_assessment_source: Option<UvmPortabilityAssessmentSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    portability_assessment_unavailable_reason: Option<UvmPortabilityAssessmentUnavailableReason>,
    effective_claim_tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_claim_status: Option<String>,
    resolution_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateTemplateRequest {
    name: String,
    architecture: String,
    vcpu: u16,
    memory_mb: u64,
    cpu_topology: String,
    numa_policy: String,
    firmware_profile: String,
    boot_device: Option<String>,
    device_profile: String,
    migration_policy: String,
    apple_guest_allowed: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_execution_intent")]
    execution_intent: Option<UvmExecutionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateInstanceRequest {
    project_id: String,
    name: String,
    template_id: Option<String>,
    boot_image_id: String,
    install_media_image_id: Option<String>,
    architecture: Option<String>,
    guest_os: String,
    vcpu: Option<u16>,
    memory_mb: Option<u64>,
    cpu_topology: Option<String>,
    numa_policy: Option<String>,
    firmware_profile: Option<String>,
    boot_device: Option<String>,
    device_profile: Option<String>,
    migration_policy: Option<String>,
    apple_guest_approved: Option<bool>,
    host_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrateInstanceRequest {
    to_node_id: String,
    reason: String,
    #[serde(default)]
    target_capability_id: Option<String>,
    #[serde(default)]
    checkpoint_reference: Option<String>,
    #[serde(default)]
    checkpoint_kind: Option<String>,
    #[serde(default)]
    migration_max_downtime_ms: Option<u32>,
    #[serde(default)]
    portability_assessment: Option<UvmPortabilityAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotRequest {
    name: String,
    crash_consistent: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreRequest {
    snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransitionOutcome {
    Applied(StoredDocument<UvmInstanceRecord>),
    AlreadyAtTarget(StoredDocument<UvmInstanceRecord>),
}

/// UVM control-plane service.
#[derive(Debug, Clone)]
pub struct UvmControlService {
    templates: DocumentStore<UvmTemplateRecord>,
    instances: DocumentStore<UvmInstanceRecord>,
    snapshots: DocumentStore<UvmSnapshotRecord>,
    migrations: DocumentStore<UvmMigrationRecord>,
    migration_workflows: WorkflowCollection<UvmMigrationRecord>,
    reconciliations: DocumentStore<UvmReconciliationReport>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl UvmControlService {
    /// Open the UVM control service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("uvm-control");
        Ok(Self {
            templates: DocumentStore::open(root.join("templates.json")).await?,
            instances: DocumentStore::open(root.join("instances.json")).await?,
            snapshots: DocumentStore::open(root.join("snapshots.json")).await?,
            migrations: DocumentStore::open(root.join("migrations.json")).await?,
            migration_workflows: WorkflowCollection::open_local(
                root.join("migration_workflows.json"),
            )
            .await?,
            reconciliations: DocumentStore::open(root.join("reconciliations.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn create_template(
        &self,
        request: CreateTemplateRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let apple_guest_allowed = request.apple_guest_allowed.unwrap_or(false);
        let name = normalize_resource_name(&request.name, "name")?;
        let architecture = normalize_architecture(&request.architecture)?;
        let cpu_topology = normalize_profile(&request.cpu_topology, "cpu_topology")?;
        let numa_policy = normalize_profile(&request.numa_policy, "numa_policy")?;
        let firmware_profile = normalize_firmware_profile(&request.firmware_profile)?;
        let boot_device = normalize_boot_device(request.boot_device.as_deref().unwrap_or("disk"))?;
        let device_profile = normalize_profile(&request.device_profile, "device_profile")?;
        let migration_policy = normalize_migration_policy(&request.migration_policy)?;
        enforce_firmware_compatibility(&architecture, &firmware_profile)?;
        if self
            .templates
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .any(|(_, value)| value.value.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "template name already exists in this scope",
            ));
        }

        let id = UvmTemplateId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate UVM template id")
                .with_detail(error.to_string())
        })?;
        let machine_family =
            default_machine_family_for_template(&architecture, apple_guest_allowed);
        let guest_profile = default_guest_profile_for_template(apple_guest_allowed);
        let execution_intent = request
            .execution_intent
            .unwrap_or_else(|| default_execution_intent_for_guest_profile(&guest_profile));
        let restore_policy_tier = default_restore_policy_tier();
        let migration_policy_tier = migration_policy_tier_for_policy(&migration_policy)?;
        let record = UvmTemplateRecord {
            id: id.clone(),
            name,
            architecture,
            vcpu: request.vcpu.max(1),
            memory_mb: request.memory_mb.max(512),
            cpu_topology,
            numa_policy,
            firmware_profile,
            boot_device,
            device_profile,
            migration_policy,
            machine_family,
            guest_profile,
            claim_tier: default_claim_tier_key(),
            execution_intent,
            claim_tier_policy: default_claim_tier_policy(),
            restore_policy_tier,
            migration_policy_tier,
            apple_guest_allowed,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let stored = self.templates.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "uvm.template.created.v1",
            "uvm_template",
            id.as_str(),
            "created",
            serde_json::json!({
                "architecture": record.architecture,
                "vcpu": record.vcpu,
                "memory_mb": record.memory_mb,
            }),
            context,
        )
        .await?;
        entity_response(
            StatusCode::CREATED,
            &record,
            &record.metadata,
            stored.version,
        )
    }

    async fn create_instance(
        &self,
        request: CreateInstanceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_resource_name(&request.name, "name")?;
        let project_id = ProjectId::parse(request.project_id).map_err(|error| {
            PlatformError::invalid("invalid project_id").with_detail(error.to_string())
        })?;
        let image_id = UvmImageId::parse(request.boot_image_id).map_err(|error| {
            PlatformError::invalid("invalid boot_image_id").with_detail(error.to_string())
        })?;
        let install_media_image_id = request
            .install_media_image_id
            .map(|raw| {
                UvmImageId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid install_media_image_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;

        let template = request
            .template_id
            .as_ref()
            .map(|raw| {
                UvmTemplateId::parse(raw.to_owned())
                    .map_err(|error| {
                        PlatformError::invalid("invalid template_id").with_detail(error.to_string())
                    })
                    .map(|id| (id.clone(), id.to_string()))
            })
            .transpose()?;
        let template_record = if let Some((_, key)) = template.as_ref() {
            let stored = self
                .templates
                .get(key)
                .await?
                .ok_or_else(|| PlatformError::not_found("template does not exist"))?;
            if stored.deleted {
                return Err(PlatformError::not_found("template does not exist"));
            }
            Some(stored.value)
        } else {
            None
        };

        let architecture = match (&request.architecture, &template_record) {
            (Some(raw), _) => normalize_architecture(raw)?,
            (None, Some(template_record)) => normalize_architecture(&template_record.architecture)?,
            (None, None) => String::from("x86_64"),
        };
        let guest_os = normalize_guest_os(&request.guest_os)?;
        let cpu_topology = match (&request.cpu_topology, &template_record) {
            (Some(raw), _) => normalize_profile(raw, "cpu_topology")?,
            (None, Some(template_record)) => {
                normalize_profile(&template_record.cpu_topology, "cpu_topology")?
            }
            (None, None) => String::from("balanced"),
        };
        let numa_policy = match (&request.numa_policy, &template_record) {
            (Some(raw), _) => normalize_profile(raw, "numa_policy")?,
            (None, Some(template_record)) => {
                normalize_profile(&template_record.numa_policy, "numa_policy")?
            }
            (None, None) => String::from("preferred_local"),
        };
        let firmware_profile = match (&request.firmware_profile, &template_record) {
            (Some(raw), _) => normalize_firmware_profile(raw)?,
            (None, Some(template_record)) => {
                normalize_firmware_profile(&template_record.firmware_profile)?
            }
            (None, None) => String::from("uefi_secure"),
        };
        let boot_device = match (
            &request.boot_device,
            &template_record,
            &install_media_image_id,
        ) {
            (Some(raw), _, _) => normalize_boot_device(raw)?,
            (None, Some(template_record), _) => {
                normalize_boot_device(&template_record.boot_device)?
            }
            (None, None, Some(_)) => String::from(BootDevice::Cdrom.as_str()),
            (None, None, None) => String::from(BootDevice::Disk.as_str()),
        };
        if boot_device == BootDevice::Cdrom.as_str() && install_media_image_id.is_none() {
            return Err(PlatformError::conflict(
                "boot_device `cdrom` requires install_media_image_id",
            ));
        }
        let device_profile = match (&request.device_profile, &template_record) {
            (Some(raw), _) => normalize_profile(raw, "device_profile")?,
            (None, Some(template_record)) => {
                normalize_profile(&template_record.device_profile, "device_profile")?
            }
            (None, None) => String::from("cloud-balanced"),
        };
        let migration_policy = match (&request.migration_policy, &template_record) {
            (Some(raw), _) => normalize_migration_policy(raw)?,
            (None, Some(template_record)) => {
                normalize_migration_policy(&template_record.migration_policy)?
            }
            (None, None) => String::from("best_effort_live"),
        };
        enforce_firmware_compatibility(&architecture, &firmware_profile)?;

        let template_vcpu = template_record.as_ref().map_or(2_u16, |record| record.vcpu);
        let template_memory = template_record
            .as_ref()
            .map_or(2048_u64, |record| record.memory_mb);
        let vcpu = request.vcpu.unwrap_or(template_vcpu).max(1);
        let memory_mb = request.memory_mb.unwrap_or(template_memory).max(512);
        let apple_guest_approved = request.apple_guest_approved.unwrap_or(false);
        let guest_profile = default_guest_profile_for_instance(&guest_os);
        let machine_family = default_machine_family_for_instance(&architecture, &guest_os);
        let execution_intent = template_record
            .as_ref()
            .map(|record| record.execution_intent.clone())
            .unwrap_or_else(|| default_execution_intent_for_guest_profile(&guest_profile));
        let claim_tier_policy = template_record
            .as_ref()
            .map(|record| record.claim_tier_policy)
            .unwrap_or_else(default_claim_tier_policy);
        let restore_policy_tier = template_record
            .as_ref()
            .map(|record| record.restore_policy_tier)
            .unwrap_or_else(default_restore_policy_tier);
        let migration_policy_tier = effective_migration_policy_tier(
            template_record
                .as_ref()
                .map(|record| record.migration_policy_tier),
            &migration_policy,
        )?;
        enforce_apple_guest_guardrails(
            &guest_os,
            &architecture,
            apple_guest_approved,
            template_record
                .as_ref()
                .is_some_and(|record| record.apple_guest_allowed),
        )?;
        let host_node_id = request
            .host_node_id
            .map(|raw| {
                NodeId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid host_node_id").with_detail(error.to_string())
                })
            })
            .transpose()?;
        if self
            .instances
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .any(|(_, value)| {
                value.value.project_id == project_id && value.value.name.eq_ignore_ascii_case(&name)
            })
        {
            return Err(PlatformError::conflict(
                "instance name already exists in this project",
            ));
        }

        let id = UvmInstanceId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate UVM instance id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let record = UvmInstanceRecord {
            id: id.clone(),
            project_id,
            name,
            template_id: template
                .as_ref()
                .map(|(template_id, _)| template_id.clone()),
            boot_image_id: image_id,
            architecture,
            guest_os,
            vcpu,
            memory_mb,
            cpu_topology,
            numa_policy,
            firmware_profile,
            boot_device,
            device_profile,
            install_media_image_id,
            migration_policy,
            machine_family,
            guest_profile,
            claim_tier: default_claim_tier_key(),
            execution_intent,
            claim_tier_policy,
            restore_policy_tier,
            migration_policy_tier,
            apple_guest_approved,
            host_node_id,
            state: UvmInstanceState::Stopped,
            last_transition_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let stored = self.instances.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "uvm.instance.created.v1",
            "uvm_instance",
            id.as_str(),
            "created",
            serde_json::json!({
                "project_id": record.project_id,
                "architecture": record.architecture,
                "guest_os": record.guest_os,
                "vcpu": record.vcpu,
                "memory_mb": record.memory_mb,
            }),
            context,
        )
        .await?;
        entity_response(
            StatusCode::CREATED,
            &record,
            &record.metadata,
            stored.version,
        )
    }

    async fn get_template(&self, template_id: &str) -> Result<http::Response<ApiBody>> {
        let stored = self
            .templates
            .get(template_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("template does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("template does not exist"));
        }
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_instance(&self, instance_id: &str) -> Result<http::Response<ApiBody>> {
        let stored = self.load_instance(instance_id).await?;
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_snapshot(&self, snapshot_id: &str) -> Result<http::Response<ApiBody>> {
        let stored = self
            .snapshots
            .get(snapshot_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("snapshot does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("snapshot does not exist"));
        }
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_migration(&self, migration_id: &str) -> Result<http::Response<ApiBody>> {
        let stored = self
            .migrations
            .get(migration_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("migration does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("migration does not exist"));
        }
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_outbox_message(&self, message_id: &str) -> Result<http::Response<ApiBody>> {
        let message = self
            .outbox
            .list_all()
            .await?
            .into_iter()
            .find(|message| message.id == message_id)
            .ok_or_else(|| PlatformError::not_found("outbox message does not exist"))?;
        json_response(StatusCode::OK, &message)
    }

    async fn list_runtime_sessions_for_instance(
        &self,
        instance_id: &str,
        list_request: Option<&ListRequest>,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = self.load_instance(instance_id).await?.value.id;
        let mut records = self
            .load_external_stored_collection::<UvmRuntimeSessionReadRecord>(
                "uvm-node",
                "runtime_sessions.json",
                "UVM node runtime session view",
            )
            .await?
            .into_iter()
            .filter(|stored| stored.value.instance_id == instance_id)
            .map(|stored| stored.value)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.last_transition_at.cmp(&right.last_transition_at))
                .then(left.id.as_str().cmp(right.id.as_str()))
        });
        paginated_json_response(records, list_request)
    }

    async fn get_runtime_session_for_instance(
        &self,
        instance_id: &str,
        session_id: &str,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = self.load_instance(instance_id).await?.value.id;
        let session_id = UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
        })?;
        let stored = self
            .load_external_stored_document::<UvmRuntimeSessionReadRecord>(
                "uvm-node",
                "runtime_sessions.json",
                session_id.as_str(),
                "UVM node runtime session view",
            )
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if stored.value.instance_id != instance_id {
            return Err(PlatformError::not_found("runtime session does not exist"));
        }
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn list_runtime_checkpoints_for_instance(
        &self,
        instance_id: &str,
        list_request: Option<&ListRequest>,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = self.load_instance(instance_id).await?.value.id;
        let mut records = self
            .load_external_stored_collection::<UvmRuntimeCheckpointReadRecord>(
                "uvm-node",
                "runtime_checkpoints.json",
                "UVM node runtime checkpoint view",
            )
            .await?
            .into_iter()
            .filter(|stored| stored.value.instance_id == instance_id)
            .map(|stored| stored.value)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.id.as_str().cmp(right.id.as_str()))
        });
        paginated_json_response(records, list_request)
    }

    async fn get_runtime_checkpoint_for_instance(
        &self,
        instance_id: &str,
        checkpoint_id: &str,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = self.load_instance(instance_id).await?.value.id;
        let checkpoint_id = UvmCheckpointId::parse(checkpoint_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid runtime checkpoint id").with_detail(error.to_string())
        })?;
        let stored = self
            .load_external_stored_document::<UvmRuntimeCheckpointReadRecord>(
                "uvm-node",
                "runtime_checkpoints.json",
                checkpoint_id.as_str(),
                "UVM node runtime checkpoint view",
            )
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime checkpoint does not exist"))?;
        if stored.value.instance_id != instance_id {
            return Err(PlatformError::not_found(
                "runtime checkpoint does not exist",
            ));
        }
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_resolved_instance_contract(
        &self,
        instance_id: &str,
    ) -> Result<http::Response<ApiBody>> {
        let instance = self.load_instance(instance_id).await?.value;
        let mut resolution_notes = Vec::new();

        let template = if let Some(template_id) = instance.template_id.as_ref() {
            let stored = self.templates.get(template_id.as_str()).await?;
            match stored {
                Some(stored) if !stored.deleted => Some(stored.value),
                _ => {
                    resolution_notes.push(format!(
                        "template {} referenced by control state is missing from uvm-control",
                        template_id.as_str()
                    ));
                    None
                }
            }
        } else {
            None
        };

        let boot_image = self
            .load_external_document::<UvmImageContractSnapshot>(
                "uvm-image",
                "images.json",
                instance.boot_image_id.as_str(),
                "UVM image contract",
            )
            .await?;
        match boot_image.as_ref() {
            Some(image) => {
                if !image.verified {
                    resolution_notes
                        .push(format!("boot image {} is not verified", image.id.as_str()));
                }
                if image.execution_intent != instance.execution_intent {
                    resolution_notes.push(String::from(
                        "boot image execution_intent diverges from control execution_intent",
                    ));
                }
                if image.claim_tier != instance.claim_tier {
                    resolution_notes.push(format!(
                        "boot image claim_tier {} differs from control claim_tier {}",
                        image.claim_tier, instance.claim_tier
                    ));
                }
                if !image.preferred_boot_device.is_empty()
                    && image.preferred_boot_device != instance.boot_device
                {
                    resolution_notes.push(format!(
                        "boot image preferred_boot_device {} differs from control boot_device {}",
                        image.preferred_boot_device, instance.boot_device
                    ));
                }
                if let Some(requirement) = image.compatibility_requirement.as_ref() {
                    if requirement.guest_architecture.as_str() != instance.architecture {
                        resolution_notes.push(format!(
                            "boot image compatibility guest_architecture {} differs from control architecture {}",
                            requirement.guest_architecture.as_str(),
                            instance.architecture
                        ));
                    }
                    if requirement.machine_family.as_str() != instance.machine_family {
                        resolution_notes.push(format!(
                            "boot image compatibility machine_family {} differs from control machine_family {}",
                            requirement.machine_family.as_str(),
                            instance.machine_family
                        ));
                    }
                    if requirement.guest_profile.as_str() != instance.guest_profile {
                        resolution_notes.push(format!(
                            "boot image compatibility guest_profile {} differs from control guest_profile {}",
                            requirement.guest_profile.as_str(),
                            instance.guest_profile
                        ));
                    }
                    if requirement.boot_device.as_str() != instance.boot_device {
                        resolution_notes.push(format!(
                            "boot image compatibility boot_device {} differs from control boot_device {}",
                            requirement.boot_device.as_str(),
                            instance.boot_device
                        ));
                    }
                    if requirement.claim_tier.as_str() != instance.claim_tier {
                        resolution_notes.push(format!(
                            "boot image compatibility claim_tier {} differs from control claim_tier {}",
                            requirement.claim_tier.as_str(),
                            instance.claim_tier
                        ));
                    }
                }
            }
            None => {
                resolution_notes.push(format!(
                    "boot image {} referenced by control state is missing from uvm-image",
                    instance.boot_image_id.as_str()
                ));
            }
        }

        let install_media_image = if let Some(install_media_image_id) =
            instance.install_media_image_id.as_ref()
        {
            let image = self
                .load_external_document::<UvmImageContractSnapshot>(
                    "uvm-image",
                    "images.json",
                    install_media_image_id.as_str(),
                    "UVM install media image contract",
                )
                .await?;
            match image.as_ref() {
                Some(image) => {
                    if !image.verified {
                        resolution_notes.push(format!(
                            "install media image {} is not verified",
                            image.id.as_str()
                        ));
                    }
                    if !image.install_media {
                        resolution_notes.push(format!(
                            "install media image {} is not marked as install_media",
                            image.id.as_str()
                        ));
                    }
                }
                None => {
                    resolution_notes.push(format!(
                            "install media image {} referenced by control state is missing from uvm-image",
                            install_media_image_id.as_str()
                        ));
                }
            }
            image
        } else {
            None
        };

        let runtime_session = self
            .latest_runtime_session_for_instance(&instance.id)
            .await?;
        let runtime_access = if let Some(runtime_session) = runtime_session.as_ref() {
            self.latest_runtime_access_for_runtime_session(&runtime_session.id)
                .await?
        } else {
            None
        };
        if runtime_session.is_none()
            && matches!(
                instance.state,
                UvmInstanceState::Running | UvmInstanceState::Migrating
            )
        {
            resolution_notes.push(String::from(
                "control state expects a live runtime session but uvm-node has no active session for this instance",
            ));
        }

        if let Some(runtime_session) = runtime_session.as_ref() {
            if runtime_session.state != instance_state_summary_key(instance.state) {
                resolution_notes.push(format!(
                    "runtime session state {} differs from control state {}",
                    runtime_session.state,
                    instance_state_summary_key(instance.state)
                ));
            }
            if runtime_session.claim_tier != instance.claim_tier {
                resolution_notes.push(format!(
                    "runtime claim_tier {} differs from control claim_tier {}",
                    runtime_session.claim_tier, instance.claim_tier
                ));
            }
            if let Some(host_node_id) = instance.host_node_id.as_ref()
                && runtime_session.node_id != *host_node_id
            {
                resolution_notes.push(format!(
                    "runtime session node {} differs from control host_node_id {}",
                    runtime_session.node_id.as_str(),
                    host_node_id.as_str()
                ));
            }
        }

        let runtime_session_intent = if let Some(runtime_session) = runtime_session.as_ref() {
            let intent = self
                .load_external_document::<UvmRuntimeSessionIntentContractSnapshot>(
                    "uvm-node",
                    "runtime_session_intents.json",
                    runtime_session.id.as_str(),
                    "UVM runtime session intent",
                )
                .await?;
            if intent.is_none() {
                resolution_notes.push(format!(
                    "runtime session {} exists without a matching runtime_session_intents record",
                    runtime_session.id.as_str()
                ));
            }
            intent
        } else {
            None
        };

        if let Some(runtime_session_intent) = runtime_session_intent.as_ref()
            && runtime_session_intent.execution_intent != instance.execution_intent
        {
            resolution_notes.push(String::from(
                "runtime execution_intent diverges from control execution_intent",
            ));
        }

        let runtime_preflight_id = runtime_session_intent
            .as_ref()
            .and_then(|intent| intent.last_portability_preflight_id.as_ref().cloned());
        let runtime_preflight = if let Some(runtime_preflight_id) = runtime_preflight_id.as_ref() {
            self.load_external_document::<UvmRuntimePreflightContractSnapshot>(
                "uvm-node",
                "runtime_preflights.json",
                runtime_preflight_id.as_str(),
                "UVM runtime preflight",
            )
            .await?
        } else {
            None
        };

        if let (Some(runtime_session), Some(runtime_preflight)) =
            (runtime_session.as_ref(), runtime_preflight.as_ref())
            && let Some(selected_backend) = runtime_preflight.selected_backend.as_deref()
            && runtime_session.accelerator_backend != selected_backend
        {
            resolution_notes.push(format!(
                "runtime session accelerator_backend {} differs from linked runtime preflight selected_backend {}",
                runtime_session.accelerator_backend, selected_backend
            ));
        }

        let claim_decision = self
            .latest_claim_decision_for_runtime_lineage(
                runtime_session.as_ref().map(|session| &session.id),
                runtime_preflight_id.as_ref(),
            )
            .await?;

        let host_evidence = if let Some(host_evidence_id) = claim_decision
            .as_ref()
            .and_then(|decision| decision.host_evidence_id.as_ref())
        {
            let evidence = self
                .load_external_document::<UvmObserveHostEvidenceContractSnapshot>(
                    "uvm-observe",
                    "host_evidence.json",
                    host_evidence_id.as_str(),
                    "UVM observe host evidence",
                )
                .await?;
            if evidence.is_none() {
                resolution_notes.push(format!(
                    "claim decision references missing host evidence {}",
                    host_evidence_id.as_str()
                ));
            }
            evidence
        } else {
            None
        };

        let latest_perf_attestations = self
            .latest_perf_attestations_for_instance(&instance.id)
            .await?;
        if claim_decision.is_none() && !latest_perf_attestations.is_empty() {
            resolution_notes.push(String::from(
                "observe perf evidence exists but no claim decision links to the current runtime lineage",
            ));
        }

        let runtime_execution_intent = runtime_session_intent
            .as_ref()
            .map(|intent| intent.execution_intent.clone());
        let effective_execution_intent = runtime_execution_intent
            .clone()
            .unwrap_or_else(|| instance.execution_intent.clone());

        let (
            effective_portability_assessment,
            portability_assessment_source,
            portability_assessment_unavailable_reason,
        ) = if let Some(claim_decision) = claim_decision.as_ref() {
            (
                claim_decision.portability_assessment.clone(),
                Some(claim_decision.portability_assessment_source),
                claim_decision.portability_assessment_unavailable_reason,
            )
        } else if let Some(runtime_session_intent) = runtime_session_intent.as_ref() {
            if let Some(assessment) = runtime_session_intent
                .first_placement_portability_assessment
                .clone()
            {
                (
                    Some(assessment),
                    Some(UvmPortabilityAssessmentSource::FirstPlacementLineage),
                    None,
                )
            } else if let Some(runtime_preflight) = runtime_preflight.as_ref() {
                (
                    runtime_preflight.portability_assessment.clone(),
                    runtime_preflight
                        .portability_assessment
                        .as_ref()
                        .map(|_| UvmPortabilityAssessmentSource::LinkedRuntimePreflightLineage),
                    None,
                )
            } else {
                (None, None, None)
            }
        } else if let Some(runtime_preflight) = runtime_preflight.as_ref() {
            (
                runtime_preflight.portability_assessment.clone(),
                runtime_preflight
                    .portability_assessment
                    .as_ref()
                    .map(|_| UvmPortabilityAssessmentSource::RuntimePreflightFallback),
                None,
            )
        } else {
            (None, None, None)
        };

        if let Some(unavailable_reason) = portability_assessment_unavailable_reason {
            resolution_notes.push(format!(
                "portability assessment is unavailable: {}",
                unavailable_reason.as_str()
            ));
        }

        let effective_claim_tier = claim_decision
            .as_ref()
            .map(|decision| decision.highest_claim_tier.clone())
            .or_else(|| {
                runtime_session
                    .as_ref()
                    .map(|session| session.claim_tier.clone())
            })
            .unwrap_or_else(|| instance.claim_tier.clone());
        let effective_claim_status = claim_decision
            .as_ref()
            .map(|decision| decision.claim_status.clone());

        json_response(
            StatusCode::OK,
            &UvmResolvedContractView {
                instance,
                template,
                boot_image,
                install_media_image,
                runtime_session,
                runtime_access,
                runtime_execution_intent,
                runtime_preflight,
                claim_decision,
                host_evidence,
                latest_perf_attestations,
                effective_execution_intent,
                effective_portability_assessment,
                portability_assessment_source,
                portability_assessment_unavailable_reason,
                effective_claim_tier,
                effective_claim_status,
                resolution_notes,
            },
        )
    }

    #[cfg(test)]
    async fn start_instance(
        &self,
        instance_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let headers = HeaderMap::new();
        self.start_instance_with_headers(instance_id, &headers, context)
            .await
    }

    async fn start_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        match self
            .transition_instance_with_headers(
                instance_id,
                headers,
                UvmInstanceState::Stopped,
                UvmInstanceState::Running,
            )
            .await?
        {
            TransitionOutcome::Applied(instance) => {
                self.append_event(
                    "uvm.instance.started.v1",
                    "uvm_instance",
                    instance_id,
                    "started",
                    serde_json::json!({}),
                    context,
                )
                .await?;
                entity_response(
                    StatusCode::OK,
                    &instance.value,
                    &instance.value.metadata,
                    instance.version,
                )
            }
            TransitionOutcome::AlreadyAtTarget(instance) => entity_response(
                StatusCode::OK,
                &instance.value,
                &instance.value.metadata,
                instance.version,
            ),
        }
    }

    #[cfg(test)]
    async fn stop_instance(
        &self,
        instance_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let headers = HeaderMap::new();
        self.stop_instance_with_headers(instance_id, &headers, context)
            .await
    }

    async fn stop_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        match self
            .transition_instance_with_headers(
                instance_id,
                headers,
                UvmInstanceState::Running,
                UvmInstanceState::Stopped,
            )
            .await?
        {
            TransitionOutcome::Applied(instance) => {
                self.append_event(
                    "uvm.instance.stopped.v1",
                    "uvm_instance",
                    instance_id,
                    "stopped",
                    serde_json::json!({}),
                    context,
                )
                .await?;
                entity_response(
                    StatusCode::OK,
                    &instance.value,
                    &instance.value.metadata,
                    instance.version,
                )
            }
            TransitionOutcome::AlreadyAtTarget(instance) => entity_response(
                StatusCode::OK,
                &instance.value,
                &instance.value.metadata,
                instance.version,
            ),
        }
    }

    async fn reboot_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let stored = self.load_instance(instance_id).await?;
        assert_matches_concurrency(headers, &stored)?;
        if stored.value.state != UvmInstanceState::Running {
            return Err(PlatformError::conflict(
                "instance must be running before reboot",
            ));
        }
        let mut instance = stored.value;
        instance.last_transition_at = OffsetDateTime::now_utc();
        instance.metadata.touch(instance_record_etag(&instance));
        let updated = self
            .instances
            .upsert(instance_id, instance.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "uvm.instance.rebooted.v1",
            "uvm_instance",
            instance_id,
            "rebooted",
            serde_json::json!({}),
            context,
        )
        .await?;
        entity_response(
            StatusCode::OK,
            &updated.value,
            &updated.value.metadata,
            updated.version,
        )
    }

    #[cfg(test)]
    async fn migrate_instance(
        &self,
        instance_id: &str,
        request: MigrateInstanceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let headers = HeaderMap::new();
        self.migrate_instance_with_headers(instance_id, &headers, request, context)
            .await
    }

    async fn migrate_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        request: MigrateInstanceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let reason = normalize_reason(&request.reason)?;
        let to_node_id = NodeId::parse(request.to_node_id).map_err(|error| {
            PlatformError::invalid("invalid to_node_id").with_detail(error.to_string())
        })?;
        let target_capability_id = request
            .target_capability_id
            .as_deref()
            .map(normalize_target_capability_id)
            .transpose()?;
        let stored = self.load_instance(instance_id).await?;
        assert_matches_concurrency(headers, &stored)?;
        let mut instance = stored.value;
        let prior_state = instance.state;
        if instance.state == UvmInstanceState::Migrating {
            return Err(PlatformError::conflict(
                "instance state does not permit migration",
            ));
        }
        if matches!(
            instance.state,
            UvmInstanceState::Provisioning | UvmInstanceState::Failed
        ) {
            return Err(PlatformError::conflict(
                "instance state does not permit migration",
            ));
        }
        if instance.migration_policy == "cold_only" && prior_state == UvmInstanceState::Running {
            return Err(PlatformError::conflict(
                "cold_only migration policy requires a stopped instance",
            ));
        }
        if instance.host_node_id.as_ref() == Some(&to_node_id) {
            return entity_response(
                StatusCode::OK,
                &instance,
                &instance.metadata,
                stored.version,
            );
        }
        if self.has_active_migration_workflow(&instance.id).await? {
            return Err(PlatformError::conflict(
                "instance already has an active migration workflow",
            ));
        }

        let checkpoint_reference = request
            .checkpoint_reference
            .as_deref()
            .map(normalize_checkpoint_reference)
            .transpose()?
            .unwrap_or_else(|| String::from(instance.restore_policy_tier.as_str()));
        let checkpoint_kind = request
            .checkpoint_kind
            .as_deref()
            .map(normalize_checkpoint_kind)
            .transpose()?
            .unwrap_or(migration_checkpoint_kind_for_policy(
                &instance.migration_policy,
            )?);
        let migration_max_downtime_ms = Some(match request.migration_max_downtime_ms {
            Some(value) => normalize_migration_max_downtime_ms(value)?,
            None => default_migration_max_downtime_ms_for_policy(&instance.migration_policy)?,
        });
        let portability_assessment = request.portability_assessment;
        let portability_assessment_source = if portability_assessment.is_some() {
            UvmPortabilityAssessmentSource::RequestFallback
        } else {
            UvmPortabilityAssessmentSource::Unavailable
        };
        let portability_assessment_unavailable_reason = None;

        let migration_id = UvmMigrationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate migration id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let migration = UvmMigrationRecord {
            id: migration_id.clone(),
            instance_id: instance.id.clone(),
            from_node_id: instance.host_node_id.clone(),
            to_node_id: to_node_id.clone(),
            reason,
            target_capability_id,
            checkpoint_reference: checkpoint_reference.clone(),
            checkpoint_kind: checkpoint_kind.clone(),
            migration_max_downtime_ms,
            portability_assessment,
            portability_assessment_source,
            portability_assessment_unavailable_reason,
            workflow_kind: String::from(UVM_MIGRATION_WORKFLOW_KIND),
            state: String::from("pending"),
            started_at: now,
            completed_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(migration_id.to_string()),
                sha256_hex(migration_id.as_str().as_bytes()),
            ),
        };
        let stored_workflow = self
            .migration_workflows
            .create(
                migration_id.as_str(),
                build_migration_workflow(migration.clone()),
            )
            .await?;
        self.sync_migration_projection(&stored_workflow.value)
            .await?;
        self.append_event(
            "uvm.instance.migration_requested.v1",
            "uvm_migration",
            migration_id.as_str(),
            "requested",
            serde_json::json!({
                "instance_id": instance.id,
                "from_node_id": migration.from_node_id,
                "to_node_id": migration.to_node_id,
                "reason": migration.reason,
                "target_capability_id": migration.target_capability_id,
                "checkpoint_reference": migration.checkpoint_reference,
                "checkpoint_kind": migration.checkpoint_kind,
                "migration_max_downtime_ms": migration.migration_max_downtime_ms,
                "portability_assessment_source": migration.portability_assessment_source,
            }),
            context,
        )
        .await?;

        let running_workflow = self
            .migration_workflows
            .mutate(migration_id.as_str(), |workflow| {
                workflow.set_phase(WorkflowPhase::Running);
                workflow.current_step_index = Some(0);
                if let Some(step) = workflow.step_mut(0) {
                    step.transition(
                        WorkflowStepState::Completed,
                        Some(format!(
                            "resolved checkpoint reference {} as {}",
                            checkpoint_reference, checkpoint_kind
                        )),
                    );
                }
                workflow.current_step_index = Some(1);
                let portability_denied = workflow
                    .state
                    .portability_assessment
                    .as_ref()
                    .is_some_and(|assessment| !assessment.supported);
                let portability_step_detail = migration_portability_step_detail(&workflow.state);
                if let Some(step) = workflow.step_mut(1) {
                    let step_state = if portability_denied {
                        WorkflowStepState::Failed
                    } else {
                        WorkflowStepState::Completed
                    };
                    step.transition(step_state, Some(portability_step_detail));
                }
                if portability_denied {
                    workflow.set_phase(WorkflowPhase::Failed);
                    return Ok(());
                }
                workflow.current_step_index = Some(UVM_MIGRATION_FINAL_STEP_INDEX);
                let cutover_node_id = workflow.state.to_node_id.to_string();
                if let Some(step) = workflow.step_mut(UVM_MIGRATION_FINAL_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Active,
                        Some(format!(
                            "committing control-plane cutover to node {}",
                            cutover_node_id
                        )),
                    );
                }
                Ok(())
            })
            .await?;
        self.sync_migration_projection(&running_workflow.value)
            .await?;
        if running_workflow.value.phase == WorkflowPhase::Failed {
            self.append_event(
                "uvm.migration.failed.v1",
                "uvm_migration",
                migration_id.as_str(),
                "failed",
                serde_json::json!({
                    "instance_id": instance.id,
                    "from_node_id": migration.from_node_id,
                    "to_node_id": migration.to_node_id,
                    "blockers": migration
                        .portability_assessment
                        .as_ref()
                        .map(|assessment| assessment.blockers.clone())
                        .unwrap_or_default(),
                }),
                context,
            )
            .await?;
            return Err(PlatformError::conflict(
                "portability assessment does not permit migration",
            )
            .with_detail(
                migration
                    .portability_assessment
                    .as_ref()
                    .map(|assessment| assessment.blockers.join("; "))
                    .filter(|detail| !detail.is_empty())
                    .unwrap_or_else(|| {
                        String::from("request portability evidence marked the move unsupported")
                    }),
            ));
        }

        instance.state = match prior_state {
            UvmInstanceState::Stopped => UvmInstanceState::Stopped,
            _ => UvmInstanceState::Running,
        };
        instance.host_node_id = Some(to_node_id.clone());
        instance.last_transition_at = now;
        instance.metadata.touch(instance_record_etag(&instance));
        if let Err(error) = self
            .instances
            .upsert(instance_id, instance.clone(), Some(stored.version))
            .await
        {
            let _ = self
                .mark_migration_workflow_failed(&migration_id, &error)
                .await;
            return Err(error);
        }
        let completed_workflow = self
            .migration_workflows
            .mutate(migration_id.as_str(), |workflow| {
                workflow.current_step_index = Some(UVM_MIGRATION_FINAL_STEP_INDEX);
                let completed_node_id = workflow.state.to_node_id.to_string();
                if let Some(step) = workflow.step_mut(UVM_MIGRATION_FINAL_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Completed,
                        Some(format!(
                            "updated control-plane host node to {}",
                            completed_node_id
                        )),
                    );
                }
                workflow.set_phase(WorkflowPhase::Completed);
                Ok(())
            })
            .await?;
        self.sync_migration_projection(&completed_workflow.value)
            .await?;
        self.append_event(
            "uvm.migration.completed.v1",
            "uvm_migration",
            migration_id.as_str(),
            "completed",
            serde_json::json!({
                "instance_id": instance.id,
                "from_node_id": migration.from_node_id,
                "to_node_id": migration.to_node_id,
                "resulting_state": format!("{:?}", instance.state),
                "target_capability_id": migration.target_capability_id,
                "checkpoint_reference": migration.checkpoint_reference,
                "checkpoint_kind": migration.checkpoint_kind,
                "migration_max_downtime_ms": migration.migration_max_downtime_ms,
                "portability_assessment_source": migration.portability_assessment_source,
            }),
            context,
        )
        .await?;
        let migration = build_migration_projection(&completed_workflow.value);
        entity_response(
            StatusCode::OK,
            &migration,
            &migration.metadata,
            completed_workflow.version,
        )
    }

    #[cfg(test)]
    async fn snapshot_instance(
        &self,
        instance_id: &str,
        request: SnapshotRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let headers = HeaderMap::new();
        self.snapshot_instance_with_headers(instance_id, &headers, request, context)
            .await
    }

    async fn snapshot_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        request: SnapshotRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let snapshot_name = normalize_resource_name(&request.name, "name")?;
        let stored = self.load_instance(instance_id).await?;
        assert_matches_concurrency(headers, &stored)?;
        let instance = stored.value;
        if matches!(
            instance.state,
            UvmInstanceState::Provisioning | UvmInstanceState::Migrating | UvmInstanceState::Failed
        ) {
            return Err(PlatformError::conflict(
                "instance is not in a snapshot-safe state",
            ));
        }
        let crash_consistent = request.crash_consistent.unwrap_or(true);
        if instance.state == UvmInstanceState::Running && !crash_consistent {
            return Err(PlatformError::conflict(
                "running instances require crash_consistent snapshots",
            ));
        }
        if let Some(existing) = self
            .snapshots
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value)
            .find(|snapshot| {
                snapshot.value.instance_id == instance.id
                    && snapshot.value.name.eq_ignore_ascii_case(&snapshot_name)
            })
        {
            if existing.value.crash_consistent != crash_consistent {
                return Err(PlatformError::conflict(
                    "snapshot name already exists for this instance",
                ));
            }
            return entity_response(
                StatusCode::OK,
                &existing.value,
                &existing.value.metadata,
                existing.version,
            );
        }

        let snapshot_id = UvmSnapshotId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate snapshot id")
                .with_detail(error.to_string())
        })?;
        let snapshot = UvmSnapshotRecord {
            id: snapshot_id.clone(),
            instance_id: instance.id,
            name: snapshot_name,
            crash_consistent,
            state: String::from("ready"),
            created_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(snapshot_id.to_string()),
                sha256_hex(snapshot_id.as_str().as_bytes()),
            ),
        };
        let stored_snapshot = self
            .snapshots
            .create(snapshot_id.as_str(), snapshot.clone())
            .await?;
        self.append_event(
            "uvm.snapshot.created.v1",
            "uvm_snapshot",
            snapshot_id.as_str(),
            "created",
            serde_json::json!({
                "instance_id": snapshot.instance_id,
                "crash_consistent": snapshot.crash_consistent,
            }),
            context,
        )
        .await?;
        entity_response(
            StatusCode::CREATED,
            &snapshot,
            &snapshot.metadata,
            stored_snapshot.version,
        )
    }

    #[cfg(test)]
    async fn restore_instance(
        &self,
        instance_id: &str,
        request: RestoreRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let headers = HeaderMap::new();
        self.restore_instance_with_headers(instance_id, &headers, request, context)
            .await
    }

    async fn restore_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        request: RestoreRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let snapshot_id = UvmSnapshotId::parse(request.snapshot_id).map_err(|error| {
            PlatformError::invalid("invalid snapshot_id").with_detail(error.to_string())
        })?;
        let snapshot = self
            .snapshots
            .get(snapshot_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("snapshot does not exist"))?;
        if snapshot.deleted {
            return Err(PlatformError::not_found("snapshot does not exist"));
        }
        let stored = self.load_instance(instance_id).await?;
        assert_matches_concurrency(headers, &stored)?;
        if snapshot.value.instance_id.as_str() != instance_id {
            return Err(PlatformError::conflict(
                "snapshot does not belong to the requested instance",
            ));
        }
        if snapshot.value.state != "ready" {
            return Err(PlatformError::conflict(
                "snapshot is not in a restore-ready state",
            ));
        }
        let mut instance = stored.value;
        if matches!(
            instance.state,
            UvmInstanceState::Provisioning | UvmInstanceState::Migrating
        ) {
            return Err(PlatformError::conflict(
                "instance state does not permit restore",
            ));
        }
        if instance.state == UvmInstanceState::Stopped && instance.host_node_id.is_none() {
            return entity_response(
                StatusCode::OK,
                &instance,
                &instance.metadata,
                stored.version,
            );
        }
        instance.state = UvmInstanceState::Stopped;
        instance.host_node_id = None;
        instance.last_transition_at = OffsetDateTime::now_utc();
        instance.metadata.touch(instance_record_etag(&instance));
        let updated = self
            .instances
            .upsert(instance_id, instance.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "uvm.snapshot.restored.v1",
            "uvm_instance",
            instance_id,
            "restored",
            serde_json::json!({
                "snapshot_id": snapshot_id,
            }),
            context,
        )
        .await?;
        entity_response(
            StatusCode::OK,
            &updated.value,
            &updated.value.metadata,
            updated.version,
        )
    }

    async fn transition_instance_with_headers(
        &self,
        instance_id: &str,
        headers: &HeaderMap,
        from_state: UvmInstanceState,
        to_state: UvmInstanceState,
    ) -> Result<TransitionOutcome> {
        let stored = self.load_instance(instance_id).await?;
        assert_matches_concurrency(headers, &stored)?;
        if stored.value.state == to_state {
            return Ok(TransitionOutcome::AlreadyAtTarget(stored));
        }
        if stored.value.state != from_state {
            return Err(PlatformError::conflict(format!(
                "instance state mismatch: expected {:?}, got {:?}",
                from_state, stored.value.state
            )));
        }
        let mut instance = stored.value.clone();
        instance.state = to_state;
        instance.last_transition_at = OffsetDateTime::now_utc();
        instance.metadata.touch(instance_record_etag(&instance));
        let applied = self
            .instances
            .upsert(instance_id, instance, Some(stored.version))
            .await?;
        Ok(TransitionOutcome::Applied(applied))
    }

    async fn load_instance(&self, instance_id: &str) -> Result<StoredDocument<UvmInstanceRecord>> {
        let stored = self
            .instances
            .get(instance_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("instance does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("instance does not exist"));
        }
        Ok(stored)
    }

    async fn has_active_migration_workflow(&self, instance_id: &UvmInstanceId) -> Result<bool> {
        Ok(self
            .migration_workflows
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .any(|(_, stored)| {
                stored.value.subject_id == instance_id.as_str()
                    && matches!(
                        stored.value.phase,
                        WorkflowPhase::Pending | WorkflowPhase::Running | WorkflowPhase::Paused
                    )
            }))
    }

    async fn sync_migration_projection(&self, workflow: &UvmMigrationWorkflow) -> Result<()> {
        let key = workflow.id.as_str();
        let record = build_migration_projection(workflow);
        loop {
            match self.migrations.get(key).await? {
                Some(existing) if !existing.deleted && existing.value == record => return Ok(()),
                Some(existing) => {
                    match self
                        .migrations
                        .upsert(key, record.clone(), Some(existing.version))
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self.migrations.create(key, record.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                },
            }
        }
    }

    async fn mark_migration_workflow_failed(
        &self,
        migration_id: &UvmMigrationId,
        error: &PlatformError,
    ) -> Result<()> {
        let detail = error
            .detail
            .clone()
            .unwrap_or_else(|| error.message.clone());
        let failed = self
            .migration_workflows
            .mutate(migration_id.as_str(), |workflow| {
                workflow.current_step_index = Some(UVM_MIGRATION_FINAL_STEP_INDEX);
                if let Some(step) = workflow.step_mut(UVM_MIGRATION_FINAL_STEP_INDEX) {
                    step.transition(WorkflowStepState::Failed, Some(detail.clone()));
                }
                workflow.set_phase(WorkflowPhase::Failed);
                Ok(())
            })
            .await?;
        self.sync_migration_projection(&failed.value).await
    }

    async fn reconcile_instances(
        &self,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_sessions = self.load_runtime_session_snapshots().await?;
        let instances = self.instances.list().await?;
        let mut issues = Vec::new();
        let mut runtimes_by_instance =
            std::collections::BTreeMap::<String, Vec<UvmNodeRuntimeSessionSnapshot>>::new();
        for runtime in &runtime_sessions {
            runtimes_by_instance
                .entry(runtime.instance_id.clone())
                .or_default()
                .push(runtime.clone());
        }
        for (_, stored) in instances.iter().filter(|(_, stored)| !stored.deleted) {
            let instance = &stored.value;
            let runtime_matches = runtimes_by_instance
                .remove(instance.id.as_str())
                .unwrap_or_default();
            match instance.state {
                UvmInstanceState::Running => {
                    if runtime_matches.is_empty() {
                        issues.push(UvmReconciliationIssue {
                            severity: String::from("critical"),
                            code: String::from("running_instance_without_runtime"),
                            instance_id: Some(instance.id.clone()),
                            runtime_session_id: None,
                            detail: String::from(
                                "control-plane instance is running but no node-plane runtime session exists",
                            ),
                        });
                    }
                    for runtime in runtime_matches {
                        if runtime.state != "running" {
                            issues.push(UvmReconciliationIssue {
                                severity: String::from("high"),
                                code: String::from("running_instance_runtime_state_mismatch"),
                                instance_id: Some(instance.id.clone()),
                                runtime_session_id: Some(runtime.runtime_session_id.clone()),
                                detail: format!(
                                    "control-plane instance is running but runtime session on node {} reports state {}",
                                    runtime.node_id, runtime.state
                                ),
                            });
                        }
                    }
                }
                UvmInstanceState::Stopped => {
                    for runtime in runtime_matches {
                        issues.push(UvmReconciliationIssue {
                            severity: String::from("high"),
                            code: String::from("stopped_instance_with_runtime"),
                            instance_id: Some(instance.id.clone()),
                            runtime_session_id: Some(runtime.runtime_session_id.clone()),
                            detail: format!(
                                "control-plane instance is stopped but runtime session on node {} reports state {}",
                                runtime.node_id, runtime.state
                            ),
                        });
                    }
                }
                UvmInstanceState::Migrating => {
                    if runtime_matches
                        .iter()
                        .all(|runtime| !runtime.migration_in_progress)
                    {
                        issues.push(UvmReconciliationIssue {
                            severity: String::from("high"),
                            code: String::from("migrating_instance_without_runtime_lock"),
                            instance_id: Some(instance.id.clone()),
                            runtime_session_id: None,
                            detail: String::from(
                                "control-plane instance is migrating but no node-plane runtime session reports migration_in_progress",
                            ),
                        });
                    }
                }
                UvmInstanceState::Provisioning | UvmInstanceState::Failed => {}
            }
        }
        for runtimes in runtimes_by_instance.into_values() {
            for runtime in runtimes {
                issues.push(UvmReconciliationIssue {
                    severity: String::from("medium"),
                    code: String::from("orphan_runtime_session"),
                    instance_id: None,
                    runtime_session_id: Some(runtime.runtime_session_id.clone()),
                    detail: format!(
                        "node-plane runtime session for instance {} exists on node {} without a control-plane instance record",
                        runtime.instance_id, runtime.node_id
                    ),
                });
            }
        }

        let report_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate UVM reconciliation report id")
                .with_detail(error.to_string())
        })?;
        let report = UvmReconciliationReport {
            id: report_id.clone(),
            generated_at: OffsetDateTime::now_utc(),
            total_instances: instances
                .iter()
                .filter(|(_, stored)| !stored.deleted)
                .count(),
            total_runtime_sessions: runtime_sessions.len(),
            status: String::from(if issues.is_empty() {
                "clean"
            } else {
                "drift_detected"
            }),
            issues,
        };
        self.reconciliations
            .create(report.id.as_str(), report.clone())
            .await?;
        self.append_event(
            "uvm.control.reconciled.v1",
            "uvm_reconciliation_report",
            report.id.as_str(),
            "reconciled",
            serde_json::json!({
                "status": report.status,
                "total_instances": report.total_instances,
                "total_runtime_sessions": report.total_runtime_sessions,
                "issue_count": report.issues.len(),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &report)
    }

    async fn control_summary(&self) -> Result<http::Response<ApiBody>> {
        let mut template_count = 0_usize;
        let mut instance_count = 0_usize;
        let mut instance_state_totals = BTreeMap::new();
        let mut template_claim_tier_totals = BTreeMap::new();
        let mut instance_claim_tier_totals = BTreeMap::new();
        let mut template_preferred_backend_totals = BTreeMap::new();
        let mut instance_preferred_backend_totals = BTreeMap::new();
        let latest_claim_decision = self.load_latest_claim_decision_snapshot().await?;

        for (_, stored) in self.templates.list().await? {
            if stored.deleted {
                continue;
            }
            let template = stored.value;
            template_count += 1;
            increment_summary_total(&mut template_claim_tier_totals, template.claim_tier);
            increment_summary_total(
                &mut template_preferred_backend_totals,
                preferred_backend_summary_key(template.execution_intent.preferred_backend),
            );
        }

        for (_, stored) in self.instances.list().await? {
            if stored.deleted {
                continue;
            }
            let instance = stored.value;
            instance_count += 1;
            increment_summary_total(
                &mut instance_state_totals,
                instance_state_summary_key(instance.state),
            );
            increment_summary_total(&mut instance_claim_tier_totals, instance.claim_tier);
            increment_summary_total(
                &mut instance_preferred_backend_totals,
                preferred_backend_summary_key(instance.execution_intent.preferred_backend),
            );
        }

        json_response(
            StatusCode::OK,
            &UvmControlSummary {
                template_count,
                instance_count,
                instance_state_totals,
                template_claim_tier_totals,
                instance_claim_tier_totals,
                template_preferred_backend_totals,
                instance_preferred_backend_totals,
                effective_claim_publication_state: latest_claim_decision
                    .as_ref()
                    .map(|decision| decision.claim_status.clone()),
                failing_workload_classes: latest_claim_decision
                    .map(|decision| decision.failing_workload_classes)
                    .unwrap_or_default(),
            },
        )
    }

    async fn load_external_collection<T>(
        &self,
        service_dir: &str,
        file_name: &str,
        label: &str,
    ) -> Result<Vec<T>>
    where
        T: DeserializeOwned,
    {
        let Some(platform_root) = self.state_root.parent() else {
            return Ok(Vec::new());
        };
        let path = platform_root.join(service_dir).join(file_name);
        if fs::metadata(&path).await.is_err() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).await.map_err(|error| {
            PlatformError::unavailable(format!("failed to read {label}"))
                .with_detail(error.to_string())
        })?;
        let collection: DocumentCollection<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label}"))
                    .with_detail(error.to_string())
            })?;
        let mut values = Vec::new();
        for (_, stored) in collection.records {
            if stored.deleted {
                continue;
            }
            let value = serde_json::from_value(stored.value).map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label} record"))
                    .with_detail(error.to_string())
            })?;
            values.push(value);
        }
        Ok(values)
    }

    async fn load_external_document<T>(
        &self,
        service_dir: &str,
        file_name: &str,
        document_id: &str,
        label: &str,
    ) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let Some(platform_root) = self.state_root.parent() else {
            return Ok(None);
        };
        let path = platform_root.join(service_dir).join(file_name);
        if fs::metadata(&path).await.is_err() {
            return Ok(None);
        }
        let bytes = fs::read(&path).await.map_err(|error| {
            PlatformError::unavailable(format!("failed to read {label}"))
                .with_detail(error.to_string())
        })?;
        let collection: DocumentCollection<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label}"))
                    .with_detail(error.to_string())
            })?;
        let Some(stored) = collection.records.get(document_id) else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        let value = serde_json::from_value(stored.value.clone()).map_err(|error| {
            PlatformError::invalid(format!("failed to decode {label} record"))
                .with_detail(error.to_string())
        })?;
        Ok(Some(value))
    }

    async fn load_external_stored_collection<T>(
        &self,
        service_dir: &str,
        file_name: &str,
        label: &str,
    ) -> Result<Vec<StoredDocument<T>>>
    where
        T: DeserializeOwned,
    {
        let Some(platform_root) = self.state_root.parent() else {
            return Ok(Vec::new());
        };
        let path = platform_root.join(service_dir).join(file_name);
        if fs::metadata(&path).await.is_err() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).await.map_err(|error| {
            PlatformError::unavailable(format!("failed to read {label}"))
                .with_detail(error.to_string())
        })?;
        let collection: DocumentCollection<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label}"))
                    .with_detail(error.to_string())
            })?;
        let mut values = Vec::new();
        for (_, stored) in collection.records {
            if stored.deleted {
                continue;
            }
            let value = serde_json::from_value(stored.value).map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label} record"))
                    .with_detail(error.to_string())
            })?;
            values.push(StoredDocument {
                version: stored.version,
                updated_at: stored.updated_at,
                deleted: stored.deleted,
                value,
            });
        }
        Ok(values)
    }

    async fn load_external_stored_document<T>(
        &self,
        service_dir: &str,
        file_name: &str,
        document_id: &str,
        label: &str,
    ) -> Result<Option<StoredDocument<T>>>
    where
        T: DeserializeOwned,
    {
        let Some(platform_root) = self.state_root.parent() else {
            return Ok(None);
        };
        let path = platform_root.join(service_dir).join(file_name);
        if fs::metadata(&path).await.is_err() {
            return Ok(None);
        }
        let bytes = fs::read(&path).await.map_err(|error| {
            PlatformError::unavailable(format!("failed to read {label}"))
                .with_detail(error.to_string())
        })?;
        let collection: DocumentCollection<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                PlatformError::invalid(format!("failed to decode {label}"))
                    .with_detail(error.to_string())
            })?;
        let Some(stored) = collection.records.get(document_id) else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        let value = serde_json::from_value(stored.value.clone()).map_err(|error| {
            PlatformError::invalid(format!("failed to decode {label} record"))
                .with_detail(error.to_string())
        })?;
        Ok(Some(StoredDocument {
            version: stored.version,
            updated_at: stored.updated_at,
            deleted: stored.deleted,
            value,
        }))
    }

    async fn latest_runtime_session_for_instance(
        &self,
        instance_id: &UvmInstanceId,
    ) -> Result<Option<UvmRuntimeSessionContractSnapshot>> {
        let mut rows = self
            .load_external_collection::<UvmRuntimeSessionContractSnapshot>(
                "uvm-node",
                "runtime_sessions.json",
                "UVM node runtime session view",
            )
            .await?
            .into_iter()
            .filter(|row| row.instance_id == *instance_id)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.last_transition_at.cmp(&right.last_transition_at))
                .then(left.id.as_str().cmp(right.id.as_str()))
        });
        Ok(rows.pop())
    }

    async fn latest_runtime_access_for_runtime_session(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> Result<Option<UvmRuntimeNetworkAccessContractSnapshot>> {
        let mut rows = self
            .load_external_collection::<UvmRunnerSupervisionContractSnapshot>(
                "uvm-node",
                "runner_supervision.json",
                "UVM runner supervision view",
            )
            .await?
            .into_iter()
            .filter(|row| row.runtime_session_id == *runtime_session_id)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.runtime_incarnation
                .cmp(&right.runtime_incarnation)
                .then(left.last_event_at.cmp(&right.last_event_at))
                .then(left.state.cmp(&right.state))
        });
        Ok(rows.pop().and_then(|row| row.network_access))
    }

    async fn latest_claim_decision_for_runtime_lineage(
        &self,
        runtime_session_id: Option<&UvmRuntimeSessionId>,
        runtime_preflight_id: Option<&AuditId>,
    ) -> Result<Option<UvmObserveClaimDecisionContractSnapshot>> {
        let rows = self
            .load_external_collection::<UvmObserveClaimDecisionContractSnapshot>(
                "uvm-observe",
                "claim_decisions.json",
                "UVM observe claim decision view",
            )
            .await?;

        let mut matching = if let Some(runtime_session_id) = runtime_session_id {
            let session_matching = rows
                .iter()
                .filter(|row| row.runtime_session_id.as_ref() == Some(runtime_session_id))
                .cloned()
                .collect::<Vec<_>>();
            if !session_matching.is_empty() {
                session_matching
            } else if let Some(runtime_preflight_id) = runtime_preflight_id {
                rows.into_iter()
                    .filter(|row| row.runtime_preflight_id.as_ref() == Some(runtime_preflight_id))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else if let Some(runtime_preflight_id) = runtime_preflight_id {
            rows.into_iter()
                .filter(|row| row.runtime_preflight_id.as_ref() == Some(runtime_preflight_id))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        matching.sort_by(|left, right| {
            left.decided_at
                .cmp(&right.decided_at)
                .then(left.id.as_str().cmp(right.id.as_str()))
        });
        Ok(matching.pop())
    }

    async fn latest_perf_attestations_for_instance(
        &self,
        instance_id: &UvmInstanceId,
    ) -> Result<Vec<UvmObservePerfAttestationContractSnapshot>> {
        let rows = self
            .load_external_collection::<UvmObservePerfAttestationContractSnapshot>(
                "uvm-observe",
                "perf_attestations.json",
                "UVM observe perf attestation view",
            )
            .await?;
        let mut latest_by_workload = BTreeMap::new();
        for row in rows
            .into_iter()
            .filter(|row| row.instance_id == *instance_id)
        {
            let workload_class = row.workload_class.clone();
            let replace = latest_by_workload
                .get(&workload_class)
                .map(|current: &UvmObservePerfAttestationContractSnapshot| {
                    row.measured_at > current.measured_at
                        || (row.measured_at == current.measured_at
                            && row.id.as_str() > current.id.as_str())
                })
                .unwrap_or(true);
            if replace {
                latest_by_workload.insert(workload_class, row);
            }
        }
        let mut latest = latest_by_workload.into_values().collect::<Vec<_>>();
        latest.sort_by(|left, right| {
            left.workload_class
                .cmp(&right.workload_class)
                .then(left.measured_at.cmp(&right.measured_at))
                .then(left.id.as_str().cmp(right.id.as_str()))
        });
        Ok(latest)
    }

    async fn load_runtime_session_snapshots(&self) -> Result<Vec<UvmNodeRuntimeSessionSnapshot>> {
        self.load_external_collection(
            "uvm-node",
            "runtime_sessions.json",
            "UVM node runtime session view",
        )
        .await
    }

    async fn load_latest_claim_decision_snapshot(
        &self,
    ) -> Result<Option<UvmObserveClaimDecisionSnapshot>> {
        let mut latest = self
            .load_external_collection::<UvmObserveClaimDecisionSnapshot>(
                "uvm-observe",
                "claim_decisions.json",
                "UVM observe claim decision view",
            )
            .await?;
        latest.sort_by(|left, right| {
            left.decided_at
                .cmp(&right.decided_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(latest.pop())
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
        let details_json = serde_json::to_string(&details).map_err(|error| {
            PlatformError::unavailable("failed to encode event details")
                .with_detail(error.to_string())
        })?;
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("uvm-control"),
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
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
                action: action.to_owned(),
                details,
            }),
        };
        self.audit_log.append(&event).await?;
        let correlation_id = context.correlation_id.clone();
        let idempotency = sha256_hex(
            format!(
                "uvm-control-event:v1|{}|{}|{}|{}|{}|{}",
                event_type, resource_kind, resource_id, action, correlation_id, details_json
            )
            .as_bytes(),
        );
        let _ = self
            .outbox
            .enqueue(event_type, event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for UvmControlService {
    fn name(&self) -> &'static str {
        "uvm-control"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/uvm"),
            uhost_runtime::RouteClaim::exact("/uvm/control/summary"),
            uhost_runtime::RouteClaim::prefix("/uvm/templates"),
            uhost_runtime::RouteClaim::prefix("/uvm/instances"),
            uhost_runtime::RouteClaim::prefix("/uvm/snapshots"),
            uhost_runtime::RouteClaim::prefix("/uvm/migrations"),
            uhost_runtime::RouteClaim::prefix("/uvm/reconciliation"),
            uhost_runtime::RouteClaim::prefix("/uvm/outbox"),
        ];
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
                (Method::GET, ["uvm"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "hypervisor": "uvm",
                    }),
                )
                .map(Some),
                (Method::GET, ["uvm", "control", "summary"]) => {
                    self.control_summary().await.map(Some)
                }
                (Method::GET, ["uvm", "templates"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self
                        .templates
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    records.sort_by(|left, right| {
                        left.name
                            .cmp(&right.name)
                            .then(left.id.as_str().cmp(right.id.as_str()))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::GET, ["uvm", "templates", template_id]) => {
                    self.get_template(template_id).await.map(Some)
                }
                (Method::POST, ["uvm", "templates"]) => {
                    let body: CreateTemplateRequest = parse_json(request).await?;
                    self.create_template(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "instances"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self
                        .instances
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    records.sort_by(|left, right| {
                        left.name
                            .cmp(&right.name)
                            .then(left.id.as_str().cmp(right.id.as_str()))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::GET, ["uvm", "instances", instance_id, "runtime-sessions"]) => {
                    let list_request = list_request_from_query(&query)?;
                    self.list_runtime_sessions_for_instance(instance_id, list_request.as_ref())
                        .await
                        .map(Some)
                }
                (
                    Method::GET,
                    [
                        "uvm",
                        "instances",
                        instance_id,
                        "runtime-sessions",
                        session_id,
                    ],
                ) => self
                    .get_runtime_session_for_instance(instance_id, session_id)
                    .await
                    .map(Some),
                (Method::GET, ["uvm", "instances", instance_id, "runtime-checkpoints"]) => {
                    let list_request = list_request_from_query(&query)?;
                    self.list_runtime_checkpoints_for_instance(instance_id, list_request.as_ref())
                        .await
                        .map(Some)
                }
                (
                    Method::GET,
                    [
                        "uvm",
                        "instances",
                        instance_id,
                        "runtime-checkpoints",
                        checkpoint_id,
                    ],
                ) => self
                    .get_runtime_checkpoint_for_instance(instance_id, checkpoint_id)
                    .await
                    .map(Some),
                (Method::GET, ["uvm", "instances", instance_id, "resolved-contract"]) => self
                    .get_resolved_instance_contract(instance_id)
                    .await
                    .map(Some),
                (Method::GET, ["uvm", "instances", instance_id]) => {
                    self.get_instance(instance_id).await.map(Some)
                }
                (Method::POST, ["uvm", "instances"]) => {
                    let body: CreateInstanceRequest = parse_json(request).await?;
                    self.create_instance(body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "instances", instance_id, "start"]) => self
                    .start_instance_with_headers(instance_id, request.headers(), &context)
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "instances", instance_id, "stop"]) => self
                    .stop_instance_with_headers(instance_id, request.headers(), &context)
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "instances", instance_id, "reboot"]) => self
                    .reboot_instance_with_headers(instance_id, request.headers(), &context)
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "instances", instance_id, "migrate"]) => {
                    let headers = request.headers().clone();
                    let body: MigrateInstanceRequest = parse_json(request).await?;
                    self.migrate_instance_with_headers(instance_id, &headers, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "instances", instance_id, "snapshot"]) => {
                    let headers = request.headers().clone();
                    let body: SnapshotRequest = parse_json(request).await?;
                    self.snapshot_instance_with_headers(instance_id, &headers, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "instances", instance_id, "restore"]) => {
                    let headers = request.headers().clone();
                    let body: RestoreRequest = parse_json(request).await?;
                    self.restore_instance_with_headers(instance_id, &headers, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "snapshots"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self
                        .snapshots
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    records.sort_by(|left, right| {
                        left.created_at
                            .cmp(&right.created_at)
                            .then(left.name.cmp(&right.name))
                            .then(left.id.as_str().cmp(right.id.as_str()))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::GET, ["uvm", "snapshots", snapshot_id]) => {
                    self.get_snapshot(snapshot_id).await.map(Some)
                }
                (Method::GET, ["uvm", "migrations"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self
                        .migrations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    records.sort_by(|left, right| {
                        left.started_at
                            .cmp(&right.started_at)
                            .then(left.id.as_str().cmp(right.id.as_str()))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::GET, ["uvm", "migrations", migration_id]) => {
                    self.get_migration(migration_id).await.map(Some)
                }
                (Method::GET, ["uvm", "reconciliation"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self
                        .reconciliations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    records.sort_by(|left, right| {
                        right
                            .generated_at
                            .cmp(&left.generated_at)
                            .then(left.id.as_str().cmp(right.id.as_str()))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::POST, ["uvm", "reconciliation"]) => {
                    self.reconcile_instances(&context).await.map(Some)
                }
                (Method::GET, ["uvm", "outbox"]) => {
                    let list_request = list_request_from_query(&query)?;
                    let mut records = self.outbox.list_all().await?;
                    records.sort_by(|left, right| {
                        left.created_at
                            .cmp(&right.created_at)
                            .then(left.id.cmp(&right.id))
                    });
                    paginated_json_response(records, list_request.as_ref()).map(Some)
                }
                (Method::GET, ["uvm", "outbox", message_id]) => {
                    self.get_outbox_message(message_id).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

const MAX_NAME_LEN: usize = 128;
const MAX_PROFILE_LEN: usize = 64;
const MAX_GUEST_OS_LEN: usize = 96;
const MAX_REASON_LEN: usize = 512;
const MAX_REFERENCE_LEN: usize = 256;
const RECORD_VERSION_HEADER: HeaderName = HeaderName::from_static("x-record-version");
const DEFAULT_PAGE_LIMIT: usize = 50;
const MAX_PAGE_LIMIT: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OffsetPageCursor {
    offset: usize,
}

trait HasMetadata {
    fn metadata(&self) -> &ResourceMetadata;
}

impl HasMetadata for UvmTemplateRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for UvmInstanceRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for UvmSnapshotRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for UvmMigrationRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for UvmRuntimeSessionReadRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for UvmRuntimeCheckpointReadRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

fn entity_response<T>(
    status: StatusCode,
    payload: &T,
    metadata: &ResourceMetadata,
    version: u64,
) -> Result<Response<ApiBody>>
where
    T: Serialize,
{
    let response = json_response(status, payload)?;
    let mut response = with_etag(response, format!("\"{}\"", metadata.etag))?;
    response.headers_mut().insert(
        RECORD_VERSION_HEADER,
        HeaderValue::from_str(&version.to_string()).map_err(|error| {
            PlatformError::invalid("invalid x-record-version header").with_detail(error.to_string())
        })?,
    );
    Ok(response)
}

fn expected_record_version(headers: &HeaderMap) -> Result<Option<u64>> {
    let Some(value) = headers.get(&RECORD_VERSION_HEADER) else {
        return Ok(None);
    };
    let version = value
        .to_str()
        .map_err(|error| {
            PlatformError::invalid("invalid x-record-version header").with_detail(error.to_string())
        })?
        .parse::<u64>()
        .map_err(|error| {
            PlatformError::invalid("invalid x-record-version header").with_detail(error.to_string())
        })?;
    Ok(Some(version))
}

fn expected_if_match(headers: &HeaderMap) -> Result<Option<ConcurrencyToken>> {
    let Some(value) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|error| {
        PlatformError::invalid("invalid If-Match header").with_detail(error.to_string())
    })?;
    let trimmed = value.trim();
    if trimmed == "*" {
        return Ok(None);
    }
    Ok(Some(ConcurrencyToken::new(
        trimmed.trim_matches('"').to_owned(),
    )))
}

fn assert_matches_concurrency<T>(headers: &HeaderMap, stored: &StoredDocument<T>) -> Result<()>
where
    T: HasMetadata,
{
    if let Some(expected_version) = expected_record_version(headers)?
        && expected_version != stored.version
    {
        return Err(PlatformError::conflict("record version does not match"));
    }

    if let Some(expected_etag) = expected_if_match(headers)?
        && expected_etag.as_str() != stored.value.metadata().etag.as_str()
    {
        return Err(PlatformError::conflict("etag does not match"));
    }

    Ok(())
}

fn list_request_from_query(query: &BTreeMap<String, String>) -> Result<Option<ListRequest>> {
    if !query.contains_key("limit") && !query.contains_key("cursor") {
        return Ok(None);
    }

    let request = ListRequest {
        limit: Some(
            query
                .get("limit")
                .map_or(Ok(DEFAULT_PAGE_LIMIT), |value| parse_page_limit(value))?,
        ),
        cursor: query.get("cursor").cloned().map(PageCursor::new),
        ..ListRequest::default()
    };
    request.validate().map_err(map_list_request_error)?;
    Ok(Some(request))
}

fn map_list_request_error(error: ListRequestError) -> PlatformError {
    match error {
        ListRequestError::InvalidLimit => {
            PlatformError::invalid("list limit must be greater than zero")
        }
        ListRequestError::EmptyFilterField { .. } => {
            PlatformError::invalid("list filters must not be empty")
        }
    }
}

fn parse_page_limit(value: &str) -> Result<usize> {
    let limit = value.parse::<usize>().map_err(|error| {
        PlatformError::invalid("invalid list limit").with_detail(error.to_string())
    })?;
    if limit == 0 {
        return Err(PlatformError::invalid(
            "list limit must be greater than zero",
        ));
    }
    Ok(limit.min(MAX_PAGE_LIMIT))
}

fn encode_offset_page_cursor(offset: usize) -> Result<PageCursor> {
    let bytes = serde_json::to_vec(&OffsetPageCursor { offset }).map_err(|error| {
        PlatformError::invalid("failed to encode page cursor").with_detail(error.to_string())
    })?;
    Ok(PageCursor::new(base64url_encode(&bytes)))
}

fn decode_offset_page_cursor(cursor: &PageCursor) -> Result<usize> {
    let bytes = base64url_decode(cursor.as_str()).map_err(|error| {
        PlatformError::invalid("invalid page cursor").with_detail(error.to_string())
    })?;
    let decoded: OffsetPageCursor = serde_json::from_slice(&bytes).map_err(|error| {
        PlatformError::invalid("invalid page cursor").with_detail(error.to_string())
    })?;
    Ok(decoded.offset)
}

fn paginated_json_response<T>(
    items: Vec<T>,
    list_request: Option<&ListRequest>,
) -> Result<Response<ApiBody>>
where
    T: Clone + Serialize,
{
    if let Some(list_request) = list_request {
        return json_response(StatusCode::OK, &page_from_items(items, list_request)?);
    }
    json_response(StatusCode::OK, &items)
}

fn page_from_items<T>(items: Vec<T>, request: &ListRequest) -> Result<Page<T>>
where
    T: Clone,
{
    let limit = request.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let start = request
        .cursor
        .as_ref()
        .map(decode_offset_page_cursor)
        .transpose()?
        .unwrap_or(0);
    if start > items.len() {
        return Err(PlatformError::conflict(
            "page cursor is ahead of the current result set",
        ));
    }

    let end = start.saturating_add(limit).min(items.len());
    let next_cursor = (end < items.len())
        .then(|| encode_offset_page_cursor(end))
        .transpose()?;

    Ok(Page {
        items: items[start..end].to_vec(),
        next_cursor,
    })
}

fn instance_record_etag(record: &UvmInstanceRecord) -> String {
    sha256_hex(
        format!(
            "{}:{:?}:{}:{}",
            record.id.as_str(),
            record.state,
            record
                .host_node_id
                .as_ref()
                .map(|node_id| node_id.as_str())
                .unwrap_or(""),
            record.last_transition_at.unix_timestamp_nanos(),
        )
        .as_bytes(),
    )
}

fn build_migration_workflow(record: UvmMigrationRecord) -> UvmMigrationWorkflow {
    WorkflowInstance::new(
        record.id.to_string(),
        UVM_MIGRATION_WORKFLOW_KIND,
        UVM_MIGRATION_WORKFLOW_SUBJECT_KIND,
        record.instance_id.to_string(),
        record,
        vec![
            WorkflowStep::new("resolve_checkpoint_contract", 0),
            WorkflowStep::new("validate_portability_evidence", 1),
            WorkflowStep::new(
                "commit_control_plane_cutover",
                UVM_MIGRATION_FINAL_STEP_INDEX,
            ),
        ],
    )
}

fn build_migration_projection(workflow: &UvmMigrationWorkflow) -> UvmMigrationRecord {
    let mut record = workflow.state.clone();
    record.workflow_kind = String::from(UVM_MIGRATION_WORKFLOW_KIND);
    record.state = String::from(workflow_phase_label(&workflow.phase));
    record.started_at = workflow.created_at;
    record.completed_at = workflow.completed_at;
    record.metadata.created_at = workflow.created_at;
    record.metadata.updated_at = workflow.updated_at;
    record.metadata.lifecycle = migration_metadata_lifecycle(&workflow.phase);
    record.metadata.etag = sha256_hex(
        format!(
            "{}:{}:{:?}",
            workflow.id,
            workflow_phase_label(&workflow.phase),
            workflow.current_step_index,
        )
        .as_bytes(),
    );
    record.metadata.annotations.insert(
        String::from("uvm.migration.workflow_kind"),
        String::from(UVM_MIGRATION_WORKFLOW_KIND),
    );
    record.metadata.annotations.insert(
        String::from("uvm.migration.workflow_phase"),
        String::from(workflow_phase_label(&workflow.phase)),
    );
    if let Some(current_step_index) = workflow.current_step_index {
        if let Some(step) = workflow
            .steps
            .iter()
            .find(|step| step.index == current_step_index)
        {
            record.metadata.annotations.insert(
                String::from("uvm.migration.current_step"),
                step.name.clone(),
            );
        }
    } else {
        record
            .metadata
            .annotations
            .remove("uvm.migration.current_step");
    }
    record
}

fn migration_portability_step_detail(record: &UvmMigrationRecord) -> String {
    match record.portability_assessment.as_ref() {
        Some(assessment) if assessment.supported => format!(
            "stored portability assessment from {} with {} evidence row(s)",
            record.portability_assessment_source.as_str(),
            assessment.evidence.len(),
        ),
        Some(assessment) => {
            let blockers = if assessment.blockers.is_empty() {
                String::from("requested move is unsupported")
            } else {
                assessment.blockers.join("; ")
            };
            format!(
                "portability assessment from {} denied the move: {}",
                record.portability_assessment_source.as_str(),
                blockers,
            )
        }
        None => String::from(
            "no portability assessment supplied; workflow preserved request contract only",
        ),
    }
}

fn workflow_phase_label(phase: &WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Pending => "pending",
        WorkflowPhase::Running => "running",
        WorkflowPhase::Paused => "paused",
        WorkflowPhase::Completed => "completed",
        WorkflowPhase::Failed => "failed",
        WorkflowPhase::RolledBack => "rolled_back",
    }
}

fn migration_metadata_lifecycle(phase: &WorkflowPhase) -> ResourceLifecycleState {
    match phase {
        WorkflowPhase::Pending | WorkflowPhase::Running | WorkflowPhase::Paused => {
            ResourceLifecycleState::Pending
        }
        WorkflowPhase::Completed => ResourceLifecycleState::Ready,
        WorkflowPhase::Failed | WorkflowPhase::RolledBack => ResourceLifecycleState::Failed,
    }
}

fn increment_summary_total(totals: &mut BTreeMap<String, usize>, key: String) {
    let entry = totals.entry(key).or_insert(0);
    *entry += 1;
}

fn instance_state_summary_key(state: UvmInstanceState) -> String {
    String::from(match state {
        UvmInstanceState::Provisioning => "provisioning",
        UvmInstanceState::Stopped => "stopped",
        UvmInstanceState::Running => "running",
        UvmInstanceState::Migrating => "migrating",
        UvmInstanceState::Failed => "failed",
    })
}

fn preferred_backend_summary_key(preferred_backend: Option<HypervisorBackend>) -> String {
    preferred_backend
        .map(|backend| String::from(backend.as_str()))
        .unwrap_or_else(|| String::from("unspecified"))
}

fn default_machine_family_key() -> String {
    String::from(MachineFamily::GeneralPurposePci.as_str())
}

fn default_guest_profile_key() -> String {
    String::from(GuestProfile::LinuxStandard.as_str())
}

fn default_claim_tier_key() -> String {
    String::from(ClaimTier::Compatible.as_str())
}

fn default_runtime_network_mode_key() -> String {
    String::from("guest_control_only")
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum StoredExecutionIntent {
    Contract(UvmExecutionIntent),
    LegacyKey(String),
}

fn default_execution_intent() -> UvmExecutionIntent {
    UvmExecutionIntent::default()
}

fn default_claim_tier_policy() -> ClaimTier {
    ClaimTier::Compatible
}

fn default_restore_policy_tier() -> RestorePolicyTier {
    RestorePolicyTier::LatestCheckpoint
}

fn default_migration_policy_tier() -> MigrationPolicyTier {
    MigrationPolicyTier::LiveOptional
}

fn default_migration_checkpoint_reference() -> String {
    String::from(RestorePolicyTier::LatestCheckpoint.as_str())
}

fn default_migration_checkpoint_kind() -> String {
    String::from("unspecified")
}

fn default_migration_workflow_kind() -> String {
    String::from(UVM_MIGRATION_WORKFLOW_KIND)
}

fn guest_architecture_from_key(architecture: &str) -> GuestArchitecture {
    match architecture {
        "aarch64" => GuestArchitecture::Aarch64,
        _ => GuestArchitecture::X86_64,
    }
}

fn default_machine_family_for_template(architecture: &str, apple_guest_allowed: bool) -> String {
    let guest_os = if apple_guest_allowed {
        "apple"
    } else {
        "linux"
    };
    String::from(
        MachineFamily::default_for_guest(guest_architecture_from_key(architecture), guest_os)
            .as_str(),
    )
}

fn default_guest_profile_for_template(apple_guest_allowed: bool) -> String {
    if apple_guest_allowed {
        return String::from(GuestProfile::AppleGuest.as_str());
    }
    String::from(GuestProfile::LinuxStandard.as_str())
}

fn default_machine_family_for_instance(architecture: &str, guest_os: &str) -> String {
    String::from(
        MachineFamily::default_for_guest(guest_architecture_from_key(architecture), guest_os)
            .as_str(),
    )
}

fn default_guest_profile_for_instance(guest_os: &str) -> String {
    String::from(GuestProfile::default_for_guest(guest_os).as_str())
}

fn default_boot_device_key() -> String {
    String::from(BootDevice::Disk.as_str())
}

fn deserialize_execution_intent<'de, D>(
    deserializer: D,
) -> std::result::Result<UvmExecutionIntent, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_optional_execution_intent(deserializer)
        .map(|value| value.unwrap_or_else(default_execution_intent))
}

fn deserialize_optional_execution_intent<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<UvmExecutionIntent>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StoredExecutionIntent>::deserialize(deserializer)?
        .map(|value| match value {
            StoredExecutionIntent::Contract(intent) => Ok(intent),
            StoredExecutionIntent::LegacyKey(key) => parse_legacy_execution_intent_key(&key),
        })
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn parse_legacy_execution_intent_key(
    value: &str,
) -> std::result::Result<UvmExecutionIntent, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "backend_agnostic" => Ok(UvmExecutionIntent::default()),
        "host_specific" => Ok(UvmExecutionIntent::default_for_guest_profile(
            GuestProfile::AppleGuest,
        )),
        other => Err(format!("unknown execution_intent `{other}`")),
    }
}

fn default_execution_intent_for_guest_profile(guest_profile: &str) -> UvmExecutionIntent {
    GuestProfile::parse(guest_profile)
        .map(UvmExecutionIntent::default_for_guest_profile)
        .unwrap_or_default()
}

fn normalize_boot_device(value: &str) -> Result<String> {
    Ok(String::from(BootDevice::parse(value)?.as_str()))
}

fn migration_policy_tier_for_policy(migration_policy: &str) -> Result<MigrationPolicyTier> {
    Ok(MigrationPolicyTier::for_policy(MigrationPolicy::parse(
        migration_policy,
    )?))
}

fn effective_migration_policy_tier(
    inherited: Option<MigrationPolicyTier>,
    migration_policy: &str,
) -> Result<MigrationPolicyTier> {
    let policy = MigrationPolicy::parse(migration_policy)?;
    Ok(inherited.map_or_else(
        || MigrationPolicyTier::for_policy(policy),
        |tier| tier.downgrade_for_policy(policy),
    ))
}

fn normalize_architecture(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "x86_64" | "aarch64" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "architecture must be `x86_64` or `aarch64`",
        )),
    }
}

fn normalize_guest_os(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("guest_os may not be empty"));
    }
    if normalized.len() > MAX_GUEST_OS_LEN {
        return Err(PlatformError::invalid(format!(
            "guest_os exceeds {MAX_GUEST_OS_LEN} bytes"
        )));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "guest_os may not contain control characters",
        ));
    }
    Ok(normalized)
}

fn normalize_profile(value: &str, field: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > MAX_PROFILE_LEN {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds {MAX_PROFILE_LEN} bytes"
        )));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters",
        )));
    }
    if field == "cpu_topology" && normalized == "symmetric" {
        return Ok(String::from("balanced"));
    }
    Ok(normalized)
}

fn normalize_firmware_profile(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "uefi_secure" | "uefi_standard" | "bios" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "firmware_profile must be `uefi_secure`, `uefi_standard`, or `bios`",
        )),
    }
}

fn normalize_migration_policy(value: &str) -> Result<String> {
    Ok(String::from(MigrationPolicy::parse(value)?.as_str()))
}

fn normalize_resource_name(value: &str, field: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > MAX_NAME_LEN {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds {MAX_NAME_LEN} bytes"
        )));
    }
    if !normalized.chars().all(is_name_character) {
        return Err(PlatformError::invalid(format!(
            "{field} contains unsupported characters",
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_reason(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("reason may not be empty"));
    }
    if normalized.len() > MAX_REASON_LEN {
        return Err(PlatformError::invalid(format!(
            "reason exceeds {MAX_REASON_LEN} bytes"
        )));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "reason may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_target_capability_id(value: &str) -> Result<String> {
    UvmNodeCapabilityId::parse(value.to_owned())
        .map(|id| id.to_string())
        .map_err(|error| {
            PlatformError::invalid("invalid target_capability_id").with_detail(error.to_string())
        })
}

fn normalize_checkpoint_reference(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(
            "checkpoint_reference may not be empty",
        ));
    }
    if normalized.len() > MAX_REFERENCE_LEN {
        return Err(PlatformError::invalid(format!(
            "checkpoint_reference exceeds {MAX_REFERENCE_LEN} bytes"
        )));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "checkpoint_reference may not contain control characters",
        ));
    }
    if normalized.eq_ignore_ascii_case(RestorePolicyTier::LatestCheckpoint.as_str()) {
        return Ok(String::from(RestorePolicyTier::LatestCheckpoint.as_str()));
    }
    if let Ok(checkpoint_id) = UvmCheckpointId::parse(normalized.to_owned()) {
        return Ok(checkpoint_id.to_string());
    }
    if is_absolute_reference(normalized) {
        return Ok(normalized.to_owned());
    }
    Err(PlatformError::invalid(
        "checkpoint_reference must be `latest_checkpoint`, a checkpoint id, or an absolute URI",
    ))
}

fn normalize_checkpoint_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "crash_consistent" | "live_precopy" | "live_postcopy" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "checkpoint_kind must be `crash_consistent`, `live_precopy`, or `live_postcopy`",
        )),
    }
}

fn normalize_migration_max_downtime_ms(value: u32) -> Result<u32> {
    if value == 0 {
        return Err(PlatformError::invalid(
            "migration_max_downtime_ms must be greater than zero",
        ));
    }
    Ok(value)
}

fn migration_checkpoint_kind_for_policy(migration_policy: &str) -> Result<String> {
    let kind = match MigrationPolicy::parse(migration_policy)?.strategy() {
        MigrationStrategy::Cold => "crash_consistent",
        MigrationStrategy::LivePreCopy => "live_precopy",
        MigrationStrategy::LivePostCopy => "live_postcopy",
    };
    Ok(String::from(kind))
}

fn default_migration_max_downtime_ms_for_policy(migration_policy: &str) -> Result<u32> {
    Ok(match MigrationPolicy::parse(migration_policy)? {
        MigrationPolicy::ColdOnly => 300_000,
        MigrationPolicy::BestEffortLive => 5_000,
        MigrationPolicy::StrictLive => 500,
        MigrationPolicy::LivePostCopy => 250,
    })
}

fn is_absolute_reference(value: &str) -> bool {
    value.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && !rest.is_empty()
            && scheme.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            })
    })
}

fn is_name_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ' ')
}

fn enforce_apple_guest_guardrails(
    guest_os: &str,
    architecture: &str,
    apple_guest_approved: bool,
    template_approved: bool,
) -> Result<()> {
    let apple_guest = guest_os.contains("macos") || guest_os.contains("ios");
    if !apple_guest {
        return Ok(());
    }
    if architecture != "aarch64" {
        return Err(PlatformError::invalid(
            "apple guest workloads require aarch64 architecture",
        ));
    }
    if !apple_guest_approved || !template_approved {
        return Err(PlatformError::invalid(
            "apple guest workloads require explicit legal guardrail approval",
        ));
    }
    Ok(())
}

fn enforce_firmware_compatibility(architecture: &str, firmware_profile: &str) -> Result<()> {
    if architecture == "aarch64" && firmware_profile == "bios" {
        return Err(PlatformError::invalid(
            "bios firmware_profile is not supported for aarch64 guests",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::header::ETAG;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use serde::de::DeserializeOwned;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::{
        CreateInstanceRequest, CreateTemplateRequest, MigrateInstanceRequest,
        RECORD_VERSION_HEADER, RestoreRequest, SnapshotRequest, UVM_MIGRATION_WORKFLOW_KIND,
        UvmControlService, UvmControlSummary, UvmImageContractSnapshot, UvmInstanceRecord,
        UvmInstanceState, UvmMigrationRecord, UvmObserveClaimDecisionContractSnapshot,
        UvmObserveClaimDecisionSnapshot, UvmObserveHostEvidenceContractSnapshot,
        UvmObservePerfAttestationContractSnapshot, UvmResolvedContractView,
        UvmRunnerSupervisionContractSnapshot, UvmRuntimeCheckpointReadRecord,
        UvmRuntimeNetworkAccessContractSnapshot, UvmRuntimePreflightContractSnapshot,
        UvmRuntimeSessionContractSnapshot, UvmRuntimeSessionIntentContractSnapshot,
        UvmRuntimeSessionReadRecord, UvmSnapshotRecord, UvmTemplateRecord,
    };
    use time::OffsetDateTime;
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_runtime::{
        HttpIdempotencyJournal, HttpService, PlatformRuntime, RouteRequestClass, RouteSurface,
        RouteSurfaceBinding, RuntimeAccessConfig, ServiceRegistration,
    };
    use uhost_store::{
        DocumentCollection, DocumentStore, OutboxMessage, WorkflowPhase, WorkflowStepState,
    };
    use uhost_types::{
        AuditId, NodeId, OwnershipScope, Page, PlatformEvent, ProjectId, ResourceMetadata,
        UvmCheckpointId, UvmClaimDecisionId, UvmHostEvidenceId, UvmImageId, UvmNodeCapabilityId,
        UvmPerfAttestationId, UvmRuntimeSessionId,
    };
    use uhost_uvm::{
        ClaimTier, GuestArchitecture, GuestProfile, HypervisorBackend, MigrationPolicyTier,
        RestorePolicyTier, UvmBackendFallbackPolicy, UvmCompatibilityEvidence,
        UvmCompatibilityEvidenceSource, UvmCompatibilityRequirement, UvmEvidenceStrictness,
        UvmExecutionIntent, UvmPortabilityAssessment, UvmPortabilityAssessmentSource,
        UvmPortabilityTier,
    };

    async fn parse_api_body<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    fn service_request(
        method: &str,
        uri: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Request<uhost_runtime::RequestBody> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if body.is_some() && !headers.iter().any(|(name, _)| *name == "content-type") {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(uhost_runtime::RequestBody::Right(Full::new(Bytes::from(
                body.unwrap_or_default().to_owned(),
            ))))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn runtime_request(
        method: &str,
        uri: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Request<Incoming> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if body.is_some() && !headers.iter().any(|(name, _)| *name == "content-type") {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(make_incoming_with_body(body.unwrap_or_default().as_bytes()).await)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn make_incoming_with_body(bytes: &[u8]) -> Incoming {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = bytes.to_vec();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream
                .write_all(response_head.as_bytes())
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            stream
                .write_all(&payload)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            stream
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method("GET")
            .uri("/payload")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap_or_else(|error| panic!("{error}"));
        let response = sender
            .send_request(request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        server.await.unwrap_or_else(|error| panic!("{error}"));
        response.into_body()
    }

    #[tokio::test]
    async fn template_lists_switch_to_shared_page_shape_when_pagination_is_requested() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        for name in ["charlie", "alpha", "bravo"] {
            let response = service
                .create_template(
                    CreateTemplateRequest {
                        name: String::from(name),
                        architecture: String::from("x86_64"),
                        vcpu: 2,
                        memory_mb: 2048,
                        cpu_topology: String::from("balanced"),
                        numa_policy: String::from("preferred_local"),
                        firmware_profile: String::from("uefi_secure"),
                        boot_device: None,
                        device_profile: String::from("cloud-balanced"),
                        migration_policy: String::from("best_effort_live"),
                        apple_guest_allowed: Some(false),
                        execution_intent: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let first_page = service
            .handle(
                service_request("GET", "/uvm/templates?limit=2", None, &[]),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing paginated template response"));
        let first_page: Page<UvmTemplateRecord> = parse_api_body(first_page).await;
        assert_eq!(
            first_page
                .items
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "bravo"]
        );
        let cursor = first_page
            .next_cursor
            .clone()
            .unwrap_or_else(|| panic!("missing next cursor"));

        let second_page = service
            .handle(
                service_request(
                    "GET",
                    &format!("/uvm/templates?limit=2&cursor={}", cursor.as_str()),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing paginated template response"));
        let second_page: Page<UvmTemplateRecord> = parse_api_body(second_page).await;
        assert_eq!(
            second_page
                .items
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            vec!["charlie"]
        );
        assert!(second_page.next_cursor.is_none());

        let legacy_response = service
            .handle(service_request("GET", "/uvm/templates", None, &[]), context)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing template list response"));
        let legacy_records: Vec<UvmTemplateRecord> = parse_api_body(legacy_response).await;
        assert_eq!(legacy_records.len(), 3);
    }

    #[tokio::test]
    async fn instance_mutations_emit_and_enforce_concurrency_headers() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let template_response = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template: UvmTemplateRecord = parse_api_body(template_response).await;

        let instance_response = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("api"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(instance_response.status(), StatusCode::CREATED);
        let created_etag = instance_response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("missing created etag"));
        let created_version = instance_response
            .headers()
            .get(&RECORD_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("missing created version"));
        let instance: UvmInstanceRecord = parse_api_body(instance_response).await;

        let stale_version_error = service
            .handle(
                service_request(
                    "POST",
                    &format!("/uvm/instances/{}/start", instance.id),
                    Some("{}"),
                    &[(RECORD_VERSION_HEADER.as_str(), "999")],
                ),
                context.clone(),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected stale version conflict"));
        assert_eq!(stale_version_error.code, uhost_core::ErrorCode::Conflict);

        let started_response = service
            .handle(
                service_request(
                    "POST",
                    &format!("/uvm/instances/{}/start", instance.id),
                    Some("{}"),
                    &[(RECORD_VERSION_HEADER.as_str(), &created_version)],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing start response"));
        assert_eq!(started_response.status(), StatusCode::OK);
        assert!(started_response.headers().contains_key(ETAG));
        assert!(
            started_response
                .headers()
                .contains_key(&RECORD_VERSION_HEADER)
        );
        let started_etag = started_response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("missing updated etag"));
        assert_ne!(started_etag, created_etag);
        let started: UvmInstanceRecord = parse_api_body(started_response).await;
        assert_eq!(started.state, UvmInstanceState::Running);

        let stale_etag_error = service
            .handle(
                service_request(
                    "POST",
                    &format!("/uvm/instances/{}/stop", instance.id),
                    Some("{}"),
                    &[("If-Match", &created_etag)],
                ),
                context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected stale etag conflict"));
        assert_eq!(stale_etag_error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn runtime_idempotency_replays_create_template_responses() {
        const ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
            RouteSurfaceBinding::exact_safe("/uvm", RouteSurface::Tenant, RouteRequestClass::Read),
            RouteSurfaceBinding::exact_safe(
                "/uvm/control/summary",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/templates",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/templates",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/instances",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/instances",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/snapshots",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/snapshots",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/migrations",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/migrations",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/reconciliation",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/reconciliation",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
            RouteSurfaceBinding::prefix_safe(
                "/uvm/outbox",
                RouteSurface::Tenant,
                RouteRequestClass::Read,
            ),
            RouteSurfaceBinding::prefix_unsafe(
                "/uvm/outbox",
                RouteSurface::Tenant,
                RouteRequestClass::AsyncMutate,
            ),
        ];

        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = Arc::new(
            UvmControlService::open(temp.path())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let journal = HttpIdempotencyJournal::open(temp.path().join("http-idempotency.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime = PlatformRuntime::new(vec![ServiceRegistration::new(
            service.clone(),
            ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        )
        .with_idempotency_journal(journal);

        let payload = serde_json::json!({
            "name": "idem-template",
            "architecture": "x86_64",
            "vcpu": 4,
            "memory_mb": 4096,
            "cpu_topology": "balanced",
            "numa_policy": "preferred_local",
            "firmware_profile": "uefi_secure",
            "device_profile": "cloud-balanced",
            "migration_policy": "best_effort_live",
            "apple_guest_allowed": false
        })
        .to_string();

        let first = runtime
            .dispatch(
                runtime_request(
                    "POST",
                    "/uvm/templates",
                    Some(&payload),
                    &[("Idempotency-Key", "uvm-template-idem-1")],
                )
                .await,
            )
            .await;
        let first_status = first.status();
        let first_body = first
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();

        let second = runtime
            .dispatch(
                runtime_request(
                    "POST",
                    "/uvm/templates",
                    Some(&payload),
                    &[("Idempotency-Key", "uvm-template-idem-1")],
                )
                .await,
            )
            .await;
        let second_status = second.status();
        let second_body = second
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();

        assert_eq!(first_status, StatusCode::CREATED);
        assert_eq!(second_status, StatusCode::CREATED);
        assert_eq!(second_body, first_body);
        assert_eq!(
            service
                .templates
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .into_iter()
                .filter(|(_, stored)| !stored.deleted)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn create_instance_enforces_apple_guardrails() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let template = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("standard"),
                    architecture: String::from("aarch64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(template.status(), StatusCode::CREATED);

        let error = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("mac-vm"),
                    template_id: service
                        .templates
                        .list()
                        .await
                        .unwrap_or_else(|error| panic!("{error}"))
                        .first()
                        .map(|(_, value)| value.value.id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: Some(String::from("aarch64")),
                    guest_os: String::from("macos-14"),
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected legal guardrail rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn apple_guest_templates_default_host_specific_execution_intent_when_omitted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("apple-guest-template"),
                    architecture: String::from("aarch64"),
                    vcpu: 4,
                    memory_mb: 8192,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("cold_only"),
                    apple_guest_allowed: Some(true),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);

        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(
            template.execution_intent,
            UvmExecutionIntent::default_for_guest_profile(GuestProfile::AppleGuest)
        );
    }

    #[tokio::test]
    async fn omitted_execution_intent_and_policy_tiers_are_derived_and_propagated() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("live-required-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("live_postcopy"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(template.execution_intent, UvmExecutionIntent::default());
        assert_eq!(template.claim_tier_policy, ClaimTier::Compatible);
        assert_eq!(
            template.restore_policy_tier,
            RestorePolicyTier::LatestCheckpoint
        );
        assert_eq!(
            template.migration_policy_tier,
            MigrationPolicyTier::LiveRequired
        );

        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("intent-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(instance.execution_intent, template.execution_intent);
        assert_eq!(instance.claim_tier_policy, template.claim_tier_policy);
        assert_eq!(instance.restore_policy_tier, template.restore_policy_tier);
        assert_eq!(
            instance.migration_policy_tier,
            template.migration_policy_tier
        );
    }

    #[tokio::test]
    async fn overridden_instance_migration_policy_downgrades_inherited_policy_tier() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("live-required-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("live_postcopy"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("cold-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: Some(String::from("cold_only")),
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(
            template.migration_policy_tier,
            MigrationPolicyTier::LiveRequired
        );
        assert_eq!(instance.migration_policy, "cold_only");
        assert_eq!(
            instance.migration_policy_tier,
            MigrationPolicyTier::StopAndCopy
        );
        assert_eq!(instance.claim_tier_policy, template.claim_tier_policy);
        assert_eq!(instance.restore_policy_tier, template.restore_policy_tier);
    }

    #[tokio::test]
    async fn explicit_execution_intent_persists_on_template_and_instances_inherit_it() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let explicit_intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
            required_portability_tier: UvmPortabilityTier::AcceleratorRequired,
            evidence_strictness: UvmEvidenceStrictness::RequireMeasured,
        };

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("explicit-intent-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: Some(explicit_intent.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(template.execution_intent, explicit_intent);

        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("explicit-intent-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(instance.execution_intent, template.execution_intent);
    }

    #[tokio::test]
    async fn legacy_string_execution_intent_records_are_still_readable() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("legacy-template"),
                    architecture: String::from("aarch64"),
                    vcpu: 4,
                    memory_mb: 8192,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("cold_only"),
                    apple_guest_allowed: Some(true),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(service);

        let template_path = temp.path().join("uvm-control").join("templates.json");
        let bytes = tokio::fs::read(&template_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut collection: DocumentCollection<serde_json::Value> =
            serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));
        let stored = collection
            .records
            .values_mut()
            .next()
            .unwrap_or_else(|| panic!("missing stored template"));
        stored.value["execution_intent"] = serde_json::Value::String(String::from("host_specific"));
        let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(&template_path, payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template = reopened
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(
            template.execution_intent,
            UvmExecutionIntent::default_for_guest_profile(GuestProfile::AppleGuest)
        );
    }

    #[tokio::test]
    async fn instance_can_carry_install_media_and_cdrom_boot_intent() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let template = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("installer-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("bios"),
                    boot_device: Some(String::from("cdrom")),
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("cold_only"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(template.status(), StatusCode::CREATED);

        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let install_media_image_id =
            UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("ubuntu-installer"),
                    template_id: Some(template_id),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: Some(install_media_image_id.to_string()),
                    architecture: None,
                    guest_os: String::from("ubuntu-26.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(instance.boot_device, "cdrom");
        assert_eq!(
            instance.install_media_image_id.as_ref(),
            Some(&install_media_image_id)
        );
    }

    #[tokio::test]
    async fn lifecycle_records_snapshot_and_migration() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let host_node_id =
            uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));

        let created = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: Some(host_node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let _ = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let snapshot = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("pre-maintenance"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot.status(), StatusCode::CREATED);
        let snapshot_id = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing snapshot"));
        let snapshot_again = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("pre-maintenance"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot_again.status(), StatusCode::OK);
        let snapshot_id_again = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing snapshot"));
        assert_eq!(snapshot_id_again, snapshot_id);

        let node_id = uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let migration = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: node_id.to_string(),
                    reason: String::from("rebalance"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migration.status(), StatusCode::OK);

        let restored = service
            .restore_instance(
                &instance_id,
                RestoreRequest {
                    snapshot_id: snapshot_id.clone(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored.status(), StatusCode::OK);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!outbox.is_empty());
    }

    #[tokio::test]
    async fn read_helpers_return_control_plane_records_and_outbox_messages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let initial_node_id =
            uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node_id =
            uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created_template = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("reader-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created_template.status(), StatusCode::CREATED);
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));

        let created_instance = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("reader-instance"),
                    template_id: Some(template_id.clone()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: Some(initial_node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created_instance.status(), StatusCode::CREATED);
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let _ = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("reader-snapshot"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let snapshot_id = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing snapshot"));

        let _ = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: target_node_id.to_string(),
                    reason: String::from("reader-rebalance"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_id = service
            .migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing migration"));
        let outbox_message_id = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|value| value.id.clone())
            .unwrap_or_else(|| panic!("missing outbox message"));

        let template: UvmTemplateRecord = parse_api_body(
            service
                .get_template(&template_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(template.id.to_string(), template_id);

        let instance: UvmInstanceRecord = parse_api_body(
            service
                .get_instance(&instance_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(instance.id.to_string(), instance_id);

        let snapshot: UvmSnapshotRecord = parse_api_body(
            service
                .get_snapshot(&snapshot_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(snapshot.id.to_string(), snapshot_id);

        let migration: UvmMigrationRecord = parse_api_body(
            service
                .get_migration(&migration_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(migration.id.to_string(), migration_id);

        let outbox_message: OutboxMessage<PlatformEvent> = parse_api_body(
            service
                .get_outbox_message(&outbox_message_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(outbox_message.id, outbox_message_id);
    }

    #[tokio::test]
    async fn migrate_persists_workflow_contract_fields_and_projection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_capability_id =
            UvmNodeCapabilityId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("workflow-migrate"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("workflow-instance"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: Some(source_node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let portability_assessment = UvmPortabilityAssessment {
            intent: UvmExecutionIntent::default(),
            supported: true,
            eligible_backends: vec![HypervisorBackend::Kvm],
            selected_backend: Some(HypervisorBackend::Kvm),
            selected_via_fallback: false,
            selection_reason: Some(String::from("request-provided portability evidence")),
            blockers: Vec::new(),
            evidence: vec![UvmCompatibilityEvidence {
                source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                summary: String::from("node capability preflight approved the target"),
                evidence_mode: Some(String::from("measured")),
            }],
        };

        let response = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: target_node_id.to_string(),
                    reason: String::from("rebalance"),
                    target_capability_id: Some(target_capability_id.to_string()),
                    checkpoint_reference: Some(String::from("object://checkpoints/uvm/live-1")),
                    checkpoint_kind: Some(String::from("live_precopy")),
                    migration_max_downtime_ms: Some(750),
                    portability_assessment: Some(portability_assessment.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let migration: UvmMigrationRecord = parse_api_body(response).await;
        assert_eq!(
            migration.target_capability_id.as_deref(),
            Some(target_capability_id.as_str())
        );
        assert_eq!(
            migration.checkpoint_reference,
            "object://checkpoints/uvm/live-1"
        );
        assert_eq!(migration.checkpoint_kind, "live_precopy");
        assert_eq!(migration.migration_max_downtime_ms, Some(750));
        assert_eq!(
            migration.portability_assessment,
            Some(portability_assessment.clone())
        );
        assert_eq!(
            migration.portability_assessment_source,
            UvmPortabilityAssessmentSource::RequestFallback
        );
        assert_eq!(migration.workflow_kind, UVM_MIGRATION_WORKFLOW_KIND);
        assert_eq!(migration.state, "completed");

        let workflow = service
            .migration_workflows
            .get(migration.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migration workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.value.steps.len(), 3);
        assert_eq!(workflow.value.steps[0].state, WorkflowStepState::Completed);
        assert_eq!(workflow.value.steps[1].state, WorkflowStepState::Completed);
        assert_eq!(workflow.value.steps[2].state, WorkflowStepState::Completed);

        let instance = service
            .instances
            .get(instance_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing instance after migrate"));
        assert_eq!(
            instance.value.host_node_id.map(|id| id.to_string()),
            Some(target_node_id.to_string())
        );
    }

    #[tokio::test]
    async fn lifecycle_operations_are_replay_safe() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let host_node_id =
            uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: Some(host_node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let baseline_outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();

        let started = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::OK);
        let after_start = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(after_start.len(), baseline_outbox + 1);
        let started_again = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started_again.status(), StatusCode::OK);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            after_start.len()
        );

        let snapshot = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("pre-maintenance"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot.status(), StatusCode::CREATED);
        let snapshot_id = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing snapshot"));

        let node_id = uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let migrated = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: node_id.to_string(),
                    reason: String::from("rebalance"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migrated.status(), StatusCode::OK);
        let after_migrate = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migrations = service
            .migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(after_migrate.len() >= after_start.len() + 2);
        assert_eq!(migrations.len(), 1);
        let migrated_again = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: node_id.to_string(),
                    reason: String::from("rebalance"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migrated_again.status(), StatusCode::OK);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            after_migrate.len()
        );
        assert_eq!(
            service
                .migrations
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            migrations.len()
        );

        let restored = service
            .restore_instance(
                &instance_id,
                RestoreRequest {
                    snapshot_id: snapshot_id.clone(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored.status(), StatusCode::OK);
        let after_restore = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(after_restore.len(), after_migrate.len() + 1);
        let restored_again = service
            .restore_instance(
                &instance_id,
                RestoreRequest {
                    snapshot_id: snapshot_id.clone(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_again.status(), StatusCode::OK);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            after_restore.len()
        );

        let stopped = service
            .stop_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stopped.status(), StatusCode::OK);
        let stopped_again = service
            .stop_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stopped_again.status(), StatusCode::OK);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            after_restore.len()
        );
    }

    #[tokio::test]
    async fn migrate_keeps_stopped_instances_stopped() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));
        let node_id = uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let migrated = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: node_id.to_string(),
                    reason: String::from("rebalance"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migrated.status(), StatusCode::OK);

        let instance = service
            .instances
            .get(instance_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(instance.value.state, UvmInstanceState::Stopped);
    }

    #[tokio::test]
    async fn deleted_templates_and_snapshots_are_rejected() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing template"));
        service
            .templates
            .soft_delete(template.value.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let error = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    template_id: Some(template.value.id.to_string()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected deleted template rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::NotFound);

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux-2"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing active template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api-restore"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing active instance"));
        let snapshot = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("pre-maintenance"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot.status(), StatusCode::CREATED);
        let snapshot = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing snapshot"));
        service
            .snapshots
            .soft_delete(snapshot.value.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let error = service
            .restore_instance(
                &instance_id,
                RestoreRequest {
                    snapshot_id: snapshot.value.id.to_string(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected deleted snapshot rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn template_and_instance_names_are_case_insensitive_unique() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("Linux-Std"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let duplicate_template_error = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux-std"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate template name conflict"));
        assert_eq!(
            duplicate_template_error.code,
            uhost_core::ErrorCode::Conflict
        );

        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("Api-Gateway"),
                    template_id: Some(template_id.clone()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let duplicate_instance_error = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api-gateway"),
                    template_id: Some(template_id),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate instance name conflict"));
        assert_eq!(
            duplicate_instance_error.code,
            uhost_core::ErrorCode::Conflict
        );
    }

    #[tokio::test]
    async fn migration_policy_and_restore_guards_are_enforced() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node_id = uhost_types::NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("cold-only-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("cold_only"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("restore-case"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: Some(node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let _ = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_error = service
            .migrate_instance(
                &instance_id,
                MigrateInstanceRequest {
                    to_node_id: uhost_types::NodeId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    reason: String::from("policy check"),
                    target_capability_id: None,
                    checkpoint_reference: None,
                    checkpoint_kind: None,
                    migration_max_downtime_ms: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected cold_only migration rejection while running"));
        assert_eq!(migration_error.code, uhost_core::ErrorCode::Conflict);

        let snapshot = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("restore-point"),
                    crash_consistent: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot.status(), StatusCode::CREATED);
        let snapshot_id = service
            .snapshots
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing snapshot"));

        let restored = service
            .restore_instance(
                &instance_id,
                RestoreRequest {
                    snapshot_id: snapshot_id.clone(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored.status(), StatusCode::OK);
        let restored_instance = service
            .instances
            .get(&instance_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored instance"));
        assert_eq!(restored_instance.value.state, UvmInstanceState::Stopped);
        assert!(restored_instance.value.host_node_id.is_none());

        let outbox_after_restore = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();
        let restored_again = service
            .restore_instance(&instance_id, RestoreRequest { snapshot_id }, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_again.status(), StatusCode::OK);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            outbox_after_restore
        );
    }

    #[tokio::test]
    async fn running_snapshot_requires_crash_consistent_mode() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("linux"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));

        let _ = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let error = service
            .snapshot_instance(
                &instance_id,
                SnapshotRequest {
                    name: String::from("unsafe-running"),
                    crash_consistent: Some(false),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected crash_consistent guard"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn symmetric_cpu_topology_is_canonicalized_to_balanced() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("balanced-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("symmetric"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(stored_template.cpu_topology, "balanced");

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("balanced-instance"),
                    template_id: Some(stored_template.id.to_string()),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("ubuntu-24.04"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: None,
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));
        assert_eq!(stored_instance.cpu_topology, "balanced");
    }

    #[tokio::test]
    async fn control_service_accepts_live_postcopy_migration_policy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("postcopy-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("live_postcopy"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);

        let template = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing template"));
        assert_eq!(template.migration_policy, "live_postcopy");
    }

    #[tokio::test]
    async fn control_summary_reports_document_backed_totals() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let preferred_kvm_intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
            required_portability_tier: UvmPortabilityTier::AcceleratorRequired,
            evidence_strictness: UvmEvidenceStrictness::RequireMeasured,
        };

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("baseline-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("kvm-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: Some(preferred_kvm_intent),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let templates = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let baseline_template_id = templates
            .iter()
            .find(|(_, value)| value.value.name == "baseline-template")
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing baseline template"));
        let kvm_template_id = templates
            .iter()
            .find(|(_, value)| value.value.name == "kvm-template")
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing kvm template"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("baseline-instance"),
                    template_id: Some(baseline_template_id),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("kvm-instance"),
                    template_id: Some(kvm_template_id),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let kvm_instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .iter()
            .find(|(_, value)| value.value.name == "kvm-instance")
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing kvm instance"));
        let _ = service
            .start_instance(&kvm_instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .control_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let summary: UvmControlSummary = parse_api_body(response).await;
        assert_eq!(summary.template_count, 2);
        assert_eq!(summary.instance_count, 2);
        assert_eq!(summary.instance_state_totals.get("running"), Some(&1));
        assert_eq!(summary.instance_state_totals.get("stopped"), Some(&1));
        assert_eq!(
            summary.template_claim_tier_totals.get("compatible"),
            Some(&2)
        );
        assert_eq!(
            summary.instance_claim_tier_totals.get("compatible"),
            Some(&2)
        );
        assert_eq!(
            summary.template_preferred_backend_totals.get("unspecified"),
            Some(&1)
        );
        assert_eq!(
            summary.template_preferred_backend_totals.get("kvm"),
            Some(&1)
        );
        assert_eq!(
            summary.instance_preferred_backend_totals.get("unspecified"),
            Some(&1)
        );
        assert_eq!(
            summary.instance_preferred_backend_totals.get("kvm"),
            Some(&1)
        );
        assert_eq!(summary.effective_claim_publication_state, None);
        assert!(summary.failing_workload_classes.is_empty());
    }

    #[tokio::test]
    async fn control_summary_surfaces_latest_claim_publication_state_and_failing_workload_classes()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let claim_decisions =
            DocumentStore::open(temp.path().join("uvm-observe").join("claim_decisions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        claim_decisions
            .create(
                "ucd-older",
                UvmObserveClaimDecisionSnapshot {
                    id: String::from("ucd-older"),
                    claim_status: String::from("restricted"),
                    failing_workload_classes: vec![String::from("io_intensive")],
                    decided_at: OffsetDateTime::from_unix_timestamp(1)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        claim_decisions
            .create(
                "ucd-latest",
                UvmObserveClaimDecisionSnapshot {
                    id: String::from("ucd-latest"),
                    claim_status: String::from("allowed"),
                    failing_workload_classes: vec![
                        String::from("cpu_intensive"),
                        String::from("network_intensive"),
                    ],
                    decided_at: OffsetDateTime::from_unix_timestamp(2)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .control_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let summary: UvmControlSummary = parse_api_body(response).await;
        assert_eq!(
            summary.effective_claim_publication_state.as_deref(),
            Some("allowed")
        );
        assert_eq!(
            summary.failing_workload_classes,
            vec![
                String::from("cpu_intensive"),
                String::from("network_intensive"),
            ]
        );
    }

    #[tokio::test]
    async fn control_summary_route_is_claimed() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            service
                .route_claims()
                .iter()
                .any(|claim| claim.path() == "/uvm/control/summary"
                    && claim.matches("/uvm/control/summary"))
        );
    }

    #[tokio::test]
    async fn resolved_instance_contract_is_available_via_http_handle() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let template_response = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("resolved-http-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template: UvmTemplateRecord = parse_api_body(template_response).await;

        let instance_response = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("resolved-http-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance: UvmInstanceRecord = parse_api_body(instance_response).await;

        let response = service
            .handle(
                service_request(
                    "GET",
                    &format!("/uvm/instances/{}/resolved-contract", instance.id),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resolved contract response"));
        assert_eq!(response.status(), StatusCode::OK);
        let view: UvmResolvedContractView = parse_api_body(response).await;
        assert_eq!(view.instance.id, instance.id);
        assert_eq!(
            view.template.as_ref().map(|record| record.id.clone()),
            Some(template.id)
        );
        assert!(view.boot_image.is_none());
        assert!(
            view.resolution_notes
                .iter()
                .any(|note| note.contains("boot image") && note.contains("missing"))
        );
    }

    #[tokio::test]
    async fn instance_runtime_session_and_checkpoint_routes_project_node_truth() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let template_response = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("runtime-adjacent-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template: UvmTemplateRecord = parse_api_body(template_response).await;

        let target_instance_response = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("runtime-adjacent-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let target_instance: UvmInstanceRecord = parse_api_body(target_instance_response).await;

        let other_instance_response = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("runtime-adjacent-other-instance"),
                    template_id: Some(template.id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let other_instance: UvmInstanceRecord = parse_api_body(other_instance_response).await;

        let base_time = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let other_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let target_session_one = UvmRuntimeSessionReadRecord {
            id: UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}")),
            instance_id: target_instance.id.clone(),
            node_id: target_node_id.clone(),
            capability_id: UvmNodeCapabilityId::generate()
                .unwrap_or_else(|error| panic!("{error}")),
            claim_tier: String::from("competitive"),
            accelerator_backend: String::from("kvm"),
            state: String::from("running"),
            migration_in_progress: false,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            last_error: None,
            created_at: base_time,
            last_transition_at: base_time,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(target_instance.project_id.to_string()),
                String::from("runtime-session-one"),
            ),
        };
        let target_session_two = UvmRuntimeSessionReadRecord {
            id: UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}")),
            instance_id: target_instance.id.clone(),
            node_id: target_node_id.clone(),
            capability_id: UvmNodeCapabilityId::generate()
                .unwrap_or_else(|error| panic!("{error}")),
            claim_tier: String::from("competitive"),
            accelerator_backend: String::from("kvm"),
            state: String::from("migrating"),
            migration_in_progress: true,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            last_error: None,
            created_at: base_time + time::Duration::minutes(5),
            last_transition_at: base_time + time::Duration::minutes(5),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(target_instance.project_id.to_string()),
                String::from("runtime-session-two"),
            ),
        };
        let other_session = UvmRuntimeSessionReadRecord {
            id: UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}")),
            instance_id: other_instance.id.clone(),
            node_id: other_node_id.clone(),
            capability_id: UvmNodeCapabilityId::generate()
                .unwrap_or_else(|error| panic!("{error}")),
            claim_tier: String::from("competitive"),
            accelerator_backend: String::from("kvm"),
            state: String::from("running"),
            migration_in_progress: false,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            last_error: None,
            created_at: base_time + time::Duration::minutes(1),
            last_transition_at: base_time + time::Duration::minutes(1),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(other_instance.project_id.to_string()),
                String::from("runtime-session-other"),
            ),
        };

        let runtime_sessions =
            DocumentStore::open(temp.path().join("uvm-node").join("runtime_sessions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runtime_sessions
            .create(target_session_one.id.as_str(), target_session_one.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime_sessions
            .create(target_session_two.id.as_str(), target_session_two.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime_sessions
            .create(other_session.id.as_str(), other_session.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let target_checkpoint_one = UvmRuntimeCheckpointReadRecord {
            id: UvmCheckpointId::generate().unwrap_or_else(|error| panic!("{error}")),
            runtime_session_id: target_session_one.id.clone(),
            instance_id: target_instance.id.clone(),
            source_node_id: target_node_id.clone(),
            target_node_id: target_node_id.clone(),
            kind: String::from("crash_consistent"),
            checkpoint_uri: String::from("object://checkpoints/runtime-adjacent-1"),
            memory_bitmap_hash: String::from("a11ce"),
            disk_generation: 11,
            envelope_digest: String::from("digest-runtime-1"),
            provenance: serde_json::json!({"source_pid": 1001_u32}),
            created_at: base_time + time::Duration::minutes(10),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(target_instance.project_id.to_string()),
                String::from("runtime-checkpoint-one"),
            ),
        };
        let target_checkpoint_two = UvmRuntimeCheckpointReadRecord {
            id: UvmCheckpointId::generate().unwrap_or_else(|error| panic!("{error}")),
            runtime_session_id: target_session_two.id.clone(),
            instance_id: target_instance.id.clone(),
            source_node_id: target_node_id.clone(),
            target_node_id: target_node_id.clone(),
            kind: String::from("live_precopy"),
            checkpoint_uri: String::from("object://checkpoints/runtime-adjacent-2"),
            memory_bitmap_hash: String::from("b16b00b5"),
            disk_generation: 12,
            envelope_digest: String::from("digest-runtime-2"),
            provenance: serde_json::json!({"source_pid": 1002_u32}),
            created_at: base_time + time::Duration::minutes(12),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(target_instance.project_id.to_string()),
                String::from("runtime-checkpoint-two"),
            ),
        };
        let other_checkpoint = UvmRuntimeCheckpointReadRecord {
            id: UvmCheckpointId::generate().unwrap_or_else(|error| panic!("{error}")),
            runtime_session_id: other_session.id.clone(),
            instance_id: other_instance.id.clone(),
            source_node_id: other_node_id.clone(),
            target_node_id: other_node_id,
            kind: String::from("crash_consistent"),
            checkpoint_uri: String::from("object://checkpoints/runtime-adjacent-other"),
            memory_bitmap_hash: String::from("c0ffee"),
            disk_generation: 9,
            envelope_digest: String::from("digest-runtime-other"),
            provenance: serde_json::json!({"source_pid": 9001_u32}),
            created_at: base_time + time::Duration::minutes(8),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(other_instance.project_id.to_string()),
                String::from("runtime-checkpoint-other"),
            ),
        };

        let runtime_checkpoints = DocumentStore::open(
            temp.path()
                .join("uvm-node")
                .join("runtime_checkpoints.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        runtime_checkpoints
            .create(
                target_checkpoint_one.id.as_str(),
                target_checkpoint_one.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime_checkpoints
            .create(
                target_checkpoint_two.id.as_str(),
                target_checkpoint_two.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime_checkpoints
            .create(other_checkpoint.id.as_str(), other_checkpoint.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_page_response = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-sessions?limit=1",
                        target_instance.id
                    ),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime sessions page"));
        assert_eq!(first_page_response.status(), StatusCode::OK);
        let first_page: Page<UvmRuntimeSessionReadRecord> =
            parse_api_body(first_page_response).await;
        assert_eq!(first_page.items.len(), 1);
        assert_eq!(first_page.items[0].id, target_session_one.id);
        let next_cursor = first_page
            .next_cursor
            .clone()
            .unwrap_or_else(|| panic!("missing runtime session cursor"));

        let second_page_response = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-sessions?limit=1&cursor={}",
                        target_instance.id,
                        next_cursor.as_str()
                    ),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime sessions page"));
        assert_eq!(second_page_response.status(), StatusCode::OK);
        let second_page: Page<UvmRuntimeSessionReadRecord> =
            parse_api_body(second_page_response).await;
        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].id, target_session_two.id);
        assert!(second_page.next_cursor.is_none());

        let session_response = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-sessions/{}",
                        target_instance.id, target_session_two.id
                    ),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session detail"));
        assert_eq!(session_response.status(), StatusCode::OK);
        assert!(session_response.headers().contains_key(ETAG));
        assert_eq!(
            session_response
                .headers()
                .get(&RECORD_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let session: UvmRuntimeSessionReadRecord = parse_api_body(session_response).await;
        assert_eq!(session.id, target_session_two.id);

        let checkpoints_response = service
            .handle(
                service_request(
                    "GET",
                    &format!("/uvm/instances/{}/runtime-checkpoints", target_instance.id),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime checkpoints list"));
        assert_eq!(checkpoints_response.status(), StatusCode::OK);
        let checkpoints: Vec<UvmRuntimeCheckpointReadRecord> =
            parse_api_body(checkpoints_response).await;
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].id, target_checkpoint_one.id);
        assert_eq!(checkpoints[1].id, target_checkpoint_two.id);

        let checkpoint_response = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-checkpoints/{}",
                        target_instance.id, target_checkpoint_two.id
                    ),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime checkpoint detail"));
        assert_eq!(checkpoint_response.status(), StatusCode::OK);
        assert!(checkpoint_response.headers().contains_key(ETAG));
        assert_eq!(
            checkpoint_response
                .headers()
                .get(&RECORD_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let checkpoint: UvmRuntimeCheckpointReadRecord = parse_api_body(checkpoint_response).await;
        assert_eq!(checkpoint.id, target_checkpoint_two.id);

        let hidden_session_error = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-sessions/{}",
                        target_instance.id, other_session.id
                    ),
                    None,
                    &[],
                ),
                context.clone(),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected foreign runtime session to be hidden"));
        assert_eq!(hidden_session_error.code, uhost_core::ErrorCode::NotFound);

        let hidden_checkpoint_error = service
            .handle(
                service_request(
                    "GET",
                    &format!(
                        "/uvm/instances/{}/runtime-checkpoints/{}",
                        target_instance.id, other_checkpoint.id
                    ),
                    None,
                    &[],
                ),
                context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected foreign runtime checkpoint to be hidden"));
        assert_eq!(
            hidden_checkpoint_error.code,
            uhost_core::ErrorCode::NotFound
        );
    }

    #[tokio::test]
    async fn resolved_instance_contract_joins_control_image_node_and_observe_truth() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let explicit_intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
            required_portability_tier: UvmPortabilityTier::AcceleratorRequired,
            evidence_strictness: UvmEvidenceStrictness::RequireMeasured,
        };

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("resolved-contract-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: Some(explicit_intent.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.clone())
            .unwrap_or_else(|| panic!("missing template"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("resolved-contract-instance"),
                    template_id: Some(template_id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: Some(node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));

        let runtime_session_id =
            UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            UvmNodeCapabilityId::generate().unwrap_or_else(|error| panic!("{error}"));
        let preflight_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let claim_decision_id =
            UvmClaimDecisionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let host_evidence_id =
            UvmHostEvidenceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let perf_general_old =
            UvmPerfAttestationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let perf_general_latest =
            UvmPerfAttestationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let perf_network =
            UvmPerfAttestationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let portability = UvmPortabilityAssessment {
            intent: explicit_intent.clone(),
            supported: true,
            eligible_backends: vec![HypervisorBackend::Kvm],
            selected_backend: Some(HypervisorBackend::Kvm),
            selected_via_fallback: false,
            selection_reason: Some(String::from("matched runtime lineage")),
            blockers: Vec::new(),
            evidence: Vec::new(),
        };

        let image_store = DocumentStore::open(temp.path().join("uvm-image").join("images.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        image_store
            .create(
                instance.boot_image_id.as_str(),
                UvmImageContractSnapshot {
                    id: instance.boot_image_id.clone(),
                    guest_profile: instance.guest_profile.clone(),
                    machine_family: instance.machine_family.clone(),
                    claim_tier: String::from("competitive"),
                    verified: true,
                    preferred_boot_device: instance.boot_device.clone(),
                    install_media: false,
                    execution_intent: explicit_intent.clone(),
                    compatibility_requirement: Some(
                        UvmCompatibilityRequirement::parse_keys(
                            GuestArchitecture::parse(&instance.architecture)
                                .unwrap_or_else(|error| panic!("{error}")),
                            &instance.machine_family,
                            &instance.guest_profile,
                            &instance.boot_device,
                            &instance.claim_tier,
                        )
                        .unwrap_or_else(|error| panic!("{error}")),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime_sessions =
            DocumentStore::open(temp.path().join("uvm-node").join("runtime_sessions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runtime_sessions
            .create(
                runtime_session_id.as_str(),
                UvmRuntimeSessionContractSnapshot {
                    id: runtime_session_id.clone(),
                    instance_id: instance.id.clone(),
                    node_id: node_id.clone(),
                    capability_id: capability_id.clone(),
                    claim_tier: String::from("competitive"),
                    accelerator_backend: String::from("kvm"),
                    state: String::from("stopped"),
                    migration_in_progress: false,
                    created_at: OffsetDateTime::from_unix_timestamp(10)
                        .unwrap_or_else(|error| panic!("{error}")),
                    last_transition_at: OffsetDateTime::from_unix_timestamp(11)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runner_supervision =
            DocumentStore::open(temp.path().join("uvm-node").join("runner_supervision.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runner_supervision
            .create(
                "resolved-contract-runtime-access-1",
                UvmRunnerSupervisionContractSnapshot {
                    runtime_session_id: runtime_session_id.clone(),
                    runtime_incarnation: 1,
                    state: String::from("running"),
                    network_access: Some(UvmRuntimeNetworkAccessContractSnapshot {
                        network_mode: String::from("guest_owned_usernet_nat"),
                        internet_nat: true,
                        ssh_available: false,
                        guest_exec_route_available: false,
                        ingress_http_ready: true,
                        ingress_tcp_ready: true,
                        ingress_udp_ready: true,
                        egress_transport: Some(String::from(
                            "guest_owned_tcp_udp_http_https_nat_v1",
                        )),
                        ingress_transport: Some(String::from("guest_owned_tcp_udp_http_nat_v1")),
                        ingress_http_bind: Some(String::from("127.0.0.1:19082")),
                        ingress_http_url: Some(String::from("http://127.0.0.1:19082")),
                        ingress_tcp_bind: Some(String::from("127.0.0.1:19083")),
                        ingress_tcp_service: Some(String::from("default")),
                        ingress_udp_bind: Some(String::from("127.0.0.1:19084")),
                        ingress_udp_service: Some(String::from("default")),
                        guest_web_root: Some(String::from("/var/www")),
                        supported_guest_commands: vec![
                            String::from("ip addr"),
                            String::from("ip route"),
                            String::from("hostname -I"),
                            String::from("resolvectl status"),
                            String::from("nslookup <hostname>"),
                            String::from("getent hosts <hostname>"),
                            String::from("curl <http-or-https-url>"),
                            String::from("curl -I <http-or-https-url>"),
                            String::from("fetch <http-or-https-url>"),
                            String::from("nc <host> <port>"),
                            String::from("nc -z <host> <port>"),
                            String::from("nc <host> <port> <payload>"),
                            String::from("nc -u <host> <port>"),
                            String::from("nc -zu <host> <port>"),
                            String::from("nc -u <host> <port> <payload>"),
                        ],
                    }),
                    last_event_at: OffsetDateTime::from_unix_timestamp(12)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_intents = DocumentStore::open(
            temp.path()
                .join("uvm-node")
                .join("runtime_session_intents.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        runtime_session_intents
            .create(
                runtime_session_id.as_str(),
                UvmRuntimeSessionIntentContractSnapshot {
                    runtime_session_id: runtime_session_id.clone(),
                    instance_id: instance.id.clone(),
                    execution_intent: explicit_intent.clone(),
                    first_placement_portability_assessment: Some(portability.clone()),
                    last_portability_preflight_id: Some(preflight_id.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflights =
            DocumentStore::open(temp.path().join("uvm-node").join("runtime_preflights.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runtime_preflights
            .create(
                preflight_id.as_str(),
                UvmRuntimePreflightContractSnapshot {
                    id: preflight_id.clone(),
                    selected_backend: Some(String::from("kvm")),
                    blockers: Vec::new(),
                    portability_assessment: Some(portability.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let host_evidence =
            DocumentStore::open(temp.path().join("uvm-observe").join("host_evidence.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        host_evidence
            .create(
                host_evidence_id.as_str(),
                UvmObserveHostEvidenceContractSnapshot {
                    id: host_evidence_id.clone(),
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("bare_metal"),
                    hardware_virtualization: true,
                    nested_virtualization: false,
                    qemu_available: true,
                    collected_at: OffsetDateTime::from_unix_timestamp(12)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claim_decisions =
            DocumentStore::open(temp.path().join("uvm-observe").join("claim_decisions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        claim_decisions
            .create(
                claim_decision_id.as_str(),
                UvmObserveClaimDecisionContractSnapshot {
                    id: claim_decision_id.clone(),
                    host_evidence_id: Some(host_evidence_id.clone()),
                    runtime_session_id: Some(runtime_session_id.clone()),
                    runtime_preflight_id: Some(preflight_id.clone()),
                    highest_claim_tier: String::from("competitive"),
                    claim_status: String::from("allowed"),
                    native_indistinguishable_status: true,
                    prohibited_claim_count: 0,
                    missing_required_workload_classes: Vec::new(),
                    failing_workload_classes: Vec::new(),
                    portability_assessment: Some(portability.clone()),
                    portability_assessment_source:
                        UvmPortabilityAssessmentSource::FirstPlacementLineage,
                    portability_assessment_unavailable_reason: None,
                    decided_at: OffsetDateTime::from_unix_timestamp(13)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let perf_attestations = DocumentStore::open(
            temp.path()
                .join("uvm-observe")
                .join("perf_attestations.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        perf_attestations
            .create(
                perf_general_old.as_str(),
                UvmObservePerfAttestationContractSnapshot {
                    id: perf_general_old.clone(),
                    instance_id: instance.id.clone(),
                    workload_class: String::from("general"),
                    claim_tier: String::from("competitive"),
                    claim_evidence_mode: String::from("measured"),
                    native_indistinguishable: true,
                    measured_at: OffsetDateTime::from_unix_timestamp(14)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        perf_attestations
            .create(
                perf_general_latest.as_str(),
                UvmObservePerfAttestationContractSnapshot {
                    id: perf_general_latest.clone(),
                    instance_id: instance.id.clone(),
                    workload_class: String::from("general"),
                    claim_tier: String::from("competitive"),
                    claim_evidence_mode: String::from("measured"),
                    native_indistinguishable: true,
                    measured_at: OffsetDateTime::from_unix_timestamp(15)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        perf_attestations
            .create(
                perf_network.as_str(),
                UvmObservePerfAttestationContractSnapshot {
                    id: perf_network.clone(),
                    instance_id: instance.id.clone(),
                    workload_class: String::from("network_intensive"),
                    claim_tier: String::from("competitive"),
                    claim_evidence_mode: String::from("measured"),
                    native_indistinguishable: true,
                    measured_at: OffsetDateTime::from_unix_timestamp(16)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_resolved_instance_contract(instance.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let view: UvmResolvedContractView = parse_api_body(response).await;
        assert_eq!(view.instance.id, instance.id);
        assert_eq!(
            view.template.as_ref().map(|template| template.id.clone()),
            Some(template_id.clone())
        );
        assert_eq!(
            view.boot_image.as_ref().map(|image| image.id.clone()),
            Some(instance.boot_image_id.clone())
        );
        assert_eq!(
            view.runtime_session
                .as_ref()
                .map(|session| session.id.clone()),
            Some(runtime_session_id.clone())
        );
        let runtime_access = view
            .runtime_access
            .as_ref()
            .unwrap_or_else(|| panic!("missing resolved runtime access"));
        assert_eq!(runtime_access.network_mode, "guest_owned_usernet_nat");
        assert!(runtime_access.internet_nat);
        assert!(runtime_access.ingress_tcp_ready);
        assert!(runtime_access.ingress_udp_ready);
        assert_eq!(
            runtime_access.ingress_http_url.as_deref(),
            Some("http://127.0.0.1:19082")
        );
        assert_eq!(
            runtime_access.ingress_tcp_bind.as_deref(),
            Some("127.0.0.1:19083")
        );
        assert_eq!(
            runtime_access.ingress_udp_bind.as_deref(),
            Some("127.0.0.1:19084")
        );
        assert_eq!(view.runtime_execution_intent, Some(explicit_intent.clone()));
        assert_eq!(
            view.claim_decision
                .as_ref()
                .map(|decision| decision.id.clone()),
            Some(claim_decision_id.clone())
        );
        assert_eq!(
            view.host_evidence
                .as_ref()
                .map(|evidence| evidence.id.clone()),
            Some(host_evidence_id.clone())
        );
        assert_eq!(view.latest_perf_attestations.len(), 2);
        assert_eq!(
            view.latest_perf_attestations
                .iter()
                .find(|sample| sample.workload_class == "general")
                .map(|sample| sample.id.clone()),
            Some(perf_general_latest)
        );
        assert_eq!(view.effective_execution_intent, explicit_intent);
        assert_eq!(view.effective_claim_tier, "competitive");
        assert_eq!(view.effective_claim_status.as_deref(), Some("allowed"));
        assert_eq!(
            view.portability_assessment_source,
            Some(UvmPortabilityAssessmentSource::FirstPlacementLineage)
        );
        assert!(
            view.effective_portability_assessment
                .as_ref()
                .map(|assessment| assessment.supported)
                .unwrap_or(false)
        );
        assert!(
            view.resolution_notes
                .iter()
                .any(|note| note.contains("boot image claim_tier competitive differs"))
        );
        assert!(
            view.resolution_notes
                .iter()
                .any(|note| note.contains("runtime claim_tier competitive differs"))
        );
    }

    #[tokio::test]
    async fn resolved_instance_contract_prefers_claim_decision_portability_over_runtime_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let explicit_intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
            required_portability_tier: UvmPortabilityTier::AcceleratorRequired,
            evidence_strictness: UvmEvidenceStrictness::RequireMeasured,
        };
        let runtime_portability = UvmPortabilityAssessment {
            intent: explicit_intent.clone(),
            supported: true,
            eligible_backends: vec![HypervisorBackend::Kvm],
            selected_backend: Some(HypervisorBackend::Kvm),
            selected_via_fallback: false,
            selection_reason: Some(String::from("runtime lineage admits kvm")),
            blockers: Vec::new(),
            evidence: Vec::new(),
        };
        let observe_portability = UvmPortabilityAssessment {
            intent: explicit_intent.clone(),
            supported: false,
            eligible_backends: Vec::new(),
            selected_backend: None,
            selected_via_fallback: false,
            selection_reason: Some(String::from("observe portability gate denied placement")),
            blockers: vec![String::from("observe veto")],
            evidence: Vec::new(),
        };

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("resolved-contract-portability-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 4,
                    memory_mb: 4096,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: Some(explicit_intent.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.clone())
            .unwrap_or_else(|| panic!("missing template"));

        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("resolved-contract-portability-instance"),
                    template_id: Some(template_id.to_string()),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: Some(node_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing instance"));

        let runtime_session_id =
            UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            UvmNodeCapabilityId::generate().unwrap_or_else(|error| panic!("{error}"));
        let preflight_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let claim_decision_id =
            UvmClaimDecisionId::generate().unwrap_or_else(|error| panic!("{error}"));

        let runtime_sessions =
            DocumentStore::open(temp.path().join("uvm-node").join("runtime_sessions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runtime_sessions
            .create(
                runtime_session_id.as_str(),
                UvmRuntimeSessionContractSnapshot {
                    id: runtime_session_id.clone(),
                    instance_id: instance.id.clone(),
                    node_id: node_id.clone(),
                    capability_id,
                    claim_tier: instance.claim_tier.clone(),
                    accelerator_backend: String::from("kvm"),
                    state: String::from("stopped"),
                    migration_in_progress: false,
                    created_at: OffsetDateTime::from_unix_timestamp(10)
                        .unwrap_or_else(|error| panic!("{error}")),
                    last_transition_at: OffsetDateTime::from_unix_timestamp(11)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_intents = DocumentStore::open(
            temp.path()
                .join("uvm-node")
                .join("runtime_session_intents.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        runtime_session_intents
            .create(
                runtime_session_id.as_str(),
                UvmRuntimeSessionIntentContractSnapshot {
                    runtime_session_id: runtime_session_id.clone(),
                    instance_id: instance.id.clone(),
                    execution_intent: explicit_intent.clone(),
                    first_placement_portability_assessment: Some(runtime_portability.clone()),
                    last_portability_preflight_id: Some(preflight_id.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflights =
            DocumentStore::open(temp.path().join("uvm-node").join("runtime_preflights.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        runtime_preflights
            .create(
                preflight_id.as_str(),
                UvmRuntimePreflightContractSnapshot {
                    id: preflight_id.clone(),
                    selected_backend: Some(String::from("kvm")),
                    blockers: Vec::new(),
                    portability_assessment: Some(runtime_portability),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let claim_decisions =
            DocumentStore::open(temp.path().join("uvm-observe").join("claim_decisions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        claim_decisions
            .create(
                claim_decision_id.as_str(),
                UvmObserveClaimDecisionContractSnapshot {
                    id: claim_decision_id.clone(),
                    host_evidence_id: None,
                    runtime_session_id: Some(runtime_session_id.clone()),
                    runtime_preflight_id: Some(preflight_id.clone()),
                    highest_claim_tier: instance.claim_tier.clone(),
                    claim_status: String::from("blocked"),
                    native_indistinguishable_status: false,
                    prohibited_claim_count: 1,
                    missing_required_workload_classes: vec![String::from("general")],
                    failing_workload_classes: vec![String::from("general")],
                    portability_assessment: Some(observe_portability.clone()),
                    portability_assessment_source: UvmPortabilityAssessmentSource::RequestFallback,
                    portability_assessment_unavailable_reason: None,
                    decided_at: OffsetDateTime::from_unix_timestamp(12)
                        .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_resolved_instance_contract(instance.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let view: UvmResolvedContractView = parse_api_body(response).await;
        assert_eq!(
            view.claim_decision
                .as_ref()
                .map(|decision| decision.id.clone()),
            Some(claim_decision_id)
        );
        assert_eq!(
            view.effective_portability_assessment,
            Some(observe_portability)
        );
        assert_eq!(
            view.portability_assessment_source,
            Some(UvmPortabilityAssessmentSource::RequestFallback)
        );
        assert_eq!(view.portability_assessment_unavailable_reason, None);
        assert_eq!(view.runtime_execution_intent, Some(explicit_intent));
    }

    #[tokio::test]
    async fn resolved_instance_contract_surfaces_missing_external_truth_without_failing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("missing-truth-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_standard"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("missing-truth-instance"),
                    template_id: Some(template_id),
                    boot_image_id: UvmImageId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: Some(
                        NodeId::generate()
                            .unwrap_or_else(|error| panic!("{error}"))
                            .to_string(),
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));
        let _ = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .get_resolved_instance_contract(&instance_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let view: UvmResolvedContractView = parse_api_body(response).await;
        assert!(view.boot_image.is_none());
        assert!(view.runtime_session.is_none());
        assert!(view.claim_decision.is_none());
        assert!(view.host_evidence.is_none());
        assert!(view.latest_perf_attestations.is_empty());
        assert_eq!(view.effective_claim_tier, ClaimTier::Compatible.as_str());
        assert_eq!(view.effective_claim_status, None);
        assert!(
            view.resolution_notes
                .iter()
                .any(|note| note.contains("boot image") && note.contains("missing"))
        );
        assert!(
            view.resolution_notes
                .iter()
                .any(|note| note.contains("no active session"))
        );
    }

    #[tokio::test]
    async fn reconciliation_detects_missing_runtime_for_running_instance() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let image_id = UvmImageId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("reconcile-template"),
                    architecture: String::from("x86_64"),
                    vcpu: 2,
                    memory_mb: 2048,
                    cpu_topology: String::from("balanced"),
                    numa_policy: String::from("preferred_local"),
                    firmware_profile: String::from("uefi_secure"),
                    boot_device: None,
                    device_profile: String::from("cloud-balanced"),
                    migration_policy: String::from("best_effort_live"),
                    apple_guest_allowed: Some(false),
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing template"));
        let _ = service
            .create_instance(
                CreateInstanceRequest {
                    project_id: project_id.to_string(),
                    name: String::from("reconcile-vm"),
                    template_id: Some(template_id),
                    boot_image_id: image_id.to_string(),
                    install_media_image_id: None,
                    architecture: None,
                    guest_os: String::from("linux"),
                    vcpu: None,
                    memory_mb: None,
                    cpu_topology: None,
                    numa_policy: None,
                    firmware_profile: None,
                    boot_device: None,
                    device_profile: None,
                    migration_policy: None,
                    apple_guest_approved: Some(false),
                    host_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let instance_id = service
            .instances
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing instance"));
        let _ = service
            .start_instance(&instance_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .reconcile_instances(&context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let reports = service
            .reconciliations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let report = reports
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing reconciliation report"));
        assert_eq!(report.status, "drift_detected");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "running_instance_without_runtime")
        );
    }
}
