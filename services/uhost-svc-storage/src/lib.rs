//! Object and volume storage service.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use bytes::Bytes;
use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use uhost_api::{
    ApiBody, empty_body, full_body, json_response, parse_json, path_segments, read_body, with_etag,
};
use uhost_core::{ErrorCode, PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::workflow::{WorkflowEffectLedgerRecord, WorkflowStepEffectExecution};
use uhost_store::{
    BlobStore, DocumentStore, MetadataCollection, MetadataJournal, StoredDocument,
    WorkflowCollection, WorkflowInstance, WorkflowPhase, WorkflowStep, WorkflowStepState,
};
use uhost_types::{
    ArchiveId, AuditId, BucketId, DurabilityTierId, FileShareId, OwnershipScope, PrincipalKind,
    RehydrateJobId, ResourceLifecycleState, ResourceMetadata, StorageClassId, UploadId, VolumeId,
};

/// Resource families that can bind to storage classes and durability tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageResourceKind {
    Bucket,
    Volume,
    Database,
}

/// Storage media exposed by one storage class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMedium {
    Object,
    Block,
    File,
    Archive,
}

/// Failure-domain spread enforced by one durability tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFailureDomainScope {
    Cell,
    Region,
    CrossRegion,
}

/// Explicit storage binding attached to one durable resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBinding {
    pub storage_class_id: StorageClassId,
    pub durability_tier_id: DurabilityTierId,
}

/// Storage-class metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageClassRecord {
    pub id: StorageClassId,
    pub name: String,
    pub medium: StorageMedium,
    pub supported_resource_kinds: Vec<StorageResourceKind>,
    pub metadata: ResourceMetadata,
}

impl StorageClassRecord {
    fn supports_resource_kind(&self, kind: StorageResourceKind) -> bool {
        self.supported_resource_kinds.contains(&kind)
    }
}

/// Durability-tier metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityTierRecord {
    pub id: DurabilityTierId,
    pub name: String,
    pub minimum_replica_count: u8,
    pub failure_domain_scope: StorageFailureDomainScope,
    pub supported_resource_kinds: Vec<StorageResourceKind>,
    pub metadata: ResourceMetadata,
}

impl DurabilityTierRecord {
    fn supports_resource_kind(&self, kind: StorageResourceKind) -> bool {
        self.supported_resource_kinds.contains(&kind)
    }
}

/// Object bucket metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketRecord {
    pub id: BucketId,
    pub name: String,
    pub owner_id: String,
    #[serde(default)]
    pub storage_binding: Option<StorageBinding>,
    pub metadata: ResourceMetadata,
}

/// Block volume metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub id: VolumeId,
    pub name: String,
    pub size_gb: u32,
    pub attached_to: Option<String>,
    #[serde(default)]
    pub storage_binding: Option<StorageBinding>,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileShareProtocol {
    Nfs,
    Smb,
}

impl FileShareProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nfs => "nfs",
            Self::Smb => "smb",
        }
    }
}

/// Managed file-share metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileShareRecord {
    pub id: FileShareId,
    pub name: String,
    pub capacity_gb: u32,
    pub protocol: FileShareProtocol,
    pub mounted_to: Option<String>,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAccessState {
    Archived,
    Available,
}

impl ArchiveAccessState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Archived => "archived",
            Self::Available => "available",
        }
    }
}

/// Managed archive-storage metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub id: ArchiveId,
    pub name: String,
    pub size_bytes: u64,
    pub access_state: ArchiveAccessState,
    pub rehydrated_until: Option<OffsetDateTime>,
    pub last_rehydrate_job_id: Option<RehydrateJobId>,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveRehydratePriority {
    Standard,
    Expedited,
    Bulk,
}

impl ArchiveRehydratePriority {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Expedited => "expedited",
            Self::Bulk => "bulk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveRehydrateJobState {
    Pending,
    Running,
    Completed,
    Failed,
}

/// Durable archive rehydrate request and outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRehydrateJobRecord {
    pub id: RehydrateJobId,
    pub archive_id: ArchiveId,
    pub priority: ArchiveRehydratePriority,
    pub restore_window_hours: u16,
    pub state: ArchiveRehydrateJobState,
    pub requested_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
    pub rehydrated_until: OffsetDateTime,
    pub reason: Option<String>,
    pub metadata: ResourceMetadata,
}

/// Multipart upload session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadSession {
    pub id: UploadId,
    pub bucket_id: BucketId,
    pub object_key: String,
    pub parts: BTreeMap<u32, String>,
    pub completed: bool,
    pub object_digest: Option<String>,
    pub metadata: ResourceMetadata,
}

/// Public summary of one ready volume recovery point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRecoveryPointSummary {
    /// Restored volume identifier.
    pub volume_id: VolumeId,
    /// Optimistic concurrency version of the persisted recovery point record.
    pub version: u64,
    /// Monotonic execution count captured by the storage recovery lineage.
    pub execution_count: u64,
    /// Stable recovery-point ETag captured by the restore workflow.
    pub etag: String,
    /// Timestamp of the latest persisted snapshot represented by this recovery point.
    pub captured_at: OffsetDateTime,
}

/// Operator-facing summary of one volume snapshot policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSnapshotPolicySummary {
    /// Volume identifier bound to this snapshot policy.
    pub volume_id: VolumeId,
    /// Stable recovery class enforced by this policy.
    pub recovery_class: String,
    /// Human-readable policy state.
    pub state: String,
    /// Lifecycle state of the persisted policy record.
    pub lifecycle: String,
    /// Snapshot cadence in minutes.
    pub interval_minutes: u32,
    /// Number of snapshots retained by policy.
    pub retention_snapshots: u16,
    /// Recovery point objective in minutes.
    pub recovery_point_objective_minutes: u32,
    /// Scheduled timestamp for the next policy-driven snapshot.
    pub next_snapshot_after: OffsetDateTime,
}

/// Operator-facing recovery history entry for one persisted recovery-point revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRecoveryHistoryEntry {
    /// Volume identifier that owns this recovery-point revision.
    pub volume_id: VolumeId,
    /// Optimistic concurrency version of the persisted recovery-point revision.
    pub version: u64,
    /// Monotonic execution count captured by this revision.
    pub execution_count: u64,
    /// Stable recovery-point ETag for this revision.
    pub etag: String,
    /// Timestamp of the persisted snapshot captured by this revision.
    pub captured_at: OffsetDateTime,
    /// Whether this revision still matches the current ready recovery point.
    pub current: bool,
}

/// Public summary of one durable volume restore action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRestoreActionSummary {
    /// Durable restore action identifier.
    pub id: AuditId,
    /// Workflow identifier that drove this action.
    pub workflow_id: String,
    /// Target volume identifier.
    pub volume_id: VolumeId,
    /// Human-readable restore action state.
    pub state: String,
    /// Source recovery point volume identifier.
    pub source_recovery_point_volume_id: VolumeId,
    /// Source recovery point record version.
    pub source_recovery_point_version: u64,
    /// Source recovery point execution count.
    pub source_recovery_point_execution_count: u64,
    /// Source recovery point ETag.
    pub source_recovery_point_etag: String,
    /// Source recovery point capture timestamp.
    pub source_recovery_point_captured_at: OffsetDateTime,
    /// Stable recovery class executed by this restore action.
    pub recovery_class: String,
    /// Optional operator-supplied reason captured with the restore request.
    pub requested_reason: Option<String>,
    /// Timestamp when the restore action was requested.
    pub requested_at: OffsetDateTime,
    /// Timestamp when the restore action first left the pending state.
    pub started_at: Option<OffsetDateTime>,
    /// Timestamp when the restore action completed, if it has completed.
    pub completed_at: Option<OffsetDateTime>,
    /// Lifecycle state of the persisted restore-action projection.
    pub lifecycle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSummaryResponse {
    pub bucket_count: usize,
    pub volume_count: usize,
    pub attachment_count: usize,
    pub file_share_count: usize,
    pub archive_count: usize,
    pub upload_session_count: usize,
    pub archive_rehydrate_job_count: usize,
    pub recovery_point_count: usize,
    pub restore_action_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBucketRequest {
    name: String,
    owner_id: String,
    #[serde(default)]
    storage_class_id: Option<String>,
    #[serde(default)]
    durability_tier_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateVolumeRequest {
    name: String,
    size_gb: u32,
    #[serde(default)]
    storage_class_id: Option<String>,
    #[serde(default)]
    durability_tier_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateFileShareRequest {
    name: String,
    capacity_gb: u32,
    #[serde(default)]
    protocol: Option<FileShareProtocol>,
    #[serde(default)]
    mounted_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateArchiveRequest {
    name: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateStorageClassRequest {
    name: String,
    medium: StorageMedium,
    supported_resource_kinds: Vec<StorageResourceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDurabilityTierRequest {
    name: String,
    minimum_replica_count: u8,
    failure_domain_scope: StorageFailureDomainScope,
    supported_resource_kinds: Vec<StorageResourceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateUploadRequest {
    bucket_id: String,
    object_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateArchiveRehydrateJobRequest {
    archive_id: String,
    #[serde(default)]
    priority: Option<ArchiveRehydratePriority>,
    #[serde(default)]
    restore_window_hours: Option<u16>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateVolumeRestoreActionRequest {
    #[serde(default)]
    recovery_point_version: Option<u64>,
    #[serde(default)]
    recovery_point_etag: Option<String>,
    #[serde(default)]
    reason: Option<String>,
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

fn with_request_correlation(error: PlatformError, context: &RequestContext) -> PlatformError {
    error.with_correlation_id(context.correlation_id.clone())
}

fn with_optional_request_correlation(
    error: PlatformError,
    context: Option<&RequestContext>,
) -> PlatformError {
    match context {
        Some(context) => with_request_correlation(error, context),
        None => error,
    }
}

fn storage_backend_error_detail(error: &PlatformError) -> String {
    error.detail.as_deref().map_or_else(
        || error.message.clone(),
        |detail| format!("{} ({detail})", error.message),
    )
}

fn is_storage_corruption_error(error: &PlatformError) -> bool {
    matches!(
        error.message.as_str(),
        "blob integrity sidecar mismatch"
            | "failed to decode blob integrity sidecar"
            | "blob part truncated during concat"
            | "blob truncated during read"
    )
}

fn remap_object_download_error(
    digest: &str,
    error: PlatformError,
    context: Option<&RequestContext>,
) -> PlatformError {
    let error = if is_storage_corruption_error(&error) {
        PlatformError::storage_corruption("object integrity verification failed").with_detail(
            format!("digest={digest} {}", storage_backend_error_detail(&error)),
        )
    } else {
        error
    };
    with_optional_request_correlation(error, context)
}

const DEFAULT_OBJECT_STORAGE_CLASS_ID: &str = "stc_objectstandard";
const DEFAULT_BLOCK_STORAGE_CLASS_ID: &str = "stc_blockstandard";
const DEFAULT_ARCHIVE_REHYDRATE_WINDOW_HOURS: u16 = 24;
const DEFAULT_OBJECT_DURABILITY_TIER_ID: &str = "dur_objectregional";
const DEFAULT_BLOCK_DURABILITY_TIER_ID: &str = "dur_blockregional";

const VOLUME_SNAPSHOT_WORKFLOW_KIND: &str = "storage.volume.snapshot_intent";
const VOLUME_SNAPSHOT_WORKFLOW_SUBJECT_KIND: &str = "volume";
const VOLUME_RECOVERY_POINT_ACTION_KIND: &str = "storage.volume.snapshot_execution";
const VOLUME_SNAPSHOT_FINAL_STEP_INDEX: usize = 2;
const VOLUME_RESTORE_WORKFLOW_KIND: &str = "storage.volume.restore_intent";
const VOLUME_RESTORE_WORKFLOW_SUBJECT_KIND: &str = "volume";
const VOLUME_RESTORE_ACTION_KIND: &str = "storage.volume.restore_execution";
const VOLUME_RESTORE_RECONCILER_RUNNER_ID: &str = "storage:volume-restore-reconciler";
const VOLUME_RESTORE_FINAL_STEP_INDEX: usize = 2;
const VOLUME_RESTORE_APPLY_EFFECT_KIND: &str = "apply_recovery_point";
const DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES: u32 = 60;
const DEFAULT_VOLUME_SNAPSHOT_RETENTION: u16 = 24;
const DEFAULT_VOLUME_RECOVERY_POINT_OBJECTIVE_MINUTES: u32 = 60;
const BLOB_GC_WORKFLOW_KIND: &str = "storage.blob.gc";
const BLOB_GC_WORKFLOW_SUBJECT_KIND: &str = "blob";
const BLOB_GC_CONFIRM_STEP_INDEX: usize = 0;
const BLOB_GC_DELETE_STEP_INDEX: usize = 1;
const BLOB_GC_RETRY_DELAY_SECONDS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VolumeRecoveryClass {
    ScheduledSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VolumeSnapshotPolicyState {
    Pending,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeSnapshotPolicy {
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    state: VolumeSnapshotPolicyState,
    interval_minutes: u32,
    retention_snapshots: u16,
    recovery_point_objective_minutes: u32,
    next_snapshot_after: OffsetDateTime,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeSnapshotWorkflowState {
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    target_policy_state: VolumeSnapshotPolicyState,
    interval_minutes: u32,
    retention_snapshots: u16,
    recovery_point_objective_minutes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VolumeRecoveryPointTrigger {
    PolicyActivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeRecoveryPoint {
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    capture_trigger: VolumeRecoveryPointTrigger,
    execution_count: u64,
    latest_snapshot_at: OffsetDateTime,
    next_snapshot_after: OffsetDateTime,
    interval_minutes: u32,
    retention_snapshots: u16,
    recovery_point_objective_minutes: u32,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeRecoveryPointRevision {
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    recovery_point_version: u64,
    execution_count: u64,
    captured_at: OffsetDateTime,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedVolumeRecoveryPoint {
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    recovery_point_version: u64,
    recovery_point_execution_count: u64,
    recovery_point_etag: String,
    recovery_point_captured_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeRestoreWorkflowState {
    restore_action_id: AuditId,
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    recovery_point_volume_id: VolumeId,
    recovery_point_version: u64,
    recovery_point_execution_count: u64,
    recovery_point_etag: String,
    recovery_point_captured_at: OffsetDateTime,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum VolumeRestoreApplyLedgerRecord {
    Current(WorkflowEffectLedgerRecord),
    Legacy(LegacyVolumeRestoreApplyLedgerRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyVolumeRestoreApplyLedgerRecord {
    idempotency_key: String,
    workflow_id: String,
    volume_id: VolumeId,
    recovery_point_volume_id: VolumeId,
    recovery_point_version: u64,
    recovery_point_execution_count: u64,
    recovery_point_etag: String,
    result_digest: String,
    recorded_at: OffsetDateTime,
}

impl VolumeRestoreApplyLedgerRecord {
    fn current(record: WorkflowEffectLedgerRecord) -> Self {
        Self::Current(record)
    }

    fn result_digest(&self) -> &str {
        match self {
            Self::Current(record) => record.result_digest.as_str(),
            Self::Legacy(record) => record.result_digest.as_str(),
        }
    }

    fn recorded_at(&self) -> OffsetDateTime {
        match self {
            Self::Current(record) => record.recorded_at,
            Self::Legacy(record) => record.recorded_at,
        }
    }

    fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VolumeRestoreActionState {
    Pending,
    Running,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VolumeRestoreAction {
    id: AuditId,
    workflow_id: String,
    workflow_kind: String,
    volume_id: VolumeId,
    recovery_class: VolumeRecoveryClass,
    source_recovery_point_volume_id: VolumeId,
    source_recovery_point_version: u64,
    source_recovery_point_execution_count: u64,
    source_recovery_point_etag: String,
    source_recovery_point_captured_at: OffsetDateTime,
    state: VolumeRestoreActionState,
    requested_reason: Option<String>,
    requested_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    completed_at: Option<OffsetDateTime>,
    metadata: ResourceMetadata,
}

type VolumeRestoreWorkflow = WorkflowInstance<VolumeRestoreWorkflowState>;
type BlobGcWorkflow = WorkflowInstance<BlobGcWorkflowState>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlobReferenceRecord {
    digest: String,
    reference_count: u64,
    owners: Vec<String>,
    physical_blob_present: bool,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlobGcWorkflowState {
    digest: String,
    reference_count: u64,
    physical_blob_present: bool,
    deletion_attempts: u32,
    last_outcome: Option<String>,
}

/// Storage service.
#[derive(Debug, Clone)]
pub struct StorageService {
    storage_classes: DocumentStore<StorageClassRecord>,
    durability_tiers: DocumentStore<DurabilityTierRecord>,
    buckets: DocumentStore<BucketRecord>,
    volumes: DocumentStore<VolumeRecord>,
    file_shares: DocumentStore<FileShareRecord>,
    archives: DocumentStore<ArchiveRecord>,
    volume_snapshot_policies: MetadataCollection<VolumeSnapshotPolicy>,
    volume_snapshot_workflows: WorkflowCollection<VolumeSnapshotWorkflowState>,
    volume_recovery_points: MetadataCollection<VolumeRecoveryPoint>,
    volume_recovery_point_revisions: MetadataCollection<VolumeRecoveryPointRevision>,
    volume_restore_actions: MetadataCollection<VolumeRestoreAction>,
    volume_restore_workflows: WorkflowCollection<VolumeRestoreWorkflowState>,
    volume_restore_apply_ledger: DocumentStore<VolumeRestoreApplyLedgerRecord>,
    archive_rehydrate_jobs: DocumentStore<ArchiveRehydrateJobRecord>,
    uploads: DocumentStore<UploadSession>,
    blob_references: MetadataCollection<BlobReferenceRecord>,
    blob_gc_workflows: WorkflowCollection<BlobGcWorkflowState>,
    blobs: BlobStore,
    metadata_journal: MetadataJournal,
    blob_accounting_guard: Arc<Mutex<()>>,
    state_root: PathBuf,
}

impl StorageService {
    /// Open storage state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("storage");
        let service = Self {
            storage_classes: DocumentStore::open(root.join("storage_classes.json")).await?,
            durability_tiers: DocumentStore::open(root.join("durability_tiers.json")).await?,
            buckets: DocumentStore::open(root.join("buckets.json")).await?,
            volumes: DocumentStore::open(root.join("volumes.json")).await?,
            file_shares: DocumentStore::open(root.join("file_shares.json")).await?,
            archives: DocumentStore::open(root.join("archives.json")).await?,
            volume_snapshot_policies: MetadataCollection::open_local(
                root.join("volume_snapshot_policies.json"),
            )
            .await?,
            volume_snapshot_workflows: WorkflowCollection::open_local(
                root.join("volume_snapshot_workflows.json"),
            )
            .await?,
            volume_recovery_points: MetadataCollection::open_local(
                root.join("volume_recovery_points.json"),
            )
            .await?,
            volume_recovery_point_revisions: MetadataCollection::open_local(
                root.join("volume_recovery_point_revisions.json"),
            )
            .await?,
            volume_restore_actions: MetadataCollection::open_local(
                root.join("volume_restore_actions.json"),
            )
            .await?,
            volume_restore_workflows: WorkflowCollection::open_local(
                root.join("volume_restore_workflows.json"),
            )
            .await?,
            volume_restore_apply_ledger: DocumentStore::open(
                root.join("volume_restore_apply_ledger.json"),
            )
            .await?,
            archive_rehydrate_jobs: DocumentStore::open(root.join("archive_rehydrate_jobs.json"))
                .await?,
            uploads: DocumentStore::open(root.join("uploads.json")).await?,
            blob_references: MetadataCollection::open_local(root.join("blob_references.json"))
                .await?,
            blob_gc_workflows: WorkflowCollection::open_local(root.join("blob_gc_workflows.json"))
                .await?,
            blobs: BlobStore::open(root.join("blobs")).await?,
            metadata_journal: MetadataJournal::open(root.join("metadata_journal")).await?,
            blob_accounting_guard: Arc::new(Mutex::new(())),
            state_root: root,
        };
        service.reconcile_storage_taxonomy().await?;
        service.reconcile_bucket_bindings().await?;
        service.reconcile_volume_bindings().await?;
        service.reconcile_volume_snapshot_lifecycle().await?;
        service.reconcile_volume_restore_workflows().await?;
        service
            .migrate_legacy_volume_restore_apply_ledgers()
            .await?;
        {
            let _blob_guard = service.blob_accounting_guard.lock().await;
            let _cleanup_pending = service.reconcile_blob_accounting_and_gc_locked().await?;
        }
        Ok(service)
    }

    async fn reconcile_storage_taxonomy(&self) -> Result<()> {
        for storage_class in builtin_storage_classes() {
            self.ensure_builtin_storage_class(storage_class).await?;
        }
        for durability_tier in builtin_durability_tiers() {
            self.ensure_builtin_durability_tier(durability_tier).await?;
        }
        Ok(())
    }

    async fn ensure_builtin_storage_class(&self, record: StorageClassRecord) -> Result<()> {
        let key = record.id.as_str().to_owned();
        match self.storage_classes.get(key.as_str()).await? {
            Some(stored) if !stored.deleted && stored.value == record => Ok(()),
            Some(stored) => {
                let _ = self
                    .storage_classes
                    .upsert(key.as_str(), record, Some(stored.version))
                    .await?;
                Ok(())
            }
            None => match self
                .storage_classes
                .create(key.as_str(), record.clone())
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if matches!(error.code, ErrorCode::Conflict) => {
                    let stored =
                        self.storage_classes
                            .get(key.as_str())
                            .await?
                            .ok_or_else(|| {
                                PlatformError::conflict(
                                    "storage class already exists but could not be loaded",
                                )
                            })?;
                    let _ = self
                        .storage_classes
                        .upsert(key.as_str(), record, Some(stored.version))
                        .await?;
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
    }

    async fn ensure_builtin_durability_tier(&self, record: DurabilityTierRecord) -> Result<()> {
        let key = record.id.as_str().to_owned();
        match self.durability_tiers.get(key.as_str()).await? {
            Some(stored) if !stored.deleted && stored.value == record => Ok(()),
            Some(stored) => {
                let _ = self
                    .durability_tiers
                    .upsert(key.as_str(), record, Some(stored.version))
                    .await?;
                Ok(())
            }
            None => match self
                .durability_tiers
                .create(key.as_str(), record.clone())
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if matches!(error.code, ErrorCode::Conflict) => {
                    let stored =
                        self.durability_tiers
                            .get(key.as_str())
                            .await?
                            .ok_or_else(|| {
                                PlatformError::conflict(
                                    "durability tier already exists but could not be loaded",
                                )
                            })?;
                    let _ = self
                        .durability_tiers
                        .upsert(key.as_str(), record, Some(stored.version))
                        .await?;
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
    }

    async fn reconcile_bucket_bindings(&self) -> Result<()> {
        let default_binding = self
            .resolve_storage_binding(StorageResourceKind::Bucket, None, None)
            .await?;
        for (key, stored) in self.buckets.list().await? {
            if stored.deleted || stored.value.storage_binding.is_some() {
                continue;
            }

            let mut bucket = stored.value;
            bucket.storage_binding = Some(default_binding.clone());
            bucket.metadata.touch(storage_binding_etag(
                bucket.id.as_str(),
                bucket.storage_binding.as_ref(),
            ));
            let _ = self
                .buckets
                .upsert(&key, bucket, Some(stored.version))
                .await?;
        }
        Ok(())
    }

    async fn reconcile_volume_bindings(&self) -> Result<()> {
        let default_binding = self
            .resolve_storage_binding(StorageResourceKind::Volume, None, None)
            .await?;
        for (key, stored) in self.volumes.list().await? {
            if stored.deleted || stored.value.storage_binding.is_some() {
                continue;
            }

            let mut volume = stored.value;
            volume.storage_binding = Some(default_binding.clone());
            volume.metadata.touch(storage_binding_etag(
                volume.id.as_str(),
                volume.storage_binding.as_ref(),
            ));
            let _ = self
                .volumes
                .upsert(&key, volume, Some(stored.version))
                .await?;
        }
        Ok(())
    }

    async fn create_storage_class(
        &self,
        request: CreateStorageClassRequest,
    ) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "storage class name")?;
        let supported_resource_kinds =
            normalize_supported_resource_kinds(request.supported_resource_kinds)?;
        let id = StorageClassId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate storage class id")
                .with_detail(error.to_string())
        })?;
        let record = StorageClassRecord {
            id: id.clone(),
            name,
            medium: request.medium,
            supported_resource_kinds,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.storage_classes
            .create(id.as_str(), record.clone())
            .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_durability_tier(
        &self,
        request: CreateDurabilityTierRequest,
    ) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "durability tier name")?;
        if request.minimum_replica_count == 0 {
            return Err(PlatformError::invalid(
                "minimum_replica_count must be greater than zero",
            ));
        }
        let supported_resource_kinds =
            normalize_supported_resource_kinds(request.supported_resource_kinds)?;
        let id = DurabilityTierId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate durability tier id")
                .with_detail(error.to_string())
        })?;
        let record = DurabilityTierRecord {
            id: id.clone(),
            name,
            minimum_replica_count: request.minimum_replica_count,
            failure_domain_scope: request.failure_domain_scope,
            supported_resource_kinds,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.durability_tiers
            .create(id.as_str(), record.clone())
            .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn list_active_storage_classes(&self) -> Result<Vec<StorageClassRecord>> {
        let mut values = self
            .storage_classes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_active_durability_tiers(&self) -> Result<Vec<DurabilityTierRecord>> {
        let mut values = self
            .durability_tiers
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn load_active_storage_class(&self, id: &StorageClassId) -> Result<StorageClassRecord> {
        let stored = self
            .storage_classes
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("storage class does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict("storage class has been deleted"));
        }
        Ok(stored.value)
    }

    async fn load_active_durability_tier(
        &self,
        id: &DurabilityTierId,
    ) -> Result<DurabilityTierRecord> {
        let stored = self
            .durability_tiers
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("durability tier does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict("durability tier has been deleted"));
        }
        Ok(stored.value)
    }

    pub async fn resolve_storage_binding(
        &self,
        resource_kind: StorageResourceKind,
        requested_storage_class_id: Option<&str>,
        requested_durability_tier_id: Option<&str>,
    ) -> Result<StorageBinding> {
        let storage_class_id = if let Some(raw_id) = requested_storage_class_id {
            let id = StorageClassId::parse(raw_id).map_err(|error| {
                PlatformError::invalid("invalid storage_class_id").with_detail(error.to_string())
            })?;
            let storage_class = self.load_active_storage_class(&id).await?;
            if !storage_class.supports_resource_kind(resource_kind) {
                return Err(PlatformError::invalid(format!(
                    "storage class does not support {} resources",
                    storage_resource_kind_label(resource_kind),
                )));
            }
            storage_class.id
        } else {
            default_storage_binding(resource_kind).storage_class_id
        };
        let durability_tier_id = if let Some(raw_id) = requested_durability_tier_id {
            let id = DurabilityTierId::parse(raw_id).map_err(|error| {
                PlatformError::invalid("invalid durability_tier_id").with_detail(error.to_string())
            })?;
            let durability_tier = self.load_active_durability_tier(&id).await?;
            if !durability_tier.supports_resource_kind(resource_kind) {
                return Err(PlatformError::invalid(format!(
                    "durability tier does not support {} resources",
                    storage_resource_kind_label(resource_kind),
                )));
            }
            durability_tier.id
        } else {
            default_storage_binding(resource_kind).durability_tier_id
        };
        Ok(StorageBinding {
            storage_class_id,
            durability_tier_id,
        })
    }

    async fn create_bucket(&self, request: CreateBucketRequest) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "bucket name")?;
        let owner_id = normalize_owner_id(&request.owner_id)?;
        let storage_binding = self
            .resolve_storage_binding(
                StorageResourceKind::Bucket,
                request.storage_class_id.as_deref(),
                request.durability_tier_id.as_deref(),
            )
            .await?;
        let id = BucketId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate bucket id")
                .with_detail(error.to_string())
        })?;
        let metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            storage_binding_etag(id.as_str(), Some(&storage_binding)),
        );
        let bucket = BucketRecord {
            id: id.clone(),
            name,
            owner_id,
            storage_binding: Some(storage_binding),
            metadata,
        };
        self.buckets.create(id.as_str(), bucket.clone()).await?;
        json_response(StatusCode::CREATED, &bucket)
    }

    async fn create_volume(&self, request: CreateVolumeRequest) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "volume name")?;
        if request.size_gb == 0 {
            return Err(PlatformError::invalid("size_gb must be greater than zero"));
        }
        let storage_binding = self
            .resolve_storage_binding(
                StorageResourceKind::Volume,
                request.storage_class_id.as_deref(),
                request.durability_tier_id.as_deref(),
            )
            .await?;
        let id = VolumeId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate volume id")
                .with_detail(error.to_string())
        })?;
        let metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            storage_binding_etag(id.as_str(), Some(&storage_binding)),
        );
        let volume = VolumeRecord {
            id: id.clone(),
            name,
            size_gb: request.size_gb,
            attached_to: None,
            storage_binding: Some(storage_binding),
            metadata,
        };
        self.volumes.create(id.as_str(), volume.clone()).await?;
        self.ensure_volume_snapshot_lifecycle(&volume).await?;
        json_response(StatusCode::CREATED, &volume)
    }

    async fn create_file_share(
        &self,
        request: CreateFileShareRequest,
    ) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "file share name")?;
        if request.capacity_gb == 0 {
            return Err(PlatformError::invalid(
                "capacity_gb must be greater than zero",
            ));
        }
        let mounted_to = request
            .mounted_to
            .as_deref()
            .map(normalize_mount_target)
            .transpose()?;
        let protocol = request.protocol.unwrap_or(FileShareProtocol::Nfs);
        let id = FileShareId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate file share id")
                .with_detail(error.to_string())
        })?;
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            sha256_hex(id.as_str().as_bytes()),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;
        metadata.annotations.insert(
            String::from("storage.inventory.kind"),
            String::from("file_share"),
        );
        metadata.annotations.insert(
            String::from("storage.file_share.protocol"),
            String::from(protocol.as_str()),
        );
        if let Some(target) = &mounted_to {
            metadata.annotations.insert(
                String::from("storage.file_share.mounted_to"),
                target.clone(),
            );
        }

        let share = FileShareRecord {
            id: id.clone(),
            name,
            capacity_gb: request.capacity_gb,
            protocol,
            mounted_to,
            metadata,
        };
        self.file_shares.create(id.as_str(), share.clone()).await?;
        json_response(StatusCode::CREATED, &share)
    }

    async fn create_archive(&self, request: CreateArchiveRequest) -> Result<Response<ApiBody>> {
        let name = normalize_name(&request.name, "archive name")?;
        if request.size_bytes == 0 {
            return Err(PlatformError::invalid(
                "size_bytes must be greater than zero",
            ));
        }
        let id = ArchiveId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate archive id")
                .with_detail(error.to_string())
        })?;
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            sha256_hex(id.as_str().as_bytes()),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;
        metadata.annotations.insert(
            String::from("storage.inventory.kind"),
            String::from("archive"),
        );
        metadata.annotations.insert(
            String::from("storage.archive.access_state"),
            String::from(ArchiveAccessState::Archived.as_str()),
        );
        let archive = ArchiveRecord {
            id: id.clone(),
            name,
            size_bytes: request.size_bytes,
            access_state: ArchiveAccessState::Archived,
            rehydrated_until: None,
            last_rehydrate_job_id: None,
            metadata,
        };
        self.archives.create(id.as_str(), archive.clone()).await?;
        json_response(StatusCode::CREATED, &archive)
    }

    async fn create_archive_rehydrate_job(
        &self,
        request: CreateArchiveRehydrateJobRequest,
    ) -> Result<Response<ApiBody>> {
        let archive_id = ArchiveId::parse(request.archive_id).map_err(|error| {
            PlatformError::invalid("invalid archive_id").with_detail(error.to_string())
        })?;
        let restore_window_hours = request
            .restore_window_hours
            .unwrap_or(DEFAULT_ARCHIVE_REHYDRATE_WINDOW_HOURS);
        if restore_window_hours == 0 {
            return Err(PlatformError::invalid(
                "restore_window_hours must be greater than zero",
            ));
        }
        let reason = normalize_optional_text(request.reason.as_deref(), "rehydrate reason")?;
        let priority = request
            .priority
            .unwrap_or(ArchiveRehydratePriority::Standard);
        let stored_archive = self
            .archives
            .get(archive_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("archive does not exist"))?;
        if stored_archive.deleted {
            return Err(PlatformError::conflict("archive has been deleted"));
        }

        let job_id = RehydrateJobId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate archive rehydrate job id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let rehydrated_until = now + Duration::hours(i64::from(restore_window_hours));
        let mut archive = stored_archive.value;
        archive.access_state = ArchiveAccessState::Available;
        archive.rehydrated_until = Some(rehydrated_until);
        archive.last_rehydrate_job_id = Some(job_id.clone());
        archive.metadata.lifecycle = ResourceLifecycleState::Ready;
        archive.metadata.annotations.insert(
            String::from("storage.inventory.kind"),
            String::from("archive"),
        );
        archive.metadata.annotations.insert(
            String::from("storage.archive.access_state"),
            String::from(ArchiveAccessState::Available.as_str()),
        );
        archive.metadata.annotations.insert(
            String::from("storage.archive.last_rehydrate_job_id"),
            job_id.to_string(),
        );
        archive.metadata.annotations.insert(
            String::from("storage.archive.restore_window_hours"),
            restore_window_hours.to_string(),
        );
        archive.metadata.annotations.insert(
            String::from("storage.archive.rehydrate_priority"),
            String::from(priority.as_str()),
        );
        if let Some(reason) = &reason {
            archive.metadata.annotations.insert(
                String::from("storage.archive.rehydrate_reason"),
                reason.clone(),
            );
        } else {
            archive
                .metadata
                .annotations
                .remove("storage.archive.rehydrate_reason");
        }
        archive.metadata.touch(sha256_hex(
            format!(
                "{}:{}:{}:{}",
                archive.id.as_str(),
                job_id.as_str(),
                priority.as_str(),
                rehydrated_until.unix_timestamp(),
            )
            .as_bytes(),
        ));
        let _ = self
            .archives
            .upsert(archive_id.as_str(), archive, Some(stored_archive.version))
            .await?;

        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(archive_id.to_string()),
            sha256_hex(
                format!(
                    "{}:{}:{}:{}",
                    job_id.as_str(),
                    archive_id.as_str(),
                    priority.as_str(),
                    restore_window_hours,
                )
                .as_bytes(),
            ),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;
        metadata.annotations.insert(
            String::from("storage.inventory.kind"),
            String::from("archive_rehydrate_job"),
        );
        metadata.annotations.insert(
            String::from("storage.archive.access_state"),
            String::from(ArchiveAccessState::Available.as_str()),
        );
        let job = ArchiveRehydrateJobRecord {
            id: job_id.clone(),
            archive_id,
            priority,
            restore_window_hours,
            state: ArchiveRehydrateJobState::Completed,
            requested_at: now,
            started_at: Some(now),
            completed_at: Some(now),
            rehydrated_until,
            reason,
            metadata,
        };
        self.archive_rehydrate_jobs
            .create(job_id.as_str(), job.clone())
            .await?;
        json_response(StatusCode::CREATED, &job)
    }

    async fn reconcile_volume_snapshot_lifecycle(&self) -> Result<()> {
        for (_, stored) in self.volumes.list().await? {
            if stored.deleted {
                continue;
            }
            self.ensure_volume_snapshot_lifecycle(&stored.value).await?;
        }
        Ok(())
    }

    async fn reconcile_volume_restore_workflows(&self) -> Result<()> {
        let workflows = self.volume_restore_workflows.list().await?;
        for (key, stored) in workflows {
            if stored.deleted {
                continue;
            }

            let stored = self
                .reconcile_volume_restore_workflow_primitives(&key, stored)
                .await?;
            if stored.deleted {
                continue;
            }
            self.sync_volume_restore_action_projection(&stored.value)
                .await?;
        }
        Ok(())
    }

    async fn migrate_legacy_volume_restore_apply_ledgers(&self) -> Result<()> {
        for (idempotency_key, stored) in self.volume_restore_apply_ledger.list().await? {
            if stored.deleted || !stored.value.is_legacy() {
                continue;
            }

            let workflow_id = match &stored.value {
                VolumeRestoreApplyLedgerRecord::Legacy(record) => record.workflow_id.clone(),
                VolumeRestoreApplyLedgerRecord::Current(_) => continue,
            };
            let workflow = self
                .load_volume_restore_workflow(workflow_id.as_str())
                .await?;
            validate_volume_restore_apply_ledger(&stored.value, &workflow.value)?;
            self.upgrade_volume_restore_apply_ledger_if_needed(
                idempotency_key.as_str(),
                &workflow.value,
                &stored,
            )
            .await?;
        }
        Ok(())
    }

    async fn reconcile_volume_restore_workflow_primitives(
        &self,
        key: &str,
        mut stored: StoredDocument<VolumeRestoreWorkflow>,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        loop {
            let mut workflow = stored.value.clone();
            let observed_at = OffsetDateTime::now_utc();
            if !apply_volume_restore_reconciliation_primitives(&mut workflow, observed_at)? {
                return Ok(stored);
            }

            match self
                .volume_restore_workflows
                .upsert(key, workflow, Some(stored.version))
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(error) if error.code == ErrorCode::Conflict => {
                    stored = self
                        .volume_restore_workflows
                        .get(key)
                        .await?
                        .ok_or_else(|| {
                            PlatformError::not_found(
                                "volume restore workflow disappeared during reconciliation",
                            )
                        })?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn ensure_volume_snapshot_lifecycle(&self, volume: &VolumeRecord) -> Result<()> {
        let policy = self.ensure_volume_snapshot_policy(volume).await?;
        self.ensure_volume_snapshot_workflow(volume, &policy)
            .await?;
        let policy = self.activate_volume_snapshot_policy(&volume.id).await?;
        self.ensure_volume_recovery_point(&policy).await
    }

    async fn ensure_volume_snapshot_policy(
        &self,
        volume: &VolumeRecord,
    ) -> Result<VolumeSnapshotPolicy> {
        let key = volume.id.as_str();
        let policy = build_volume_snapshot_policy(volume);
        match self.volume_snapshot_policies.get(key).await? {
            Some(stored) if !stored.deleted => Ok(stored.value),
            Some(stored) => {
                let _ = self
                    .volume_snapshot_policies
                    .upsert(key, policy.clone(), Some(stored.version))
                    .await?;
                Ok(policy)
            }
            None => match self
                .volume_snapshot_policies
                .create(key, policy.clone())
                .await
            {
                Ok(_) => Ok(policy),
                Err(error) if matches!(error.code, ErrorCode::Conflict) => self
                    .volume_snapshot_policies
                    .get(key)
                    .await?
                    .filter(|stored| !stored.deleted)
                    .map(|stored| stored.value)
                    .ok_or_else(|| {
                        PlatformError::conflict(
                            "volume snapshot policy already exists with deleted state",
                        )
                    }),
                Err(error) => Err(error),
            },
        }
    }

    async fn ensure_volume_snapshot_workflow(
        &self,
        volume: &VolumeRecord,
        policy: &VolumeSnapshotPolicy,
    ) -> Result<()> {
        let key = volume.id.as_str();
        let workflow = build_volume_snapshot_workflow(policy);
        match self.volume_snapshot_workflows.get(key).await? {
            Some(stored) if !stored.deleted => Ok(()),
            Some(stored) => {
                let _ = self
                    .volume_snapshot_workflows
                    .upsert(key, workflow, Some(stored.version))
                    .await?;
                Ok(())
            }
            None => match self.volume_snapshot_workflows.create(key, workflow).await {
                Ok(_) => Ok(()),
                Err(error) if matches!(error.code, ErrorCode::Conflict) => Ok(()),
                Err(error) => Err(error),
            },
        }
    }

    async fn activate_volume_snapshot_policy(
        &self,
        volume_id: &VolumeId,
    ) -> Result<VolumeSnapshotPolicy> {
        let workflow_stored = self
            .volume_snapshot_workflows
            .get(volume_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("volume snapshot workflow does not exist"))?;
        let policy_stored = self
            .volume_snapshot_policies
            .get(volume_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("volume snapshot policy does not exist"))?;

        if workflow_stored.value.phase == WorkflowPhase::Completed
            && policy_stored.value.state == VolumeSnapshotPolicyState::Active
            && policy_stored.value.metadata.lifecycle == ResourceLifecycleState::Ready
        {
            return Ok(policy_stored.value);
        }

        let mut workflow = workflow_stored.value;
        workflow.set_phase(WorkflowPhase::Running);
        workflow.current_step_index = Some(0);
        if let Some(step) = workflow.step_mut(0) {
            step.transition(
                WorkflowStepState::Completed,
                Some(String::from("retention policy attached")),
            );
        }
        workflow.current_step_index = Some(1);
        if let Some(step) = workflow.step_mut(1) {
            step.transition(
                WorkflowStepState::Completed,
                Some(String::from("snapshot schedule registered")),
            );
        }
        workflow.current_step_index = Some(VOLUME_SNAPSHOT_FINAL_STEP_INDEX);
        if let Some(step) = workflow.step_mut(VOLUME_SNAPSHOT_FINAL_STEP_INDEX) {
            step.transition(
                WorkflowStepState::Completed,
                Some(String::from("recovery window armed")),
            );
        }
        workflow.set_phase(WorkflowPhase::Completed);
        let _ = self
            .volume_snapshot_workflows
            .upsert(volume_id.as_str(), workflow, Some(workflow_stored.version))
            .await?;

        let mut policy = policy_stored.value;
        policy.state = VolumeSnapshotPolicyState::Active;
        policy.next_snapshot_after =
            OffsetDateTime::now_utc() + Duration::minutes(i64::from(policy.interval_minutes));
        policy.metadata.lifecycle = ResourceLifecycleState::Ready;
        policy.metadata.touch(sha256_hex(
            format!("{}:snapshot-policy:active", volume_id.as_str()).as_bytes(),
        ));
        let _ = self
            .volume_snapshot_policies
            .upsert(volume_id.as_str(), policy, Some(policy_stored.version))
            .await?;
        self.volume_snapshot_policies
            .get(volume_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
            .ok_or_else(|| PlatformError::not_found("volume snapshot policy does not exist"))
    }

    async fn ensure_volume_recovery_point(&self, policy: &VolumeSnapshotPolicy) -> Result<()> {
        if policy.state != VolumeSnapshotPolicyState::Active
            || policy.metadata.lifecycle != ResourceLifecycleState::Ready
        {
            return Err(PlatformError::conflict(
                "volume snapshot policy must be active before recording a recovery point",
            ));
        }

        let key = policy.volume_id.as_str();
        let recovery_point = build_volume_recovery_point(policy);
        let stored = match self.volume_recovery_points.get(key).await? {
            Some(stored) if !stored.deleted => stored,
            Some(stored) => {
                self.volume_recovery_points
                    .upsert(key, recovery_point, Some(stored.version))
                    .await?
            }
            None => match self
                .volume_recovery_points
                .create(key, recovery_point.clone())
                .await
            {
                Ok(stored) => stored,
                Err(error) if matches!(error.code, ErrorCode::Conflict) => self
                    .volume_recovery_points
                    .get(key)
                    .await?
                    .filter(|stored| !stored.deleted)
                    .clone()
                    .ok_or_else(|| {
                        PlatformError::conflict(
                            "volume recovery point already exists with deleted state",
                        )
                    })?,
                Err(error) => return Err(error),
            },
        };
        self.archive_volume_recovery_point_revision(&stored).await
    }

    async fn archive_volume_recovery_point_revision(
        &self,
        stored: &StoredDocument<VolumeRecoveryPoint>,
    ) -> Result<()> {
        let revision = build_volume_recovery_point_revision(stored);
        let key = volume_recovery_point_revision_key(
            &revision.volume_id,
            revision.recovery_point_version,
        );
        match self
            .volume_recovery_point_revisions
            .create(&key, revision.clone())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if matches!(error.code, ErrorCode::Conflict) => {
                let existing = self
                    .volume_recovery_point_revisions
                    .get(&key)
                    .await?
                    .ok_or_else(|| {
                        PlatformError::conflict(
                            "volume recovery point revision already exists but could not be loaded",
                        )
                    })?;
                if existing.deleted {
                    return Err(PlatformError::conflict(
                        "volume recovery point revision already exists with deleted state",
                    ));
                }
                if existing.value != revision {
                    return Err(PlatformError::conflict(
                        "volume recovery point revision already exists with different lineage",
                    ));
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn load_active_volume(
        &self,
        volume_id: &VolumeId,
    ) -> Result<StoredDocument<VolumeRecord>> {
        let stored = self
            .volumes
            .get(volume_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("volume does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict("volume has been deleted"));
        }
        Ok(stored)
    }

    async fn load_ready_volume_recovery_point(
        &self,
        volume_id: &VolumeId,
    ) -> Result<SelectedVolumeRecoveryPoint> {
        let stored = self
            .volume_recovery_points
            .get(volume_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("volume recovery point does not exist"))?;
        if stored.value.metadata.lifecycle != ResourceLifecycleState::Ready {
            return Err(PlatformError::conflict(
                "volume recovery point must be ready before restore",
            ));
        }
        self.archive_volume_recovery_point_revision(&stored).await?;
        Ok(build_selected_volume_recovery_point(&stored))
    }

    async fn load_volume_recovery_point_revision(
        &self,
        volume_id: &VolumeId,
        recovery_point_version: u64,
        expected_etag: Option<&str>,
    ) -> Result<Option<SelectedVolumeRecoveryPoint>> {
        let key = volume_recovery_point_revision_key(volume_id, recovery_point_version);
        let Some(stored) = self.volume_recovery_point_revisions.get(&key).await? else {
            return Ok(None);
        };
        if stored.deleted || stored.value.metadata.lifecycle != ResourceLifecycleState::Ready {
            return Ok(None);
        }
        if expected_etag.is_some_and(|etag| stored.value.metadata.etag != etag) {
            return Ok(None);
        }
        Ok(Some(build_selected_volume_recovery_point_from_revision(
            &stored.value,
        )))
    }

    async fn load_volume_restore_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        let stored = self
            .volume_restore_workflows
            .get(workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("volume restore workflow does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict(
                "volume restore workflow has been deleted",
            ));
        }
        Ok(stored)
    }

    async fn load_volume_restore_action(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<VolumeRestoreAction>> {
        let stored = self
            .volume_restore_actions
            .get(workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("volume restore action does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict(
                "volume restore action has been deleted",
            ));
        }
        Ok(stored)
    }

    async fn start_volume_restore(
        &self,
        volume_id: &VolumeId,
        reason: Option<String>,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        let recovery_point = self.load_ready_volume_recovery_point(volume_id).await?;
        self.start_volume_restore_with_recovery_point(volume_id, recovery_point, reason)
            .await
    }

    async fn start_volume_restore_with_recovery_point(
        &self,
        volume_id: &VolumeId,
        recovery_point: SelectedVolumeRecoveryPoint,
        reason: Option<String>,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        if recovery_point.volume_id != *volume_id {
            return Err(PlatformError::conflict(
                "volume recovery point does not belong to the requested volume",
            ));
        }
        let volume = self.load_active_volume(volume_id).await?;
        let restore_action_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate volume restore id")
                .with_detail(error.to_string())
        })?;
        let workflow = build_volume_restore_workflow(
            &restore_action_id,
            &volume.value,
            &recovery_point,
            reason,
        );
        let stored = self
            .volume_restore_workflows
            .create(restore_action_id.as_str(), workflow)
            .await?;
        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        Ok(stored)
    }

    async fn persist_volume_restore_workflow(
        &self,
        workflow_id: &str,
        workflow: VolumeRestoreWorkflow,
        expected_version: u64,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        let stored = self
            .volume_restore_workflows
            .upsert(workflow_id, workflow, Some(expected_version))
            .await?;
        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        Ok(stored)
    }

    async fn mutate_volume_restore_workflow<F>(
        &self,
        workflow_id: &str,
        mutate: F,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>>
    where
        F: FnMut(&mut VolumeRestoreWorkflow) -> Result<()>,
    {
        let stored = self
            .volume_restore_workflows
            .mutate(workflow_id, mutate)
            .await?;
        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        Ok(stored)
    }

    async fn sync_volume_restore_action_projection(
        &self,
        workflow: &VolumeRestoreWorkflow,
    ) -> Result<()> {
        let key = workflow.id.as_str();
        let action = build_volume_restore_action_projection(workflow);
        match self.volume_restore_actions.get(key).await? {
            Some(stored) => {
                let _ = self
                    .volume_restore_actions
                    .upsert(key, action, Some(stored.version))
                    .await?;
                Ok(())
            }
            None => match self
                .volume_restore_actions
                .create(key, action.clone())
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if matches!(error.code, ErrorCode::Conflict) => {
                    let stored = self.volume_restore_actions.get(key).await?.ok_or_else(|| {
                        PlatformError::conflict(
                            "volume restore action already exists but could not be loaded",
                        )
                    })?;
                    let _ = self
                        .volume_restore_actions
                        .upsert(key, action, Some(stored.version))
                        .await?;
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
    }

    async fn prepare_volume_restore_apply_step(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        let mut stored = self.load_volume_restore_workflow(workflow_id).await?;

        if matches!(
            workflow_step_state(&stored.value, 0),
            Some(WorkflowStepState::Pending)
        ) {
            let mut workflow = stored.value.clone();
            let recovery_point_version = workflow.state.recovery_point_version;
            workflow.current_step_index = Some(0);
            workflow.set_phase(WorkflowPhase::Running);
            if let Some(step) = workflow.step_mut(0) {
                step.transition(
                    WorkflowStepState::Completed,
                    Some(format!(
                        "selected persisted recovery point version {recovery_point_version}"
                    )),
                );
            }
            workflow.current_step_index = Some(1);
            if let Some(step) = workflow.step_mut(1) {
                step.transition(
                    WorkflowStepState::Active,
                    Some(String::from("preparing restore execution")),
                );
            }
            stored = self
                .persist_volume_restore_workflow(workflow_id, workflow, stored.version)
                .await?;
        }

        if matches!(
            workflow_step_state(&stored.value, 1),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let mut workflow = stored.value.clone();
            let recovery_point_version = workflow.state.recovery_point_version;
            workflow.current_step_index = Some(1);
            workflow.set_phase(WorkflowPhase::Running);
            if let Some(step) = workflow.step_mut(1) {
                step.transition(
                    WorkflowStepState::Completed,
                    Some(String::from("restore execution prepared")),
                );
            }
            workflow.current_step_index = Some(VOLUME_RESTORE_FINAL_STEP_INDEX);
            if let Some(step) = workflow.step_mut(VOLUME_RESTORE_FINAL_STEP_INDEX) {
                step.transition(
                    WorkflowStepState::Active,
                    Some(format!(
                        "applying persisted recovery point version {recovery_point_version}"
                    )),
                );
            }
            stored = self
                .persist_volume_restore_workflow(workflow_id, workflow, stored.version)
                .await?;
        }

        Ok(stored)
    }

    async fn begin_volume_restore_apply_effect(
        &self,
        workflow_id: &str,
    ) -> Result<(
        StoredDocument<VolumeRestoreWorkflow>,
        WorkflowStepEffectExecution,
    )> {
        let stored = self.load_volume_restore_workflow(workflow_id).await?;
        if stored.value.workflow_kind != VOLUME_RESTORE_WORKFLOW_KIND {
            return Err(PlatformError::conflict(
                "workflow is not a storage volume restore workflow",
            ));
        }
        let detail = volume_restore_apply_effect_detail(&stored.value.state);
        let idempotency_key = volume_restore_apply_effect_idempotency_key(&stored.value.state);
        let (stored, effect_execution) = self
            .volume_restore_workflows
            .begin_step_effect_at(
                workflow_id,
                VOLUME_RESTORE_FINAL_STEP_INDEX,
                VOLUME_RESTORE_APPLY_EFFECT_KIND,
                idempotency_key.as_str(),
                Some(detail),
                OffsetDateTime::now_utc(),
            )
            .await?;
        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        Ok((stored, effect_execution))
    }

    async fn persist_volume_restore_apply_effect_completion(
        &self,
        workflow_id: &str,
        result_digest: &str,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        let stored = self.load_volume_restore_workflow(workflow_id).await?;
        if stored.value.workflow_kind != VOLUME_RESTORE_WORKFLOW_KIND {
            return Err(PlatformError::conflict(
                "workflow is not a storage volume restore workflow",
            ));
        }
        let detail = volume_restore_apply_effect_detail(&stored.value.state);
        let (stored, _effect) = self
            .volume_restore_workflows
            .complete_step_effect_at(
                workflow_id,
                VOLUME_RESTORE_FINAL_STEP_INDEX,
                VOLUME_RESTORE_APPLY_EFFECT_KIND,
                Some(result_digest),
                Some(detail),
                OffsetDateTime::now_utc(),
            )
            .await?;
        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        Ok(stored)
    }

    async fn finalize_volume_restore_after_apply_effect(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<VolumeRestoreWorkflow>> {
        self.mutate_volume_restore_workflow(workflow_id, |workflow| {
            if workflow.workflow_kind != VOLUME_RESTORE_WORKFLOW_KIND {
                return Err(PlatformError::conflict(
                    "workflow is not a storage volume restore workflow",
                ));
            }
            if workflow.phase == WorkflowPhase::Completed {
                return Ok(());
            }
            let state = workflow.state.clone();
            workflow.current_step_index = Some(VOLUME_RESTORE_FINAL_STEP_INDEX);
            let step = workflow
                .step_mut(VOLUME_RESTORE_FINAL_STEP_INDEX)
                .ok_or_else(|| PlatformError::conflict("volume restore apply step is missing"))?;
            let effect = step
                .effect(VOLUME_RESTORE_APPLY_EFFECT_KIND)
                .cloned()
                .ok_or_else(|| {
                    PlatformError::conflict("volume restore apply effect has not been journaled")
                })?;
            if effect.completed_at.is_none() {
                return Err(PlatformError::conflict(
                    "volume restore apply effect is not completed",
                ));
            }
            step.transition(
                WorkflowStepState::Completed,
                Some(
                    effect
                        .detail
                        .unwrap_or_else(|| volume_restore_apply_effect_detail(&state)),
                ),
            );
            workflow.set_phase(WorkflowPhase::Completed);
            Ok(())
        })
        .await
    }

    async fn apply_volume_restore_to_volume(
        &self,
        workflow: &VolumeRestoreWorkflow,
        idempotency_key: &str,
    ) -> Result<String> {
        if workflow.workflow_kind != VOLUME_RESTORE_WORKFLOW_KIND {
            return Err(PlatformError::conflict(
                "workflow is not a storage volume restore workflow",
            ));
        }
        let idempotency_key = normalize_volume_restore_apply_idempotency_key(idempotency_key)?;
        let apply_effect = workflow
            .step(VOLUME_RESTORE_FINAL_STEP_INDEX)
            .and_then(|step| step.effect(VOLUME_RESTORE_APPLY_EFFECT_KIND))
            .ok_or_else(|| {
                PlatformError::conflict("volume restore apply effect has not been journaled")
            })?;
        if apply_effect.idempotency_key != idempotency_key {
            return Err(PlatformError::conflict(
                "volume restore apply idempotency key does not match journaled workflow effect",
            ));
        }

        loop {
            if let Some(result_digest) = self
                .replay_volume_restore_apply_ledger_result(workflow, idempotency_key)
                .await?
            {
                return Ok(result_digest);
            }

            let state = &workflow.state;
            let stored = self.load_active_volume(&state.volume_id).await?;
            let mut volume = stored.value;
            volume.metadata.lifecycle = ResourceLifecycleState::Ready;
            volume.metadata.annotations.insert(
                String::from("storage.restore.last_action_id"),
                state.restore_action_id.to_string(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.workflow_id"),
                workflow.id.clone(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.workflow_kind"),
                String::from(VOLUME_RESTORE_WORKFLOW_KIND),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.action_kind"),
                String::from(VOLUME_RESTORE_ACTION_KIND),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.source_recovery_point_volume_id"),
                state.recovery_point_volume_id.to_string(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.source_recovery_point_version"),
                state.recovery_point_version.to_string(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.source_recovery_point_execution_count"),
                state.recovery_point_execution_count.to_string(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.source_recovery_point_etag"),
                state.recovery_point_etag.clone(),
            );
            volume.metadata.annotations.insert(
                String::from("storage.restore.source_recovery_point_captured_at"),
                state
                    .recovery_point_captured_at
                    .unix_timestamp()
                    .to_string(),
            );
            if let Some(reason) = &state.reason {
                volume.metadata.annotations.insert(
                    String::from("storage.restore.request_reason"),
                    reason.clone(),
                );
            } else {
                volume
                    .metadata
                    .annotations
                    .remove("storage.restore.request_reason");
            }
            volume.metadata.touch(sha256_hex(
                format!(
                    "{}:restore:{}:{}",
                    state.volume_id.as_str(),
                    state.restore_action_id.as_str(),
                    state.recovery_point_etag,
                )
                .as_bytes(),
            ));
            let result_digest = volume.metadata.etag.clone();
            let ledger = build_volume_restore_apply_ledger_record(
                workflow,
                result_digest.as_str(),
                OffsetDateTime::now_utc(),
            )?;

            let mut batch = self.metadata_journal.batch();
            batch.upsert_document(
                &self.volumes,
                state.volume_id.as_str(),
                volume,
                Some(stored.version),
            )?;
            batch.create_document(&self.volume_restore_apply_ledger, idempotency_key, ledger)?;
            match batch.commit().await {
                Ok(()) => return Ok(result_digest),
                Err(error) if error.code == ErrorCode::Conflict => {
                    if let Some(result_digest) = self
                        .replay_volume_restore_apply_ledger_result(workflow, idempotency_key)
                        .await?
                    {
                        return Ok(result_digest);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn replay_volume_restore_apply_ledger_result(
        &self,
        workflow: &VolumeRestoreWorkflow,
        idempotency_key: &str,
    ) -> Result<Option<String>> {
        let Some(existing) = self
            .volume_restore_apply_ledger
            .get(idempotency_key)
            .await?
        else {
            return Ok(None);
        };
        if existing.deleted {
            return Err(PlatformError::conflict(
                "volume restore apply ledger entry has been deleted",
            ));
        }
        validate_volume_restore_apply_ledger(&existing.value, workflow)?;
        self.upgrade_volume_restore_apply_ledger_if_needed(idempotency_key, workflow, &existing)
            .await?;
        Ok(Some(existing.value.result_digest().to_owned()))
    }

    async fn upgrade_volume_restore_apply_ledger_if_needed(
        &self,
        idempotency_key: &str,
        workflow: &VolumeRestoreWorkflow,
        stored: &StoredDocument<VolumeRestoreApplyLedgerRecord>,
    ) -> Result<()> {
        if !stored.value.is_legacy() {
            return Ok(());
        }
        let upgraded = build_volume_restore_apply_ledger_record(
            workflow,
            stored.value.result_digest(),
            stored.value.recorded_at(),
        )?;
        match self
            .volume_restore_apply_ledger
            .upsert(idempotency_key, upgraded, Some(stored.version))
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.code == ErrorCode::Conflict => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn execute_volume_restore(&self, workflow_id: &str) -> Result<VolumeRestoreAction> {
        let mut stored = self.load_volume_restore_workflow(workflow_id).await?;
        if stored.value.workflow_kind != VOLUME_RESTORE_WORKFLOW_KIND {
            return Err(PlatformError::conflict(
                "workflow is not a storage volume restore workflow",
            ));
        }

        if stored.value.phase == WorkflowPhase::Completed {
            self.sync_volume_restore_action_projection(&stored.value)
                .await?;
            return self
                .load_volume_restore_action(workflow_id)
                .await
                .map(|stored| stored.value);
        }

        if matches!(
            stored.value.phase,
            WorkflowPhase::Failed | WorkflowPhase::RolledBack
        ) {
            return Err(PlatformError::conflict(
                "volume restore workflow is not executable",
            ));
        }

        self.load_active_volume(&stored.value.state.volume_id)
            .await?;

        self.prepare_volume_restore_apply_step(workflow_id).await?;
        let (effect_stored, effect_execution) =
            self.begin_volume_restore_apply_effect(workflow_id).await?;
        if let WorkflowStepEffectExecution::Execute(effect) = effect_execution {
            let result_digest = self
                .apply_volume_restore_to_volume(
                    &effect_stored.value,
                    effect.idempotency_key.as_str(),
                )
                .await?;
            let _stored = self
                .persist_volume_restore_apply_effect_completion(workflow_id, &result_digest)
                .await?;
        }
        stored = self
            .finalize_volume_restore_after_apply_effect(workflow_id)
            .await?;

        self.sync_volume_restore_action_projection(&stored.value)
            .await?;
        self.load_volume_restore_action(workflow_id)
            .await
            .map(|stored| stored.value)
    }

    /// Restore a volume from its currently persisted recovery point and return
    /// the durable restore action identifier.
    pub async fn restore_volume_from_recovery_point(
        &self,
        volume_id: &VolumeId,
        reason: Option<String>,
    ) -> Result<AuditId> {
        let started = self.start_volume_restore(volume_id, reason).await?;
        let action = self
            .execute_volume_restore(started.value.id.as_str())
            .await?;
        Ok(action.id)
    }

    /// Restore a volume from one persisted recovery-point revision selected by
    /// stored version and optional ETag.
    pub async fn restore_volume_from_selected_recovery_point(
        &self,
        volume_id: &VolumeId,
        recovery_point_version: u64,
        expected_etag: Option<&str>,
        reason: Option<String>,
    ) -> Result<AuditId> {
        let recovery_point = self
            .load_volume_recovery_point_revision(volume_id, recovery_point_version, expected_etag)
            .await?
            .ok_or_else(|| PlatformError::not_found("volume recovery point does not exist"))?;
        let started = self
            .start_volume_restore_with_recovery_point(volume_id, recovery_point, reason)
            .await?;
        let action = self
            .execute_volume_restore(started.value.id.as_str())
            .await?;
        Ok(action.id)
    }

    /// Describe one volume snapshot policy through an operator-only inspection
    /// view.
    pub async fn inspect_volume_snapshot_policy(
        &self,
        volume_id: &str,
        context: &RequestContext,
    ) -> Result<VolumeSnapshotPolicySummary> {
        require_operator_principal(context, "snapshot policy inspection")?;
        let volume_id = parse_volume_id(volume_id)?;
        self.load_active_volume(&volume_id).await?;
        let stored = self
            .volume_snapshot_policies
            .get(volume_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| {
                PlatformError::not_found("volume snapshot policy does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })?;
        Ok(build_volume_snapshot_policy_summary(&stored.value))
    }

    /// Describe the current ready recovery point for one volume through an
    /// operator-only inspection view.
    pub async fn inspect_ready_volume_recovery_point(
        &self,
        volume_id: &str,
        context: &RequestContext,
    ) -> Result<VolumeRecoveryPointSummary> {
        require_operator_principal(context, "recovery point inspection")?;
        let volume_id = parse_volume_id(volume_id)?;
        self.load_active_volume(&volume_id).await?;
        self.describe_ready_volume_recovery_point(&volume_id)
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("volume recovery point does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })
    }

    /// List persisted recovery-point history for one volume through an
    /// operator-only inspection view.
    pub async fn list_volume_recovery_history(
        &self,
        volume_id: &str,
        context: &RequestContext,
    ) -> Result<Vec<VolumeRecoveryHistoryEntry>> {
        require_operator_principal(context, "recovery history inspection")?;
        let volume_id = parse_volume_id(volume_id)?;
        self.load_active_volume(&volume_id).await?;
        let current = self
            .describe_ready_volume_recovery_point(&volume_id)
            .await?;
        let prefix = format!("{}:", volume_id.as_str());
        let mut values = self
            .volume_recovery_point_revisions
            .list()
            .await?
            .into_iter()
            .filter(|(key, stored)| {
                key.starts_with(prefix.as_str())
                    && !stored.deleted
                    && stored.value.metadata.lifecycle == ResourceLifecycleState::Ready
            })
            .map(|(_, stored)| build_volume_recovery_history_entry(&stored.value, current.as_ref()))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            right
                .version
                .cmp(&left.version)
                .then_with(|| right.captured_at.cmp(&left.captured_at))
                .then_with(|| right.etag.cmp(&left.etag))
        });
        Ok(values)
    }

    /// List persisted restore actions for one volume through an operator-only
    /// inspection view.
    pub async fn list_volume_restore_actions(
        &self,
        volume_id: &str,
        context: &RequestContext,
    ) -> Result<Vec<VolumeRestoreActionSummary>> {
        require_operator_principal(context, "restore action inspection")?;
        let volume_id = parse_volume_id(volume_id)?;
        self.load_active_volume(&volume_id).await?;
        let mut values = self
            .volume_restore_actions
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.volume_id == volume_id)
            .map(|(_, stored)| build_volume_restore_action_summary(&stored.value))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            right
                .requested_at
                .cmp(&left.requested_at)
                .then_with(|| right.id.as_str().cmp(left.id.as_str()))
        });
        Ok(values)
    }

    /// Create one volume restore action through an operator-only API.
    async fn create_volume_restore_action(
        &self,
        volume_id: &str,
        request: CreateVolumeRestoreActionRequest,
        context: &RequestContext,
    ) -> Result<VolumeRestoreActionSummary> {
        require_operator_principal(context, "volume restore action")?;
        let volume_id = parse_volume_id(volume_id)?;
        let recovery_point_etag = request
            .recovery_point_etag
            .as_deref()
            .map(str::trim)
            .filter(|etag| !etag.is_empty())
            .map(ToOwned::to_owned);
        if request.recovery_point_version.is_none() && recovery_point_etag.is_some() {
            return Err(PlatformError::invalid(
                "recovery_point_etag requires recovery_point_version",
            ));
        }
        let reason = normalize_optional_reason(request.reason)?;
        let action_id = match request.recovery_point_version {
            Some(recovery_point_version) => {
                self.restore_volume_from_selected_recovery_point(
                    &volume_id,
                    recovery_point_version,
                    recovery_point_etag.as_deref(),
                    reason,
                )
                .await?
            }
            None => {
                self.restore_volume_from_recovery_point(&volume_id, reason)
                    .await?
            }
        };
        self.describe_volume_restore_action(&action_id)
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("volume restore action does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })
    }

    /// Describe one volume restore action through an operator-only inspection
    /// view.
    pub async fn inspect_volume_restore_action(
        &self,
        action_id: &str,
        context: &RequestContext,
    ) -> Result<VolumeRestoreActionSummary> {
        require_operator_principal(context, "restore action inspection")?;
        let action_id = parse_restore_action_id(action_id)?;
        self.describe_volume_restore_action(&action_id)
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("volume restore action does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })
    }

    /// Ensure one attached volume exists for the given managed resource and
    /// that its recovery lineage is ready for restore operations.
    pub async fn ensure_attached_volume(
        &self,
        attached_to: &str,
        name: &str,
        size_gb: u32,
        requested_binding: Option<&StorageBinding>,
    ) -> Result<VolumeRecord> {
        let attached_to = normalize_attachment_target(attached_to)?;
        let name = normalize_name(name, "volume name")?;
        if size_gb == 0 {
            return Err(PlatformError::invalid("size_gb must be greater than zero"));
        }
        let desired_binding = match requested_binding {
            Some(binding) => {
                self.resolve_storage_binding(
                    StorageResourceKind::Volume,
                    Some(binding.storage_class_id.as_str()),
                    Some(binding.durability_tier_id.as_str()),
                )
                .await?
            }
            None => {
                self.resolve_storage_binding(StorageResourceKind::Volume, None, None)
                    .await?
            }
        };

        let mut attached_volumes = self
            .list_active_volumes()
            .await?
            .into_iter()
            .filter(|volume| volume.attached_to.as_deref() == Some(attached_to.as_str()))
            .collect::<Vec<_>>();
        if attached_volumes.len() > 1 {
            return Err(PlatformError::conflict(format!(
                "multiple active volumes are attached to `{attached_to}`"
            )));
        }
        if let Some(volume) = attached_volumes.pop() {
            let stored = self.load_active_volume(&volume.id).await?;
            let mut volume = stored.value;
            match volume.storage_binding.as_ref() {
                Some(current_binding) if *current_binding == desired_binding => {}
                Some(_) => {
                    return Err(PlatformError::conflict(
                        "attached volume already uses a different storage binding",
                    ));
                }
                None => {
                    volume.storage_binding = Some(desired_binding.clone());
                    volume.metadata.touch(storage_binding_etag(
                        volume.id.as_str(),
                        volume.storage_binding.as_ref(),
                    ));
                    let _ = self
                        .volumes
                        .upsert(volume.id.as_str(), volume.clone(), Some(stored.version))
                        .await?;
                }
            }
            self.ensure_volume_snapshot_lifecycle(&volume).await?;
            return Ok(volume);
        }

        let id = VolumeId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate attached volume id")
                .with_detail(error.to_string())
        })?;
        let metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            storage_binding_etag(id.as_str(), Some(&desired_binding)),
        );
        let volume = VolumeRecord {
            id: id.clone(),
            name,
            size_gb,
            attached_to: Some(attached_to),
            storage_binding: Some(desired_binding),
            metadata,
        };
        self.volumes.create(id.as_str(), volume.clone()).await?;
        self.ensure_volume_snapshot_lifecycle(&volume).await?;
        Ok(volume)
    }

    /// Describe the currently persisted ready recovery point for one volume.
    pub async fn describe_ready_volume_recovery_point(
        &self,
        volume_id: &VolumeId,
    ) -> Result<Option<VolumeRecoveryPointSummary>> {
        let Some(stored) = self.volume_recovery_points.get(volume_id.as_str()).await? else {
            return Ok(None);
        };
        if stored.deleted || stored.value.metadata.lifecycle != ResourceLifecycleState::Ready {
            return Ok(None);
        }
        self.archive_volume_recovery_point_revision(&stored).await?;
        Ok(Some(build_volume_recovery_point_summary(&stored)))
    }

    /// Describe one persisted ready volume recovery-point revision by stored
    /// version and optional ETag.
    pub async fn describe_volume_recovery_point(
        &self,
        volume_id: &VolumeId,
        recovery_point_version: u64,
        expected_etag: Option<&str>,
    ) -> Result<Option<VolumeRecoveryPointSummary>> {
        Ok(self
            .load_volume_recovery_point_revision(volume_id, recovery_point_version, expected_etag)
            .await?
            .map(|recovery_point| {
                build_volume_recovery_point_summary_from_selected(&recovery_point)
            }))
    }

    /// Describe one persisted volume restore action by identifier.
    pub async fn describe_volume_restore_action(
        &self,
        action_id: &AuditId,
    ) -> Result<Option<VolumeRestoreActionSummary>> {
        let Some(stored) = self.volume_restore_actions.get(action_id.as_str()).await? else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        Ok(Some(build_volume_restore_action_summary(&stored.value)))
    }

    async fn create_upload(&self, request: CreateUploadRequest) -> Result<Response<ApiBody>> {
        let bucket_id = BucketId::parse(request.bucket_id).map_err(|error| {
            PlatformError::invalid("invalid bucket_id").with_detail(error.to_string())
        })?;
        let object_key = normalize_object_key(&request.object_key)?;
        let bucket = self
            .buckets
            .get(bucket_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("bucket does not exist"))?;
        if bucket.deleted {
            return Err(PlatformError::conflict("bucket has been deleted"));
        }
        let id = UploadId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate upload id")
                .with_detail(error.to_string())
        })?;
        let upload = UploadSession {
            id: id.clone(),
            bucket_id,
            object_key,
            parts: BTreeMap::new(),
            completed: false,
            object_digest: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.uploads.create(id.as_str(), upload.clone()).await?;
        json_response(StatusCode::CREATED, &upload)
    }

    async fn upload_part(
        &self,
        upload_id: &str,
        part_number: &str,
        body: Bytes,
    ) -> Result<Response<ApiBody>> {
        let upload_guard = upload_operation_guard(upload_id);
        let _guard = upload_guard.lock().await;
        let _blob_guard = self.blob_accounting_guard.lock().await;
        let part_number = part_number.parse::<u32>().map_err(|error| {
            PlatformError::invalid("invalid part number").with_detail(error.to_string())
        })?;
        if part_number == 0 {
            return Err(PlatformError::invalid(
                "part number must be greater than zero",
            ));
        }
        let stored = self
            .uploads
            .get(upload_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("upload does not exist"))?;
        let mut upload = stored.value;
        if upload.completed {
            return Err(PlatformError::conflict("upload already completed"));
        }

        let blob = self.blobs.put_with_status(body).await?;
        upload
            .parts
            .insert(part_number, blob.metadata.digest.clone());
        upload
            .metadata
            .touch(sha256_hex(blob.metadata.digest.as_bytes()));
        if let Err(error) = self
            .uploads
            .upsert(upload_id, upload.clone(), Some(stored.version))
            .await
        {
            if let Err(reconcile_error) = self.reconcile_blob_accounting_and_gc_locked().await {
                return Err(error.with_detail(format!(
                    "blob reference reconcile failed after upload-part error: {reconcile_error}"
                )));
            }
            return Err(error);
        }
        let _cleanup_pending = self.reconcile_blob_accounting_and_gc_locked().await?;
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "upload_id": upload_id,
                "part_number": part_number,
                "digest": blob.metadata.digest,
                "size": blob.metadata.size,
            }),
        )
    }

    async fn complete_upload(
        &self,
        upload_id: &str,
        context: Option<&RequestContext>,
    ) -> Result<Response<ApiBody>> {
        let upload_guard = upload_operation_guard(upload_id);
        let _guard = upload_guard.lock().await;
        let _blob_guard = self.blob_accounting_guard.lock().await;
        let stored = self
            .uploads
            .get(upload_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("upload does not exist"))?;
        let upload = stored.value;
        if upload.completed {
            return self
                .resume_completed_upload_cleanup(upload_id, upload)
                .await;
        }
        if upload.parts.is_empty() {
            return Err(PlatformError::invalid("cannot complete empty upload"));
        }

        let mut ordered_digests = upload
            .parts
            .iter()
            .map(|(part_number, digest)| (*part_number, digest.clone()))
            .collect::<Vec<_>>();
        ordered_digests.sort_by_key(|(part, _)| *part);
        let digest_list = ordered_digests
            .into_iter()
            .map(|(_, digest)| digest)
            .collect::<Vec<_>>();

        let object = self
            .blobs
            .concat_with_status(&digest_list)
            .await
            .map_err(|error| {
                let detail = storage_backend_error_detail(&error);
                let error = if is_storage_corruption_error(&error) {
                    PlatformError::storage_corruption("failed to assemble upload object")
                } else {
                    PlatformError::unavailable("failed to assemble upload object")
                };
                with_optional_request_correlation(
                    error.with_detail(format!("upload_id={upload_id} {detail}")),
                    context,
                )
            })?;
        let mut committed_upload = upload;
        committed_upload.completed = true;
        committed_upload.object_digest = Some(object.metadata.digest.clone());
        committed_upload.parts.clear();
        committed_upload
            .metadata
            .touch(sha256_hex(object.metadata.digest.as_bytes()));
        if let Err(error) = self
            .uploads
            .upsert(upload_id, committed_upload, Some(stored.version))
            .await
        {
            if let Err(reconcile_error) = self.reconcile_blob_accounting_and_gc_locked().await {
                return Err(error.with_detail(format!(
                    "blob reference reconcile failed after complete-upload error: {reconcile_error}"
                )));
            }
            return Err(error);
        }
        let cleanup_pending = self
            .reconcile_blob_accounting_and_gc_locked()
            .await
            // The upload is already durable at this point; keep the response
            // successful and surface that cleanup still needs follow-up.
            .unwrap_or(true);
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "upload_id": upload_id,
                "object_digest": object.metadata.digest,
                "size": object.metadata.size,
                "cleanup_pending": cleanup_pending,
            }),
        )
    }

    async fn resume_completed_upload_cleanup(
        &self,
        upload_id: &str,
        upload: UploadSession,
    ) -> Result<Response<ApiBody>> {
        let object_digest = upload
            .object_digest
            .clone()
            .ok_or_else(|| PlatformError::conflict("completed upload is missing object_digest"))?;
        let object = self
            .blobs
            .get(&object_digest)
            .await?
            .ok_or_else(|| PlatformError::not_found("completed upload object is missing"))?;
        let cleanup_pending = self
            .reconcile_blob_accounting_and_gc_locked()
            .await
            .unwrap_or(true);
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "upload_id": upload_id,
                "object_digest": object_digest,
                "size": object.len(),
                "cleanup_pending": cleanup_pending,
            }),
        )
    }

    async fn reconcile_blob_accounting_and_gc_locked(&self) -> Result<bool> {
        let uploads = self.uploads.list().await?;
        let mut owners_by_digest: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (upload_key, stored) in uploads {
            if stored.deleted {
                continue;
            }
            let upload = self
                .normalize_completed_upload_parts_locked(&upload_key, stored)
                .await?;
            self.collect_blob_reference_owners(&upload, &mut owners_by_digest);
        }

        let physical_digests = self.blobs.list_digests().await?;
        let physical_digest_set = physical_digests.into_iter().collect::<BTreeSet<_>>();
        let stored_references = self
            .blob_references
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .collect::<BTreeMap<_, _>>();
        let stored_workflows = self
            .blob_gc_workflows
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| (stored.value.state.digest.clone(), stored))
            .collect::<BTreeMap<_, _>>();

        let mut all_digests = owners_by_digest.keys().cloned().collect::<BTreeSet<_>>();
        all_digests.extend(physical_digest_set.iter().cloned());
        all_digests.extend(stored_references.keys().cloned());
        all_digests.extend(stored_workflows.keys().cloned());

        for digest in all_digests {
            let owners = owners_by_digest.remove(&digest).unwrap_or_default();
            let physical_blob_present = physical_digest_set.contains(&digest);
            self.persist_blob_reference_record_locked(
                &digest,
                &owners,
                physical_blob_present,
                stored_references.get(&digest),
            )
            .await?;
            self.persist_blob_gc_workflow_locked(
                &digest,
                owners.len() as u64,
                physical_blob_present,
                stored_workflows.get(&digest),
            )
            .await?;
        }

        self.run_due_blob_gc_workflows_locked().await
    }

    async fn normalize_completed_upload_parts_locked(
        &self,
        upload_key: &str,
        stored: StoredDocument<UploadSession>,
    ) -> Result<UploadSession> {
        let upload = stored.value;
        if !upload.completed || upload.parts.is_empty() {
            return Ok(upload);
        }
        let Some(object_digest) = upload.object_digest.clone() else {
            return Ok(upload);
        };

        let mut normalized = upload;
        normalized.parts.clear();
        normalized
            .metadata
            .touch(sha256_hex(object_digest.as_bytes()));
        match self
            .uploads
            .upsert(upload_key, normalized.clone(), Some(stored.version))
            .await
        {
            Ok(updated) => Ok(updated.value),
            Err(error) if matches!(error.code, ErrorCode::Conflict) => Ok(normalized),
            Err(error) => Err(error),
        }
    }

    fn collect_blob_reference_owners(
        &self,
        upload: &UploadSession,
        owners_by_digest: &mut BTreeMap<String, Vec<String>>,
    ) {
        if upload.completed {
            if let Some(object_digest) = upload.object_digest.clone() {
                owners_by_digest
                    .entry(object_digest)
                    .or_default()
                    .push(format!("upload:{}:object", upload.id));
            }
            return;
        }

        for (part_number, digest) in &upload.parts {
            owners_by_digest
                .entry(digest.clone())
                .or_default()
                .push(format!("upload:{}:part:{part_number}", upload.id));
        }
    }

    async fn persist_blob_reference_record_locked(
        &self,
        digest: &str,
        owners: &[String],
        physical_blob_present: bool,
        existing: Option<&StoredDocument<BlobReferenceRecord>>,
    ) -> Result<()> {
        if owners.is_empty() && !physical_blob_present {
            if let Some(existing) = existing {
                self.blob_references
                    .soft_delete(digest, Some(existing.version))
                    .await?;
            }
            return Ok(());
        }

        let record = build_blob_reference_record(digest, owners, physical_blob_present);
        if let Some(existing) = existing {
            if existing.value == record {
                return Ok(());
            }
            let _ = self
                .blob_references
                .upsert(digest, record, Some(existing.version))
                .await?;
            return Ok(());
        }

        let _ = self.blob_references.create(digest, record).await?;
        Ok(())
    }

    async fn persist_blob_gc_workflow_locked(
        &self,
        digest: &str,
        reference_count: u64,
        physical_blob_present: bool,
        existing: Option<&StoredDocument<BlobGcWorkflow>>,
    ) -> Result<()> {
        let orphaned = physical_blob_present && reference_count == 0;
        match existing {
            Some(existing) => {
                let mut workflow = existing.value.clone();
                update_blob_gc_workflow_state(
                    &mut workflow,
                    reference_count,
                    physical_blob_present,
                    orphaned,
                );
                if workflow == existing.value {
                    return Ok(());
                }
                let workflow_id = blob_gc_workflow_id(digest);
                let _ = self
                    .blob_gc_workflows
                    .upsert(workflow_id.as_str(), workflow, Some(existing.version))
                    .await?;
            }
            None => {
                let workflow = build_blob_gc_workflow(
                    digest,
                    reference_count,
                    physical_blob_present,
                    orphaned,
                );
                let workflow_id = blob_gc_workflow_id(digest);
                let _ = self
                    .blob_gc_workflows
                    .create(workflow_id.as_str(), workflow)
                    .await?;
            }
        }
        Ok(())
    }

    async fn run_due_blob_gc_workflows_locked(&self) -> Result<bool> {
        let now = OffsetDateTime::now_utc();
        let workflows = self.blob_gc_workflows.list().await?;
        let mut cleanup_pending = false;

        for (workflow_key, stored) in workflows {
            if stored.deleted {
                continue;
            }
            if matches!(stored.value.phase, WorkflowPhase::Completed) {
                continue;
            }
            if !stored.value.is_due_at(now) {
                cleanup_pending = true;
                continue;
            }
            let updated = self
                .execute_blob_gc_workflow_locked(&workflow_key, stored)
                .await?;
            if !matches!(updated.phase, WorkflowPhase::Completed) {
                cleanup_pending = true;
            }
        }

        Ok(cleanup_pending)
    }

    async fn execute_blob_gc_workflow_locked(
        &self,
        workflow_key: &str,
        stored: StoredDocument<BlobGcWorkflow>,
    ) -> Result<BlobGcWorkflow> {
        let mut workflow = stored.value;
        let now = OffsetDateTime::now_utc();
        workflow.set_phase_at(WorkflowPhase::Running, now);
        workflow.current_step_index = Some(BLOB_GC_CONFIRM_STEP_INDEX);
        let confirm_detail = format!(
            "reference_count={} physical_blob_present={}",
            workflow.state.reference_count, workflow.state.physical_blob_present
        );
        if let Some(step) = workflow.step_mut(BLOB_GC_CONFIRM_STEP_INDEX) {
            step.transition(WorkflowStepState::Completed, Some(confirm_detail));
        }

        if workflow.state.reference_count > 0 || !workflow.state.physical_blob_present {
            workflow.current_step_index = Some(BLOB_GC_DELETE_STEP_INDEX);
            if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
                step.transition(
                    WorkflowStepState::RolledBack,
                    Some(String::from("blob is referenced or already absent")),
                );
            }
            workflow.state.last_outcome = Some(String::from("gc skipped"));
            workflow.set_next_attempt_at(None, now);
            workflow.set_phase_at(WorkflowPhase::Completed, now);
            let updated = self
                .blob_gc_workflows
                .upsert(workflow_key, workflow.clone(), Some(stored.version))
                .await?;
            return Ok(updated.value);
        }

        workflow.current_step_index = Some(BLOB_GC_DELETE_STEP_INDEX);
        if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
            step.transition(WorkflowStepState::Active, None);
        }

        match self.blobs.delete(&workflow.state.digest).await {
            Ok(()) => {
                workflow.state.physical_blob_present = false;
                workflow.state.last_outcome = Some(String::from("blob deleted"));
                if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Completed,
                        Some(String::from("blob deleted")),
                    );
                }
                workflow.set_next_attempt_at(None, now);
                workflow.set_phase_at(WorkflowPhase::Completed, now);
                self.clear_blob_reference_record_locked(&workflow.state.digest)
                    .await?;
            }
            Err(error) if matches!(error.code, ErrorCode::NotFound) => {
                workflow.state.physical_blob_present = false;
                workflow.state.last_outcome = Some(String::from("blob already absent"));
                if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Completed,
                        Some(String::from("blob already absent")),
                    );
                }
                workflow.set_next_attempt_at(None, now);
                workflow.set_phase_at(WorkflowPhase::Completed, now);
                self.clear_blob_reference_record_locked(&workflow.state.digest)
                    .await?;
            }
            Err(error) => {
                workflow.state.deletion_attempts =
                    workflow.state.deletion_attempts.saturating_add(1);
                workflow.state.last_outcome = Some(error.to_string());
                if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
                    step.transition(WorkflowStepState::Failed, Some(error.to_string()));
                }
                workflow.set_next_attempt_at(
                    Some(now + Duration::seconds(BLOB_GC_RETRY_DELAY_SECONDS)),
                    now,
                );
                workflow.set_phase_at(WorkflowPhase::Failed, now);
            }
        }

        let updated = self
            .blob_gc_workflows
            .upsert(workflow_key, workflow.clone(), Some(stored.version))
            .await?;
        Ok(updated.value)
    }

    async fn clear_blob_reference_record_locked(&self, digest: &str) -> Result<()> {
        if let Some(stored) = self.blob_references.get(digest).await?
            && !stored.deleted
        {
            self.blob_references
                .soft_delete(digest, Some(stored.version))
                .await?;
        }
        Ok(())
    }

    async fn fetch_object(
        &self,
        digest: &str,
        range_header: Option<&HeaderValue>,
        context: Option<&RequestContext>,
    ) -> Result<Response<ApiBody>> {
        let metadata = self
            .blobs
            .metadata(digest)
            .await
            .map_err(|error| remap_object_download_error(digest, error, context))?
            .ok_or_else(|| PlatformError::not_found("object not found"))?;
        match parse_object_range_header(range_header, metadata.size)? {
            ObjectRangeSelection::Full => {
                let bytes = self
                    .blobs
                    .get(&metadata.digest)
                    .await
                    .map_err(|error| remap_object_download_error(&metadata.digest, error, context))?
                    .ok_or_else(|| PlatformError::not_found("object not found"))?;
                object_response(
                    StatusCode::OK,
                    &metadata.digest,
                    metadata.size,
                    None,
                    full_body(bytes),
                )
            }
            ObjectRangeSelection::Partial(range) => {
                let bytes = self
                    .blobs
                    .get_range(&metadata.digest, range.start, range.end_inclusive)
                    .await
                    .map_err(|error| remap_object_download_error(&metadata.digest, error, context))?
                    .ok_or_else(|| PlatformError::not_found("object not found"))?;
                debug_assert_eq!(range.len(), bytes.len() as u64);
                object_response(
                    StatusCode::PARTIAL_CONTENT,
                    &metadata.digest,
                    metadata.size,
                    Some(range),
                    full_body(bytes),
                )
            }
            ObjectRangeSelection::Unsatisfiable => {
                object_range_not_satisfiable_response(&metadata.digest, metadata.size)
            }
        }
    }

    async fn list_active_buckets(&self) -> Result<Vec<BucketRecord>> {
        let mut values = self
            .buckets
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_active_volumes(&self) -> Result<Vec<VolumeRecord>> {
        let mut values = self
            .volumes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_active_file_shares(&self) -> Result<Vec<FileShareRecord>> {
        let mut values = self
            .file_shares
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_active_archives(&self) -> Result<Vec<ArchiveRecord>> {
        let mut values = self
            .archives
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_active_archive_rehydrate_jobs(&self) -> Result<Vec<ArchiveRehydrateJobRecord>> {
        let mut values = self
            .archive_rehydrate_jobs
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn storage_summary(&self) -> Result<StorageSummaryResponse> {
        let buckets = self.list_active_buckets().await?;
        let volumes = self.list_active_volumes().await?;
        let file_shares = self.list_active_file_shares().await?;
        let archives = self.list_active_archives().await?;
        let bucket_count = buckets.len();
        let volume_count = volumes.len();
        let attachment_count = volumes
            .iter()
            .filter(|volume| volume.attached_to.is_some())
            .count();
        let file_share_count = file_shares.len();
        let archive_count = archives.len();
        let upload_session_count = self
            .uploads
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        let archive_rehydrate_job_count = self
            .archive_rehydrate_jobs
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        let recovery_point_count = self
            .volume_recovery_points
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| {
                !stored.deleted && stored.value.metadata.lifecycle == ResourceLifecycleState::Ready
            })
            .count();
        let restore_action_count = self
            .volume_restore_actions
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        Ok(StorageSummaryResponse {
            bucket_count,
            volume_count,
            attachment_count,
            file_share_count,
            archive_count,
            upload_session_count,
            archive_rehydrate_job_count,
            recovery_point_count,
            restore_action_count,
        })
    }
}

fn upload_operation_guard(upload_id: &str) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = registry.get(upload_id).and_then(Weak::upgrade) {
        return existing;
    }

    registry.retain(|_, guard| guard.strong_count() > 0);
    let guard = Arc::new(Mutex::new(()));
    registry.insert(upload_id.to_owned(), Arc::downgrade(&guard));
    guard
}

fn blob_gc_workflow_id(digest: &str) -> String {
    format!("storage-blob-gc-{digest}")
}

fn build_blob_reference_record(
    digest: &str,
    owners: &[String],
    physical_blob_present: bool,
) -> BlobReferenceRecord {
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Platform,
        Some(String::from("storage-blob-accounting")),
        sha256_hex(format!("{digest}:{}:{physical_blob_present}", owners.join("|")).as_bytes()),
    );
    metadata.lifecycle = if owners.is_empty() {
        if physical_blob_present {
            ResourceLifecycleState::Draining
        } else {
            ResourceLifecycleState::Deleted
        }
    } else if physical_blob_present {
        ResourceLifecycleState::Ready
    } else {
        ResourceLifecycleState::Failed
    };
    BlobReferenceRecord {
        digest: digest.to_owned(),
        reference_count: owners.len() as u64,
        owners: owners.to_vec(),
        physical_blob_present,
        metadata,
    }
}

fn build_blob_gc_workflow(
    digest: &str,
    reference_count: u64,
    physical_blob_present: bool,
    orphaned: bool,
) -> BlobGcWorkflow {
    let mut workflow = WorkflowInstance::new(
        blob_gc_workflow_id(digest),
        BLOB_GC_WORKFLOW_KIND,
        BLOB_GC_WORKFLOW_SUBJECT_KIND,
        digest,
        BlobGcWorkflowState {
            digest: digest.to_owned(),
            reference_count,
            physical_blob_present,
            deletion_attempts: 0,
            last_outcome: None,
        },
        vec![
            WorkflowStep::new("confirm_orphaned_blob", BLOB_GC_CONFIRM_STEP_INDEX),
            WorkflowStep::new("delete_blob", BLOB_GC_DELETE_STEP_INDEX),
        ],
    );
    update_blob_gc_workflow_state(
        &mut workflow,
        reference_count,
        physical_blob_present,
        orphaned,
    );
    workflow
}

fn update_blob_gc_workflow_state(
    workflow: &mut BlobGcWorkflow,
    reference_count: u64,
    physical_blob_present: bool,
    orphaned: bool,
) {
    workflow.state.reference_count = reference_count;
    workflow.state.physical_blob_present = physical_blob_present;
    if orphaned {
        workflow.completed_at = None;
        workflow.current_step_index = Some(BLOB_GC_CONFIRM_STEP_INDEX);
        workflow.set_next_attempt_at(Some(OffsetDateTime::now_utc()), OffsetDateTime::now_utc());
        workflow.set_phase(WorkflowPhase::Pending);
        if let Some(step) = workflow.step_mut(BLOB_GC_CONFIRM_STEP_INDEX) {
            step.transition(WorkflowStepState::Pending, None);
        }
        if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
            step.transition(WorkflowStepState::Pending, None);
        }
        return;
    }

    workflow.current_step_index = Some(BLOB_GC_DELETE_STEP_INDEX);
    workflow.set_next_attempt_at(None, OffsetDateTime::now_utc());
    if let Some(step) = workflow.step_mut(BLOB_GC_CONFIRM_STEP_INDEX) {
        step.transition(
            WorkflowStepState::Completed,
            Some(format!(
                "reference_count={reference_count} physical_blob_present={physical_blob_present}"
            )),
        );
    }
    if let Some(step) = workflow.step_mut(BLOB_GC_DELETE_STEP_INDEX) {
        step.transition(
            WorkflowStepState::RolledBack,
            Some(String::from("blob remains referenced or already absent")),
        );
    }
    workflow.state.last_outcome = Some(String::from("gc not required"));
    workflow.set_phase(WorkflowPhase::Completed);
}

fn normalize_name(value: &str, field: &'static str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid(format!("{field} is too long")));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_owner_id(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("owner_id may not be empty"));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid("owner_id is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "owner_id may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_attachment_target(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("attached_to may not be empty"));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid("attached_to is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "attached_to may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_mount_target(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("mounted_to may not be empty"));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid("mounted_to is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "mounted_to may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_optional_text(value: Option<&str>, field: &'static str) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > 256 {
        return Err(PlatformError::invalid(format!("{field} is too long")));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    Ok(Some(normalized.to_owned()))
}

fn normalize_supported_resource_kinds(
    mut kinds: Vec<StorageResourceKind>,
) -> Result<Vec<StorageResourceKind>> {
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        return Err(PlatformError::invalid(
            "supported_resource_kinds may not be empty",
        ));
    }
    Ok(kinds)
}

fn storage_resource_kind_label(kind: StorageResourceKind) -> &'static str {
    match kind {
        StorageResourceKind::Bucket => "bucket",
        StorageResourceKind::Volume => "volume",
        StorageResourceKind::Database => "database",
    }
}

fn storage_binding_etag(resource_id: &str, binding: Option<&StorageBinding>) -> String {
    let (storage_class_id, durability_tier_id) = binding.map_or(("", ""), |binding| {
        (
            binding.storage_class_id.as_str(),
            binding.durability_tier_id.as_str(),
        )
    });
    sha256_hex(
        format!("{resource_id}:storage-binding:{storage_class_id}:{durability_tier_id}").as_bytes(),
    )
}

fn storage_class_id(value: &'static str) -> StorageClassId {
    StorageClassId::parse(value)
        .unwrap_or_else(|error| panic!("invalid builtin storage class id {value}: {error}"))
}

fn durability_tier_id(value: &'static str) -> DurabilityTierId {
    DurabilityTierId::parse(value)
        .unwrap_or_else(|error| panic!("invalid builtin durability tier id {value}: {error}"))
}

fn default_storage_binding(resource_kind: StorageResourceKind) -> StorageBinding {
    match resource_kind {
        StorageResourceKind::Bucket => StorageBinding {
            storage_class_id: storage_class_id(DEFAULT_OBJECT_STORAGE_CLASS_ID),
            durability_tier_id: durability_tier_id(DEFAULT_OBJECT_DURABILITY_TIER_ID),
        },
        StorageResourceKind::Volume | StorageResourceKind::Database => StorageBinding {
            storage_class_id: storage_class_id(DEFAULT_BLOCK_STORAGE_CLASS_ID),
            durability_tier_id: durability_tier_id(DEFAULT_BLOCK_DURABILITY_TIER_ID),
        },
    }
}

fn builtin_storage_classes() -> Vec<StorageClassRecord> {
    vec![
        StorageClassRecord {
            id: storage_class_id(DEFAULT_OBJECT_STORAGE_CLASS_ID),
            name: String::from("object-standard"),
            medium: StorageMedium::Object,
            supported_resource_kinds: vec![StorageResourceKind::Bucket],
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(String::from(DEFAULT_OBJECT_STORAGE_CLASS_ID)),
                sha256_hex(DEFAULT_OBJECT_STORAGE_CLASS_ID.as_bytes()),
            ),
        },
        StorageClassRecord {
            id: storage_class_id(DEFAULT_BLOCK_STORAGE_CLASS_ID),
            name: String::from("block-standard"),
            medium: StorageMedium::Block,
            supported_resource_kinds: vec![
                StorageResourceKind::Volume,
                StorageResourceKind::Database,
            ],
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(String::from(DEFAULT_BLOCK_STORAGE_CLASS_ID)),
                sha256_hex(DEFAULT_BLOCK_STORAGE_CLASS_ID.as_bytes()),
            ),
        },
    ]
}

fn builtin_durability_tiers() -> Vec<DurabilityTierRecord> {
    vec![
        DurabilityTierRecord {
            id: durability_tier_id(DEFAULT_OBJECT_DURABILITY_TIER_ID),
            name: String::from("object-regional"),
            minimum_replica_count: 2,
            failure_domain_scope: StorageFailureDomainScope::Region,
            supported_resource_kinds: vec![StorageResourceKind::Bucket],
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(String::from(DEFAULT_OBJECT_DURABILITY_TIER_ID)),
                sha256_hex(DEFAULT_OBJECT_DURABILITY_TIER_ID.as_bytes()),
            ),
        },
        DurabilityTierRecord {
            id: durability_tier_id(DEFAULT_BLOCK_DURABILITY_TIER_ID),
            name: String::from("block-replicated"),
            minimum_replica_count: 3,
            failure_domain_scope: StorageFailureDomainScope::Region,
            supported_resource_kinds: vec![
                StorageResourceKind::Volume,
                StorageResourceKind::Database,
            ],
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(String::from(DEFAULT_BLOCK_DURABILITY_TIER_ID)),
                sha256_hex(DEFAULT_BLOCK_DURABILITY_TIER_ID.as_bytes()),
            ),
        },
    ]
}

fn normalize_object_key(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("object_key may not be empty"));
    }
    if normalized.len() > 1024 {
        return Err(PlatformError::invalid("object_key is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "object_key may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_optional_reason(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.len() > 512 {
        return Err(PlatformError::invalid("reason is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "reason may not contain control characters",
        ));
    }
    Ok(Some(normalized.to_owned()))
}

fn parse_volume_id(value: &str) -> Result<VolumeId> {
    VolumeId::parse(value)
        .map_err(|error| PlatformError::invalid("invalid volume_id").with_detail(error.to_string()))
}

fn parse_restore_action_id(value: &str) -> Result<AuditId> {
    AuditId::parse(value).map_err(|error| {
        PlatformError::invalid("invalid restore_action_id").with_detail(error.to_string())
    })
}

fn build_volume_snapshot_policy(volume: &VolumeRecord) -> VolumeSnapshotPolicy {
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Project,
        Some(volume.id.to_string()),
        sha256_hex(format!("{}:snapshot-policy", volume.id.as_str()).as_bytes()),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.slice"),
        String::from("snapshot_policy"),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_id"),
        volume.id.to_string(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_kind"),
        String::from(VOLUME_SNAPSHOT_WORKFLOW_KIND),
    );

    VolumeSnapshotPolicy {
        volume_id: volume.id.clone(),
        recovery_class: VolumeRecoveryClass::ScheduledSnapshot,
        state: VolumeSnapshotPolicyState::Pending,
        interval_minutes: DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES,
        retention_snapshots: DEFAULT_VOLUME_SNAPSHOT_RETENTION,
        recovery_point_objective_minutes: DEFAULT_VOLUME_RECOVERY_POINT_OBJECTIVE_MINUTES,
        next_snapshot_after: OffsetDateTime::now_utc()
            + Duration::minutes(i64::from(DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES)),
        metadata,
    }
}

fn build_volume_snapshot_policy_summary(
    policy: &VolumeSnapshotPolicy,
) -> VolumeSnapshotPolicySummary {
    VolumeSnapshotPolicySummary {
        volume_id: policy.volume_id.clone(),
        recovery_class: volume_recovery_class_label(policy.recovery_class).to_owned(),
        state: volume_snapshot_policy_state_label(policy.state).to_owned(),
        lifecycle: resource_lifecycle_state_label(policy.metadata.lifecycle).to_owned(),
        interval_minutes: policy.interval_minutes,
        retention_snapshots: policy.retention_snapshots,
        recovery_point_objective_minutes: policy.recovery_point_objective_minutes,
        next_snapshot_after: policy.next_snapshot_after,
    }
}

fn build_volume_snapshot_workflow(
    policy: &VolumeSnapshotPolicy,
) -> WorkflowInstance<VolumeSnapshotWorkflowState> {
    let mut workflow = WorkflowInstance::new(
        policy.volume_id.to_string(),
        VOLUME_SNAPSHOT_WORKFLOW_KIND,
        VOLUME_SNAPSHOT_WORKFLOW_SUBJECT_KIND,
        policy.volume_id.to_string(),
        VolumeSnapshotWorkflowState {
            volume_id: policy.volume_id.clone(),
            recovery_class: policy.recovery_class,
            target_policy_state: VolumeSnapshotPolicyState::Active,
            interval_minutes: policy.interval_minutes,
            retention_snapshots: policy.retention_snapshots,
            recovery_point_objective_minutes: policy.recovery_point_objective_minutes,
        },
        vec![
            WorkflowStep::new("attach_snapshot_policy", 0),
            WorkflowStep::new("register_snapshot_schedule", 1),
            WorkflowStep::new("arm_recovery_window", VOLUME_SNAPSHOT_FINAL_STEP_INDEX),
        ],
    );

    if policy.state == VolumeSnapshotPolicyState::Active {
        workflow.current_step_index = Some(VOLUME_SNAPSHOT_FINAL_STEP_INDEX);
        for (index, detail) in [
            (0, "retention policy attached"),
            (1, "snapshot schedule registered"),
            (VOLUME_SNAPSHOT_FINAL_STEP_INDEX, "recovery window armed"),
        ] {
            if let Some(step) = workflow.step_mut(index) {
                step.transition(WorkflowStepState::Completed, Some(String::from(detail)));
            }
        }
        workflow.set_phase(WorkflowPhase::Completed);
    }

    workflow
}

fn build_volume_recovery_point(policy: &VolumeSnapshotPolicy) -> VolumeRecoveryPoint {
    let latest_snapshot_at = OffsetDateTime::now_utc();
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Project,
        Some(policy.volume_id.to_string()),
        sha256_hex(format!("{}:recovery-point:1", policy.volume_id.as_str()).as_bytes()),
    );
    metadata.lifecycle = ResourceLifecycleState::Ready;
    metadata.annotations.insert(
        String::from("storage.lifecycle.slice"),
        String::from("recovery_point"),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_id"),
        policy.volume_id.to_string(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_kind"),
        String::from(VOLUME_SNAPSHOT_WORKFLOW_KIND),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.action_kind"),
        String::from(VOLUME_RECOVERY_POINT_ACTION_KIND),
    );

    VolumeRecoveryPoint {
        volume_id: policy.volume_id.clone(),
        recovery_class: policy.recovery_class,
        capture_trigger: VolumeRecoveryPointTrigger::PolicyActivation,
        execution_count: 1,
        latest_snapshot_at,
        next_snapshot_after: policy.next_snapshot_after,
        interval_minutes: policy.interval_minutes,
        retention_snapshots: policy.retention_snapshots,
        recovery_point_objective_minutes: policy.recovery_point_objective_minutes,
        metadata,
    }
}

fn build_volume_recovery_point_summary(
    stored: &StoredDocument<VolumeRecoveryPoint>,
) -> VolumeRecoveryPointSummary {
    VolumeRecoveryPointSummary {
        volume_id: stored.value.volume_id.clone(),
        version: stored.version,
        execution_count: stored.value.execution_count,
        etag: stored.value.metadata.etag.clone(),
        captured_at: stored.value.latest_snapshot_at,
    }
}

fn build_selected_volume_recovery_point(
    stored: &StoredDocument<VolumeRecoveryPoint>,
) -> SelectedVolumeRecoveryPoint {
    SelectedVolumeRecoveryPoint {
        volume_id: stored.value.volume_id.clone(),
        recovery_class: stored.value.recovery_class,
        recovery_point_version: stored.version,
        recovery_point_execution_count: stored.value.execution_count,
        recovery_point_etag: stored.value.metadata.etag.clone(),
        recovery_point_captured_at: stored.value.latest_snapshot_at,
    }
}

fn build_selected_volume_recovery_point_from_revision(
    revision: &VolumeRecoveryPointRevision,
) -> SelectedVolumeRecoveryPoint {
    SelectedVolumeRecoveryPoint {
        volume_id: revision.volume_id.clone(),
        recovery_class: revision.recovery_class,
        recovery_point_version: revision.recovery_point_version,
        recovery_point_execution_count: revision.execution_count,
        recovery_point_etag: revision.metadata.etag.clone(),
        recovery_point_captured_at: revision.captured_at,
    }
}

fn build_volume_recovery_point_summary_from_selected(
    recovery_point: &SelectedVolumeRecoveryPoint,
) -> VolumeRecoveryPointSummary {
    VolumeRecoveryPointSummary {
        volume_id: recovery_point.volume_id.clone(),
        version: recovery_point.recovery_point_version,
        execution_count: recovery_point.recovery_point_execution_count,
        etag: recovery_point.recovery_point_etag.clone(),
        captured_at: recovery_point.recovery_point_captured_at,
    }
}

fn build_volume_recovery_history_entry(
    revision: &VolumeRecoveryPointRevision,
    current: Option<&VolumeRecoveryPointSummary>,
) -> VolumeRecoveryHistoryEntry {
    let is_current = current.is_some_and(|current| {
        current.version == revision.recovery_point_version && current.etag == revision.metadata.etag
    });
    VolumeRecoveryHistoryEntry {
        volume_id: revision.volume_id.clone(),
        version: revision.recovery_point_version,
        execution_count: revision.execution_count,
        etag: revision.metadata.etag.clone(),
        captured_at: revision.captured_at,
        current: is_current,
    }
}

fn build_volume_recovery_point_revision(
    stored: &StoredDocument<VolumeRecoveryPoint>,
) -> VolumeRecoveryPointRevision {
    VolumeRecoveryPointRevision {
        volume_id: stored.value.volume_id.clone(),
        recovery_class: stored.value.recovery_class,
        recovery_point_version: stored.version,
        execution_count: stored.value.execution_count,
        captured_at: stored.value.latest_snapshot_at,
        metadata: stored.value.metadata.clone(),
    }
}

fn volume_recovery_point_revision_key(volume_id: &VolumeId, recovery_point_version: u64) -> String {
    format!("{}:{recovery_point_version}", volume_id.as_str())
}

fn volume_restore_apply_effect_idempotency_key(state: &VolumeRestoreWorkflowState) -> String {
    sha256_hex(
        format!(
            "storage-volume-restore-apply:v1:{}:{}:{}:{}",
            state.restore_action_id.as_str(),
            state.volume_id.as_str(),
            state.recovery_point_version,
            state.recovery_point_etag,
        )
        .as_bytes(),
    )
}

fn volume_restore_apply_effect_detail(state: &VolumeRestoreWorkflowState) -> String {
    format!(
        "restored volume from persisted recovery point version {}",
        state.recovery_point_version
    )
}

fn normalize_volume_restore_apply_idempotency_key(idempotency_key: &str) -> Result<&str> {
    let trimmed = idempotency_key.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "volume restore apply idempotency key may not be empty",
        ));
    }
    Ok(trimmed)
}

fn build_volume_restore_apply_ledger_record(
    workflow: &VolumeRestoreWorkflow,
    result_digest: &str,
    recorded_at: OffsetDateTime,
) -> Result<VolumeRestoreApplyLedgerRecord> {
    Ok(VolumeRestoreApplyLedgerRecord::current(
        WorkflowEffectLedgerRecord::from_workflow_effect_at(
            workflow,
            VOLUME_RESTORE_FINAL_STEP_INDEX,
            VOLUME_RESTORE_APPLY_EFFECT_KIND,
            result_digest,
            recorded_at,
        )?,
    ))
}

fn validate_volume_restore_apply_ledger(
    record: &VolumeRestoreApplyLedgerRecord,
    workflow: &VolumeRestoreWorkflow,
) -> Result<()> {
    match record {
        VolumeRestoreApplyLedgerRecord::Current(record) => record.validate_for_workflow(workflow),
        VolumeRestoreApplyLedgerRecord::Legacy(record) => {
            validate_legacy_volume_restore_apply_ledger(record, workflow)
        }
    }
}

fn validate_legacy_volume_restore_apply_ledger(
    record: &LegacyVolumeRestoreApplyLedgerRecord,
    workflow: &VolumeRestoreWorkflow,
) -> Result<()> {
    let effect = workflow
        .step(VOLUME_RESTORE_FINAL_STEP_INDEX)
        .and_then(|step| step.effect(VOLUME_RESTORE_APPLY_EFFECT_KIND))
        .ok_or_else(|| {
            PlatformError::conflict("volume restore apply effect has not been journaled")
        })?;
    let state = &workflow.state;
    if record.workflow_id != workflow.id
        || record.idempotency_key != effect.idempotency_key
        || record.volume_id != state.volume_id
        || record.recovery_point_volume_id != state.recovery_point_volume_id
        || record.recovery_point_version != state.recovery_point_version
        || record.recovery_point_execution_count != state.recovery_point_execution_count
        || record.recovery_point_etag != state.recovery_point_etag
    {
        return Err(PlatformError::conflict(
            "volume restore apply idempotency key already belongs to a different recovery point",
        ));
    }
    Ok(())
}

fn build_volume_restore_workflow(
    restore_action_id: &AuditId,
    volume: &VolumeRecord,
    recovery_point: &SelectedVolumeRecoveryPoint,
    reason: Option<String>,
) -> VolumeRestoreWorkflow {
    WorkflowInstance::new(
        restore_action_id.to_string(),
        VOLUME_RESTORE_WORKFLOW_KIND,
        VOLUME_RESTORE_WORKFLOW_SUBJECT_KIND,
        volume.id.to_string(),
        VolumeRestoreWorkflowState {
            restore_action_id: restore_action_id.clone(),
            volume_id: volume.id.clone(),
            recovery_class: recovery_point.recovery_class,
            recovery_point_volume_id: recovery_point.volume_id.clone(),
            recovery_point_version: recovery_point.recovery_point_version,
            recovery_point_execution_count: recovery_point.recovery_point_execution_count,
            recovery_point_etag: recovery_point.recovery_point_etag.clone(),
            recovery_point_captured_at: recovery_point.recovery_point_captured_at,
            reason,
        },
        vec![
            WorkflowStep::new("select_persisted_recovery_point", 0),
            WorkflowStep::new("prepare_restore_execution", 1),
            WorkflowStep::new("apply_recovery_point", VOLUME_RESTORE_FINAL_STEP_INDEX),
        ],
    )
}

fn build_volume_restore_action_projection(workflow: &VolumeRestoreWorkflow) -> VolumeRestoreAction {
    let state = volume_restore_action_state_from_phase(&workflow.phase);
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Project,
        Some(workflow.state.volume_id.to_string()),
        sha256_hex(
            format!(
                "{}:{}:{}",
                workflow.id,
                workflow_phase_label(&workflow.phase),
                workflow.state.recovery_point_etag,
            )
            .as_bytes(),
        ),
    );
    metadata.created_at = workflow.created_at;
    metadata.updated_at = workflow.updated_at;
    metadata.lifecycle = volume_restore_metadata_lifecycle(state);
    metadata.annotations.insert(
        String::from("storage.lifecycle.slice"),
        String::from("restore_action"),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_id"),
        workflow.id.clone(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.workflow_kind"),
        workflow.workflow_kind.clone(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.action_kind"),
        String::from(VOLUME_RESTORE_ACTION_KIND),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.source_recovery_point_volume_id"),
        workflow.state.recovery_point_volume_id.to_string(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.source_recovery_point_version"),
        workflow.state.recovery_point_version.to_string(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.source_recovery_point_execution_count"),
        workflow.state.recovery_point_execution_count.to_string(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.source_recovery_point_etag"),
        workflow.state.recovery_point_etag.clone(),
    );
    metadata.annotations.insert(
        String::from("storage.lifecycle.source_recovery_point_captured_at"),
        workflow
            .state
            .recovery_point_captured_at
            .unix_timestamp()
            .to_string(),
    );
    if let Some(reason) = &workflow.state.reason {
        metadata.annotations.insert(
            String::from("storage.lifecycle.restore_reason"),
            reason.clone(),
        );
    }

    VolumeRestoreAction {
        id: workflow.state.restore_action_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_kind: workflow.workflow_kind.clone(),
        volume_id: workflow.state.volume_id.clone(),
        recovery_class: workflow.state.recovery_class,
        source_recovery_point_volume_id: workflow.state.recovery_point_volume_id.clone(),
        source_recovery_point_version: workflow.state.recovery_point_version,
        source_recovery_point_execution_count: workflow.state.recovery_point_execution_count,
        source_recovery_point_etag: workflow.state.recovery_point_etag.clone(),
        source_recovery_point_captured_at: workflow.state.recovery_point_captured_at,
        state,
        requested_reason: workflow.state.reason.clone(),
        requested_at: workflow.created_at,
        started_at: workflow
            .steps
            .iter()
            .filter(|step| step.state != WorkflowStepState::Pending)
            .map(|step| step.updated_at)
            .min(),
        completed_at: workflow.completed_at,
        metadata,
    }
}

fn build_volume_restore_action_summary(action: &VolumeRestoreAction) -> VolumeRestoreActionSummary {
    VolumeRestoreActionSummary {
        id: action.id.clone(),
        workflow_id: action.workflow_id.clone(),
        volume_id: action.volume_id.clone(),
        state: volume_restore_action_state_label(action.state).to_owned(),
        source_recovery_point_volume_id: action.source_recovery_point_volume_id.clone(),
        source_recovery_point_version: action.source_recovery_point_version,
        source_recovery_point_execution_count: action.source_recovery_point_execution_count,
        source_recovery_point_etag: action.source_recovery_point_etag.clone(),
        source_recovery_point_captured_at: action.source_recovery_point_captured_at,
        recovery_class: volume_recovery_class_label(action.recovery_class).to_owned(),
        requested_reason: action.requested_reason.clone(),
        requested_at: action.requested_at,
        started_at: action.started_at,
        completed_at: action.completed_at,
        lifecycle: resource_lifecycle_state_label(action.metadata.lifecycle).to_owned(),
    }
}

fn volume_recovery_class_label(recovery_class: VolumeRecoveryClass) -> &'static str {
    match recovery_class {
        VolumeRecoveryClass::ScheduledSnapshot => "scheduled_snapshot",
    }
}

fn volume_snapshot_policy_state_label(state: VolumeSnapshotPolicyState) -> &'static str {
    match state {
        VolumeSnapshotPolicyState::Pending => "pending",
        VolumeSnapshotPolicyState::Active => "active",
    }
}

fn volume_restore_action_state_label(state: VolumeRestoreActionState) -> &'static str {
    match state {
        VolumeRestoreActionState::Pending => "pending",
        VolumeRestoreActionState::Running => "running",
        VolumeRestoreActionState::Completed => "completed",
        VolumeRestoreActionState::Failed => "failed",
        VolumeRestoreActionState::RolledBack => "rolled_back",
    }
}

fn volume_restore_action_state_from_phase(phase: &WorkflowPhase) -> VolumeRestoreActionState {
    match phase {
        WorkflowPhase::Pending => VolumeRestoreActionState::Pending,
        WorkflowPhase::Running | WorkflowPhase::Paused => VolumeRestoreActionState::Running,
        WorkflowPhase::Completed => VolumeRestoreActionState::Completed,
        WorkflowPhase::Failed => VolumeRestoreActionState::Failed,
        WorkflowPhase::RolledBack => VolumeRestoreActionState::RolledBack,
    }
}

fn volume_restore_metadata_lifecycle(state: VolumeRestoreActionState) -> ResourceLifecycleState {
    match state {
        VolumeRestoreActionState::Pending | VolumeRestoreActionState::Running => {
            ResourceLifecycleState::Pending
        }
        VolumeRestoreActionState::Completed => ResourceLifecycleState::Ready,
        VolumeRestoreActionState::Failed | VolumeRestoreActionState::RolledBack => {
            ResourceLifecycleState::Failed
        }
    }
}

fn resource_lifecycle_state_label(state: ResourceLifecycleState) -> &'static str {
    match state {
        ResourceLifecycleState::Pending => "pending",
        ResourceLifecycleState::Ready => "ready",
        ResourceLifecycleState::Draining => "draining",
        ResourceLifecycleState::Suspended => "suspended",
        ResourceLifecycleState::Failed => "failed",
        ResourceLifecycleState::Deleted => "deleted",
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

fn volume_restore_reconciliation_lease_duration() -> Duration {
    Duration::minutes(5)
}

fn volume_restore_workflow_requires_reconciliation(workflow: &VolumeRestoreWorkflow) -> bool {
    matches!(
        workflow.phase,
        WorkflowPhase::Pending | WorkflowPhase::Running
    )
}

fn apply_volume_restore_reconciliation_primitives(
    workflow: &mut VolumeRestoreWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    let desired_next_attempt_at =
        volume_restore_workflow_requires_reconciliation(workflow).then_some(observed_at);
    let active_claim = workflow
        .runner_claim
        .clone()
        .filter(|claim| claim.is_active_at(observed_at));

    if active_claim
        .as_ref()
        .is_some_and(|claim| claim.runner_id != VOLUME_RESTORE_RECONCILER_RUNNER_ID)
    {
        return Ok(false);
    }

    let mut changed = false;
    if desired_next_attempt_at.is_some() {
        if let Some(active_claim) = active_claim.as_ref() {
            let fencing_token = active_claim.fencing_token.clone();
            workflow.heartbeat_runner_at(
                VOLUME_RESTORE_RECONCILER_RUNNER_ID,
                fencing_token.as_str(),
                volume_restore_reconciliation_lease_duration(),
                observed_at,
            )?;
        } else {
            workflow.claim_runner_at(
                VOLUME_RESTORE_RECONCILER_RUNNER_ID,
                volume_restore_reconciliation_lease_duration(),
                observed_at,
            )?;
        }
        changed = true;
    }

    if workflow.next_attempt_at != desired_next_attempt_at {
        workflow.set_next_attempt_at(desired_next_attempt_at, observed_at);
        changed = true;
    }

    Ok(changed)
}

fn workflow_step_state(
    workflow: &VolumeRestoreWorkflow,
    index: usize,
) -> Option<WorkflowStepState> {
    workflow
        .steps
        .iter()
        .find(|step| step.index == index)
        .map(|step| step.state.clone())
}

impl HttpService for StorageService {
    fn name(&self) -> &'static str {
        "storage"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/storage")];
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
            let range_header = request.headers().get(RANGE).cloned();
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["storage"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["storage", "summary"]) => {
                    let summary = self.storage_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["storage", "storage-classes"]) => {
                    let values = self.list_active_storage_classes().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "storage-classes"]) => {
                    let body: CreateStorageClassRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_storage_class(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "durability-tiers"]) => {
                    let values = self.list_active_durability_tiers().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "durability-tiers"]) => {
                    let body: CreateDurabilityTierRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_durability_tier(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "buckets"]) => {
                    let values = self.list_active_buckets().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "buckets"]) => {
                    let body: CreateBucketRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_bucket(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "file-shares"]) => {
                    let values = self.list_active_file_shares().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "file-shares"]) => {
                    let body: CreateFileShareRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_file_share(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "volumes"]) => {
                    let values = self.list_active_volumes().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "volumes"]) => {
                    let body: CreateVolumeRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_volume(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "volumes", volume_id, "snapshot-policy"]) => {
                    let summary = self
                        .inspect_volume_snapshot_policy(volume_id, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["storage", "volumes", volume_id, "recovery-point"]) => {
                    let summary = self
                        .inspect_ready_volume_recovery_point(volume_id, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["storage", "volumes", volume_id, "recovery-history"]) => {
                    let values = self
                        .list_volume_recovery_history(volume_id, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["storage", "volumes", volume_id, "restore-actions"]) => {
                    let values = self
                        .list_volume_restore_actions(volume_id, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "volumes", volume_id, "restore-actions"]) => {
                    let body: CreateVolumeRestoreActionRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    let action = self
                        .create_volume_restore_action(volume_id, body, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::CREATED, &action).map(Some)
                }
                (Method::GET, ["storage", "restore-actions", action_id]) => {
                    let action = self
                        .inspect_volume_restore_action(action_id, &context)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    json_response(StatusCode::OK, &action).map(Some)
                }
                (Method::GET, ["storage", "archives"]) => {
                    let values = self.list_active_archives().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "archives"]) => {
                    let body: CreateArchiveRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_archive(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::GET, ["storage", "archive-rehydrate-jobs"]) => {
                    let values = self.list_active_archive_rehydrate_jobs().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["storage", "archive-rehydrate-jobs"]) => {
                    let body: CreateArchiveRehydrateJobRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_archive_rehydrate_job(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::POST, ["storage", "uploads"]) => {
                    let body: CreateUploadRequest = parse_json(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.create_upload(body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::PUT, ["storage", "uploads", upload_id, "parts", part_number]) => {
                    let body = read_body(request)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))?;
                    self.upload_part(upload_id, part_number, body)
                        .await
                        .map_err(|error| with_request_correlation(error, &context))
                        .map(Some)
                }
                (Method::POST, ["storage", "uploads", upload_id, "complete"]) => self
                    .complete_upload(upload_id, Some(&context))
                    .await
                    .map(Some)
                    .map_err(|error| with_request_correlation(error, &context)),
                (Method::GET, ["storage", "objects", digest]) => self
                    .fetch_object(digest, range_header.as_ref(), Some(&context))
                    .await
                    .map(Some)
                    .map_err(|error| with_request_correlation(error, &context)),
                _ => Ok(None),
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectByteRange {
    start: u64,
    end_inclusive: u64,
}

impl ObjectByteRange {
    fn len(self) -> u64 {
        self.end_inclusive - self.start + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectRangeSelection {
    Full,
    Partial(ObjectByteRange),
    Unsatisfiable,
}

fn parse_object_range_header(
    header: Option<&HeaderValue>,
    object_size: u64,
) -> Result<ObjectRangeSelection> {
    let Some(header) = header else {
        return Ok(ObjectRangeSelection::Full);
    };
    if object_size == 0 {
        return Ok(ObjectRangeSelection::Unsatisfiable);
    }

    let raw = header.to_str().map_err(|error| {
        PlatformError::invalid("invalid Range header").with_detail(error.to_string())
    })?;
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return Err(PlatformError::invalid("invalid Range header")
            .with_detail("only bytes ranges are supported"));
    };
    if spec.contains(',') {
        return Err(PlatformError::invalid("invalid Range header")
            .with_detail("multiple ranges are not supported"));
    }
    let Some((start_raw, end_raw)) = spec.split_once('-') else {
        return Err(PlatformError::invalid("invalid Range header")
            .with_detail("range must use bytes=start-end syntax"));
    };

    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();
    if start_raw.is_empty() {
        let suffix_length = end_raw.parse::<u64>().map_err(|error| {
            PlatformError::invalid("invalid Range header").with_detail(error.to_string())
        })?;
        if suffix_length == 0 {
            return Err(PlatformError::invalid("invalid Range header")
                .with_detail("suffix length must be greater than zero"));
        }
        let read_length = suffix_length.min(object_size);
        return Ok(ObjectRangeSelection::Partial(ObjectByteRange {
            start: object_size - read_length,
            end_inclusive: object_size - 1,
        }));
    }

    let start = start_raw.parse::<u64>().map_err(|error| {
        PlatformError::invalid("invalid Range header").with_detail(error.to_string())
    })?;
    if start >= object_size {
        return Ok(ObjectRangeSelection::Unsatisfiable);
    }
    let end_inclusive = if end_raw.is_empty() {
        object_size - 1
    } else {
        end_raw.parse::<u64>().map_err(|error| {
            PlatformError::invalid("invalid Range header").with_detail(error.to_string())
        })?
    };
    if end_inclusive < start {
        return Err(PlatformError::invalid("invalid Range header")
            .with_detail(format!("range end precedes start: {raw}")));
    }

    Ok(ObjectRangeSelection::Partial(ObjectByteRange {
        start,
        end_inclusive: end_inclusive.min(object_size - 1),
    }))
}

fn object_download_response(
    status: StatusCode,
    digest: &str,
    content_length: u64,
    content_range: Option<String>,
    body: ApiBody,
) -> Result<Response<ApiBody>> {
    let mut builder = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, content_length.to_string());
    if let Some(content_range) = content_range {
        builder = builder.header(CONTENT_RANGE, content_range);
    }
    let response = builder.body(body).map_err(|error| {
        PlatformError::unavailable("failed to build object response").with_detail(error.to_string())
    })?;
    with_etag(response, format!("\"{digest}\""))
}

fn object_response(
    status: StatusCode,
    digest: &str,
    object_size: u64,
    range: Option<ObjectByteRange>,
    body: ApiBody,
) -> Result<Response<ApiBody>> {
    object_download_response(
        status,
        digest,
        range.map_or(object_size, ObjectByteRange::len),
        range.map(|range| {
            format!(
                "bytes {}-{}/{}",
                range.start, range.end_inclusive, object_size
            )
        }),
        body,
    )
}

fn object_range_not_satisfiable_response(
    digest: &str,
    object_size: u64,
) -> Result<Response<ApiBody>> {
    object_download_response(
        StatusCode::RANGE_NOT_SATISFIABLE,
        digest,
        0,
        Some(format!("bytes */{object_size}")),
        empty_body(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;

    use bytes::Bytes;
    use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG};
    use http::{HeaderValue, Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use serde::Deserialize;
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Barrier;
    use uhost_api::{ApiBody, error_response};
    use uhost_core::{ErrorCode, PlatformError, RequestContext, sha256_hex};
    use uhost_runtime::HttpService;
    use uhost_store::workflow::WorkflowStepEffectExecution;
    use uhost_store::{WorkflowPhase, WorkflowStepState};

    use super::{
        ArchiveAccessState, ArchiveRecord, ArchiveRehydrateJobRecord, ArchiveRehydrateJobState,
        ArchiveRehydratePriority, BucketRecord, CreateArchiveRehydrateJobRequest,
        CreateArchiveRequest, CreateBucketRequest, CreateDurabilityTierRequest,
        CreateFileShareRequest, CreateStorageClassRequest, CreateUploadRequest,
        CreateVolumeRequest, CreateVolumeRestoreActionRequest,
        DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES, DEFAULT_VOLUME_SNAPSHOT_RETENTION,
        DurabilityTierRecord, FileShareProtocol, FileShareRecord,
        LegacyVolumeRestoreApplyLedgerRecord, StorageClassRecord, StorageFailureDomainScope,
        StorageMedium, StorageResourceKind, StorageService, StorageSummaryResponse, UploadSession,
        VOLUME_RECOVERY_POINT_ACTION_KIND, VOLUME_RESTORE_ACTION_KIND,
        VOLUME_RESTORE_APPLY_EFFECT_KIND, VOLUME_RESTORE_FINAL_STEP_INDEX,
        VOLUME_RESTORE_WORKFLOW_KIND, VOLUME_SNAPSHOT_FINAL_STEP_INDEX,
        VOLUME_SNAPSHOT_WORKFLOW_KIND, VolumeRecord, VolumeRecoveryPointTrigger,
        VolumeRestoreActionState, VolumeRestoreApplyLedgerRecord, VolumeSnapshotPolicyState,
        default_storage_binding, normalize_object_key, workflow_step_state,
    };
    use uhost_types::{
        ArchiveId, BucketId, FileShareId, OwnershipScope, PrincipalIdentity, PrincipalKind,
        RehydrateJobId, ResourceLifecycleState, ResourceMetadata, UploadId, VolumeId,
    };

    #[derive(Debug, Deserialize)]
    struct ErrorEnvelope {
        error: PlatformError,
    }

    fn metadata_with_offset(owner_id: &str, offset_seconds: i64) -> ResourceMetadata {
        let created_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(offset_seconds);
        ResourceMetadata {
            created_at,
            updated_at: created_at,
            lifecycle: ResourceLifecycleState::Pending,
            ownership_scope: OwnershipScope::Project,
            owner_id: Some(owner_id.to_owned()),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            deleted_at: None,
            etag: format!("etag-{owner_id}"),
        }
    }

    fn operator_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::Operator,
                "operator:test",
            ))
    }

    fn workload_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(PrincipalKind::Workload, "svc:test"))
    }

    fn request_context() -> RequestContext {
        RequestContext::new().unwrap_or_else(|error| panic!("{error}"))
    }

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

    async fn dispatch_request(
        service: &StorageService,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> http::Response<ApiBody> {
        dispatch_request_with_context(service, method, uri, body, request_context()).await
    }

    async fn dispatch_request_with_context(
        service: &StorageService,
        method: &str,
        uri: &str,
        body: Option<&str>,
        context: RequestContext,
    ) -> http::Response<ApiBody> {
        match service
            .handle(service_request(method, uri, body), context)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => panic!("route {method} {uri} was not handled"),
            Err(error) => error_response(&error),
        }
    }

    async fn parse_error_response(
        response: http::Response<ApiBody>,
    ) -> (StatusCode, PlatformError) {
        let status = response.status();
        let envelope: ErrorEnvelope = parse_api_body(response).await;
        (status, envelope.error)
    }

    async fn assert_error_envelope_preserves_correlation_id(
        service: &StorageService,
        method: &str,
        uri: &str,
        body: Option<&str>,
        context: RequestContext,
        expected_status: StatusCode,
        expected_code: ErrorCode,
        expected_message: &str,
        expected_detail_substring: Option<&str>,
    ) {
        let correlation_id = context.correlation_id.clone();
        let (status, error) = parse_error_response(
            dispatch_request_with_context(service, method, uri, body, context).await,
        )
        .await;
        assert_eq!(status, expected_status);
        assert_eq!(error.code, expected_code);
        assert_eq!(error.message, expected_message);
        match expected_detail_substring {
            Some(expected_detail_substring) => assert!(
                error
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains(expected_detail_substring))
            ),
            None => assert_eq!(error.detail, None),
        }
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );
    }

    async fn seed_object(service: &StorageService, object_key: &str, body: Bytes) -> String {
        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("range-test"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let upload: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: object_key.to_owned(),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        service
            .upload_part(upload.id.as_str(), "1", body)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .complete_upload(upload.id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .and_then(|stored| stored.value.object_digest)
            .unwrap_or_else(|| panic!("missing object digest"))
    }

    #[tokio::test]
    async fn fetch_object_supports_byte_ranges_and_etags() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = seed_object(
            &service,
            "objects/range.txt",
            Bytes::from_static(b"hello world"),
        )
        .await;

        let range_header = HeaderValue::from_static("bytes=6-10");
        let response = service
            .fetch_object(&digest, Some(&range_header), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::PARTIAL_CONTENT);
        let expected_etag = format!("\"{digest}\"");
        assert_eq!(
            response
                .headers()
                .get(ACCEPT_RANGES)
                .and_then(|value| value.to_str().ok()),
            Some("bytes")
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes 6-10/11")
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(
            response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(expected_etag.as_str())
        );

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        assert_eq!(body.as_ref(), b"world");
    }

    #[tokio::test]
    async fn fetch_object_returns_416_for_unsatisfiable_ranges() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = seed_object(
            &service,
            "objects/too-far.txt",
            Bytes::from_static(b"hello world"),
        )
        .await;

        let range_header = HeaderValue::from_static("bytes=99-100");
        let response = service
            .fetch_object(&digest, Some(&range_header), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes */11")
        );
        let expected_etag = format!("\"{digest}\"");
        assert_eq!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
        assert_eq!(
            response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(expected_etag.as_str())
        );

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        assert!(body.is_empty(), "416 responses should not include a body");
    }

    #[tokio::test]
    async fn http_object_download_reports_storage_corruption_for_integrity_sidecar_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = seed_object(
            &service,
            "objects/corrupt-download.txt",
            Bytes::from_static(b"hello world"),
        )
        .await;
        let sidecar_path = temp
            .path()
            .join("storage")
            .join("blobs")
            .join(&digest[..2])
            .join(&digest)
            .with_extension("integrity.json");
        let corrupted_sidecar = serde_json::to_vec(&serde_json::json!({
            "algorithm": "sha256",
            "digest": digest.as_str(),
            "size": 99_u64,
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        fs::write(&sidecar_path, corrupted_sidecar).unwrap_or_else(|error| panic!("{error}"));

        let context = request_context();
        let correlation_id = context.correlation_id.clone();
        let response = dispatch_request_with_context(
            &service,
            "GET",
            format!("/storage/objects/{digest}").as_str(),
            None,
            context,
        )
        .await;
        let (status, error) = parse_error_response(response).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, ErrorCode::StorageCorruption);
        assert_eq!(error.message, "object integrity verification failed");
        assert!(
            error.detail.as_deref().is_some_and(|detail| {
                detail.contains("blob integrity sidecar mismatch")
                    && detail.contains(format!("digest={digest}").as_str())
            }),
            "expected digest and sidecar mismatch detail, got {:?}",
            error.detail
        );
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn http_complete_upload_reports_storage_corruption_for_integrity_sidecar_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let upload_id = {
            let bucket: BucketRecord = parse_api_body(
                service
                    .create_bucket(CreateBucketRequest {
                        name: String::from("integrity-failure-owner"),
                        owner_id: String::from("owner-1"),
                        storage_class_id: None,
                        durability_tier_id: None,
                    })
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
            let upload: UploadSession = parse_api_body(
                service
                    .create_upload(CreateUploadRequest {
                        bucket_id: bucket.id.to_string(),
                        object_key: String::from("objects/corrupt-sidecar.txt"),
                    })
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
            let part_payload: serde_json::Value = parse_api_body(
                service
                    .upload_part(upload.id.as_str(), "1", Bytes::from_static(b"hello world"))
                    .await
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .await;
            let part_digest = part_payload["digest"]
                .as_str()
                .unwrap_or_else(|| panic!("missing part digest"))
                .to_owned();
            let sidecar_path = temp
                .path()
                .join("storage")
                .join("blobs")
                .join(&part_digest[..2])
                .join(&part_digest)
                .with_extension("integrity.json");
            let corrupted_sidecar = serde_json::to_vec(&serde_json::json!({
                "algorithm": "sha256",
                "digest": part_digest.as_str(),
                "size": 999_u64,
            }))
            .unwrap_or_else(|error| panic!("{error}"));
            fs::write(&sidecar_path, corrupted_sidecar).unwrap_or_else(|error| panic!("{error}"));
            upload.id
        };

        let context = request_context();
        let correlation_id = context.correlation_id.clone();
        let response = dispatch_request_with_context(
            &service,
            "POST",
            format!("/storage/uploads/{upload_id}/complete").as_str(),
            None,
            context,
        )
        .await;
        let (status, error) = parse_error_response(response).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, ErrorCode::StorageCorruption);
        assert_eq!(error.message, "failed to assemble upload object");
        assert!(
            error.detail.as_deref().is_some_and(|detail| {
                detail.contains(format!("upload_id={upload_id}").as_str())
                    && detail.contains("blob integrity sidecar mismatch")
            }),
            "expected upload id and sidecar mismatch detail, got {:?}",
            error.detail
        );
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn http_routes_create_and_list_file_shares() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .handle(
                service_request(
                    "POST",
                    "/storage/file-shares",
                    Some(
                        r#"{"name":"route-share","capacity_gb":64,"protocol":"smb","mounted_to":"instance-route"}"#,
                    ),
                ),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("file-share create route was not handled"));
        assert_eq!(response.status(), StatusCode::CREATED);
        let created: FileShareRecord = parse_api_body(response).await;
        assert_eq!(created.name, "route-share");
        assert_eq!(created.capacity_gb, 64);
        assert_eq!(created.protocol, FileShareProtocol::Smb);
        assert_eq!(created.mounted_to.as_deref(), Some("instance-route"));

        let response = service
            .handle(
                service_request("GET", "/storage/file-shares", None),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("file-share list route was not handled"));
        assert_eq!(response.status(), StatusCode::OK);
        let listed: Vec<FileShareRecord> = parse_api_body(response).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);
        assert_eq!(listed[0].protocol, FileShareProtocol::Smb);
        assert_eq!(listed[0].mounted_to.as_deref(), Some("instance-route"));
    }

    #[tokio::test]
    async fn http_routes_create_list_and_rehydrate_archives() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .handle(
                service_request(
                    "POST",
                    "/storage/archives",
                    Some(r#"{"name":"route-archive","size_bytes":16384}"#),
                ),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("archive create route was not handled"));
        assert_eq!(response.status(), StatusCode::CREATED);
        let created_archive: ArchiveRecord = parse_api_body(response).await;
        assert_eq!(created_archive.name, "route-archive");
        assert_eq!(created_archive.size_bytes, 16_384);
        assert_eq!(created_archive.access_state, ArchiveAccessState::Archived);

        let response = service
            .handle(
                service_request(
                    "POST",
                    "/storage/archive-rehydrate-jobs",
                    Some(
                        format!(
                            r#"{{"archive_id":"{}","priority":"expedited","restore_window_hours":36,"reason":"route restore"}}"#,
                            created_archive.id
                        )
                        .as_str(),
                    ),
                ),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("archive rehydrate create route was not handled"));
        assert_eq!(response.status(), StatusCode::CREATED);
        let rehydrate_job: ArchiveRehydrateJobRecord = parse_api_body(response).await;
        assert_eq!(rehydrate_job.archive_id, created_archive.id);
        assert_eq!(rehydrate_job.priority, ArchiveRehydratePriority::Expedited);
        assert_eq!(rehydrate_job.restore_window_hours, 36);
        assert_eq!(rehydrate_job.reason.as_deref(), Some("route restore"));

        let response = service
            .handle(
                service_request("GET", "/storage/archives", None),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("archive list route was not handled"));
        assert_eq!(response.status(), StatusCode::OK);
        let archives: Vec<ArchiveRecord> = parse_api_body(response).await;
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0].id, created_archive.id);
        assert_eq!(archives[0].access_state, ArchiveAccessState::Available);
        assert_eq!(
            archives[0].last_rehydrate_job_id,
            Some(rehydrate_job.id.clone())
        );
        assert_eq!(
            archives[0].rehydrated_until,
            Some(rehydrate_job.rehydrated_until)
        );

        let response = service
            .handle(
                service_request("GET", "/storage/archive-rehydrate-jobs", None),
                request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("archive rehydrate list route was not handled"));
        assert_eq!(response.status(), StatusCode::OK);
        let jobs: Vec<ArchiveRehydrateJobRecord> = parse_api_body(response).await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, rehydrate_job.id);
        assert_eq!(jobs[0].archive_id, created_archive.id);
        assert_eq!(jobs[0].state, ArchiveRehydrateJobState::Completed);
        assert_eq!(jobs[0].reason.as_deref(), Some("route restore"));
    }

    #[tokio::test]
    async fn http_routes_invalid_storage_mutations_return_full_error_envelopes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/storage-classes",
            Some(r#"{"name":"standard","medium":"object","supported_resource_kinds":"oops"}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "failed to decode request json",
            Some("invalid type"),
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/durability-tiers",
            Some(
                r#"{"name":"regional","minimum_replica_count":0,"failure_domain_scope":"region","supported_resource_kinds":["bucket"]}"#,
            ),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "minimum_replica_count must be greater than zero",
            None,
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/buckets",
            Some(r#"{"name":"broken-bucket","owner_id":1}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "failed to decode request json",
            Some("invalid type"),
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/file-shares",
            Some(r#"{"name":"broken-share","capacity_gb":"oops"}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "failed to decode request json",
            Some("invalid type"),
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/volumes",
            Some(r#"{"name":"bad-volume","size_gb":0}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "size_gb must be greater than zero",
            None,
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/archives",
            Some(r#"{"name":"bad-archive","size_bytes":0}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "size_bytes must be greater than zero",
            None,
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/archive-rehydrate-jobs",
            Some(r#"{"archive_id":"bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa","restore_window_hours":1}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "invalid archive_id",
            Some("expected id prefix `arc`"),
        )
        .await;

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/uploads",
            Some(r#"{"bucket_id":1,"object_key":"objects/bad.txt"}"#),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "failed to decode request json",
            Some("invalid type"),
        )
        .await;

        let bucket: BucketRecord = parse_api_body(
            service
                .create_bucket(CreateBucketRequest {
                    name: String::from("mutation-audit"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let upload: UploadSession = parse_api_body(
            service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/mutation-audit.txt"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let upload_part_uri = format!("/storage/uploads/{}/parts/0", upload.id);

        assert_error_envelope_preserves_correlation_id(
            &service,
            "PUT",
            upload_part_uri.as_str(),
            Some("bad"),
            request_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "part number must be greater than zero",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn operator_storage_restore_action_invalid_volume_ids_preserve_correlation_id() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_error_envelope_preserves_correlation_id(
            &service,
            "POST",
            "/storage/volumes/bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa/restore-actions",
            Some(r#"{"reason":"operator rewind"}"#),
            operator_context(),
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "invalid volume_id",
            Some("expected id prefix `vol`"),
        )
        .await;
    }

    #[tokio::test]
    async fn http_routes_summary_reflects_file_share_archive_and_rehydrate_mutations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary: StorageSummaryResponse =
            parse_api_body(dispatch_request(&service, "GET", "/storage/summary", None).await).await;
        assert_eq!(summary.file_share_count, 0);
        assert_eq!(summary.archive_count, 0);
        assert_eq!(summary.archive_rehydrate_job_count, 0);

        let _file_share: FileShareRecord = parse_api_body(
            dispatch_request(
                &service,
                "POST",
                "/storage/file-shares",
                Some(r#"{"name":"summary-share","capacity_gb":32,"protocol":"nfs"}"#),
            )
            .await,
        )
        .await;
        let summary: StorageSummaryResponse =
            parse_api_body(dispatch_request(&service, "GET", "/storage/summary", None).await).await;
        assert_eq!(summary.file_share_count, 1);
        assert_eq!(summary.archive_count, 0);
        assert_eq!(summary.archive_rehydrate_job_count, 0);

        let archive: ArchiveRecord = parse_api_body(
            dispatch_request(
                &service,
                "POST",
                "/storage/archives",
                Some(r#"{"name":"summary-archive","size_bytes":8192}"#),
            )
            .await,
        )
        .await;
        let summary: StorageSummaryResponse =
            parse_api_body(dispatch_request(&service, "GET", "/storage/summary", None).await).await;
        assert_eq!(summary.file_share_count, 1);
        assert_eq!(summary.archive_count, 1);
        assert_eq!(summary.archive_rehydrate_job_count, 0);

        let _rehydrate_job: ArchiveRehydrateJobRecord = parse_api_body(
            dispatch_request(
                &service,
                "POST",
                "/storage/archive-rehydrate-jobs",
                Some(
                    format!(
                        r#"{{"archive_id":"{}","priority":"standard","restore_window_hours":24,"reason":"summary refresh"}}"#,
                        archive.id
                    )
                    .as_str(),
                ),
            )
            .await,
        )
        .await;
        let summary: StorageSummaryResponse =
            parse_api_body(dispatch_request(&service, "GET", "/storage/summary", None).await).await;
        assert_eq!(summary.file_share_count, 1);
        assert_eq!(summary.archive_count, 1);
        assert_eq!(summary.archive_rehydrate_job_count, 1);
    }

    #[tokio::test]
    async fn bucket_and_volume_list_excludes_soft_deleted_and_is_sorted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket_a = BucketId::parse("bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let bucket_b = BucketId::parse("bkt_bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        service
            .buckets
            .create(
                bucket_b.as_str(),
                BucketRecord {
                    id: bucket_b.clone(),
                    name: String::from("bucket-b"),
                    owner_id: String::from("owner-b"),
                    storage_binding: None,
                    metadata: metadata_with_offset(bucket_b.as_str(), 2),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .buckets
            .create(
                bucket_a.as_str(),
                BucketRecord {
                    id: bucket_a.clone(),
                    name: String::from("bucket-a"),
                    owner_id: String::from("owner-a"),
                    storage_binding: None,
                    metadata: metadata_with_offset(bucket_a.as_str(), 1),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .buckets
            .soft_delete(bucket_b.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let values = service
            .list_active_buckets()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].id, bucket_a);

        let volume_a = VolumeId::parse("vol_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let volume_b = VolumeId::parse("vol_bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        service
            .volumes
            .create(
                volume_b.as_str(),
                VolumeRecord {
                    id: volume_b.clone(),
                    name: String::from("volume-b"),
                    size_gb: 20,
                    attached_to: None,
                    storage_binding: None,
                    metadata: metadata_with_offset(volume_b.as_str(), 4),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .volumes
            .create(
                volume_a.as_str(),
                VolumeRecord {
                    id: volume_a.clone(),
                    name: String::from("volume-a"),
                    size_gb: 10,
                    attached_to: None,
                    storage_binding: None,
                    metadata: metadata_with_offset(volume_a.as_str(), 3),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .volumes
            .soft_delete(volume_b.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let values = service
            .list_active_volumes()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].id, volume_a);

        let file_share_a = FileShareId::parse("fsh_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let file_share_b = FileShareId::parse("fsh_bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        service
            .file_shares
            .create(
                file_share_b.as_str(),
                FileShareRecord {
                    id: file_share_b.clone(),
                    name: String::from("share-b"),
                    capacity_gb: 200,
                    protocol: FileShareProtocol::Smb,
                    mounted_to: None,
                    metadata: metadata_with_offset(file_share_b.as_str(), 6),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .file_shares
            .create(
                file_share_a.as_str(),
                FileShareRecord {
                    id: file_share_a.clone(),
                    name: String::from("share-a"),
                    capacity_gb: 100,
                    protocol: FileShareProtocol::Nfs,
                    mounted_to: Some(String::from("instance-a")),
                    metadata: metadata_with_offset(file_share_a.as_str(), 5),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .file_shares
            .soft_delete(file_share_b.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let values = service
            .list_active_file_shares()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].id, file_share_a);

        let archive_a = ArchiveId::parse("arc_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let archive_b = ArchiveId::parse("arc_bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        service
            .archives
            .create(
                archive_b.as_str(),
                ArchiveRecord {
                    id: archive_b.clone(),
                    name: String::from("archive-b"),
                    size_bytes: 2_048,
                    access_state: ArchiveAccessState::Archived,
                    rehydrated_until: None,
                    last_rehydrate_job_id: None,
                    metadata: metadata_with_offset(archive_b.as_str(), 8),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .archives
            .create(
                archive_a.as_str(),
                ArchiveRecord {
                    id: archive_a.clone(),
                    name: String::from("archive-a"),
                    size_bytes: 1_024,
                    access_state: ArchiveAccessState::Available,
                    rehydrated_until: Some(OffsetDateTime::UNIX_EPOCH + Duration::hours(24)),
                    last_rehydrate_job_id: None,
                    metadata: metadata_with_offset(archive_a.as_str(), 7),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .archives
            .soft_delete(archive_b.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let values = service
            .list_active_archives()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].id, archive_a);

        let job_a = RehydrateJobId::parse("rhj_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let job_b = RehydrateJobId::parse("rhj_bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let job_a_metadata = metadata_with_offset(job_a.as_str(), 9);
        let job_b_metadata = metadata_with_offset(job_b.as_str(), 10);
        service
            .archive_rehydrate_jobs
            .create(
                job_b.as_str(),
                ArchiveRehydrateJobRecord {
                    id: job_b.clone(),
                    archive_id: archive_a.clone(),
                    priority: ArchiveRehydratePriority::Bulk,
                    restore_window_hours: 24,
                    state: ArchiveRehydrateJobState::Completed,
                    requested_at: job_b_metadata.created_at,
                    started_at: Some(job_b_metadata.created_at),
                    completed_at: Some(job_b_metadata.created_at),
                    rehydrated_until: job_b_metadata.created_at + Duration::hours(24),
                    reason: Some(String::from("archival test")),
                    metadata: job_b_metadata,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .archive_rehydrate_jobs
            .create(
                job_a.as_str(),
                ArchiveRehydrateJobRecord {
                    id: job_a.clone(),
                    archive_id: archive_a.clone(),
                    priority: ArchiveRehydratePriority::Standard,
                    restore_window_hours: 12,
                    state: ArchiveRehydrateJobState::Completed,
                    requested_at: job_a_metadata.created_at,
                    started_at: Some(job_a_metadata.created_at),
                    completed_at: Some(job_a_metadata.created_at),
                    rehydrated_until: job_a_metadata.created_at + Duration::hours(12),
                    reason: None,
                    metadata: job_a_metadata,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .archive_rehydrate_jobs
            .soft_delete(job_b.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let values = service
            .list_active_archive_rehydrate_jobs()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].id, job_a);
    }

    #[tokio::test]
    async fn create_endpoints_validate_user_input() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket_error = service
            .create_bucket(CreateBucketRequest {
                name: String::from("   "),
                owner_id: String::from("owner-1"),
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .expect_err("expected empty bucket name to fail");
        assert!(bucket_error.to_string().contains("bucket name"));

        let volume_error = service
            .create_volume(CreateVolumeRequest {
                name: String::from("volume-\u{0007}"),
                size_gb: 1,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .expect_err("expected control characters to fail");
        assert!(volume_error.to_string().contains("volume name"));

        let zero_volume_error = service
            .create_volume(CreateVolumeRequest {
                name: String::from("data"),
                size_gb: 0,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .expect_err("expected zero-sized volume to fail");
        assert!(zero_volume_error.to_string().contains("size_gb"));

        let file_share_error = service
            .create_file_share(CreateFileShareRequest {
                name: String::from("share"),
                capacity_gb: 0,
                protocol: None,
                mounted_to: None,
            })
            .await
            .expect_err("expected zero-sized file share to fail");
        assert!(file_share_error.to_string().contains("capacity_gb"));

        let archive_error = service
            .create_archive(CreateArchiveRequest {
                name: String::from("archive"),
                size_bytes: 0,
            })
            .await
            .expect_err("expected zero-sized archive to fail");
        assert!(archive_error.to_string().contains("size_bytes"));

        let key_error = normalize_object_key("  logs/archive.tar  ");
        assert_eq!(
            key_error.unwrap_or_else(|error| panic!("{error}")),
            "logs/archive.tar"
        );

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("deleted"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let stored_bucket = service
            .buckets
            .get(bucket.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing bucket"));
        service
            .buckets
            .soft_delete(bucket.id.as_str(), Some(stored_bucket.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let upload_error = service
            .create_upload(CreateUploadRequest {
                bucket_id: bucket.id.to_string(),
                object_key: String::from("objects/deleted.txt"),
            })
            .await
            .expect_err("soft-deleted bucket should reject uploads");
        assert!(upload_error.to_string().contains("bucket has been deleted"));

        let archive: ArchiveRecord = {
            let response = service
                .create_archive(CreateArchiveRequest {
                    name: String::from("frozen"),
                    size_bytes: 4_096,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let rehydrate_id_error = service
            .create_archive_rehydrate_job(CreateArchiveRehydrateJobRequest {
                archive_id: String::from("archive-invalid"),
                priority: None,
                restore_window_hours: None,
                reason: None,
            })
            .await
            .expect_err("expected invalid archive id to fail");
        assert!(rehydrate_id_error.to_string().contains("archive_id"));

        let rehydrate_window_error = service
            .create_archive_rehydrate_job(CreateArchiveRehydrateJobRequest {
                archive_id: archive.id.to_string(),
                priority: None,
                restore_window_hours: Some(0),
                reason: None,
            })
            .await
            .expect_err("expected zero restore window to fail");
        assert!(
            rehydrate_window_error
                .to_string()
                .contains("restore_window_hours")
        );

        let rehydrate_reason_error = service
            .create_archive_rehydrate_job(CreateArchiveRehydrateJobRequest {
                archive_id: archive.id.to_string(),
                priority: None,
                restore_window_hours: Some(1),
                reason: Some(String::from("   ")),
            })
            .await
            .expect_err("expected blank rehydrate reason to fail");
        assert!(
            rehydrate_reason_error
                .to_string()
                .contains("rehydrate reason")
        );
    }

    #[tokio::test]
    async fn open_bootstraps_builtin_storage_taxonomy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let storage_classes = service
            .list_active_storage_classes()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(storage_classes.iter().any(|record| {
            record.name == "object-standard"
                && record.medium == StorageMedium::Object
                && record.supported_resource_kinds == vec![StorageResourceKind::Bucket]
        }));
        assert!(storage_classes.iter().any(|record| {
            record.name == "block-standard"
                && record.medium == StorageMedium::Block
                && record.supported_resource_kinds
                    == vec![StorageResourceKind::Volume, StorageResourceKind::Database]
        }));

        let durability_tiers = service
            .list_active_durability_tiers()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(durability_tiers.iter().any(|record| {
            record.name == "object-regional"
                && record.minimum_replica_count == 2
                && record.failure_domain_scope == StorageFailureDomainScope::Region
        }));
        assert!(durability_tiers.iter().any(|record| {
            record.name == "block-replicated"
                && record.minimum_replica_count == 3
                && record.failure_domain_scope == StorageFailureDomainScope::Region
        }));
    }

    #[tokio::test]
    async fn create_volume_accepts_explicit_storage_binding() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let custom_class: StorageClassRecord = {
            let response = service
                .create_storage_class(CreateStorageClassRequest {
                    name: String::from("high-iops-block"),
                    medium: StorageMedium::Block,
                    supported_resource_kinds: vec![StorageResourceKind::Volume],
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let custom_tier: DurabilityTierRecord = {
            let response = service
                .create_durability_tier(CreateDurabilityTierRequest {
                    name: String::from("dual-cell"),
                    minimum_replica_count: 2,
                    failure_domain_scope: StorageFailureDomainScope::Cell,
                    supported_resource_kinds: vec![StorageResourceKind::Volume],
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("custom-bound-volume"),
                size_gb: 20,
                storage_class_id: Some(custom_class.id.to_string()),
                durability_tier_id: Some(custom_tier.id.to_string()),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let binding = volume
            .storage_binding
            .unwrap_or_else(|| panic!("missing explicit storage binding"));
        assert_eq!(binding.storage_class_id, custom_class.id);
        assert_eq!(binding.durability_tier_id, custom_tier.id);
    }

    #[tokio::test]
    async fn create_volume_bootstraps_recovery_point_and_completes_snapshot_workflow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("durable-volume"),
                size_gb: 64,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let policy = service
            .volume_snapshot_policies
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing snapshot policy"));
        assert_eq!(policy.value.volume_id, volume.id);
        assert_eq!(policy.value.state, VolumeSnapshotPolicyState::Active);
        assert_eq!(
            policy.value.interval_minutes,
            DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES
        );
        assert_eq!(
            policy.value.retention_snapshots,
            DEFAULT_VOLUME_SNAPSHOT_RETENTION
        );
        assert_eq!(
            policy.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );
        assert_eq!(
            policy
                .value
                .metadata
                .annotations
                .get("storage.lifecycle.workflow_kind")
                .map(String::as_str),
            Some(VOLUME_SNAPSHOT_WORKFLOW_KIND)
        );

        let workflow = service
            .volume_snapshot_workflows
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing snapshot workflow"));
        assert_eq!(workflow.value.workflow_kind, VOLUME_SNAPSHOT_WORKFLOW_KIND);
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            workflow.value.current_step_index,
            Some(VOLUME_SNAPSHOT_FINAL_STEP_INDEX)
        );
        assert_eq!(workflow.value.steps.len(), 3);
        assert!(
            workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let recovery_point = service
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovery point"));
        assert_eq!(recovery_point.value.volume_id, volume.id);
        assert_eq!(
            recovery_point.value.capture_trigger,
            VolumeRecoveryPointTrigger::PolicyActivation
        );
        assert_eq!(recovery_point.value.execution_count, 1);
        assert_eq!(
            recovery_point.value.interval_minutes,
            DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES
        );
        assert_eq!(
            recovery_point.value.retention_snapshots,
            DEFAULT_VOLUME_SNAPSHOT_RETENTION
        );
        assert_eq!(
            recovery_point.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );
        assert_eq!(
            recovery_point
                .value
                .metadata
                .annotations
                .get("storage.lifecycle.action_kind")
                .map(String::as_str),
            Some(VOLUME_RECOVERY_POINT_ACTION_KIND)
        );
        assert!(
            recovery_point.value.next_snapshot_after >= recovery_point.value.latest_snapshot_at
        );

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            reopened
                .volume_snapshot_policies
                .get(volume.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        assert!(
            reopened
                .volume_snapshot_workflows
                .get(volume.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        assert!(
            reopened
                .volume_recovery_points
                .get(volume.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
    }

    #[tokio::test]
    async fn ensure_attached_volume_reuses_existing_binding_and_ready_recovery_point() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .ensure_attached_volume("dbs_attached", "database-dbs_attached", 32, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.attached_to.as_deref(), Some("dbs_attached"));
        assert_eq!(
            first.storage_binding,
            Some(default_storage_binding(StorageResourceKind::Volume))
        );

        let initial_recovery_point = service
            .describe_ready_volume_recovery_point(&first.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing attached recovery point"));

        let second = service
            .ensure_attached_volume("dbs_attached", "database-dbs_attached", 32, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.id, first.id);
        assert_eq!(second.storage_binding, first.storage_binding);

        let repeated_recovery_point = service
            .describe_ready_volume_recovery_point(&second.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing repeated recovery point"));
        assert_eq!(
            repeated_recovery_point.version,
            initial_recovery_point.version
        );
        assert_eq!(
            repeated_recovery_point.execution_count,
            initial_recovery_point.execution_count
        );
        assert_eq!(repeated_recovery_point.etag, initial_recovery_point.etag);
    }

    #[tokio::test]
    async fn recovery_point_repair_is_versioned_and_preserves_completed_workflow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service_a = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let service_b = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service_a
            .create_volume(CreateVolumeRequest {
                name: String::from("protected-volume"),
                size_gb: 32,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let initial_workflow = service_a
            .volume_snapshot_workflows
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial workflow"));
        let initial_recovery_point = service_a
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        service_b
            .volume_recovery_points
            .soft_delete(volume.id.as_str(), Some(initial_recovery_point.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service_b
            .ensure_volume_snapshot_lifecycle(&volume)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let activated_workflow = service_b
            .volume_snapshot_workflows
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing activated workflow"));
        assert_eq!(activated_workflow.version, initial_workflow.version);
        assert_eq!(activated_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            activated_workflow.value.current_step_index,
            Some(VOLUME_SNAPSHOT_FINAL_STEP_INDEX)
        );
        assert!(
            activated_workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let repaired_recovery_point = service_b
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing repaired recovery point"));
        assert!(repaired_recovery_point.version > initial_recovery_point.version);
        assert_eq!(
            repaired_recovery_point.value.execution_count,
            initial_recovery_point.value.execution_count
        );
        assert_eq!(
            repaired_recovery_point.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );

        let stale = service_a
            .volume_recovery_points
            .upsert(
                volume.id.as_str(),
                initial_recovery_point.value,
                Some(initial_recovery_point.version),
            )
            .await
            .expect_err("stale recovery point update should fail");
        assert_eq!(stale.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn open_reconciles_legacy_volumes_without_changing_listing_behavior() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let legacy = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let volume_id = VolumeId::parse("vol_cccccccccccccccccccccccccc")
            .unwrap_or_else(|error| panic!("{error}"));
        legacy
            .volumes
            .create(
                volume_id.as_str(),
                VolumeRecord {
                    id: volume_id.clone(),
                    name: String::from("legacy-volume"),
                    size_gb: 8,
                    attached_to: None,
                    storage_binding: None,
                    metadata: metadata_with_offset(volume_id.as_str(), 5),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciled = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let listed = reconciled
            .list_active_volumes()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, volume_id);
        assert_eq!(
            listed[0].storage_binding,
            Some(default_storage_binding(StorageResourceKind::Volume))
        );

        let policy = reconciled
            .volume_snapshot_policies
            .get(volume_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled snapshot policy"));
        assert_eq!(policy.value.state, VolumeSnapshotPolicyState::Active);
        assert_eq!(
            policy.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );

        let workflow = reconciled
            .volume_snapshot_workflows
            .get(volume_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled snapshot workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            workflow.value.current_step_index,
            Some(VOLUME_SNAPSHOT_FINAL_STEP_INDEX)
        );
        assert!(
            workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let recovery_point = reconciled
            .volume_recovery_points
            .get(volume_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled recovery point"));
        assert_eq!(
            recovery_point.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );
    }

    #[tokio::test]
    async fn restore_volume_binds_to_selected_recovery_point_and_persists_execution_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("restore-source"),
                size_gb: 48,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let initial_recovery_point = service
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovery point"));

        let started = service
            .start_volume_restore(&volume.id, Some(String::from("operator drill")))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow_id = started.value.id.clone();
        assert_eq!(started.value.workflow_kind, VOLUME_RESTORE_WORKFLOW_KIND);
        assert_eq!(started.value.phase, WorkflowPhase::Pending);
        assert_eq!(started.value.current_step_index, None);
        assert_eq!(started.value.state.volume_id, volume.id);
        assert_eq!(
            started.value.state.recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            started.value.state.recovery_point_execution_count,
            initial_recovery_point.value.execution_count
        );
        assert_eq!(
            started.value.state.recovery_point_etag,
            initial_recovery_point.value.metadata.etag
        );
        assert_eq!(
            started.value.state.recovery_point_captured_at,
            initial_recovery_point.value.latest_snapshot_at
        );

        let pending_action = service
            .volume_restore_actions
            .get(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing pending restore action"));
        assert_eq!(
            pending_action.value.state,
            VolumeRestoreActionState::Pending
        );
        assert_eq!(pending_action.value.workflow_id, workflow_id);
        assert_eq!(
            pending_action.value.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            pending_action
                .value
                .metadata
                .annotations
                .get("storage.lifecycle.action_kind")
                .map(String::as_str),
            Some(VOLUME_RESTORE_ACTION_KIND)
        );

        let mut updated_recovery_point = initial_recovery_point.value.clone();
        updated_recovery_point.execution_count += 1;
        updated_recovery_point.latest_snapshot_at += Duration::minutes(30);
        updated_recovery_point.next_snapshot_after = updated_recovery_point.latest_snapshot_at
            + Duration::minutes(i64::from(updated_recovery_point.interval_minutes));
        updated_recovery_point.metadata.touch(sha256_hex(
            format!(
                "{}:recovery-point:{}",
                volume.id.as_str(),
                updated_recovery_point.execution_count,
            )
            .as_bytes(),
        ));
        let updated_recovery_point = service
            .volume_recovery_points
            .upsert(
                volume.id.as_str(),
                updated_recovery_point,
                Some(initial_recovery_point.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(updated_recovery_point.version > initial_recovery_point.version);

        let action = service
            .execute_volume_restore(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(action.state, VolumeRestoreActionState::Completed);
        assert_eq!(action.workflow_kind, VOLUME_RESTORE_WORKFLOW_KIND);
        assert_eq!(
            action.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            action.source_recovery_point_execution_count,
            initial_recovery_point.value.execution_count
        );
        assert_eq!(
            action.source_recovery_point_etag,
            initial_recovery_point.value.metadata.etag
        );
        assert_eq!(
            action.source_recovery_point_captured_at,
            initial_recovery_point.value.latest_snapshot_at
        );
        assert_ne!(
            action.source_recovery_point_version,
            updated_recovery_point.version
        );

        let restored_workflow = service
            .load_volume_restore_workflow(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            restored_workflow.value.current_step_index,
            Some(VOLUME_RESTORE_FINAL_STEP_INDEX)
        );
        assert!(
            restored_workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_action = reopened
            .volume_restore_actions
            .get(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reopened restore action"));
        assert_eq!(
            reopened_action.value.state,
            VolumeRestoreActionState::Completed
        );
        assert_eq!(
            reopened_action.value.source_recovery_point_version,
            initial_recovery_point.version
        );
        let restored_volume = reopened
            .volumes
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored volume"));
        let expected_recovery_point_version = initial_recovery_point.version.to_string();
        assert_eq!(
            restored_volume.value.metadata.lifecycle,
            ResourceLifecycleState::Ready
        );
        assert_eq!(
            restored_volume
                .value
                .metadata
                .annotations
                .get("storage.restore.source_recovery_point_version")
                .map(String::as_str),
            Some(expected_recovery_point_version.as_str())
        );
    }

    #[tokio::test]
    async fn historical_recovery_point_lookup_and_restore_use_persisted_revision() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("restore-history"),
                size_gb: 32,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let initial_recovery_point = service
            .describe_ready_volume_recovery_point(&volume.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        let current_recovery_point = service
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current recovery point"));
        let mut updated_recovery_point = current_recovery_point.value.clone();
        updated_recovery_point.execution_count += 1;
        updated_recovery_point.latest_snapshot_at += Duration::minutes(30);
        updated_recovery_point.next_snapshot_after = updated_recovery_point.latest_snapshot_at
            + Duration::minutes(i64::from(updated_recovery_point.interval_minutes));
        updated_recovery_point.metadata.touch(sha256_hex(
            format!(
                "{}:recovery-point:{}",
                volume.id.as_str(),
                updated_recovery_point.execution_count,
            )
            .as_bytes(),
        ));
        let updated_recovery_point = service
            .volume_recovery_points
            .upsert(
                volume.id.as_str(),
                updated_recovery_point,
                Some(current_recovery_point.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let latest_recovery_point = service
            .describe_ready_volume_recovery_point(&volume.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing latest recovery point"));
        assert_eq!(
            latest_recovery_point.version,
            updated_recovery_point.version
        );
        assert_eq!(
            latest_recovery_point.etag,
            updated_recovery_point.value.metadata.etag
        );

        let historical_recovery_point = service
            .describe_volume_recovery_point(
                &volume.id,
                initial_recovery_point.version,
                Some(initial_recovery_point.etag.as_str()),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing historical recovery point"));
        assert_eq!(
            historical_recovery_point.version,
            initial_recovery_point.version
        );
        assert_eq!(historical_recovery_point.etag, initial_recovery_point.etag);
        assert_eq!(
            historical_recovery_point.execution_count,
            initial_recovery_point.execution_count
        );
        assert_ne!(
            historical_recovery_point.version,
            latest_recovery_point.version
        );

        let restore_action_id = service
            .restore_volume_from_selected_recovery_point(
                &volume.id,
                initial_recovery_point.version,
                Some(initial_recovery_point.etag.as_str()),
                Some(String::from("historical drill")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let action = service
            .describe_volume_restore_action(&restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restore action"));
        assert_eq!(
            action.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            action.source_recovery_point_etag,
            initial_recovery_point.etag
        );
        assert_ne!(
            action.source_recovery_point_version,
            latest_recovery_point.version
        );
        assert_ne!(
            action.source_recovery_point_etag,
            latest_recovery_point.etag
        );
    }

    #[tokio::test]
    async fn restore_workflow_progression_is_versioned_and_rejects_stale_updates() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service_a = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let service_b = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service_a
            .create_volume(CreateVolumeRequest {
                name: String::from("restore-versioned"),
                size_gb: 24,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let started = service_a
            .start_volume_restore(&volume.id, Some(String::from("operator initiated")))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow_id = started.value.id.clone();
        let pending_action = service_a
            .volume_restore_actions
            .get(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing pending action"));
        assert_eq!(
            pending_action.value.state,
            VolumeRestoreActionState::Pending
        );

        let completed_action = service_b
            .execute_volume_restore(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed_action.state, VolumeRestoreActionState::Completed);

        let completed_workflow = service_b
            .load_volume_restore_workflow(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(completed_workflow.version > started.version);
        assert_eq!(completed_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            completed_workflow.value.current_step_index,
            Some(VOLUME_RESTORE_FINAL_STEP_INDEX)
        );
        assert!(
            completed_workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let completed_action = service_b
            .volume_restore_actions
            .get(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing completed action"));
        assert!(completed_action.version > pending_action.version);
        assert_eq!(
            completed_action.value.state,
            VolumeRestoreActionState::Completed
        );
        assert!(completed_action.value.started_at.is_some());
        assert!(completed_action.value.completed_at.is_some());

        let stale_workflow = service_a
            .volume_restore_workflows
            .upsert(&workflow_id, started.value, Some(started.version))
            .await
            .expect_err("stale restore workflow update should fail");
        assert_eq!(stale_workflow.code, ErrorCode::Conflict);

        let stale_action = service_a
            .volume_restore_actions
            .upsert(
                &workflow_id,
                pending_action.value,
                Some(pending_action.version),
            )
            .await
            .expect_err("stale restore action update should fail");
        assert_eq!(stale_action.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn pending_restore_reconciliation_sets_due_attempt_and_heartbeats_claims() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("restore-reconcile"),
                size_gb: 16,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_volume_restore(&volume.id, Some(String::from("restart reconcile")))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.value.runner_claim, None);
        assert_eq!(started.value.next_attempt_at, None);

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first = reopened
            .load_volume_restore_workflow(started.value.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.value.phase, WorkflowPhase::Pending);
        let first_claim = first
            .value
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing restore reconciler claim"));
        assert_eq!(
            first_claim.runner_id,
            super::VOLUME_RESTORE_RECONCILER_RUNNER_ID
        );
        assert_eq!(
            first.value.next_attempt_at,
            Some(first_claim.last_heartbeat_at)
        );

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let reopened_again = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = reopened_again
            .load_volume_restore_workflow(started.value.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_claim = second
            .value
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing heartbeated restore claim"));
        assert_eq!(
            second_claim.runner_id,
            super::VOLUME_RESTORE_RECONCILER_RUNNER_ID
        );
        assert_eq!(second_claim.claimed_at, first_claim.claimed_at);
        assert_eq!(second_claim.fencing_token, first_claim.fencing_token);
        assert!(second_claim.last_heartbeat_at > first_claim.last_heartbeat_at);
        assert!(second_claim.lease_expires_at > first_claim.lease_expires_at);
        assert_eq!(
            second.value.next_attempt_at,
            Some(second_claim.last_heartbeat_at)
        );
    }

    #[tokio::test]
    async fn restore_apply_effect_replays_completed_result_after_restart() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("restore-effect-replay"),
                size_gb: 20,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_volume_restore(&volume.id, Some(String::from("effect replay drill")))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow_id = started.value.id.clone();
        let _prepared = service
            .prepare_volume_restore_apply_step(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (journaled, effect_execution) = service
            .begin_volume_restore_apply_effect(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first restore apply effect should execute")
            }
        };
        let result_digest = service
            .apply_volume_restore_to_volume(&journaled.value, effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored_ledger = service
            .volume_restore_apply_ledger
            .get(effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted apply ledger"));
        match &stored_ledger.value {
            VolumeRestoreApplyLedgerRecord::Current(record) => {
                assert_eq!(record.workflow_id, workflow_id);
                assert_eq!(record.workflow_kind, VOLUME_RESTORE_WORKFLOW_KIND);
                assert_eq!(record.subject_kind, "volume");
                assert_eq!(record.subject_id, volume.id.to_string());
                assert_eq!(record.step_index, VOLUME_RESTORE_FINAL_STEP_INDEX);
                assert_eq!(record.step_name, "apply_recovery_point");
                assert_eq!(record.effect_kind, VOLUME_RESTORE_APPLY_EFFECT_KIND);
                assert_eq!(record.idempotency_key, effect.idempotency_key);
                assert_eq!(record.result_digest, result_digest);
            }
            VolumeRestoreApplyLedgerRecord::Legacy(_) => {
                panic!("new restore apply ledger writes should use workflow effect ledger records")
            }
        }
        let first_volume = service
            .volumes
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored volume after first apply"));
        let first_version = first_volume.version;

        let replayed_digest = service
            .apply_volume_restore_to_volume(&journaled.value, effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_volume = service
            .volumes
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored volume after replay"));
        assert_eq!(replayed_digest, result_digest);
        assert_eq!(
            replayed_volume.version, first_version,
            "idempotency ledger should prevent duplicate apply writes",
        );

        let partially_completed = service
            .persist_volume_restore_apply_effect_completion(&workflow_id, &result_digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            workflow_step_state(&partially_completed.value, VOLUME_RESTORE_FINAL_STEP_INDEX),
            Some(WorkflowStepState::Active)
        );
        let partial_effect = partially_completed.value.steps[VOLUME_RESTORE_FINAL_STEP_INDEX]
            .effect(VOLUME_RESTORE_APPLY_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing persisted apply effect"));
        assert_eq!(
            partial_effect.result_digest.as_deref(),
            Some(result_digest.as_str())
        );

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (_replayed_workflow, replay) = reopened
            .begin_volume_restore_apply_effect(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_effect = match replay {
            WorkflowStepEffectExecution::Replay(effect) => effect,
            WorkflowStepEffectExecution::Execute(_) => {
                panic!("completed apply effect should replay after restart")
            }
        };
        assert_eq!(
            replay_effect.result_digest.as_deref(),
            Some(result_digest.as_str())
        );

        let action = reopened
            .execute_volume_restore(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(action.state, VolumeRestoreActionState::Completed);
        let finalized_volume = reopened
            .volumes
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing finalized restored volume"));
        assert_eq!(
            finalized_volume.version, first_version,
            "finalization should reuse recorded effect result instead of reapplying",
        );
    }

    #[tokio::test]
    async fn legacy_restore_apply_ledger_upgrades_during_open_and_replays_after_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_volume(CreateVolumeRequest {
                name: String::from("legacy-restore-effect-ledger"),
                size_gb: 12,
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let volume: VolumeRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_volume_restore(&volume.id, Some(String::from("legacy effect replay drill")))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow_id = started.value.id.clone();
        let _prepared = service
            .prepare_volume_restore_apply_step(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (journaled, effect_execution) = service
            .begin_volume_restore_apply_effect(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first legacy restore apply effect should execute")
            }
        };
        let result_digest = service
            .apply_volume_restore_to_volume(&journaled.value, effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_ledger = service
            .volume_restore_apply_ledger
            .get(effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current apply ledger before legacy rewrite"));
        let current_ledger = match &stored_ledger.value {
            VolumeRestoreApplyLedgerRecord::Current(record) => record.clone(),
            VolumeRestoreApplyLedgerRecord::Legacy(_) => {
                panic!("setup should start from a current workflow effect ledger record")
            }
        };
        let legacy_ledger =
            VolumeRestoreApplyLedgerRecord::Legacy(LegacyVolumeRestoreApplyLedgerRecord {
                idempotency_key: current_ledger.idempotency_key.clone(),
                workflow_id: workflow_id.clone(),
                volume_id: volume.id.clone(),
                recovery_point_volume_id: journaled.value.state.recovery_point_volume_id.clone(),
                recovery_point_version: journaled.value.state.recovery_point_version,
                recovery_point_execution_count: journaled
                    .value
                    .state
                    .recovery_point_execution_count,
                recovery_point_etag: journaled.value.state.recovery_point_etag.clone(),
                result_digest: current_ledger.result_digest.clone(),
                recorded_at: current_ledger.recorded_at,
            });
        let _legacy = service
            .volume_restore_apply_ledger
            .upsert(
                effect.idempotency_key.as_str(),
                legacy_ledger,
                Some(stored_ledger.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(service);

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let upgraded_ledger = reopened
            .volume_restore_apply_ledger
            .get(effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upgraded apply ledger after reopen"));
        match upgraded_ledger.value {
            VolumeRestoreApplyLedgerRecord::Current(record) => {
                assert_eq!(record.workflow_id, workflow_id);
                assert_eq!(record.result_digest, result_digest);
                assert_eq!(record.effect_kind, VOLUME_RESTORE_APPLY_EFFECT_KIND);
            }
            VolumeRestoreApplyLedgerRecord::Legacy(_) => {
                panic!("legacy restore apply ledger should upgrade during service open")
            }
        }

        let workflow = reopened
            .load_volume_restore_workflow(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_digest = reopened
            .apply_volume_restore_to_volume(&workflow.value, effect.idempotency_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_digest, result_digest);
    }

    #[tokio::test]
    async fn restore_execution_preserves_active_volume_listing_behavior() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let volume_a = {
            let response = service
                .create_volume(CreateVolumeRequest {
                    name: String::from("restore-target-a"),
                    size_gb: 16,
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice::<VolumeRecord>(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let volume_b = {
            let response = service
                .create_volume(CreateVolumeRequest {
                    name: String::from("restore-target-b"),
                    size_gb: 20,
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice::<VolumeRecord>(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let listed_before = service
            .list_active_volumes()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let ids_before = listed_before
            .iter()
            .map(|volume| volume.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids_before, vec![volume_a.id.clone(), volume_b.id.clone()]);

        let restore_action_id = service
            .restore_volume_from_recovery_point(&volume_a.id, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_action = service
            .volume_restore_actions
            .get(restore_action_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restore action"));
        assert_eq!(
            restore_action.value.state,
            VolumeRestoreActionState::Completed
        );
        assert_eq!(restore_action.value.volume_id, volume_a.id);

        let listed_after = service
            .list_active_volumes()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let ids_after = listed_after
            .iter()
            .map(|volume| volume.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids_after, ids_before);

        let restored = listed_after
            .iter()
            .find(|volume| volume.id == volume_a.id)
            .unwrap_or_else(|| panic!("missing restored volume"));
        assert_eq!(restored.metadata.lifecycle, ResourceLifecycleState::Ready);
        assert_eq!(
            restored
                .metadata
                .annotations
                .get("storage.restore.last_action_id")
                .map(String::as_str),
            Some(restore_action_id.as_str())
        );
        assert_eq!(
            restored
                .metadata
                .annotations
                .get("storage.restore.workflow_id")
                .map(String::as_str),
            Some(restore_action.value.workflow_id.as_str())
        );

        let untouched = listed_after
            .iter()
            .find(|volume| volume.id == volume_b.id)
            .unwrap_or_else(|| panic!("missing untouched volume"));
        assert!(
            !untouched
                .metadata
                .annotations
                .contains_key("storage.restore.last_action_id")
        );
    }

    #[tokio::test]
    async fn upload_completion_orders_parts_and_rejects_zero_part_number() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket_response = service
            .create_bucket(CreateBucketRequest {
                name: String::from("primary"),
                owner_id: String::from("owner-1"),
                storage_class_id: None,
                durability_tier_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let bucket_body = bucket_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let bucket: BucketRecord =
            serde_json::from_slice(&bucket_body).unwrap_or_else(|error| panic!("{error}"));

        let upload_response = service
            .create_upload(CreateUploadRequest {
                bucket_id: bucket.id.to_string(),
                object_key: String::from("  objects/report.txt  "),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let upload_body = upload_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let upload: UploadSession =
            serde_json::from_slice(&upload_body).unwrap_or_else(|error| panic!("{error}"));
        let upload_id: UploadId = upload.id;

        let zero_part_error = service
            .upload_part(upload_id.as_str(), "0", Bytes::from_static(b"bad"))
            .await
            .expect_err("expected zero part to fail");
        assert!(
            zero_part_error
                .to_string()
                .contains("part number must be greater than zero")
        );

        let _ = service
            .upload_part(upload_id.as_str(), "2", Bytes::from_static(b"world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upload_part(upload_id.as_str(), "1", Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let complete_response = service
            .complete_upload(upload_id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(complete_response.status(), http::StatusCode::OK);

        let stored = service
            .uploads
            .get(upload_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload"));
        assert!(stored.value.completed);
        assert_eq!(stored.value.object_key, String::from("objects/report.txt"));

        let object_digest = stored
            .value
            .object_digest
            .as_ref()
            .unwrap_or_else(|| panic!("missing object digest"));
        let object = service
            .blobs
            .get(object_digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing assembled object"));
        assert_eq!(&object[..], b"hello world");
    }

    #[tokio::test]
    async fn complete_upload_cleans_part_state_and_blobs() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("primary"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap()
        };

        let upload: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/logs.tar"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap()
        };

        let mut part_digests = Vec::new();
        for (number, data) in [(1_u32, b"hello "), (2_u32, b"world!")] {
            let response = service
                .upload_part(
                    upload.id.as_str(),
                    &number.to_string(),
                    Bytes::from_static(data),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            let payload: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
            part_digests.push(
                payload["digest"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing part digest"))
                    .to_owned(),
            );
        }

        let complete = service
            .complete_upload(upload.id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(complete.status(), http::StatusCode::OK);

        // Upload record should keep the assembled object but drop part state.
        let stored = service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload record"));
        assert!(stored.value.completed);
        assert!(stored.value.object_digest.is_some());
        assert!(
            stored.value.parts.is_empty(),
            "part metadata should be cleared after completion"
        );

        // Part blobs should be deleted; the assembled object must remain.
        for digest in part_digests {
            let maybe_part = service
                .blobs
                .get(&digest)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(
                maybe_part.is_none(),
                "part blob {digest} should be removed after completion"
            );
        }
        let assembled = service
            .blobs
            .get(stored.value.object_digest.as_ref().unwrap())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("assembled object missing"));
        assert_eq!(&assembled[..], b"hello world!");
    }

    #[tokio::test]
    async fn complete_upload_preserves_single_part_object_blob() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("single"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let upload: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/one-part.txt"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let _ = service
            .upload_part(upload.id.as_str(), "1", Bytes::from_static(b"hello world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .complete_upload(upload.id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload"));
        let digest = stored
            .value
            .object_digest
            .as_ref()
            .unwrap_or_else(|| panic!("missing object digest"));
        let object = service
            .blobs
            .get(digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("single-part object blob missing"));
        assert_eq!(&object[..], b"hello world");
    }

    #[tokio::test]
    async fn concurrent_upload_parts_are_serialized_without_conflict() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("parallel"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let upload: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/parallel.txt"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let barrier = Arc::new(Barrier::new(2));
        let first = {
            let service = service.clone();
            let upload_id = upload.id.to_string();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service
                    .upload_part(&upload_id, "1", Bytes::from_static(b"hello "))
                    .await
            })
        };
        let second = {
            let service = service.clone();
            let upload_id = upload.id.to_string();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service
                    .upload_part(&upload_id, "2", Bytes::from_static(b"world"))
                    .await
            })
        };

        first
            .await
            .unwrap_or_else(|error| panic!("first upload task panicked: {error}"))
            .unwrap_or_else(|error| panic!("{error}"));
        second
            .await
            .unwrap_or_else(|error| panic!("second upload task panicked: {error}"))
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload"));
        assert_eq!(stored.value.parts.len(), 2);
        assert!(stored.value.parts.contains_key(&1));
        assert!(stored.value.parts.contains_key(&2));
    }

    #[tokio::test]
    async fn completed_upload_can_resume_cleanup_idempotently() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("resume"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let upload: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/resume.txt"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let _ = service
            .upload_part(upload.id.as_str(), "1", Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upload_part(upload.id.as_str(), "2", Bytes::from_static(b"again"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload"));
        let digest_list = stored.value.parts.values().cloned().collect::<Vec<_>>();
        let object = service
            .blobs
            .concat(&digest_list)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut completed = stored.value;
        completed.completed = true;
        completed.object_digest = Some(object.digest.clone());
        completed
            .metadata
            .touch(sha256_hex(object.digest.as_bytes()));
        let _committed = service
            .uploads
            .upsert(upload.id.as_str(), completed.clone(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for digest in completed.parts.values() {
            if digest != &object.digest {
                service
                    .blobs
                    .delete(digest)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
            }
        }

        let response = service
            .resume_completed_upload_cleanup(upload.id.as_str(), completed)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["cleanup_pending"].as_bool(), Some(false));

        let refreshed = service
            .uploads
            .get(upload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing upload after cleanup replay"));
        assert!(refreshed.value.completed);
        assert!(refreshed.value.parts.is_empty());
    }

    #[tokio::test]
    async fn orphaned_blob_is_collected_during_open_reconcile() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let orphan = service
            .blobs
            .put(Bytes::from_static(b"orphaned multipart blob"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(service);

        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let missing = service
            .blobs
            .get(&orphan.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            missing.is_none(),
            "open reconcile should delete unreferenced blob bodies"
        );

        let reference = service
            .blob_references
            .get(&orphan.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            reference.is_none() || reference.is_some_and(|stored| stored.deleted),
            "orphan reference records should be cleared after delete"
        );

        let workflow = service
            .blob_gc_workflows
            .get(super::blob_gc_workflow_id(&orphan.digest).as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blob gc workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.value.state.reference_count, 0);
        assert_eq!(
            workflow.value.state.last_outcome.as_deref(),
            Some("blob deleted")
        );
    }

    #[tokio::test]
    async fn overwriting_one_upload_part_keeps_shared_digest_alive_for_other_uploads() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("shared"),
                    owner_id: String::from("owner-1"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let upload_a: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/a.bin"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        let upload_b: UploadSession = {
            let response = service
                .create_upload(CreateUploadRequest {
                    bucket_id: bucket.id.to_string(),
                    object_key: String::from("objects/b.bin"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let _ = service
            .upload_part(upload_a.id.as_str(), "1", Bytes::from_static(b"shared"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upload_part(upload_b.id.as_str(), "1", Bytes::from_static(b"shared"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let shared_digest = service
            .uploads
            .get(upload_a.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first upload"))
            .value
            .parts
            .get(&1)
            .cloned()
            .unwrap_or_else(|| panic!("missing shared digest"));

        let _ = service
            .upload_part(
                upload_a.id.as_str(),
                "1",
                Bytes::from_static(b"replacement"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = service
            .blobs
            .get(&shared_digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("shared digest should remain for second upload"));
        assert_eq!(blob.as_ref(), b"shared");

        let reference = service
            .blob_references
            .get(&shared_digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blob reference record"));
        assert_eq!(reference.value.reference_count, 1);
        assert_eq!(
            reference.value.owners,
            vec![format!("upload:{}:part:1", upload_b.id)]
        );
    }

    #[tokio::test]
    async fn storage_summary_reports_aggregated_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bucket: BucketRecord = {
            let response = service
                .create_bucket(CreateBucketRequest {
                    name: String::from("summary"),
                    owner_id: String::from("owner-summary"),
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let volume: VolumeRecord = {
            let response = service
                .create_volume(CreateVolumeRequest {
                    name: String::from("summary-volume"),
                    size_gb: 5,
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let _attached = service
            .ensure_attached_volume("instance-summary", "attached-volume", 10, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _file_share: FileShareRecord = {
            let response = service
                .create_file_share(CreateFileShareRequest {
                    name: String::from("summary-share"),
                    capacity_gb: 50,
                    protocol: Some(FileShareProtocol::Nfs),
                    mounted_to: Some(String::from("instance-summary")),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let archive: ArchiveRecord = {
            let response = service
                .create_archive(CreateArchiveRequest {
                    name: String::from("summary-archive"),
                    size_bytes: 8_192,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let _upload = service
            .create_upload(CreateUploadRequest {
                bucket_id: bucket.id.to_string(),
                object_key: String::from("objects/summary.bin"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _restore = service
            .restore_volume_from_recovery_point(&volume.id, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let archive_rehydrate_job: ArchiveRehydrateJobRecord = {
            let response = service
                .create_archive_rehydrate_job(CreateArchiveRehydrateJobRequest {
                    archive_id: archive.id.to_string(),
                    priority: Some(ArchiveRehydratePriority::Expedited),
                    restore_window_hours: Some(12),
                    reason: Some(String::from("summary drill")),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let stored_archive = service
            .archives
            .get(archive.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing archive"));
        assert_eq!(
            stored_archive.value.access_state,
            ArchiveAccessState::Available
        );
        assert_eq!(
            stored_archive.value.last_rehydrate_job_id,
            Some(archive_rehydrate_job.id.clone())
        );

        let summary = service
            .storage_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary.bucket_count, 1);
        assert_eq!(summary.volume_count, 2);
        assert_eq!(summary.attachment_count, 1);
        assert_eq!(summary.file_share_count, 1);
        assert_eq!(summary.archive_count, 1);
        assert_eq!(summary.upload_session_count, 1);
        assert_eq!(summary.archive_rehydrate_job_count, 1);
        assert_eq!(summary.recovery_point_count, summary.volume_count);
        assert_eq!(summary.restore_action_count, 1);
    }

    #[tokio::test]
    async fn reopen_preserves_file_share_archive_inventory_and_rehydrate_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let file_share: FileShareRecord = {
            let response = service
                .create_file_share(CreateFileShareRequest {
                    name: String::from("persisted-share"),
                    capacity_gb: 128,
                    protocol: Some(FileShareProtocol::Smb),
                    mounted_to: Some(String::from("instance-persisted")),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let archive: ArchiveRecord = {
            let response = service
                .create_archive(CreateArchiveRequest {
                    name: String::from("persisted-archive"),
                    size_bytes: 16_384,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let rehydrate_job: ArchiveRehydrateJobRecord = {
            let response = service
                .create_archive_rehydrate_job(CreateArchiveRehydrateJobRequest {
                    archive_id: archive.id.to_string(),
                    priority: Some(ArchiveRehydratePriority::Bulk),
                    restore_window_hours: Some(48),
                    reason: Some(String::from("operator restore drill")),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };
        drop(service);

        let reopened = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let file_shares = reopened
            .list_active_file_shares()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(file_shares.len(), 1);
        assert_eq!(file_shares[0].id, file_share.id);
        assert_eq!(file_shares[0].protocol, FileShareProtocol::Smb);
        assert_eq!(
            file_shares[0].mounted_to.as_deref(),
            Some("instance-persisted")
        );

        let archives = reopened
            .list_active_archives()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0].id, archive.id);
        assert_eq!(archives[0].access_state, ArchiveAccessState::Available);
        assert_eq!(
            archives[0].last_rehydrate_job_id,
            Some(rehydrate_job.id.clone())
        );
        assert_eq!(
            archives[0].rehydrated_until,
            Some(rehydrate_job.rehydrated_until)
        );

        let rehydrate_jobs = reopened
            .list_active_archive_rehydrate_jobs()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rehydrate_jobs.len(), 1);
        assert_eq!(rehydrate_jobs[0].id, rehydrate_job.id);
        assert_eq!(rehydrate_jobs[0].archive_id, archive.id);
        assert_eq!(rehydrate_jobs[0].state, ArchiveRehydrateJobState::Completed);
        assert_eq!(
            rehydrate_jobs[0].reason.as_deref(),
            Some("operator restore drill")
        );

        let summary = reopened
            .storage_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.file_share_count, 1);
        assert_eq!(summary.archive_count, 1);
        assert_eq!(summary.archive_rehydrate_job_count, 1);
    }

    #[tokio::test]
    async fn operator_storage_inspection_views_require_operator_principal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let volume: VolumeRecord = {
            let response = service
                .create_volume(CreateVolumeRequest {
                    name: String::from("operator-check"),
                    size_gb: 8,
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let error = service
            .inspect_volume_snapshot_policy(volume.id.as_str(), &workload_context())
            .await
            .expect_err("workload principal should be rejected from snapshot policy inspection");
        assert_eq!(
            error.message,
            "snapshot policy inspection requires operator principal"
        );

        let error = service
            .create_volume_restore_action(
                volume.id.as_str(),
                CreateVolumeRestoreActionRequest {
                    recovery_point_version: None,
                    recovery_point_etag: None,
                    reason: Some(String::from("unauthorized restore")),
                },
                &workload_context(),
            )
            .await
            .expect_err("workload principal should be rejected from restore action creation");
        assert_eq!(
            error.message,
            "volume restore action requires operator principal"
        );
    }

    #[tokio::test]
    async fn operator_storage_snapshot_policy_missing_volume_preserves_correlation_id() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let context = operator_context();
        let correlation_id = context.correlation_id.clone();
        let (status, error) = parse_error_response(
            dispatch_request_with_context(
                &service,
                "GET",
                "/storage/volumes/vol_aaaaaaaaaaaaaaaaaaaaaaaaaa/snapshot-policy",
                None,
                context,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "volume does not exist");
        assert_eq!(error.detail, None);
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn operator_storage_recovery_point_invalid_volume_ids_preserve_correlation_id() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let context = operator_context();
        let correlation_id = context.correlation_id.clone();
        let (status, error) = parse_error_response(
            dispatch_request_with_context(
                &service,
                "GET",
                "/storage/volumes/bkt_aaaaaaaaaaaaaaaaaaaaaaaaaa/recovery-point",
                None,
                context,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(error.message, "invalid volume_id");
        assert!(
            error
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("expected id prefix `vol`"))
        );
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn operator_storage_inspection_views_project_history_and_restore_actions() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StorageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let operator_context = operator_context();

        let volume: VolumeRecord = {
            let response = service
                .create_volume(CreateVolumeRequest {
                    name: String::from("operator-history"),
                    size_gb: 16,
                    storage_class_id: None,
                    durability_tier_id: None,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
        };

        let snapshot_policy = service
            .inspect_volume_snapshot_policy(volume.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(snapshot_policy.volume_id, volume.id);
        assert_eq!(snapshot_policy.recovery_class, "scheduled_snapshot");
        assert_eq!(snapshot_policy.state, "active");
        assert_eq!(snapshot_policy.lifecycle, "ready");
        assert_eq!(
            snapshot_policy.interval_minutes,
            DEFAULT_VOLUME_SNAPSHOT_INTERVAL_MINUTES
        );
        assert_eq!(
            snapshot_policy.retention_snapshots,
            DEFAULT_VOLUME_SNAPSHOT_RETENTION
        );

        let initial_recovery_point = service
            .inspect_ready_volume_recovery_point(volume.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current_recovery_point = service
            .volume_recovery_points
            .get(volume.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current recovery point"));
        let mut updated_recovery_point = current_recovery_point.value.clone();
        updated_recovery_point.execution_count += 1;
        updated_recovery_point.latest_snapshot_at += Duration::minutes(30);
        updated_recovery_point.next_snapshot_after = updated_recovery_point.latest_snapshot_at
            + Duration::minutes(i64::from(updated_recovery_point.interval_minutes));
        updated_recovery_point.metadata.touch(sha256_hex(
            format!(
                "{}:recovery-point:{}",
                volume.id.as_str(),
                updated_recovery_point.execution_count,
            )
            .as_bytes(),
        ));
        let updated_recovery_point = service
            .volume_recovery_points
            .upsert(
                volume.id.as_str(),
                updated_recovery_point,
                Some(current_recovery_point.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current_recovery_point = service
            .inspect_ready_volume_recovery_point(volume.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            current_recovery_point.version,
            updated_recovery_point.version
        );

        let history = service
            .list_volume_recovery_history(volume.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, current_recovery_point.version);
        assert!(history[0].current);
        assert_eq!(history[1].version, initial_recovery_point.version);
        assert!(!history[1].current);

        let restore_action = service
            .create_volume_restore_action(
                volume.id.as_str(),
                CreateVolumeRestoreActionRequest {
                    recovery_point_version: Some(initial_recovery_point.version),
                    recovery_point_etag: Some(initial_recovery_point.etag.clone()),
                    reason: Some(String::from("operator rewind")),
                },
                &operator_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restore_action.volume_id, volume.id);
        assert_eq!(restore_action.state, "completed");
        assert_eq!(restore_action.recovery_class, "scheduled_snapshot");
        assert_eq!(
            restore_action.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            restore_action.source_recovery_point_etag,
            initial_recovery_point.etag
        );
        assert_eq!(
            restore_action.requested_reason,
            Some(String::from("operator rewind"))
        );
        assert_eq!(restore_action.lifecycle, "ready");
        assert!(restore_action.started_at.is_some());
        assert!(restore_action.completed_at.is_some());

        let listed_restore_actions = service
            .list_volume_restore_actions(volume.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(listed_restore_actions.len(), 1);
        assert_eq!(listed_restore_actions[0].id, restore_action.id);

        let inspected_restore_action = service
            .inspect_volume_restore_action(restore_action.id.as_str(), &operator_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(inspected_restore_action.id, restore_action.id);
        assert_eq!(
            inspected_restore_action.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_ne!(
            inspected_restore_action.source_recovery_point_version,
            current_recovery_point.version
        );
    }
}
