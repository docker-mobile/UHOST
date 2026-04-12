//! Managed data products service.
//!
//! This service keeps a strict, explicit control-plane model for managed data
//! offerings (databases, caches, and queues) and their critical operations:
//! backup, restore, failover, and maintenance transitions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{HeaderMap, Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{ErrorCode, PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::workflow::WorkflowEffectLedgerRecord;
use uhost_store::{
    AuditLog, DocumentStore, DurableOutbox, StoredDocument, WorkflowCollection, WorkflowInstance,
    WorkflowPhase, WorkflowStep, WorkflowStepEffectExecution, WorkflowStepState,
};
use uhost_svc_storage::{
    StorageBinding, StorageResourceKind, StorageService, VolumeRecord, VolumeRecoveryPointSummary,
    VolumeRestoreActionSummary,
};
use uhost_types::{
    AuditActor, AuditId, CacheClusterId, DatabaseId, EventHeader, EventPayload,
    FailoverOperationId, MigrationJobId, OwnershipScope, PlatformEvent, PrincipalKind, QueueId,
    ResourceMetadata, ServiceEvent, VolumeId,
};

fn default_database_state() -> String {
    String::from("ready")
}

fn default_primary_region() -> String {
    String::from("region-a")
}

const DATABASE_BACKING_VOLUME_ID_ANNOTATION: &str = "data.storage.backing_volume_id";
const DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION: &str = "data.storage.last_restore_action_id";
const DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION: &str = "data.storage.last_restore_backup_id";
const DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION: &str =
    "data.storage.last_restore.source_recovery_point_version";
const DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION: &str =
    "data.storage.last_restore.source_recovery_point_etag";
const DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION: &str =
    "data.storage.last_restore.source_recovery_point_captured_at";
const VOLUME_LAST_RESTORE_ACTION_ID_ANNOTATION: &str = "storage.restore.last_action_id";
const DATA_MIGRATION_STATE_PENDING: &str = "pending";
const DATA_MIGRATION_STATE_RUNNING: &str = "running";
const DATA_MIGRATION_STATE_COMPLETED: &str = "completed";
const DATA_MIGRATION_STATE_FAILED: &str = "failed";
const BACKUP_ARTIFACT_MANIFEST_SCHEMA_VERSION: u32 = 1;
const BACKUP_ARTIFACT_VERIFIER: &str = "data.backup.artifact-manifest.v1";
const DATA_BACKUP_WORKFLOW_KIND: &str = "data.backup";
const DATA_BACKUP_WORKFLOW_SUBJECT_KIND: &str = "database_backup";
const DATA_RESTORE_WORKFLOW_KIND: &str = "data.restore";
const DATA_RESTORE_WORKFLOW_SUBJECT_KIND: &str = "database_restore";
const DATA_FAILOVER_WORKFLOW_KIND: &str = "data.failover";
const DATA_FAILOVER_WORKFLOW_SUBJECT_KIND: &str = "database_failover";
const DATA_MUTATION_SUBJECT_KIND_DATABASE: &str = "database";
const DATA_BACKUP_FINAL_STEP_INDEX: usize = 2;
const DATA_RESTORE_FINAL_STEP_INDEX: usize = 2;
const DATA_FAILOVER_FINAL_STEP_INDEX: usize = 2;
const DATA_RESTORE_STORAGE_EFFECT_KIND: &str = "execute_storage_restore";
const DATA_RESTORE_PROJECTION_EFFECT_KIND: &str = "apply_database_restore_projection";
const DATA_FAILOVER_PROMOTION_EFFECT_KIND: &str = "promote_target_replica";
const DATA_EVENTS_TOPIC: &str = "data.events.v1";
const DATA_RECONCILER_ACTOR: &str = "system:data-crash-reconciler";
const RECONCILED_RESTORE_REASON: &str = "reconciled after controller death";
const DATA_TRANSFER_CHECKSUM_ALGORITHM: &str = "sha256";
const DATA_TRANSFER_SIGNATURE_SCHEME: &str = "uhost-sha256-v1";

fn backup_artifact_directory(
    state_root: &Path,
    database_id: &DatabaseId,
    backup_id: &AuditId,
) -> PathBuf {
    state_root
        .join("backup-artifacts")
        .join(database_id.as_str())
        .join(backup_id.as_str())
}

fn backup_payload_artifact_path(
    state_root: &Path,
    database_id: &DatabaseId,
    backup_id: &AuditId,
) -> PathBuf {
    backup_artifact_directory(state_root, database_id, backup_id).join("payload.json")
}

fn backup_manifest_artifact_path(
    state_root: &Path,
    database_id: &DatabaseId,
    backup_id: &AuditId,
) -> PathBuf {
    backup_artifact_directory(state_root, database_id, backup_id).join("manifest.json")
}

fn backup_payload_object_location(database_id: &DatabaseId, backup_id: &AuditId) -> String {
    format!(
        "object://data/backups/{}/artifacts/{}/payload.json",
        database_id.as_str(),
        backup_id.as_str(),
    )
}

fn backup_manifest_object_location(database_id: &DatabaseId, backup_id: &AuditId) -> String {
    format!(
        "object://data/backups/{}/artifacts/{}/manifest.json",
        database_id.as_str(),
        backup_id.as_str(),
    )
}

fn backup_artifact_key_ref(database: &ManagedDatabase) -> Option<String> {
    database.backup_policy.encryption_required.then(|| {
        format!(
            "key://data/databases/{}/backups/default",
            database.id.as_str()
        )
    })
}

async fn write_artifact_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(PlatformError::unavailable(
            "backup artifact path is missing a parent directory",
        ));
    };
    fs::create_dir_all(parent).await.map_err(|error| {
        PlatformError::unavailable("failed to create backup artifact directory")
            .with_detail(error.to_string())
    })?;
    fs::write(path, bytes).await.map_err(|error| {
        PlatformError::unavailable("failed to persist backup artifact")
            .with_detail(error.to_string())
    })
}

async fn write_json_artifact<T>(path: &Path, value: &T) -> Result<(u64, String)>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        PlatformError::unavailable("failed to serialize backup artifact")
            .with_detail(error.to_string())
    })?;
    write_artifact_bytes(path, &bytes).await?;
    Ok((bytes.len() as u64, sha256_hex(&bytes)))
}

async fn read_artifact_bytes(path: &Path, label: &str) -> Result<Vec<u8>> {
    fs::read(path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PlatformError::not_found(format!("{label} does not exist"))
                .with_detail(path.display().to_string())
        } else {
            PlatformError::unavailable(format!("failed to read {label}"))
                .with_detail(error.to_string())
        }
    })
}

async fn read_json_artifact<T>(path: &Path, label: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let bytes = read_artifact_bytes(path, label).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        PlatformError::unavailable(format!("failed to decode {label}"))
            .with_detail(error.to_string())
    })
}

fn build_verified_backup_artifact_result(
    observed_sha256: String,
    verified_at: OffsetDateTime,
) -> BackupArtifactVerificationResult {
    BackupArtifactVerificationResult {
        state: BackupArtifactVerificationState::Verified,
        verified_at,
        verifier: String::from(BACKUP_ARTIFACT_VERIFIER),
        observed_sha256,
    }
}

async fn verify_artifact_checksum(
    path: &Path,
    expected_sha256: &str,
    label: &str,
    verified_at: OffsetDateTime,
) -> Result<BackupArtifactVerificationResult> {
    let bytes = read_artifact_bytes(path, label).await?;
    let observed_sha256 = sha256_hex(&bytes);
    if observed_sha256 != expected_sha256 {
        return Err(
            PlatformError::unavailable(format!("{label} checksum verification failed"))
                .with_detail(format!(
                    "path={}, expected_sha256={expected_sha256}, observed_sha256={observed_sha256}",
                    path.display()
                )),
        );
    }
    Ok(build_verified_backup_artifact_result(
        observed_sha256,
        verified_at,
    ))
}

fn database_backing_volume_name(database: &ManagedDatabase) -> String {
    format!("database-{}", database.id.as_str())
}

fn upsert_annotation(
    annotations: &mut BTreeMap<String, String>,
    key: &'static str,
    value: String,
) -> bool {
    if annotations
        .get(key)
        .is_some_and(|current| current == &value)
    {
        return false;
    }
    annotations.insert(String::from(key), value);
    true
}

fn apply_database_storage_binding_annotations(
    database: &mut ManagedDatabase,
    volume: &VolumeRecord,
) -> bool {
    upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_BACKING_VOLUME_ID_ANNOTATION,
        volume.id.to_string(),
    )
}

fn apply_database_storage_binding(
    database: &mut ManagedDatabase,
    binding: &StorageBinding,
) -> bool {
    if database
        .storage_binding
        .as_ref()
        .is_some_and(|current| current == binding)
    {
        return false;
    }
    database.storage_binding = Some(binding.clone());
    true
}

fn apply_database_restore_lineage_annotations(
    database: &mut ManagedDatabase,
    backup_id: &AuditId,
    volume: &VolumeRecord,
    restore_action: &VolumeRestoreActionSummary,
) -> bool {
    let mut changed = apply_database_storage_binding_annotations(database, volume);
    changed |= upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION,
        restore_action.id.to_string(),
    );
    changed |= upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION,
        backup_id.to_string(),
    );
    changed |= upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION,
        restore_action.source_recovery_point_version.to_string(),
    );
    changed |= upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION,
        restore_action.source_recovery_point_etag.clone(),
    );
    changed |= upsert_annotation(
        &mut database.metadata.annotations,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION,
        restore_action
            .source_recovery_point_captured_at
            .unix_timestamp()
            .to_string(),
    );
    changed
}

fn database_storage_binding_etag(database: &ManagedDatabase, volume: &VolumeRecord) -> String {
    let (storage_class_id, durability_tier_id) =
        database
            .storage_binding
            .as_ref()
            .map_or(("", ""), |binding| {
                (
                    binding.storage_class_id.as_str(),
                    binding.durability_tier_id.as_str(),
                )
            });
    sha256_hex(
        format!(
            "{}:storage-binding:{}:{}:{}",
            database.id.as_str(),
            volume.id.as_str(),
            storage_class_id,
            durability_tier_id,
        )
        .as_bytes(),
    )
}

fn database_restore_lineage_etag(
    database: &ManagedDatabase,
    backup_id: &AuditId,
    restore_action: &VolumeRestoreActionSummary,
) -> String {
    sha256_hex(
        format!(
            "{}:database-restore:{}:{}:{}",
            database.id.as_str(),
            backup_id.as_str(),
            restore_action.id.as_str(),
            restore_action.source_recovery_point_etag,
        )
        .as_bytes(),
    )
}

/// Durable storage recovery-point lineage captured by a backup or applied by a restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStorageRecoveryPoint {
    pub volume_id: VolumeId,
    pub version: u64,
    pub execution_count: u64,
    pub etag: String,
    pub captured_at: OffsetDateTime,
}

fn build_backup_storage_recovery_point(
    recovery_point: &VolumeRecoveryPointSummary,
) -> BackupStorageRecoveryPoint {
    BackupStorageRecoveryPoint {
        volume_id: recovery_point.volume_id.clone(),
        version: recovery_point.version,
        execution_count: recovery_point.execution_count,
        etag: recovery_point.etag.clone(),
        captured_at: recovery_point.captured_at,
    }
}

fn build_restore_storage_recovery_point(
    restore_action: &VolumeRestoreActionSummary,
) -> BackupStorageRecoveryPoint {
    BackupStorageRecoveryPoint {
        volume_id: restore_action.source_recovery_point_volume_id.clone(),
        version: restore_action.source_recovery_point_version,
        execution_count: restore_action.source_recovery_point_execution_count,
        etag: restore_action.source_recovery_point_etag.clone(),
        captured_at: restore_action.source_recovery_point_captured_at,
    }
}

fn backup_storage_recovery_point_selection_reason() -> String {
    String::from(
        "backup recorded the ready storage recovery point that was current when the backup completed",
    )
}

fn current_backup_storage_recovery_point_state_reason() -> String {
    String::from(
        "persisted backup storage recovery point still matches the current ready storage recovery point",
    )
}

fn historical_backup_storage_recovery_point_state_reason() -> String {
    String::from(
        "persisted backup storage recovery point remains available as a historical storage recovery-point revision while the current ready storage recovery point has advanced",
    )
}

fn unavailable_backup_storage_recovery_point_state_reason() -> String {
    String::from(
        "persisted backup storage recovery point is unavailable in storage recovery-point history while a newer ready storage recovery point is available",
    )
}

fn historical_backup_storage_recovery_point_state_reason_without_current() -> String {
    String::from(
        "persisted backup storage recovery point remains available as a historical storage recovery-point revision, but no ready storage recovery point is currently available",
    )
}

fn unavailable_backup_storage_recovery_point_state_reason_without_current() -> String {
    String::from(
        "persisted backup storage recovery point is unavailable in storage recovery-point history and no ready storage recovery point is currently available",
    )
}

fn current_restore_selected_recovery_point_state_reason() -> String {
    String::from(
        "persisted restore-selected storage recovery point still matches the current ready storage recovery point",
    )
}

fn historical_restore_selected_recovery_point_state_reason() -> String {
    String::from(
        "persisted restore-selected storage recovery point remains available as a historical storage recovery-point revision while the current ready storage recovery point has advanced",
    )
}

fn unavailable_restore_selected_recovery_point_state_reason() -> String {
    String::from(
        "persisted restore-selected storage recovery point is unavailable in storage recovery-point history while a newer ready storage recovery point is available",
    )
}

fn historical_restore_selected_recovery_point_state_reason_without_current() -> String {
    String::from(
        "persisted restore-selected storage recovery point remains available as a historical storage recovery-point revision, but no ready storage recovery point is currently available",
    )
}

fn unavailable_restore_selected_recovery_point_state_reason_without_current() -> String {
    String::from(
        "persisted restore-selected storage recovery point is unavailable in storage recovery-point history and no ready storage recovery point is currently available",
    )
}

fn backup_storage_recovery_point_matches_summary(
    recovery_point: &BackupStorageRecoveryPoint,
    summary: &VolumeRecoveryPointSummary,
) -> bool {
    *recovery_point == build_backup_storage_recovery_point(summary)
}

/// Operator-readable projection over one persisted [`BackupStorageRecoveryPoint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStorageLineageInspection {
    /// Backup job identifier whose durable lineage is being inspected.
    pub backup_id: AuditId,
    /// Target storage volume correlated to the persisted backup.
    pub storage_volume_id: VolumeId,
    /// Persisted recovery point recorded by the backup bridge.
    pub recovery_point: BackupStorageRecoveryPoint,
    /// Stable operator-readable explanation for why this recovery point is the
    /// authoritative backup-side storage lineage.
    pub selection_reason: String,
    /// Stable operator-readable explanation for whether this persisted backup
    /// recovery point still matches current storage state or has become
    /// historical/unavailable.
    pub recovery_point_state_reason: String,
}

fn build_backup_storage_lineage_inspection(
    backup: &BackupJob,
    recovery_point_state_reason: String,
) -> Option<BackupStorageLineageInspection> {
    let lineage = backup.storage_recovery_point.as_ref()?;
    Some(BackupStorageLineageInspection {
        backup_id: backup.id.clone(),
        storage_volume_id: lineage.volume_id.clone(),
        recovery_point: lineage.clone(),
        selection_reason: backup.storage_recovery_point_selection_reason.clone(),
        recovery_point_state_reason,
    })
}

/// Explicit storage-source mode captured by one managed database restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStorageSourceMode {
    /// The restore resolved and used backup-correlated storage lineage.
    BackupCorrelatedStorageLineage,
    /// The restore fell back to the latest ready storage recovery point.
    LatestReadyFallback,
}

/// Durable storage lineage recorded by one managed database restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreStorageLineage {
    /// Explicit source mode used by the restore bridge.
    pub source_mode: RestoreStorageSourceMode,
    /// Target storage volume restored for the managed database.
    pub storage_volume_id: VolumeId,
    /// Linked storage restore action identifier.
    pub restore_action_id: AuditId,
    /// Linked storage restore workflow identifier.
    pub restore_workflow_id: String,
    /// Actual storage recovery point selected by the storage restore helper.
    pub selected_recovery_point: BackupStorageRecoveryPoint,
    /// Backup-correlated recovery point recorded by the originating backup, when one existed.
    #[serde(default)]
    pub backup_correlated_recovery_point: Option<BackupStorageRecoveryPoint>,
}

/// Operator-readable projection over one persisted [`RestoreStorageLineage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreStorageLineageInspection {
    /// Restore job identifier whose durable lineage is being inspected.
    pub restore_id: AuditId,
    /// Explicit source mode used by the persisted restore bridge.
    pub source_mode: RestoreStorageSourceMode,
    /// Target storage volume restored for the managed database.
    pub storage_volume_id: VolumeId,
    /// Linked storage restore action identifier.
    pub restore_action_id: AuditId,
    /// Linked storage restore workflow identifier.
    pub restore_workflow_id: String,
    /// Actual storage recovery point selected by the storage restore helper.
    pub selected_recovery_point: BackupStorageRecoveryPoint,
    /// Backup-correlated recovery point recorded by the originating backup, when one existed.
    #[serde(default)]
    pub backup_correlated_recovery_point: Option<BackupStorageRecoveryPoint>,
    /// Stable operator-readable explanation for why this storage recovery point was selected.
    pub selection_reason: String,
    /// Stable operator-readable explanation for whether the persisted
    /// restore-selected recovery point still matches current storage state or
    /// has become historical/unavailable.
    pub selected_recovery_point_state_reason: String,
}

fn restore_storage_selection_reason(lineage: &RestoreStorageLineage) -> String {
    match lineage.source_mode {
        RestoreStorageSourceMode::BackupCorrelatedStorageLineage => String::from(
            "selected backup-correlated storage recovery point recorded by the originating backup",
        ),
        RestoreStorageSourceMode::LatestReadyFallback
            if lineage.backup_correlated_recovery_point.is_some() =>
        {
            String::from(
                "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point",
            )
        }
        RestoreStorageSourceMode::LatestReadyFallback => String::from(
            "backup did not record storage recovery lineage; restored from the latest ready storage recovery point",
        ),
    }
}

fn build_restore_storage_lineage(
    volume: &VolumeRecord,
    restore_action: &VolumeRestoreActionSummary,
    used_backup_correlated_storage_lineage: bool,
    backup_correlated_recovery_point: Option<&BackupStorageRecoveryPoint>,
) -> RestoreStorageLineage {
    let source_mode = if used_backup_correlated_storage_lineage {
        RestoreStorageSourceMode::BackupCorrelatedStorageLineage
    } else {
        RestoreStorageSourceMode::LatestReadyFallback
    };
    RestoreStorageLineage {
        source_mode,
        storage_volume_id: volume.id.clone(),
        restore_action_id: restore_action.id.clone(),
        restore_workflow_id: restore_action.workflow_id.clone(),
        selected_recovery_point: build_restore_storage_recovery_point(restore_action),
        backup_correlated_recovery_point: backup_correlated_recovery_point.cloned(),
    }
}

fn build_restore_storage_lineage_inspection(
    restore: &RestoreJob,
    selected_recovery_point_state_reason: String,
) -> Option<RestoreStorageLineageInspection> {
    let lineage = restore.storage_restore.as_ref()?;
    Some(RestoreStorageLineageInspection {
        restore_id: restore.id.clone(),
        source_mode: lineage.source_mode,
        storage_volume_id: lineage.storage_volume_id.clone(),
        restore_action_id: lineage.restore_action_id.clone(),
        restore_workflow_id: lineage.restore_workflow_id.clone(),
        selected_recovery_point: lineage.selected_recovery_point.clone(),
        backup_correlated_recovery_point: lineage.backup_correlated_recovery_point.clone(),
        selection_reason: restore_storage_selection_reason(lineage),
        selected_recovery_point_state_reason,
    })
}

fn restore_job_storage_selection_reason(restore: &RestoreJob) -> Option<String> {
    restore
        .storage_restore
        .as_ref()
        .map(restore_storage_selection_reason)
}

/// Backup artifact class persisted for one managed database backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupArtifactKind {
    SnapshotBundle,
}

/// Verification state for one persisted backup artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupArtifactVerificationState {
    Verified,
}

/// Verification result captured for one persisted backup artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupArtifactVerificationResult {
    pub state: BackupArtifactVerificationState,
    pub verified_at: OffsetDateTime,
    pub verifier: String,
    pub observed_sha256: String,
}

/// One persisted backup artifact referenced by a durable backup manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupArtifactDescriptor {
    pub kind: BackupArtifactKind,
    pub object_location: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub key_ref: Option<String>,
    pub verification: BackupArtifactVerificationResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedBackupArtifactManifest {
    pub schema_version: u32,
    pub backup_id: AuditId,
    pub database_id: DatabaseId,
    pub generated_at: OffsetDateTime,
    pub artifacts: Vec<BackupArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedBackupPayload {
    pub schema_version: u32,
    pub backup_id: AuditId,
    pub database_id: DatabaseId,
    pub backup_kind: String,
    pub requested_by: String,
    pub reason: Option<String>,
    pub created_at: OffsetDateTime,
    pub point_in_time: Option<OffsetDateTime>,
    pub database_engine: String,
    pub database_version: String,
    pub database_storage_gb: u32,
    pub database_replica_count: u16,
    pub primary_region: String,
    pub backup_policy: BackupPolicy,
    pub storage_recovery_point: BackupStorageRecoveryPoint,
}

/// Persisted backup manifest rooted in real artifact files under the data service state directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupArtifactManifest {
    pub schema_version: u32,
    pub generated_at: OffsetDateTime,
    pub manifest_object_location: String,
    pub manifest_sha256: String,
    pub manifest_size_bytes: u64,
    #[serde(default)]
    pub manifest_key_ref: Option<String>,
    pub manifest_verification: BackupArtifactVerificationResult,
    pub artifacts: Vec<BackupArtifactDescriptor>,
}

/// Replica topology record for managed databases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseReplica {
    pub id: String,
    pub role: String,
    pub region: String,
    pub healthy: bool,
    pub lag_seconds: u64,
}

/// Backup policy model for one database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub interval_minutes: u32,
    pub retention_backups: u16,
    pub pitr_enabled: bool,
    pub encryption_required: bool,
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            interval_minutes: 60,
            retention_backups: 48,
            pitr_enabled: true,
            encryption_required: true,
        }
    }
}

/// Managed database record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedDatabase {
    pub id: DatabaseId,
    pub engine: String,
    pub version: String,
    pub storage_gb: u32,
    pub replicas: u16,
    pub tls_required: bool,
    #[serde(default)]
    pub storage_binding: Option<StorageBinding>,
    pub metadata: ResourceMetadata,
    #[serde(default = "default_database_state")]
    pub lifecycle_state: String,
    #[serde(default = "default_primary_region")]
    pub primary_region: String,
    #[serde(default)]
    pub replica_topology: Vec<DatabaseReplica>,
    #[serde(default)]
    pub backup_policy: BackupPolicy,
    #[serde(default)]
    pub storage_class: Option<String>,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub maintenance_reason: Option<String>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

/// Managed cache record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheCluster {
    pub id: CacheClusterId,
    pub engine: String,
    pub memory_mb: u64,
    pub tls_required: bool,
    pub metadata: ResourceMetadata,
}

/// Managed queue record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueService {
    pub id: QueueId,
    pub partitions: u16,
    pub retention_hours: u32,
    pub dead_letter_enabled: bool,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataChecksumCatalogEntry {
    pub artifact_uri: String,
    pub checksum: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataChecksumCatalog {
    pub algorithm: String,
    pub entries: Vec<DataChecksumCatalogEntry>,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDataTransferManifest {
    pub manifest_version: u32,
    pub flow: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub artifact_format: String,
    pub artifact_root_uri: String,
    pub checksum_catalog_checksum: String,
    pub signing_key_ref: String,
    pub signature_scheme: String,
    pub signature: String,
    pub signed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataExportJob {
    pub id: AuditId,
    pub resource_kind: String,
    pub resource_id: String,
    pub state: String,
    pub requested_by: String,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub artifact_root_uri: String,
    pub manifest_uri: String,
    pub checksum_catalog_uri: String,
    pub signed_manifest: SignedDataTransferManifest,
    pub checksum_catalog: DataChecksumCatalog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataImportJob {
    pub id: AuditId,
    pub resource_kind: String,
    pub source_resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_resource_id: Option<String>,
    pub state: String,
    pub requested_by: String,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_catalog_uri: Option<String>,
    pub verification_result: String,
    pub signed_manifest: SignedDataTransferManifest,
    pub checksum_catalog: DataChecksumCatalog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDurabilitySummary {
    pub database_count: usize,
    pub cache_count: usize,
    pub queue_count: usize,
    pub maintenance_mode_databases: usize,
    pub backup_job_count: usize,
    pub backup_job_state_counts: BTreeMap<String, usize>,
    pub restore_job_count: usize,
    pub restore_job_state_counts: BTreeMap<String, usize>,
    pub failover_count: usize,
    pub failover_state_counts: BTreeMap<String, usize>,
    pub migration_job_count: usize,
    pub migration_job_state_counts: BTreeMap<String, usize>,
    pub export_job_count: usize,
    pub export_job_state_counts: BTreeMap<String, usize>,
    pub import_job_count: usize,
    pub import_job_state_counts: BTreeMap<String, usize>,
}

/// Backup job record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: AuditId,
    pub database_id: DatabaseId,
    pub kind: String,
    pub state: String,
    pub requested_by: String,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub snapshot_uri: String,
    #[serde(default)]
    pub backup_artifact_manifest: Option<BackupArtifactManifest>,
    #[serde(default)]
    pub storage_recovery_point: Option<BackupStorageRecoveryPoint>,
    /// Stable operator-readable explanation for why the persisted storage
    /// recovery point is authoritative for this backup.
    #[serde(default = "backup_storage_recovery_point_selection_reason")]
    pub storage_recovery_point_selection_reason: String,
    pub point_in_time: Option<OffsetDateTime>,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BackupJobReply {
    id: AuditId,
    database_id: DatabaseId,
    kind: String,
    state: String,
    requested_by: String,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
    snapshot_uri: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_artifact_manifest: Option<BackupArtifactManifest>,
    #[serde(default)]
    storage_recovery_point: Option<BackupStorageRecoveryPoint>,
    storage_recovery_point_selection_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_recovery_point_state_reason: Option<String>,
    point_in_time: Option<OffsetDateTime>,
    checksum: String,
}

fn build_backup_job_reply(backup: &BackupJob) -> BackupJobReply {
    BackupJobReply {
        id: backup.id.clone(),
        database_id: backup.database_id.clone(),
        kind: backup.kind.clone(),
        state: backup.state.clone(),
        requested_by: backup.requested_by.clone(),
        created_at: backup.created_at,
        completed_at: backup.completed_at,
        snapshot_uri: backup.snapshot_uri.clone(),
        backup_artifact_manifest: backup.backup_artifact_manifest.clone(),
        storage_recovery_point: backup.storage_recovery_point.clone(),
        storage_recovery_point_selection_reason: backup
            .storage_recovery_point_selection_reason
            .clone(),
        storage_recovery_point_state_reason: None,
        point_in_time: backup.point_in_time,
        checksum: backup.checksum.clone(),
    }
}

/// Restore job record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreJob {
    pub id: AuditId,
    pub database_id: DatabaseId,
    pub backup_id: AuditId,
    pub state: String,
    pub requested_by: String,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub point_in_time: Option<OffsetDateTime>,
    pub reason: Option<String>,
    #[serde(default)]
    pub storage_restore: Option<RestoreStorageLineage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreJobReply {
    id: AuditId,
    database_id: DatabaseId,
    backup_id: AuditId,
    state: String,
    requested_by: String,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
    point_in_time: Option<OffsetDateTime>,
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_restore_source_mode: Option<RestoreStorageSourceMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_restore_selected_recovery_point: Option<BackupStorageRecoveryPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_restore_backup_correlated_recovery_point: Option<BackupStorageRecoveryPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_restore_selection_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_restore_selected_recovery_point_state_reason: Option<String>,
}

fn build_restore_job_reply(restore: &RestoreJob) -> RestoreJobReply {
    RestoreJobReply {
        id: restore.id.clone(),
        database_id: restore.database_id.clone(),
        backup_id: restore.backup_id.clone(),
        state: restore.state.clone(),
        requested_by: restore.requested_by.clone(),
        created_at: restore.created_at,
        completed_at: restore.completed_at,
        point_in_time: restore.point_in_time,
        reason: restore.reason.clone(),
        storage_restore_source_mode: restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.source_mode),
        storage_restore_selected_recovery_point: restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.selected_recovery_point.clone()),
        storage_restore_backup_correlated_recovery_point: restore
            .storage_restore
            .as_ref()
            .and_then(|lineage| lineage.backup_correlated_recovery_point.clone()),
        storage_restore_selection_reason: restore_job_storage_selection_reason(restore),
        storage_restore_selected_recovery_point_state_reason: None,
    }
}

/// Database failover record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFailoverRecord {
    pub id: FailoverOperationId,
    pub database_id: DatabaseId,
    pub from_replica_id: String,
    pub to_replica_id: String,
    pub state: String,
    pub reason: String,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DataMutationOperation {
    Backup,
    Restore,
    Failover,
}

impl DataMutationOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::Failover => "failover",
        }
    }
}

fn data_mutation_result_resource_kind(operation: DataMutationOperation) -> &'static str {
    match operation {
        DataMutationOperation::Backup => "database_backup",
        DataMutationOperation::Restore => "database_restore",
        DataMutationOperation::Failover => "database_failover",
    }
}

fn data_mutation_replay_status(operation: DataMutationOperation) -> StatusCode {
    match operation {
        DataMutationOperation::Backup => StatusCode::CREATED,
        DataMutationOperation::Restore | DataMutationOperation::Failover => StatusCode::OK,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DataMutationDedupeState {
    InFlight,
    Aborted,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DataMutationDedupeRecord {
    operation: DataMutationOperation,
    subject_kind: String,
    subject_id: String,
    idempotency_key: String,
    request_digest: String,
    state: DataMutationDedupeState,
    response_status: Option<u16>,
    response_body: Option<serde_json::Value>,
    result_resource_kind: Option<String>,
    result_resource_id: Option<String>,
    requested_by: Option<String>,
    correlation_id: String,
    request_id: String,
    attempt_count: u32,
    error_message: Option<String>,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
struct PendingDataMutationDedupe {
    key: String,
    version: u64,
    record: DataMutationDedupeRecord,
}

enum DataMutationDedupeBeginOutcome {
    Proceed(Box<Option<PendingDataMutationDedupe>>),
    Replay(http::Response<ApiBody>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DataWorkflowEvidence {
    recorded_at: OffsetDateTime,
    step: String,
    detail: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    refs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BackupWorkflowState {
    backup_id: AuditId,
    database_id: DatabaseId,
    kind: String,
    requested_by: String,
    snapshot_uri: String,
    #[serde(default)]
    backup_artifact_manifest: Option<BackupArtifactManifest>,
    #[serde(default)]
    storage_recovery_point: Option<BackupStorageRecoveryPoint>,
    #[serde(default = "backup_storage_recovery_point_selection_reason")]
    storage_recovery_point_selection_reason: String,
    point_in_time: Option<OffsetDateTime>,
    checksum: String,
    #[serde(default)]
    requested_reason: Option<String>,
    #[serde(default)]
    evidence: Vec<DataWorkflowEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreWorkflowState {
    restore_id: AuditId,
    database_id: DatabaseId,
    backup_id: AuditId,
    requested_by: String,
    point_in_time: Option<OffsetDateTime>,
    #[serde(default)]
    reason: Option<String>,
    target_volume_id: VolumeId,
    #[serde(default)]
    source_mode: Option<RestoreStorageSourceMode>,
    #[serde(default)]
    selected_recovery_point: Option<BackupStorageRecoveryPoint>,
    #[serde(default)]
    backup_correlated_recovery_point: Option<BackupStorageRecoveryPoint>,
    #[serde(default)]
    storage_restore: Option<RestoreStorageLineage>,
    #[serde(default)]
    evidence: Vec<DataWorkflowEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailoverWorkflowState {
    failover_id: FailoverOperationId,
    database_id: DatabaseId,
    from_replica_id: String,
    to_replica_id: String,
    target_region: String,
    requested_by: String,
    reason: String,
    #[serde(default)]
    evidence: Vec<DataWorkflowEvidence>,
}

type BackupWorkflow = WorkflowInstance<BackupWorkflowState>;
type RestoreWorkflow = WorkflowInstance<RestoreWorkflowState>;
type FailoverWorkflow = WorkflowInstance<FailoverWorkflowState>;

/// Database migration workflow record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMigrationJob {
    pub id: MigrationJobId,
    pub database_id: DatabaseId,
    pub kind: String,
    pub state: String,
    pub requested_by: String,
    pub created_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
    pub failed_at: Option<OffsetDateTime>,
    pub reason: Option<String>,
    #[serde(default)]
    pub source_version: Option<String>,
    #[serde(default)]
    pub target_version: Option<String>,
    #[serde(default)]
    pub source_region: Option<String>,
    #[serde(default)]
    pub target_region: Option<String>,
    #[serde(default)]
    pub source_replica_id: Option<String>,
    #[serde(default)]
    pub target_replica_id: Option<String>,
    #[serde(default)]
    pub source_storage_class: Option<String>,
    #[serde(default)]
    pub target_storage_class: Option<String>,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDatabaseRequest {
    engine: String,
    version: String,
    storage_gb: u32,
    replicas: u16,
    tls_required: bool,
    #[serde(default)]
    storage_class_id: Option<String>,
    #[serde(default)]
    durability_tier_id: Option<String>,
    #[serde(default)]
    primary_region: Option<String>,
    #[serde(default)]
    backup_policy: Option<BackupPolicy>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateCacheRequest {
    engine: String,
    memory_mb: u64,
    tls_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateQueueRequest {
    partitions: u16,
    retention_hours: u32,
    dead_letter_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBackupRequest {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    point_in_time_rfc3339: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreDatabaseRequest {
    backup_id: String,
    #[serde(default)]
    point_in_time_rfc3339: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailoverDatabaseRequest {
    #[serde(default)]
    target_replica_id: Option<String>,
    #[serde(default)]
    target_region: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MaintenanceRequest {
    enabled: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct BackupIdempotencyDigest<'a> {
    database_id: &'a str,
    kind: &'a str,
    point_in_time_unix_nanos: Option<i128>,
    reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct RestoreIdempotencyDigest<'a> {
    database_id: &'a str,
    backup_id: &'a str,
    point_in_time_unix_nanos: Option<i128>,
    reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct FailoverIdempotencyDigest<'a> {
    database_id: &'a str,
    target_replica_id: Option<&'a str>,
    target_region: Option<&'a str>,
    reason: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDataMigrationRequest {
    kind: String,
    #[serde(default)]
    target_version: Option<String>,
    #[serde(default)]
    target_region: Option<String>,
    #[serde(default)]
    source_replica_id: Option<String>,
    #[serde(default)]
    target_replica_id: Option<String>,
    #[serde(default)]
    target_storage_class: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDataExportRequest {
    #[serde(default)]
    artifact_format: Option<String>,
    #[serde(default)]
    signing_key_ref: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDataImportRequest {
    signed_manifest: SignedDataTransferManifest,
    checksum_catalog: DataChecksumCatalog,
    #[serde(default)]
    target_resource_id: Option<String>,
    #[serde(default)]
    manifest_uri: Option<String>,
    #[serde(default)]
    checksum_catalog_uri: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataTransferResourceKind {
    Database,
    Cache,
    Queue,
}

impl DataTransferResourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Cache => "cache",
            Self::Queue => "queue",
        }
    }

    fn collection_segment(self) -> &'static str {
        match self {
            Self::Database => "databases",
            Self::Cache => "caches",
            Self::Queue => "queues",
        }
    }

    fn default_artifact_format(self) -> &'static str {
        match self {
            Self::Database => "logical_dump",
            Self::Cache => "snapshot",
            Self::Queue => "segment_bundle",
        }
    }
}

#[derive(Debug, Clone)]
struct ExportMaterial {
    artifact_format: String,
    artifact_root_uri: String,
    manifest_uri: String,
    checksum_catalog_uri: String,
    checksum_entries: Vec<DataChecksumCatalogEntry>,
    details: serde_json::Value,
}

fn data_job_state_from_phase(phase: &WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Pending => "pending",
        WorkflowPhase::Running | WorkflowPhase::Paused => "running",
        WorkflowPhase::Completed => "completed",
        WorkflowPhase::Failed | WorkflowPhase::RolledBack => "failed",
    }
}

fn workflow_requires_resume(phase: &WorkflowPhase) -> bool {
    matches!(phase, WorkflowPhase::Pending | WorkflowPhase::Running)
}

fn workflow_requires_pre_ledger_effect_migration(phase: &WorkflowPhase) -> bool {
    matches!(phase, WorkflowPhase::Running | WorkflowPhase::Paused)
}

fn workflow_resume_error_is_terminal(phase: &WorkflowPhase) -> bool {
    matches!(phase, WorkflowPhase::Failed | WorkflowPhase::RolledBack)
}

fn workflow_phase_from_job_state(state: &str) -> WorkflowPhase {
    match state.trim().to_ascii_lowercase().as_str() {
        "pending" => WorkflowPhase::Pending,
        "running" | "in_progress" => WorkflowPhase::Running,
        "completed" | "ready" => WorkflowPhase::Completed,
        "rolled_back" => WorkflowPhase::RolledBack,
        _ => WorkflowPhase::Failed,
    }
}

fn push_data_workflow_evidence(
    evidence: &mut Vec<DataWorkflowEvidence>,
    step: &str,
    detail: impl Into<String>,
    refs: BTreeMap<String, String>,
) {
    evidence.push(DataWorkflowEvidence {
        recorded_at: OffsetDateTime::now_utc(),
        step: step.to_owned(),
        detail: detail.into(),
        refs,
    });
}

fn data_workflow_step_state<T>(
    workflow: &WorkflowInstance<T>,
    index: usize,
) -> Option<WorkflowStepState> {
    workflow
        .steps
        .iter()
        .find(|step| step.index == index)
        .map(|step| step.state.clone())
}

fn data_workflow_effect_replay_result_digest(
    effect_kind: &str,
    result_digest: Option<&String>,
) -> Result<String> {
    result_digest.cloned().ok_or_else(|| {
        PlatformError::conflict(format!(
            "data workflow effect `{effect_kind}` is replayable but missing a result digest"
        ))
    })
}

fn restore_storage_effect_idempotency_key(state: &RestoreWorkflowState) -> Result<String> {
    let selected_recovery_point = state.selected_recovery_point.as_ref().ok_or_else(|| {
        PlatformError::conflict("restore workflow is missing selected recovery point")
    })?;
    Ok(sha256_hex(
        format!(
            "data-restore-storage-effect:v1:{}:{}:{}:{}:{}",
            state.restore_id.as_str(),
            state.database_id.as_str(),
            state.target_volume_id.as_str(),
            selected_recovery_point.version,
            selected_recovery_point.etag,
        )
        .as_bytes(),
    ))
}

fn restore_storage_effect_detail(state: &RestoreWorkflowState) -> Result<String> {
    let selected_recovery_point = state.selected_recovery_point.as_ref().ok_or_else(|| {
        PlatformError::conflict("restore workflow is missing selected recovery point")
    })?;
    Ok(format!(
        "executing storage restore for recovery point version {}",
        selected_recovery_point.version
    ))
}

fn restore_projection_effect_idempotency_key(state: &RestoreWorkflowState) -> Result<String> {
    let storage_restore = state.storage_restore.as_ref().ok_or_else(|| {
        PlatformError::conflict("restore workflow is missing storage restore lineage")
    })?;
    Ok(sha256_hex(
        format!(
            "data-restore-projection-effect:v1:{}:{}:{}:{}:{}",
            state.restore_id.as_str(),
            state.database_id.as_str(),
            state.backup_id.as_str(),
            storage_restore.restore_action_id.as_str(),
            storage_restore.selected_recovery_point.etag,
        )
        .as_bytes(),
    ))
}

fn restore_projection_effect_detail(state: &RestoreWorkflowState) -> Result<String> {
    let storage_restore = state.storage_restore.as_ref().ok_or_else(|| {
        PlatformError::conflict("restore workflow is missing storage restore lineage")
    })?;
    Ok(format!(
        "applying database restore projection for storage restore {}",
        storage_restore.restore_action_id.as_str()
    ))
}

fn failover_promotion_effect_idempotency_key(state: &FailoverWorkflowState) -> String {
    sha256_hex(
        format!(
            "data-failover-promotion-effect:v1:{}:{}:{}:{}:{}",
            state.failover_id.as_str(),
            state.database_id.as_str(),
            state.from_replica_id,
            state.to_replica_id,
            state.target_region,
        )
        .as_bytes(),
    )
}

fn failover_promotion_effect_detail(state: &FailoverWorkflowState) -> String {
    format!(
        "promoting target replica {} in {}",
        state.to_replica_id, state.target_region
    )
}

fn restore_projection_effect_result_digest(
    database: &ManagedDatabase,
    state: &RestoreWorkflowState,
) -> Result<String> {
    let storage_restore = state.storage_restore.as_ref().ok_or_else(|| {
        PlatformError::conflict("restore workflow is missing storage restore lineage")
    })?;
    Ok(sha256_hex(
        format!(
            "data-restore-projection-result:v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            state.restore_id.as_str(),
            state.database_id.as_str(),
            state.backup_id.as_str(),
            database.lifecycle_state,
            database.maintenance_mode,
            database.maintenance_reason.as_deref().unwrap_or(""),
            storage_restore.storage_volume_id.as_str(),
            storage_restore.restore_action_id.as_str(),
            storage_restore.selected_recovery_point.version,
            storage_restore.selected_recovery_point.etag,
        )
        .as_bytes(),
    ))
}

fn failover_promotion_effect_result_digest(
    database: &ManagedDatabase,
    state: &FailoverWorkflowState,
) -> Result<String> {
    let from_replica = database
        .replica_topology
        .iter()
        .find(|replica| replica.id == state.from_replica_id)
        .ok_or_else(|| {
            PlatformError::conflict(
                "database failover source replica no longer exists for effect replay",
            )
        })?;
    let to_replica = database
        .replica_topology
        .iter()
        .find(|replica| replica.id == state.to_replica_id)
        .ok_or_else(|| {
            PlatformError::conflict(
                "database failover target replica no longer exists for effect replay",
            )
        })?;
    Ok(sha256_hex(
        format!(
            "data-failover-promotion-result:v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            state.failover_id.as_str(),
            state.database_id.as_str(),
            database.lifecycle_state,
            database.primary_region,
            from_replica.id,
            from_replica.role,
            from_replica.region,
            to_replica.id,
            to_replica.role,
            to_replica.region,
            state.target_region,
        )
        .as_bytes(),
    ))
}

fn upgrade_pre_ledger_inflight_restore_workflow(
    workflow: &mut RestoreWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    // This upgrades legacy restore workflows that were persisted before the
    // effect ledger existed, backfilling the in-flight storage step so replay
    // and crash recovery see the same ledgered shape as new workflows.
    if !workflow_requires_pre_ledger_effect_migration(&workflow.phase) {
        return Ok(false);
    }

    let mut migrated_effect_kinds = BTreeSet::new();

    if matches!(
        data_workflow_step_state(workflow, 1),
        Some(WorkflowStepState::Active)
    ) && workflow.state.selected_recovery_point.is_some()
        && workflow
            .step(1)
            .and_then(|step| step.effect(DATA_RESTORE_STORAGE_EFFECT_KIND))
            .is_none()
    {
        let detail = restore_storage_effect_detail(&workflow.state)?;
        let idempotency_key = restore_storage_effect_idempotency_key(&workflow.state)?;
        let step = workflow.step_mut(1).ok_or_else(|| {
            PlatformError::conflict("restore workflow storage execution step is missing")
        })?;
        let _effect = step.begin_effect_at(
            DATA_RESTORE_STORAGE_EFFECT_KIND,
            idempotency_key.as_str(),
            Some(detail),
            observed_at,
        )?;
        migrated_effect_kinds.insert(DATA_RESTORE_STORAGE_EFFECT_KIND);
    }

    if matches!(
        data_workflow_step_state(workflow, DATA_RESTORE_FINAL_STEP_INDEX),
        Some(WorkflowStepState::Active)
    ) && workflow.state.storage_restore.is_some()
        && workflow
            .step(DATA_RESTORE_FINAL_STEP_INDEX)
            .and_then(|step| step.effect(DATA_RESTORE_PROJECTION_EFFECT_KIND))
            .is_none()
    {
        let detail = restore_projection_effect_detail(&workflow.state)?;
        let idempotency_key = restore_projection_effect_idempotency_key(&workflow.state)?;
        let step = workflow
            .step_mut(DATA_RESTORE_FINAL_STEP_INDEX)
            .ok_or_else(|| {
                PlatformError::conflict("restore workflow projection step is missing")
            })?;
        let _effect = step.begin_effect_at(
            DATA_RESTORE_PROJECTION_EFFECT_KIND,
            idempotency_key.as_str(),
            Some(detail),
            observed_at,
        )?;
        migrated_effect_kinds.insert(DATA_RESTORE_PROJECTION_EFFECT_KIND);
    }

    if migrated_effect_kinds.is_empty() {
        return Ok(false);
    }

    let mut refs = BTreeMap::new();
    refs.insert(
        String::from("effect_kinds"),
        migrated_effect_kinds
            .into_iter()
            .collect::<Vec<_>>()
            .join(","),
    );
    push_data_workflow_evidence(
        &mut workflow.state.evidence,
        "upgrade_pre_ledger_restore_effects",
        "upgraded pre-ledger restore workflow effect journals during service open",
        refs,
    );
    workflow.touch_at(observed_at);
    Ok(true)
}

fn upgrade_pre_ledger_inflight_failover_workflow(
    workflow: &mut FailoverWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    if !workflow_requires_pre_ledger_effect_migration(&workflow.phase) {
        return Ok(false);
    }
    if !matches!(
        data_workflow_step_state(workflow, 1),
        Some(WorkflowStepState::Active)
    ) {
        return Ok(false);
    }
    if workflow
        .step(1)
        .and_then(|step| step.effect(DATA_FAILOVER_PROMOTION_EFFECT_KIND))
        .is_some()
    {
        return Ok(false);
    }

    let detail = failover_promotion_effect_detail(&workflow.state);
    let idempotency_key = failover_promotion_effect_idempotency_key(&workflow.state);
    let step = workflow
        .step_mut(1)
        .ok_or_else(|| PlatformError::conflict("failover workflow promotion step is missing"))?;
    let _effect = step.begin_effect_at(
        DATA_FAILOVER_PROMOTION_EFFECT_KIND,
        idempotency_key.as_str(),
        Some(detail),
        observed_at,
    )?;

    let mut refs = BTreeMap::new();
    refs.insert(
        String::from("effect_kind"),
        String::from(DATA_FAILOVER_PROMOTION_EFFECT_KIND),
    );
    push_data_workflow_evidence(
        &mut workflow.state.evidence,
        "upgrade_pre_ledger_failover_effects",
        "upgraded pre-ledger failover workflow effect journals during service open",
        refs,
    );
    workflow.touch_at(observed_at);
    Ok(true)
}

fn apply_backfilled_workflow_phase<T>(
    workflow: &mut WorkflowInstance<T>,
    phase: WorkflowPhase,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
) {
    let updated_at = completed_at.unwrap_or(created_at);
    let current_step_index = match phase {
        WorkflowPhase::Pending => None,
        _ => workflow.steps.last().map(|step| step.index),
    };
    let last_position = workflow.steps.len().checked_sub(1);
    for (position, step) in workflow.steps.iter_mut().enumerate() {
        step.updated_at = updated_at;
        step.detail = Some(String::from("reconciled from legacy data job projection"));
        step.state = match phase {
            WorkflowPhase::Pending => WorkflowStepState::Pending,
            WorkflowPhase::Running | WorkflowPhase::Paused => {
                if Some(position) == last_position {
                    WorkflowStepState::Active
                } else {
                    WorkflowStepState::Completed
                }
            }
            WorkflowPhase::Completed => WorkflowStepState::Completed,
            WorkflowPhase::Failed => {
                if Some(position) == last_position {
                    WorkflowStepState::Failed
                } else {
                    WorkflowStepState::Completed
                }
            }
            WorkflowPhase::RolledBack => WorkflowStepState::RolledBack,
        };
    }
    workflow.created_at = created_at;
    workflow.updated_at = updated_at;
    workflow.phase = phase.clone();
    workflow.current_step_index = current_step_index;
    workflow.completed_at = if matches!(
        phase,
        WorkflowPhase::Completed | WorkflowPhase::Failed | WorkflowPhase::RolledBack
    ) {
        Some(updated_at)
    } else {
        None
    };
    workflow.next_attempt_at = None;
    workflow.runner_claim = None;
}

fn build_backup_job_from_workflow(workflow: &BackupWorkflow) -> BackupJob {
    BackupJob {
        id: workflow.state.backup_id.clone(),
        database_id: workflow.state.database_id.clone(),
        kind: workflow.state.kind.clone(),
        state: String::from(data_job_state_from_phase(&workflow.phase)),
        requested_by: workflow.state.requested_by.clone(),
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
        snapshot_uri: workflow.state.snapshot_uri.clone(),
        backup_artifact_manifest: workflow.state.backup_artifact_manifest.clone(),
        storage_recovery_point: workflow.state.storage_recovery_point.clone(),
        storage_recovery_point_selection_reason: workflow
            .state
            .storage_recovery_point_selection_reason
            .clone(),
        point_in_time: workflow.state.point_in_time,
        checksum: workflow.state.checksum.clone(),
    }
}

fn build_restore_job_from_workflow(workflow: &RestoreWorkflow) -> RestoreJob {
    RestoreJob {
        id: workflow.state.restore_id.clone(),
        database_id: workflow.state.database_id.clone(),
        backup_id: workflow.state.backup_id.clone(),
        state: String::from(data_job_state_from_phase(&workflow.phase)),
        requested_by: workflow.state.requested_by.clone(),
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
        point_in_time: workflow.state.point_in_time,
        reason: workflow.state.reason.clone(),
        storage_restore: workflow.state.storage_restore.clone(),
    }
}

fn build_failover_record_from_workflow(workflow: &FailoverWorkflow) -> DataFailoverRecord {
    DataFailoverRecord {
        id: workflow.state.failover_id.clone(),
        database_id: workflow.state.database_id.clone(),
        from_replica_id: workflow.state.from_replica_id.clone(),
        to_replica_id: workflow.state.to_replica_id.clone(),
        state: String::from(data_job_state_from_phase(&workflow.phase)),
        reason: workflow.state.reason.clone(),
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
    }
}

fn build_backup_workflow(state: BackupWorkflowState) -> BackupWorkflow {
    WorkflowInstance::new(
        state.backup_id.to_string(),
        DATA_BACKUP_WORKFLOW_KIND,
        DATA_BACKUP_WORKFLOW_SUBJECT_KIND,
        state.backup_id.to_string(),
        state,
        vec![
            WorkflowStep::new("capture_storage_recovery_point", 0),
            WorkflowStep::new("materialize_backup_snapshot", 1),
            WorkflowStep::new("record_backup_evidence", DATA_BACKUP_FINAL_STEP_INDEX),
        ],
    )
}

fn build_restore_workflow(state: RestoreWorkflowState) -> RestoreWorkflow {
    WorkflowInstance::new(
        state.restore_id.to_string(),
        DATA_RESTORE_WORKFLOW_KIND,
        DATA_RESTORE_WORKFLOW_SUBJECT_KIND,
        state.restore_id.to_string(),
        state,
        vec![
            WorkflowStep::new("select_restore_source", 0),
            WorkflowStep::new("execute_storage_restore", 1),
            WorkflowStep::new(
                "apply_database_restore_projection",
                DATA_RESTORE_FINAL_STEP_INDEX,
            ),
        ],
    )
}

fn build_failover_workflow(state: FailoverWorkflowState) -> FailoverWorkflow {
    WorkflowInstance::new(
        state.failover_id.to_string(),
        DATA_FAILOVER_WORKFLOW_KIND,
        DATA_FAILOVER_WORKFLOW_SUBJECT_KIND,
        state.failover_id.to_string(),
        state,
        vec![
            WorkflowStep::new("prepare_failover", 0),
            WorkflowStep::new("promote_target_replica", 1),
            WorkflowStep::new("record_failover_evidence", DATA_FAILOVER_FINAL_STEP_INDEX),
        ],
    )
}

fn build_backfilled_backup_workflow(job: &BackupJob) -> BackupWorkflow {
    let mut state = BackupWorkflowState {
        backup_id: job.id.clone(),
        database_id: job.database_id.clone(),
        kind: job.kind.clone(),
        requested_by: job.requested_by.clone(),
        snapshot_uri: job.snapshot_uri.clone(),
        backup_artifact_manifest: job.backup_artifact_manifest.clone(),
        storage_recovery_point: job.storage_recovery_point.clone(),
        storage_recovery_point_selection_reason: job
            .storage_recovery_point_selection_reason
            .clone(),
        point_in_time: job.point_in_time,
        checksum: job.checksum.clone(),
        requested_reason: None,
        evidence: Vec::new(),
    };
    let mut refs = BTreeMap::new();
    refs.insert(String::from("legacy_state"), job.state.clone());
    if let Some(recovery_point) = job.storage_recovery_point.as_ref() {
        refs.insert(
            String::from("storage_recovery_point_etag"),
            recovery_point.etag.clone(),
        );
    }
    push_data_workflow_evidence(
        &mut state.evidence,
        "reconcile_legacy_backup_job",
        format!("reconciled legacy backup job in {} state", job.state),
        refs,
    );
    let mut workflow = build_backup_workflow(state);
    apply_backfilled_workflow_phase(
        &mut workflow,
        workflow_phase_from_job_state(&job.state),
        job.created_at,
        job.completed_at,
    );
    workflow
}

fn build_backfilled_restore_workflow(
    job: &RestoreJob,
    target_volume_id: VolumeId,
) -> RestoreWorkflow {
    let mut state = RestoreWorkflowState {
        restore_id: job.id.clone(),
        database_id: job.database_id.clone(),
        backup_id: job.backup_id.clone(),
        requested_by: job.requested_by.clone(),
        point_in_time: job.point_in_time,
        reason: job.reason.clone(),
        target_volume_id,
        source_mode: job
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.source_mode),
        selected_recovery_point: job
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.selected_recovery_point.clone()),
        backup_correlated_recovery_point: job
            .storage_restore
            .as_ref()
            .and_then(|lineage| lineage.backup_correlated_recovery_point.clone()),
        storage_restore: job.storage_restore.clone(),
        evidence: Vec::new(),
    };
    let mut refs = BTreeMap::new();
    refs.insert(String::from("legacy_state"), job.state.clone());
    if let Some(lineage) = job.storage_restore.as_ref() {
        refs.insert(
            String::from("restore_workflow_id"),
            lineage.restore_workflow_id.clone(),
        );
    }
    push_data_workflow_evidence(
        &mut state.evidence,
        "reconcile_legacy_restore_job",
        format!("reconciled legacy restore job in {} state", job.state),
        refs,
    );
    let mut workflow = build_restore_workflow(state);
    apply_backfilled_workflow_phase(
        &mut workflow,
        workflow_phase_from_job_state(&job.state),
        job.created_at,
        job.completed_at,
    );
    workflow
}

fn build_backfilled_failover_workflow(
    job: &DataFailoverRecord,
    target_region: String,
) -> FailoverWorkflow {
    let mut state = FailoverWorkflowState {
        failover_id: job.id.clone(),
        database_id: job.database_id.clone(),
        from_replica_id: job.from_replica_id.clone(),
        to_replica_id: job.to_replica_id.clone(),
        target_region,
        requested_by: String::from("legacy_projection"),
        reason: job.reason.clone(),
        evidence: Vec::new(),
    };
    let mut refs = BTreeMap::new();
    refs.insert(String::from("legacy_state"), job.state.clone());
    refs.insert(String::from("from_replica_id"), job.from_replica_id.clone());
    refs.insert(String::from("to_replica_id"), job.to_replica_id.clone());
    push_data_workflow_evidence(
        &mut state.evidence,
        "reconcile_legacy_failover_job",
        format!("reconciled legacy failover record in {} state", job.state),
        refs,
    );
    let mut workflow = build_failover_workflow(state);
    apply_backfilled_workflow_phase(
        &mut workflow,
        workflow_phase_from_job_state(&job.state),
        job.created_at,
        job.completed_at,
    );
    workflow
}

/// Managed data service.
#[derive(Debug, Clone)]
pub struct DataService {
    storage: StorageService,
    databases: DocumentStore<ManagedDatabase>,
    caches: DocumentStore<CacheCluster>,
    queues: DocumentStore<QueueService>,
    backup_jobs: DocumentStore<BackupJob>,
    backup_workflows: WorkflowCollection<BackupWorkflowState>,
    restore_jobs: DocumentStore<RestoreJob>,
    restore_workflows: WorkflowCollection<RestoreWorkflowState>,
    failovers: DocumentStore<DataFailoverRecord>,
    failover_workflows: WorkflowCollection<FailoverWorkflowState>,
    workflow_effect_ledgers: DocumentStore<WorkflowEffectLedgerRecord>,
    mutation_dedupes: DocumentStore<DataMutationDedupeRecord>,
    migrations: DocumentStore<DataMigrationJob>,
    export_jobs: DocumentStore<DataExportJob>,
    import_jobs: DocumentStore<DataImportJob>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl DataService {
    /// Open data state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("data");
        let service = Self {
            storage: StorageService::open(state_root.as_ref()).await?,
            databases: DocumentStore::open(root.join("databases.json")).await?,
            caches: DocumentStore::open(root.join("caches.json")).await?,
            queues: DocumentStore::open(root.join("queues.json")).await?,
            backup_jobs: DocumentStore::open(root.join("backups.json")).await?,
            backup_workflows: WorkflowCollection::open_local(root.join("backup_workflows.json"))
                .await?,
            restore_jobs: DocumentStore::open(root.join("restores.json")).await?,
            restore_workflows: WorkflowCollection::open_local(root.join("restore_workflows.json"))
                .await?,
            failovers: DocumentStore::open(root.join("failovers.json")).await?,
            failover_workflows: WorkflowCollection::open_local(
                root.join("failover_workflows.json"),
            )
            .await?,
            workflow_effect_ledgers: DocumentStore::open(root.join("workflow_effect_ledgers.json"))
                .await?,
            mutation_dedupes: DocumentStore::open(root.join("mutation-dedupes.json")).await?,
            migrations: DocumentStore::open(root.join("migrations.json")).await?,
            export_jobs: DocumentStore::open(root.join("exports.json")).await?,
            import_jobs: DocumentStore::open(root.join("imports.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.reconcile_database_topology().await?;
        service.reconcile_restore_crash_state().await?;
        service.reconcile_operation_workflows().await?;
        service
            .migrate_pre_ledger_inflight_operation_workflows()
            .await?;
        service.reconcile_incomplete_operation_workflows().await?;
        service.reconcile_operation_outbox().await?;
        Ok(service)
    }

    async fn begin_data_mutation_dedupe(
        &self,
        operation: DataMutationOperation,
        subject_id: &str,
        idempotency_key: Option<&str>,
        request_digest: &str,
        context: &RequestContext,
    ) -> Result<DataMutationDedupeBeginOutcome> {
        // Dedupe has three outcomes: no key means bypass, a fresh record means
        // this caller owns execution, and an existing record means resume,
        // recover, or replay through the stored mutation state.
        let Some(idempotency_key) = idempotency_key else {
            return Ok(DataMutationDedupeBeginOutcome::Proceed(Box::new(None)));
        };

        let key = data_mutation_dedupe_key(operation, subject_id, idempotency_key);
        let record = DataMutationDedupeRecord {
            operation,
            subject_kind: String::from(DATA_MUTATION_SUBJECT_KIND_DATABASE),
            subject_id: subject_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_digest: request_digest.to_owned(),
            state: DataMutationDedupeState::InFlight,
            response_status: None,
            response_body: None,
            result_resource_kind: None,
            result_resource_id: None,
            requested_by: context.actor.clone(),
            correlation_id: context.correlation_id.clone(),
            request_id: context.request_id.clone(),
            attempt_count: 1,
            error_message: None,
            created_at: OffsetDateTime::now_utc(),
            completed_at: None,
        };

        match self.mutation_dedupes.create(&key, record.clone()).await {
            Ok(stored) => Ok(DataMutationDedupeBeginOutcome::Proceed(Box::new(Some(
                PendingDataMutationDedupe {
                    key,
                    version: stored.version,
                    record,
                },
            )))),
            Err(error) if error.code == ErrorCode::Conflict => {
                let Some(existing) = self.mutation_dedupes.get(&key).await? else {
                    return Err(error);
                };
                self.resolve_existing_data_mutation_dedupe(
                    &key,
                    existing,
                    operation,
                    subject_id,
                    idempotency_key,
                    request_digest,
                    context,
                )
                .await
            }
            Err(error) => Err(error),
        }
    }

    async fn resolve_existing_data_mutation_dedupe(
        &self,
        key: &str,
        existing: StoredDocument<DataMutationDedupeRecord>,
        operation: DataMutationOperation,
        subject_id: &str,
        idempotency_key: &str,
        request_digest: &str,
        context: &RequestContext,
    ) -> Result<DataMutationDedupeBeginOutcome> {
        validate_data_mutation_dedupe_identity(
            &existing.value,
            operation,
            subject_id,
            idempotency_key,
            context,
        )?;
        if existing.deleted {
            return Err(PlatformError::conflict(
                "idempotency key is blocked by a deleted dedupe record",
            )
            .with_correlation_id(context.correlation_id.clone()));
        }
        if existing.value.request_digest != request_digest {
            return Err(PlatformError::conflict(format!(
                "data {} idempotency key already exists for a different request on database `{}`",
                existing.value.operation.as_str(),
                existing.value.subject_id,
            ))
            .with_correlation_id(context.correlation_id.clone()));
        }
        if existing.value.response_body.is_some() {
            return replay_data_mutation_response(&existing.value)
                .map(DataMutationDedupeBeginOutcome::Replay);
        }
        if existing.value.result_resource_kind.is_some()
            || existing.value.result_resource_id.is_some()
        {
            return self
                .recover_data_mutation_dedupe_from_result(key, existing, context)
                .await;
        }

        match existing.value.state {
            DataMutationDedupeState::Completed => Err(PlatformError::unavailable(
                "completed data idempotency record is missing response",
            )
            .with_correlation_id(context.correlation_id.clone())),
            DataMutationDedupeState::InFlight => Err(PlatformError::conflict(format!(
                "data {} request is already in flight for database `{}` and this idempotency key",
                existing.value.operation.as_str(),
                existing.value.subject_id,
            ))
            .with_correlation_id(context.correlation_id.clone())),
            DataMutationDedupeState::Aborted => {
                let mut record = existing.value;
                record.state = DataMutationDedupeState::InFlight;
                record.error_message = None;
                record.completed_at = None;
                record.requested_by = context.actor.clone();
                record.correlation_id = context.correlation_id.clone();
                record.request_id = context.request_id.clone();
                record.attempt_count = record.attempt_count.saturating_add(1);
                let stored = self
                    .mutation_dedupes
                    .upsert(key, record.clone(), Some(existing.version))
                    .await?;
                Ok(DataMutationDedupeBeginOutcome::Proceed(Box::new(Some(
                    PendingDataMutationDedupe {
                        key: key.to_owned(),
                        version: stored.version,
                        record,
                    },
                ))))
            }
        }
    }

    async fn recover_data_mutation_dedupe_from_result(
        &self,
        key: &str,
        existing: StoredDocument<DataMutationDedupeRecord>,
        context: &RequestContext,
    ) -> Result<DataMutationDedupeBeginOutcome> {
        let Some(result_resource_kind) = existing.value.result_resource_kind.as_deref() else {
            return Err(PlatformError::unavailable(
                "data idempotency record is missing result resource kind",
            )
            .with_correlation_id(context.correlation_id.clone()));
        };
        let Some(result_resource_id) = existing.value.result_resource_id.as_deref() else {
            return Err(PlatformError::unavailable(
                "data idempotency record is missing result resource id",
            )
            .with_correlation_id(context.correlation_id.clone()));
        };
        let expected_kind = data_mutation_result_resource_kind(existing.value.operation);
        if result_resource_kind != expected_kind {
            return Err(
                PlatformError::unavailable(
                    "data idempotency record result resource kind does not match the operation",
                )
                .with_detail(format!(
                    "expected_kind={expected_kind}, stored_kind={result_resource_kind}, result_resource_id={result_resource_id}",
                ))
                .with_correlation_id(context.correlation_id.clone()),
            );
        }

        let status = data_mutation_replay_status(existing.value.operation);
        let response_body = self
            .build_data_mutation_response_body_from_result(
                existing.value.operation,
                existing.value.subject_kind.as_str(),
                existing.value.subject_id.as_str(),
                result_resource_id,
                context,
            )
            .await?;
        let mut record = existing.value;
        record.state = DataMutationDedupeState::Completed;
        record.response_status = Some(status.as_u16());
        record.response_body = Some(response_body.clone());
        record.error_message = None;
        record.requested_by = context.actor.clone().or(record.requested_by);
        record.correlation_id = context.correlation_id.clone();
        record.request_id = context.request_id.clone();
        record.attempt_count = record.attempt_count.saturating_add(1);
        if record.completed_at.is_none() {
            record.completed_at = Some(OffsetDateTime::now_utc());
        }

        match self
            .mutation_dedupes
            .upsert(key, record.clone(), Some(existing.version))
            .await
        {
            Ok(_) => {
                json_response(status, &response_body).map(DataMutationDedupeBeginOutcome::Replay)
            }
            Err(error) if error.code == ErrorCode::Conflict => {
                let Some(latest) = self.mutation_dedupes.get(key).await? else {
                    return Err(error);
                };
                if latest.value.response_body.is_some() {
                    return replay_data_mutation_response(&latest.value)
                        .map(DataMutationDedupeBeginOutcome::Replay);
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn build_data_mutation_response_body_from_result(
        &self,
        operation: DataMutationOperation,
        subject_kind: &str,
        subject_id: &str,
        result_resource_id: &str,
        context: &RequestContext,
    ) -> Result<serde_json::Value> {
        match operation {
            DataMutationOperation::Backup => {
                let stored = self
                    .backup_jobs
                    .get(result_resource_id)
                    .await?
                    .ok_or_else(|| {
                        PlatformError::unavailable(
                            "backup idempotency result resource does not exist",
                        )
                        .with_detail(result_resource_id.to_owned())
                        .with_correlation_id(context.correlation_id.clone())
                    })?;
                validate_data_mutation_result_subject(
                    operation,
                    subject_kind,
                    subject_id,
                    &stored.value.database_id,
                    result_resource_id,
                    context,
                )?;
                if stored.deleted {
                    return Err(PlatformError::conflict(
                        "backup idempotency result resource has been deleted",
                    )
                    .with_correlation_id(context.correlation_id.clone()));
                }
                if stored.value.state != "completed" {
                    return Err(PlatformError::conflict(
                        "backup idempotency result resource is not completed",
                    )
                    .with_detail(format!(
                        "backup_id={}, state={}",
                        result_resource_id, stored.value.state
                    ))
                    .with_correlation_id(context.correlation_id.clone()));
                }
                let reply = self
                    .build_backup_job_reply_with_storage_state_reason(&stored.value)
                    .await?;
                serialize_response_body(&reply, "backup idempotency recovery payload")
            }
            DataMutationOperation::Restore => {
                let stored = self
                    .restore_jobs
                    .get(result_resource_id)
                    .await?
                    .ok_or_else(|| {
                        PlatformError::unavailable(
                            "restore idempotency result resource does not exist",
                        )
                        .with_detail(result_resource_id.to_owned())
                        .with_correlation_id(context.correlation_id.clone())
                    })?;
                validate_data_mutation_result_subject(
                    operation,
                    subject_kind,
                    subject_id,
                    &stored.value.database_id,
                    result_resource_id,
                    context,
                )?;
                if stored.deleted {
                    return Err(PlatformError::conflict(
                        "restore idempotency result resource has been deleted",
                    )
                    .with_correlation_id(context.correlation_id.clone()));
                }
                if stored.value.state != "completed" {
                    return Err(PlatformError::conflict(
                        "restore idempotency result resource is not completed",
                    )
                    .with_detail(format!(
                        "restore_id={}, state={}",
                        result_resource_id, stored.value.state
                    ))
                    .with_correlation_id(context.correlation_id.clone()));
                }
                let reply = self
                    .build_restore_job_reply_with_storage_state_reason(&stored.value)
                    .await?;
                serialize_response_body(&reply, "restore idempotency recovery payload")
            }
            DataMutationOperation::Failover => {
                let stored = self
                    .failovers
                    .get(result_resource_id)
                    .await?
                    .ok_or_else(|| {
                        PlatformError::unavailable(
                            "failover idempotency result resource does not exist",
                        )
                        .with_detail(result_resource_id.to_owned())
                        .with_correlation_id(context.correlation_id.clone())
                    })?;
                validate_data_mutation_result_subject(
                    operation,
                    subject_kind,
                    subject_id,
                    &stored.value.database_id,
                    result_resource_id,
                    context,
                )?;
                if stored.deleted {
                    return Err(PlatformError::conflict(
                        "failover idempotency result resource has been deleted",
                    )
                    .with_correlation_id(context.correlation_id.clone()));
                }
                if stored.value.state != "completed" {
                    return Err(PlatformError::conflict(
                        "failover idempotency result resource is not completed",
                    )
                    .with_detail(format!(
                        "failover_id={}, state={}",
                        result_resource_id, stored.value.state
                    ))
                    .with_correlation_id(context.correlation_id.clone()));
                }
                serialize_response_body(&stored.value, "failover idempotency recovery payload")
            }
        }
    }

    async fn stage_data_mutation_result_reference(
        &self,
        pending: &mut Option<PendingDataMutationDedupe>,
        status: StatusCode,
        result_resource_kind: &str,
        result_resource_id: &str,
    ) -> Result<()> {
        let Some(pending) = pending.as_mut() else {
            return Ok(());
        };

        let mut record = pending.record.clone();
        record.response_status = Some(status.as_u16());
        record.result_resource_kind = Some(result_resource_kind.to_owned());
        record.result_resource_id = Some(result_resource_id.to_owned());
        let stored = self
            .mutation_dedupes
            .upsert(&pending.key, record.clone(), Some(pending.version))
            .await?;
        pending.version = stored.version;
        pending.record = record;
        Ok(())
    }

    async fn stage_data_mutation_response(
        &self,
        pending: &mut Option<PendingDataMutationDedupe>,
        status: StatusCode,
        response_body: &serde_json::Value,
        result_resource_kind: &str,
        result_resource_id: &str,
    ) -> Result<()> {
        let Some(pending) = pending.as_mut() else {
            return Ok(());
        };

        let mut record = pending.record.clone();
        record.response_status = Some(status.as_u16());
        record.response_body = Some(response_body.clone());
        record.result_resource_kind = Some(result_resource_kind.to_owned());
        record.result_resource_id = Some(result_resource_id.to_owned());
        let stored = self
            .mutation_dedupes
            .upsert(&pending.key, record.clone(), Some(pending.version))
            .await?;
        pending.version = stored.version;
        pending.record = record;
        Ok(())
    }

    async fn complete_data_mutation_dedupe(
        &self,
        pending: &mut Option<PendingDataMutationDedupe>,
    ) -> Result<()> {
        let Some(pending) = pending.as_mut() else {
            return Ok(());
        };

        let mut record = pending.record.clone();
        record.state = DataMutationDedupeState::Completed;
        record.completed_at = Some(OffsetDateTime::now_utc());
        record.error_message = None;
        let stored = self
            .mutation_dedupes
            .upsert(&pending.key, record.clone(), Some(pending.version))
            .await?;
        pending.version = stored.version;
        pending.record = record;
        Ok(())
    }

    async fn record_data_mutation_failure(
        &self,
        pending: &mut Option<PendingDataMutationDedupe>,
        error: &PlatformError,
    ) -> Result<()> {
        let Some(pending) = pending.as_mut() else {
            return Ok(());
        };

        let mut record = pending.record.clone();
        record.error_message = Some(error.message.clone());
        if record.response_body.is_some() {
            record.state = DataMutationDedupeState::Completed;
            record.completed_at = Some(OffsetDateTime::now_utc());
        } else {
            record.state = DataMutationDedupeState::Aborted;
            record.completed_at = None;
        }
        let stored = self
            .mutation_dedupes
            .upsert(&pending.key, record.clone(), Some(pending.version))
            .await?;
        pending.version = stored.version;
        pending.record = record;
        Ok(())
    }

    async fn backup_storage_lineage_recovery_point_state_reason(
        &self,
        recovery_point: &BackupStorageRecoveryPoint,
    ) -> Result<String> {
        let current = self
            .storage
            .describe_ready_volume_recovery_point(&recovery_point.volume_id)
            .await?;
        if current.as_ref().is_some_and(|current| {
            backup_storage_recovery_point_matches_summary(recovery_point, current)
        }) {
            return Ok(current_backup_storage_recovery_point_state_reason());
        }

        let historical_revision_available = self
            .storage
            .describe_volume_recovery_point(
                &recovery_point.volume_id,
                recovery_point.version,
                Some(recovery_point.etag.as_str()),
            )
            .await?
            .is_some();

        Ok(match (current.is_some(), historical_revision_available) {
            (true, true) => historical_backup_storage_recovery_point_state_reason(),
            (true, false) => unavailable_backup_storage_recovery_point_state_reason(),
            (false, true) => {
                historical_backup_storage_recovery_point_state_reason_without_current()
            }
            (false, false) => {
                unavailable_backup_storage_recovery_point_state_reason_without_current()
            }
        })
    }

    async fn build_backup_job_reply_with_storage_state_reason(
        &self,
        backup: &BackupJob,
    ) -> Result<BackupJobReply> {
        let mut reply = build_backup_job_reply(backup);
        if let Some(recovery_point) = backup.storage_recovery_point.as_ref() {
            reply.storage_recovery_point_state_reason = Some(
                self.backup_storage_lineage_recovery_point_state_reason(recovery_point)
                    .await?,
            );
        }
        Ok(reply)
    }

    async fn persist_backup_artifact_manifest(
        &self,
        backup_id: &AuditId,
        database: &ManagedDatabase,
        kind: &str,
        requested_by: &str,
        reason: Option<String>,
        created_at: OffsetDateTime,
        point_in_time: Option<OffsetDateTime>,
        storage_recovery_point: &BackupStorageRecoveryPoint,
    ) -> Result<BackupArtifactManifest> {
        let payload_path = backup_payload_artifact_path(&self.state_root, &database.id, backup_id);
        let payload = PersistedBackupPayload {
            schema_version: BACKUP_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            backup_id: backup_id.clone(),
            database_id: database.id.clone(),
            backup_kind: kind.to_owned(),
            requested_by: requested_by.to_owned(),
            reason,
            created_at,
            point_in_time,
            database_engine: database.engine.clone(),
            database_version: database.version.clone(),
            database_storage_gb: database.storage_gb,
            database_replica_count: database.replicas,
            primary_region: database.primary_region.clone(),
            backup_policy: database.backup_policy.clone(),
            storage_recovery_point: storage_recovery_point.clone(),
        };
        let (payload_size_bytes, payload_sha256) =
            write_json_artifact(&payload_path, &payload).await?;
        let payload_verification = verify_artifact_checksum(
            &payload_path,
            &payload_sha256,
            "backup payload artifact",
            created_at,
        )
        .await?;
        let key_ref = backup_artifact_key_ref(database);
        let payload_artifact = BackupArtifactDescriptor {
            kind: BackupArtifactKind::SnapshotBundle,
            object_location: backup_payload_object_location(&database.id, backup_id),
            sha256: payload_sha256,
            size_bytes: payload_size_bytes,
            key_ref: key_ref.clone(),
            verification: payload_verification,
        };
        let persisted_manifest = PersistedBackupArtifactManifest {
            schema_version: BACKUP_ARTIFACT_MANIFEST_SCHEMA_VERSION,
            backup_id: backup_id.clone(),
            database_id: database.id.clone(),
            generated_at: created_at,
            artifacts: vec![payload_artifact],
        };
        let manifest_path =
            backup_manifest_artifact_path(&self.state_root, &database.id, backup_id);
        let (manifest_size_bytes, manifest_sha256) =
            write_json_artifact(&manifest_path, &persisted_manifest).await?;
        let manifest_verification = verify_artifact_checksum(
            &manifest_path,
            &manifest_sha256,
            "backup manifest artifact",
            created_at,
        )
        .await?;

        Ok(BackupArtifactManifest {
            schema_version: persisted_manifest.schema_version,
            generated_at: persisted_manifest.generated_at,
            manifest_object_location: backup_manifest_object_location(&database.id, backup_id),
            manifest_sha256,
            manifest_size_bytes,
            manifest_key_ref: key_ref,
            manifest_verification,
            artifacts: persisted_manifest.artifacts,
        })
    }

    async fn verify_backup_artifact_manifest(&self, backup: &BackupJob) -> Result<()> {
        let Some(manifest) = backup.backup_artifact_manifest.as_ref() else {
            return Ok(());
        };

        let manifest_path =
            backup_manifest_artifact_path(&self.state_root, &backup.database_id, &backup.id);
        verify_artifact_checksum(
            &manifest_path,
            &manifest.manifest_sha256,
            "backup manifest artifact",
            OffsetDateTime::now_utc(),
        )
        .await?;
        let persisted_manifest: PersistedBackupArtifactManifest =
            read_json_artifact(&manifest_path, "backup manifest artifact").await?;
        if persisted_manifest.schema_version != manifest.schema_version {
            return Err(PlatformError::unavailable(
                "backup artifact manifest schema_version drifted",
            )
            .with_detail(format!(
                "backup_id={}, persisted_schema_version={}, stored_schema_version={}",
                backup.id.as_str(),
                persisted_manifest.schema_version,
                manifest.schema_version,
            )));
        }
        if persisted_manifest.backup_id != backup.id
            || persisted_manifest.database_id != backup.database_id
        {
            return Err(
                PlatformError::unavailable("backup artifact manifest identity drifted")
                    .with_detail(format!(
                        "backup_id={}, manifest_backup_id={}, manifest_database_id={}",
                        backup.id.as_str(),
                        persisted_manifest.backup_id.as_str(),
                        persisted_manifest.database_id.as_str(),
                    )),
            );
        }
        if persisted_manifest.generated_at != manifest.generated_at
            || persisted_manifest.artifacts != manifest.artifacts
        {
            return Err(
                PlatformError::unavailable("backup artifact manifest contents drifted")
                    .with_detail(format!("backup_id={}", backup.id.as_str())),
            );
        }

        let primary_artifact = manifest.artifacts.first().ok_or_else(|| {
            PlatformError::unavailable("backup artifact manifest is missing artifacts")
                .with_detail(format!("backup_id={}", backup.id.as_str()))
        })?;
        if backup.snapshot_uri != primary_artifact.object_location {
            return Err(
                PlatformError::unavailable("backup snapshot_uri drifted from manifest")
                    .with_detail(format!(
                        "backup_id={}, snapshot_uri={}, manifest_object_location={}",
                        backup.id.as_str(),
                        backup.snapshot_uri,
                        primary_artifact.object_location,
                    )),
            );
        }
        if backup.checksum != primary_artifact.sha256 {
            return Err(
                PlatformError::unavailable("backup checksum drifted from manifest").with_detail(
                    format!(
                        "backup_id={}, checksum={}, manifest_sha256={}",
                        backup.id.as_str(),
                        backup.checksum,
                        primary_artifact.sha256,
                    ),
                ),
            );
        }

        for artifact in &manifest.artifacts {
            let artifact_path = match artifact.kind {
                BackupArtifactKind::SnapshotBundle => {
                    backup_payload_artifact_path(&self.state_root, &backup.database_id, &backup.id)
                }
            };
            verify_artifact_checksum(
                &artifact_path,
                &artifact.sha256,
                "backup payload artifact",
                OffsetDateTime::now_utc(),
            )
            .await?;
        }

        Ok(())
    }

    async fn restore_storage_lineage_selected_recovery_point_state_reason(
        &self,
        recovery_point: &BackupStorageRecoveryPoint,
    ) -> Result<String> {
        let current = self
            .storage
            .describe_ready_volume_recovery_point(&recovery_point.volume_id)
            .await?;
        if current.as_ref().is_some_and(|current| {
            backup_storage_recovery_point_matches_summary(recovery_point, current)
        }) {
            return Ok(current_restore_selected_recovery_point_state_reason());
        }

        let historical_revision_available = self
            .storage
            .describe_volume_recovery_point(
                &recovery_point.volume_id,
                recovery_point.version,
                Some(recovery_point.etag.as_str()),
            )
            .await?
            .is_some();

        Ok(match (current.is_some(), historical_revision_available) {
            (true, true) => historical_restore_selected_recovery_point_state_reason(),
            (true, false) => unavailable_restore_selected_recovery_point_state_reason(),
            (false, true) => {
                historical_restore_selected_recovery_point_state_reason_without_current()
            }
            (false, false) => {
                unavailable_restore_selected_recovery_point_state_reason_without_current()
            }
        })
    }

    async fn build_restore_job_reply_with_storage_state_reason(
        &self,
        restore: &RestoreJob,
    ) -> Result<RestoreJobReply> {
        let mut reply = build_restore_job_reply(restore);
        if let Some(lineage) = restore.storage_restore.as_ref() {
            reply.storage_restore_selected_recovery_point_state_reason = Some(
                self.restore_storage_lineage_selected_recovery_point_state_reason(
                    &lineage.selected_recovery_point,
                )
                .await?,
            );
        }
        Ok(reply)
    }

    async fn durability_summary(&self) -> Result<DataDurabilitySummary> {
        let databases = active_values(self.databases.list().await?);
        let caches = active_values(self.caches.list().await?);
        let queues = active_values(self.queues.list().await?);
        let backup_jobs = active_values(self.backup_jobs.list().await?);
        let restore_jobs = active_values(self.restore_jobs.list().await?);
        let failovers = active_values(self.failovers.list().await?);
        let migrations = active_values(self.migrations.list().await?);
        let exports = active_values(self.export_jobs.list().await?);
        let imports = active_values(self.import_jobs.list().await?);

        let maintenance_mode_databases = databases
            .iter()
            .filter(|database| database.maintenance_mode)
            .count();

        let mut backup_job_state_counts = BTreeMap::new();
        for job in &backup_jobs {
            *backup_job_state_counts
                .entry(job.state.clone())
                .or_default() += 1;
        }

        let mut restore_job_state_counts = BTreeMap::new();
        for job in &restore_jobs {
            *restore_job_state_counts
                .entry(job.state.clone())
                .or_default() += 1;
        }

        let mut failover_state_counts = BTreeMap::new();
        for job in &failovers {
            *failover_state_counts.entry(job.state.clone()).or_default() += 1;
        }

        let mut migration_job_state_counts = BTreeMap::new();
        for job in &migrations {
            *migration_job_state_counts
                .entry(job.state.clone())
                .or_default() += 1;
        }

        let mut export_job_state_counts = BTreeMap::new();
        for job in &exports {
            *export_job_state_counts
                .entry(job.state.clone())
                .or_default() += 1;
        }

        let mut import_job_state_counts = BTreeMap::new();
        for job in &imports {
            *import_job_state_counts
                .entry(job.state.clone())
                .or_default() += 1;
        }

        Ok(DataDurabilitySummary {
            database_count: databases.len(),
            cache_count: caches.len(),
            queue_count: queues.len(),
            maintenance_mode_databases,
            backup_job_count: backup_jobs.len(),
            backup_job_state_counts,
            restore_job_count: restore_jobs.len(),
            restore_job_state_counts,
            failover_count: failovers.len(),
            failover_state_counts,
            migration_job_count: migrations.len(),
            migration_job_state_counts,
            export_job_count: exports.len(),
            export_job_state_counts,
            import_job_count: imports.len(),
            import_job_state_counts,
        })
    }

    /// Describe one persisted database restore lineage through an operator-only inspection view.
    pub async fn describe_restore_storage_lineage(
        &self,
        restore_id: &str,
        context: &RequestContext,
    ) -> Result<RestoreStorageLineageInspection> {
        require_operator_principal(context, "restore lineage inspection")?;
        let restore_id = AuditId::parse(restore_id).map_err(|error| {
            PlatformError::invalid("invalid restore_id").with_detail(error.to_string())
        })?;
        let restore = self
            .restore_jobs
            .get(restore_id.as_str())
            .await?
            .filter(|record| !record.deleted)
            .ok_or_else(|| {
                PlatformError::not_found("restore does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })?;

        let selected_recovery_point = restore
            .value
            .storage_restore
            .as_ref()
            .map(|lineage| &lineage.selected_recovery_point)
            .ok_or_else(|| {
                PlatformError::not_found("restore storage lineage does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })?;
        let selected_recovery_point_state_reason = self
            .restore_storage_lineage_selected_recovery_point_state_reason(selected_recovery_point)
            .await?;

        build_restore_storage_lineage_inspection(
            &restore.value,
            selected_recovery_point_state_reason,
        )
        .ok_or_else(|| {
            PlatformError::not_found("restore storage lineage does not exist")
                .with_correlation_id(context.correlation_id.clone())
        })
    }

    /// Describe one persisted database backup lineage through an operator-only inspection view.
    pub async fn describe_backup_storage_lineage(
        &self,
        backup_id: &str,
        context: &RequestContext,
    ) -> Result<BackupStorageLineageInspection> {
        require_operator_principal(context, "backup lineage inspection")?;
        let backup_id = AuditId::parse(backup_id).map_err(|error| {
            PlatformError::invalid("invalid backup_id").with_detail(error.to_string())
        })?;
        let backup = self
            .backup_jobs
            .get(backup_id.as_str())
            .await?
            .filter(|record| !record.deleted)
            .ok_or_else(|| {
                PlatformError::not_found("backup does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })?;

        let recovery_point = backup.value.storage_recovery_point.clone().ok_or_else(|| {
            PlatformError::not_found("backup storage lineage does not exist")
                .with_correlation_id(context.correlation_id.clone())
        })?;
        let recovery_point_state_reason = self
            .backup_storage_lineage_recovery_point_state_reason(&recovery_point)
            .await?;

        build_backup_storage_lineage_inspection(&backup.value, recovery_point_state_reason)
            .ok_or_else(|| {
                PlatformError::not_found("backup storage lineage does not exist")
                    .with_correlation_id(context.correlation_id.clone())
            })
    }

    async fn reconcile_database_topology(&self) -> Result<()> {
        for (key, stored) in self.databases.list().await? {
            if stored.deleted {
                continue;
            }
            let mut database = stored.value;
            let mut changed = false;
            if database.primary_region.trim().is_empty() {
                database.primary_region = default_primary_region();
                changed = true;
            }
            if database.replica_topology.is_empty() {
                database.replica_topology =
                    build_replica_topology(database.replicas, &database.primary_region);
                changed = true;
            }
            if database.lifecycle_state.trim().is_empty() {
                database.lifecycle_state = default_database_state();
                changed = true;
            }
            let storage_binding = self
                .storage
                .resolve_storage_binding(StorageResourceKind::Database, None, None)
                .await?;
            let binding_changed = apply_database_storage_binding(&mut database, &storage_binding);
            changed |= binding_changed;
            let volume = self.ensure_database_storage_volume(&database).await?;
            let storage_annotation_changed =
                apply_database_storage_binding_annotations(&mut database, &volume);
            let storage_changed = binding_changed || storage_annotation_changed;
            changed |= storage_annotation_changed;
            if changed {
                if storage_changed {
                    database
                        .metadata
                        .touch(database_storage_binding_etag(&database, &volume));
                }
                self.databases
                    .upsert(&key, database, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn reconcile_restore_crash_state(&self) -> Result<()> {
        self.reconcile_missing_restore_lineage().await?;
        self.reconcile_missing_restore_jobs().await?;
        self.reconcile_database_restore_projection().await
    }

    async fn reconcile_missing_restore_lineage(&self) -> Result<()> {
        let backups = active_values(self.backup_jobs.list().await?)
            .into_iter()
            .map(|backup| (backup.id.to_string(), backup))
            .collect::<BTreeMap<_, _>>();
        let databases = active_values(self.databases.list().await?);
        let mut latest_missing_by_scope =
            BTreeMap::<(String, String), (String, u64, RestoreJob)>::new();

        for (key, stored) in self.restore_jobs.list().await? {
            if stored.deleted || stored.value.storage_restore.is_some() {
                continue;
            }
            let scope = (
                stored.value.database_id.to_string(),
                stored.value.backup_id.to_string(),
            );
            let should_replace =
                latest_missing_by_scope
                    .get(&scope)
                    .is_none_or(|(_, _, current)| {
                        restore_sort_key(&stored.value) >= restore_sort_key(current)
                    });
            if should_replace {
                latest_missing_by_scope.insert(scope, (key, stored.version, stored.value));
            }
        }

        for database in databases {
            let Some(action_id) = parse_annotation_audit_id(
                &database.metadata.annotations,
                DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION,
            ) else {
                continue;
            };
            let Some(backup_id) = parse_annotation_audit_id(
                &database.metadata.annotations,
                DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION,
            ) else {
                continue;
            };
            let Some((restore_key, version, mut restore)) =
                latest_missing_by_scope.remove(&(database.id.to_string(), backup_id.to_string()))
            else {
                continue;
            };
            let Some(backup) = backups.get(backup_id.as_str()) else {
                continue;
            };
            let Some(restore_action) = self
                .storage
                .describe_volume_restore_action(&action_id)
                .await?
            else {
                continue;
            };
            let volume = self.ensure_database_storage_volume(&database).await?;
            let lineage = build_restore_storage_lineage(
                &volume,
                &restore_action,
                restore_uses_backup_correlated_storage_lineage(backup, &restore_action),
                backup.storage_recovery_point.as_ref(),
            );
            let mut changed = false;
            if restore.storage_restore.as_ref() != Some(&lineage) {
                restore.storage_restore = Some(lineage);
                changed = true;
            }
            if restore.state != restore_action.state {
                restore.state = restore_action.state.clone();
                changed = true;
            }
            if restore.completed_at.is_none() && restore_action.state == "completed" {
                restore.completed_at = Some(latest_timestamp(
                    database.metadata.updated_at,
                    restore.created_at,
                ));
                changed = true;
            }
            if changed {
                self.restore_jobs
                    .upsert(&restore_key, restore, Some(version))
                    .await?;
            }
        }

        Ok(())
    }

    async fn reconcile_missing_restore_jobs(&self) -> Result<()> {
        let backups = active_values(self.backup_jobs.list().await?)
            .into_iter()
            .map(|backup| (backup.id.to_string(), backup))
            .collect::<BTreeMap<_, _>>();
        let mut existing_action_ids = BTreeSet::new();
        for restore in active_values(self.restore_jobs.list().await?) {
            existing_action_ids.insert(restore.id.to_string());
            if let Some(lineage) = restore.storage_restore.as_ref() {
                existing_action_ids.insert(lineage.restore_action_id.to_string());
            }
        }

        for database in active_values(self.databases.list().await?) {
            let Some(action_id) = parse_annotation_audit_id(
                &database.metadata.annotations,
                DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION,
            ) else {
                continue;
            };
            if existing_action_ids.contains(action_id.as_str()) {
                continue;
            }

            let Some(backup_id) = parse_annotation_audit_id(
                &database.metadata.annotations,
                DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION,
            ) else {
                continue;
            };
            let Some(backup) = backups.get(backup_id.as_str()) else {
                continue;
            };
            let Some(restore_action) = self
                .storage
                .describe_volume_restore_action(&action_id)
                .await?
            else {
                continue;
            };
            let volume = self.ensure_database_storage_volume(&database).await?;
            let restore = RestoreJob {
                id: action_id.clone(),
                database_id: database.id.clone(),
                backup_id: backup.id.clone(),
                state: restore_action.state.clone(),
                requested_by: String::from(DATA_RECONCILER_ACTOR),
                created_at: database.metadata.updated_at,
                completed_at: (restore_action.state == "completed").then_some(latest_timestamp(
                    database.metadata.updated_at,
                    database.metadata.created_at,
                )),
                point_in_time: None,
                reason: Some(String::from(RECONCILED_RESTORE_REASON)),
                storage_restore: Some(build_restore_storage_lineage(
                    &volume,
                    &restore_action,
                    restore_uses_backup_correlated_storage_lineage(backup, &restore_action),
                    backup.storage_recovery_point.as_ref(),
                )),
            };

            match self.restore_jobs.get(action_id.as_str()).await? {
                Some(stored) if !stored.deleted && stored.value == restore => {}
                Some(stored) => {
                    self.restore_jobs
                        .upsert(action_id.as_str(), restore, Some(stored.version))
                        .await?;
                }
                None => {
                    self.restore_jobs
                        .create(action_id.as_str(), restore)
                        .await?;
                }
            }
            existing_action_ids.insert(action_id.to_string());
        }

        Ok(())
    }

    async fn reconcile_database_restore_projection(&self) -> Result<()> {
        let mut latest_restore_by_database = BTreeMap::<String, RestoreJob>::new();
        for restore in active_values(self.restore_jobs.list().await?) {
            if restore.storage_restore.is_none() {
                continue;
            }
            let database_id = restore.database_id.to_string();
            let should_replace = latest_restore_by_database
                .get(&database_id)
                .is_none_or(|current| restore_sort_key(&restore) >= restore_sort_key(current));
            if should_replace {
                latest_restore_by_database.insert(database_id, restore);
            }
        }

        for (database_id, restore) in latest_restore_by_database {
            let Some(stored_database) = self.databases.get(&database_id).await? else {
                continue;
            };
            if stored_database.deleted {
                continue;
            }
            let Some(lineage) = restore.storage_restore.as_ref() else {
                continue;
            };
            let volume = self
                .ensure_database_storage_volume(&stored_database.value)
                .await?;
            let restore_action =
                build_restore_action_summary_from_lineage(lineage, restore.state.as_str());
            let mut database = stored_database.value;
            let mut changed = false;
            if restore.state == "completed" {
                if database.lifecycle_state != default_database_state() {
                    database.lifecycle_state = default_database_state();
                    changed = true;
                }
                if database.maintenance_mode {
                    database.maintenance_mode = false;
                    changed = true;
                }
                if database.maintenance_reason.is_some() {
                    database.maintenance_reason = None;
                    changed = true;
                }
            }
            let storage_changed =
                apply_database_storage_binding_annotations(&mut database, &volume);
            let lineage_changed = apply_database_restore_lineage_annotations(
                &mut database,
                &restore.backup_id,
                &volume,
                &restore_action,
            );
            changed |= storage_changed;
            changed |= lineage_changed;
            if changed {
                if lineage_changed {
                    database.metadata.touch(database_restore_lineage_etag(
                        &database,
                        &restore.backup_id,
                        &restore_action,
                    ));
                } else if storage_changed {
                    database
                        .metadata
                        .touch(database_storage_binding_etag(&database, &volume));
                } else {
                    database.metadata.touch(sha256_hex(
                        format!(
                            "{}:restore-reconcile:{}",
                            database.id.as_str(),
                            restore.id.as_str(),
                        )
                        .as_bytes(),
                    ));
                }
                let database_id = database.id.as_str().to_owned();
                self.databases
                    .upsert(
                        database_id.as_str(),
                        database,
                        Some(stored_database.version),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn reconcile_operation_workflows(&self) -> Result<()> {
        self.reconcile_backup_workflows().await?;
        self.reconcile_restore_workflows().await?;
        self.reconcile_failover_workflows().await
    }

    async fn reconcile_incomplete_operation_workflows(&self) -> Result<()> {
        self.resume_incomplete_backup_workflows().await?;
        self.resume_incomplete_restore_workflows().await?;
        self.resume_incomplete_failover_workflows().await
    }

    async fn migrate_pre_ledger_inflight_operation_workflows(&self) -> Result<()> {
        self.migrate_pre_ledger_inflight_restore_workflows().await?;
        self.migrate_pre_ledger_inflight_failover_workflows().await
    }

    async fn migrate_pre_ledger_inflight_restore_workflows(&self) -> Result<()> {
        for (workflow_id, stored) in self.restore_workflows.list().await? {
            if stored.deleted {
                continue;
            }
            let mut workflow = stored.value;
            if !upgrade_pre_ledger_inflight_restore_workflow(
                &mut workflow,
                OffsetDateTime::now_utc(),
            )? {
                continue;
            }
            sync_workflow_projection(&self.restore_workflows, &workflow_id, workflow).await?;
        }
        Ok(())
    }

    async fn migrate_pre_ledger_inflight_failover_workflows(&self) -> Result<()> {
        for (workflow_id, stored) in self.failover_workflows.list().await? {
            if stored.deleted {
                continue;
            }
            let mut workflow = stored.value;
            if !upgrade_pre_ledger_inflight_failover_workflow(
                &mut workflow,
                OffsetDateTime::now_utc(),
            )? {
                continue;
            }
            sync_workflow_projection(&self.failover_workflows, &workflow_id, workflow).await?;
        }
        Ok(())
    }

    async fn resume_incomplete_backup_workflows(&self) -> Result<()> {
        let workflow_ids = self
            .backup_workflows
            .list()
            .await?
            .into_iter()
            .filter_map(|(workflow_id, stored)| {
                (!stored.deleted && workflow_requires_resume(&stored.value.phase))
                    .then_some(workflow_id)
            })
            .collect::<Vec<_>>();

        for workflow_id in workflow_ids {
            if let Err(error) = self.execute_backup_workflow(workflow_id.as_str()).await {
                let phase = self
                    .backup_workflows
                    .get(workflow_id.as_str())
                    .await?
                    .filter(|stored| !stored.deleted)
                    .map(|stored| stored.value.phase);
                if !phase
                    .as_ref()
                    .is_some_and(workflow_resume_error_is_terminal)
                {
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    async fn resume_incomplete_restore_workflows(&self) -> Result<()> {
        let workflow_ids = self
            .restore_workflows
            .list()
            .await?
            .into_iter()
            .filter_map(|(workflow_id, stored)| {
                (!stored.deleted
                    && workflow_requires_resume(&stored.value.phase)
                    && (stored.value.state.selected_recovery_point.is_some()
                        || stored.value.state.storage_restore.is_some()))
                .then_some(workflow_id)
            })
            .collect::<Vec<_>>();

        for workflow_id in workflow_ids {
            if let Err(error) = self.execute_restore_workflow(workflow_id.as_str()).await {
                let phase = self
                    .restore_workflows
                    .get(workflow_id.as_str())
                    .await?
                    .filter(|stored| !stored.deleted)
                    .map(|stored| stored.value.phase);
                if !phase
                    .as_ref()
                    .is_some_and(workflow_resume_error_is_terminal)
                {
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    async fn resume_incomplete_failover_workflows(&self) -> Result<()> {
        let workflow_ids = self
            .failover_workflows
            .list()
            .await?
            .into_iter()
            .filter_map(|(workflow_id, stored)| {
                (!stored.deleted && workflow_requires_resume(&stored.value.phase))
                    .then_some(workflow_id)
            })
            .collect::<Vec<_>>();

        for workflow_id in workflow_ids {
            if let Err(error) = self.execute_failover_workflow(workflow_id.as_str()).await {
                let phase = self
                    .failover_workflows
                    .get(workflow_id.as_str())
                    .await?
                    .filter(|stored| !stored.deleted)
                    .map(|stored| stored.value.phase);
                if !phase
                    .as_ref()
                    .is_some_and(workflow_resume_error_is_terminal)
                {
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    async fn reconcile_backup_workflows(&self) -> Result<()> {
        for (key, stored) in self.backup_workflows.list().await? {
            if stored.deleted {
                continue;
            }
            sync_document_projection(
                &self.backup_jobs,
                &key,
                build_backup_job_from_workflow(&stored.value),
            )
            .await?;
        }

        for (key, stored) in self.backup_jobs.list().await? {
            if stored.deleted {
                continue;
            }
            sync_workflow_projection(
                &self.backup_workflows,
                &key,
                build_backfilled_backup_workflow(&stored.value),
            )
            .await?;
        }

        Ok(())
    }

    async fn reconcile_restore_workflows(&self) -> Result<()> {
        for (key, stored) in self.restore_workflows.list().await? {
            if stored.deleted {
                continue;
            }
            let mut projected = build_restore_job_from_workflow(&stored.value);
            if projected.storage_restore.is_none()
                && let Some(existing) = self.restore_jobs.get(&key).await?
                && !existing.deleted
                && existing.value.storage_restore.is_some()
            {
                projected.storage_restore = existing.value.storage_restore.clone();
                projected.state = existing.value.state.clone();
                projected.completed_at = existing.value.completed_at;
            }
            sync_document_projection(&self.restore_jobs, &key, projected).await?;
        }

        for (key, stored) in self.restore_jobs.list().await? {
            if stored.deleted {
                continue;
            }
            if self
                .restore_workflows
                .get(&key)
                .await?
                .is_some_and(|existing| !existing.deleted)
            {
                continue;
            }
            let target_volume_id = match self.restore_workflow_target_volume_id(&stored.value).await
            {
                Ok(target_volume_id) => target_volume_id,
                Err(error) if error.code == ErrorCode::NotFound => continue,
                Err(error) => return Err(error),
            };
            sync_workflow_projection(
                &self.restore_workflows,
                &key,
                build_backfilled_restore_workflow(&stored.value, target_volume_id),
            )
            .await?;
        }

        Ok(())
    }

    async fn reconcile_failover_workflows(&self) -> Result<()> {
        for (key, stored) in self.failover_workflows.list().await? {
            if stored.deleted {
                continue;
            }
            sync_document_projection(
                &self.failovers,
                &key,
                build_failover_record_from_workflow(&stored.value),
            )
            .await?;
        }

        for (key, stored) in self.failovers.list().await? {
            if stored.deleted {
                continue;
            }
            if self
                .failover_workflows
                .get(&key)
                .await?
                .is_some_and(|existing| !existing.deleted)
            {
                continue;
            }
            let target_region = match self.failover_workflow_target_region(&stored.value).await {
                Ok(target_region) => target_region,
                Err(error) if error.code == ErrorCode::NotFound => continue,
                Err(error) => return Err(error),
            };
            sync_workflow_projection(
                &self.failover_workflows,
                &key,
                build_backfilled_failover_workflow(&stored.value, target_region),
            )
            .await?;
        }

        Ok(())
    }

    async fn restore_workflow_target_volume_id(&self, restore: &RestoreJob) -> Result<VolumeId> {
        if let Some(lineage) = restore.storage_restore.as_ref() {
            return Ok(lineage.storage_volume_id.clone());
        }
        let database = self.load_database(restore.database_id.as_str()).await?;
        let volume = self.ensure_database_storage_volume(&database).await?;
        Ok(volume.id)
    }

    async fn failover_workflow_target_region(
        &self,
        failover: &DataFailoverRecord,
    ) -> Result<String> {
        let database = self.load_database(failover.database_id.as_str()).await?;
        Ok(database
            .replica_topology
            .iter()
            .find(|replica| replica.id == failover.to_replica_id)
            .map(|replica| replica.region.clone())
            .unwrap_or_else(|| database.primary_region.clone()))
    }

    async fn reconcile_operation_outbox(&self) -> Result<()> {
        let mut signatures = self.load_outbox_event_signatures().await?;

        for backup in active_values(self.backup_jobs.list().await?) {
            if backup.state != "completed" {
                continue;
            }
            self.ensure_outbox_event(
                &mut signatures,
                "data.database.backup.completed.v1",
                "database_backup",
                backup.id.as_str(),
                "completed",
                backup_completed_event_details(&backup),
            )
            .await?;
        }

        for restore in active_values(self.restore_jobs.list().await?) {
            if restore.state != "completed" {
                continue;
            }
            self.ensure_outbox_event(
                &mut signatures,
                "data.database.restore.completed.v1",
                "database_restore",
                restore.id.as_str(),
                "completed",
                restore_completed_event_details(&restore),
            )
            .await?;
        }

        for failover in active_values(self.failovers.list().await?) {
            if failover.state != "completed" {
                continue;
            }
            self.ensure_outbox_event(
                &mut signatures,
                "data.database.failover.completed.v1",
                "database_failover",
                failover.id.as_str(),
                "completed",
                failover_completed_event_details(&failover),
            )
            .await?;
        }

        Ok(())
    }

    async fn load_outbox_event_signatures(
        &self,
    ) -> Result<BTreeSet<(String, String, String, String)>> {
        let mut signatures = BTreeSet::new();
        for message in self.outbox.list_all().await? {
            if let Some(signature) = outbox_event_signature(&message.payload) {
                signatures.insert(signature);
            }
        }
        Ok(signatures)
    }

    async fn ensure_outbox_event(
        &self,
        signatures: &mut BTreeSet<(String, String, String, String)>,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        let signature =
            build_outbox_event_signature(event_type, resource_kind, resource_id, action);
        if signatures.contains(&signature) {
            return Ok(());
        }

        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate data event id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("data"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: String::from(DATA_RECONCILER_ACTOR),
                    actor_type: String::from("controller"),
                    source_ip: None,
                    correlation_id: format!("reconcile:{resource_kind}:{resource_id}:{action}"),
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
        let idempotency_key = format!("{event_type}:{resource_kind}:{resource_id}:{action}");
        let _ = self
            .outbox
            .enqueue(DATA_EVENTS_TOPIC, event, Some(idempotency_key.as_str()))
            .await?;
        signatures.insert(signature);
        Ok(())
    }

    async fn ensure_database_storage_volume(
        &self,
        database: &ManagedDatabase,
    ) -> Result<VolumeRecord> {
        self.storage
            .ensure_attached_volume(
                database.id.as_str(),
                &database_backing_volume_name(database),
                database.storage_gb.max(1),
                database.storage_binding.as_ref(),
            )
            .await
    }

    async fn sync_backup_job_projection(&self, workflow: &BackupWorkflow) -> Result<()> {
        sync_document_projection(
            &self.backup_jobs,
            workflow.id.as_str(),
            build_backup_job_from_workflow(workflow),
        )
        .await
    }

    async fn sync_restore_job_projection(&self, workflow: &RestoreWorkflow) -> Result<()> {
        sync_document_projection(
            &self.restore_jobs,
            workflow.id.as_str(),
            build_restore_job_from_workflow(workflow),
        )
        .await
    }

    async fn sync_failover_projection(&self, workflow: &FailoverWorkflow) -> Result<()> {
        sync_document_projection(
            &self.failovers,
            workflow.id.as_str(),
            build_failover_record_from_workflow(workflow),
        )
        .await
    }

    async fn persist_workflow_effect_ledger<T>(
        &self,
        workflow: &WorkflowInstance<T>,
        step_index: usize,
        effect_kind: &str,
        result_digest: &str,
        observed_at: OffsetDateTime,
    ) -> Result<StoredDocument<WorkflowEffectLedgerRecord>>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let ledger = WorkflowEffectLedgerRecord::from_workflow_effect_at(
            workflow,
            step_index,
            effect_kind,
            result_digest,
            observed_at,
        )?;
        let ledger_key = ledger.key().to_owned();

        loop {
            match self
                .workflow_effect_ledgers
                .get(ledger_key.as_str())
                .await?
            {
                Some(existing) if !existing.deleted => {
                    existing.value.validate_for_workflow(workflow)?;
                    if existing.value.result_digest != result_digest {
                        return Err(PlatformError::conflict(format!(
                            "workflow effect ledger for `{effect_kind}` already records a different result digest"
                        )));
                    }
                    return Ok(existing);
                }
                Some(existing) => {
                    match self
                        .workflow_effect_ledgers
                        .upsert(ledger_key.as_str(), ledger.clone(), Some(existing.version))
                        .await
                    {
                        Ok(updated) => return Ok(updated),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self
                    .workflow_effect_ledgers
                    .create(ledger_key.as_str(), ledger.clone())
                    .await
                {
                    Ok(created) => return Ok(created),
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                },
            }
        }
    }

    async fn load_workflow_effect_ledger<T>(
        &self,
        workflow: &WorkflowInstance<T>,
        step_index: usize,
        effect_kind: &str,
    ) -> Result<Option<StoredDocument<WorkflowEffectLedgerRecord>>>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let effect = match workflow
            .step(step_index)
            .and_then(|step| step.effect(effect_kind))
        {
            Some(effect) => effect,
            None => return Ok(None),
        };
        let stored = match self
            .workflow_effect_ledgers
            .get(effect.idempotency_key.as_str())
            .await?
        {
            Some(stored) if !stored.deleted => stored,
            _ => return Ok(None),
        };
        stored.value.validate_for_workflow(workflow)?;
        Ok(Some(stored))
    }

    async fn begin_restore_storage_effect(
        &self,
        workflow_id: &str,
    ) -> Result<(StoredDocument<RestoreWorkflow>, WorkflowStepEffectExecution)> {
        let stored = self.load_restore_workflow(workflow_id).await?;
        let detail = restore_storage_effect_detail(&stored.value.state)?;
        let idempotency_key = restore_storage_effect_idempotency_key(&stored.value.state)?;
        let (stored, effect_execution) = self
            .restore_workflows
            .begin_step_effect_at(
                workflow_id,
                1,
                DATA_RESTORE_STORAGE_EFFECT_KIND,
                idempotency_key.as_str(),
                Some(detail),
                OffsetDateTime::now_utc(),
            )
            .await?;
        self.sync_restore_job_projection(&stored.value).await?;
        Ok((stored, effect_execution))
    }

    async fn begin_restore_projection_effect(
        &self,
        workflow_id: &str,
    ) -> Result<(StoredDocument<RestoreWorkflow>, WorkflowStepEffectExecution)> {
        let stored = self.load_restore_workflow(workflow_id).await?;
        let detail = restore_projection_effect_detail(&stored.value.state)?;
        let idempotency_key = restore_projection_effect_idempotency_key(&stored.value.state)?;
        let (stored, effect_execution) = self
            .restore_workflows
            .begin_step_effect_at(
                workflow_id,
                DATA_RESTORE_FINAL_STEP_INDEX,
                DATA_RESTORE_PROJECTION_EFFECT_KIND,
                idempotency_key.as_str(),
                Some(detail),
                OffsetDateTime::now_utc(),
            )
            .await?;
        self.sync_restore_job_projection(&stored.value).await?;
        Ok((stored, effect_execution))
    }

    async fn begin_failover_promotion_effect(
        &self,
        workflow_id: &str,
    ) -> Result<(
        StoredDocument<FailoverWorkflow>,
        WorkflowStepEffectExecution,
    )> {
        let stored = self.load_failover_workflow(workflow_id).await?;
        let detail = failover_promotion_effect_detail(&stored.value.state);
        let idempotency_key = failover_promotion_effect_idempotency_key(&stored.value.state);
        let (stored, effect_execution) = self
            .failover_workflows
            .begin_step_effect_at(
                workflow_id,
                1,
                DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                idempotency_key.as_str(),
                Some(detail),
                OffsetDateTime::now_utc(),
            )
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok((stored, effect_execution))
    }

    async fn load_restore_storage_action_for_result(
        &self,
        state: &RestoreWorkflowState,
        result_digest: &str,
    ) -> Result<VolumeRestoreActionSummary> {
        let selected_recovery_point = state.selected_recovery_point.as_ref().ok_or_else(|| {
            PlatformError::conflict("restore workflow is missing selected recovery point")
        })?;
        let action_id = AuditId::parse(result_digest).map_err(|error| {
            PlatformError::unavailable(
                "restore effect result digest is not a valid storage restore action id",
            )
            .with_detail(error.to_string())
        })?;
        let restore_action = self
            .storage
            .describe_volume_restore_action(&action_id)
            .await?
            .ok_or_else(|| {
                PlatformError::unavailable(
                    "storage restore action does not exist after restore execution",
                )
                .with_detail(format!("restore_action_id={result_digest}"))
            })?;
        if restore_action.state != "completed"
            || restore_action.volume_id != state.target_volume_id
            || build_restore_storage_recovery_point(&restore_action) != *selected_recovery_point
        {
            return Err(PlatformError::conflict(
                "recorded storage restore effect no longer matches restore workflow state",
            ));
        }
        Ok(restore_action)
    }

    async fn build_restore_storage_lineage_for_state(
        &self,
        state: &RestoreWorkflowState,
        restore_action: &VolumeRestoreActionSummary,
    ) -> Result<RestoreStorageLineage> {
        let database = self.load_database(state.database_id.as_str()).await?;
        let volume = self.ensure_database_storage_volume(&database).await?;
        if volume.id != state.target_volume_id {
            return Err(PlatformError::conflict(
                "restore workflow target volume no longer matches the database storage volume",
            ));
        }
        Ok(build_restore_storage_lineage(
            &volume,
            restore_action,
            matches!(
                state.source_mode,
                Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage)
            ),
            state.backup_correlated_recovery_point.as_ref(),
        ))
    }

    async fn build_projected_restore_database(
        &self,
        current: ManagedDatabase,
        state: &RestoreWorkflowState,
    ) -> Result<(ManagedDatabase, bool)> {
        let storage_restore = state.storage_restore.as_ref().ok_or_else(|| {
            PlatformError::conflict("restore workflow is missing storage restore lineage")
        })?;
        let volume = self.ensure_database_storage_volume(&current).await?;
        if volume.id != state.target_volume_id {
            return Err(PlatformError::conflict(
                "restore workflow target volume no longer matches the database storage volume",
            ));
        }
        let restore_action_summary =
            build_restore_action_summary_from_lineage(storage_restore, "completed");
        let mut database = current;
        database.lifecycle_state = default_database_state();
        database.maintenance_mode = false;
        database.maintenance_reason = None;
        let storage_changed = apply_database_restore_lineage_annotations(
            &mut database,
            &state.backup_id,
            &volume,
            &restore_action_summary,
        );
        Ok((database, storage_changed))
    }

    async fn restore_projection_effect_result_if_current(
        &self,
        workflow: &RestoreWorkflow,
    ) -> Result<Option<String>> {
        let current = self
            .load_database_record(workflow.state.database_id.as_str())
            .await?;
        let (projected, _storage_changed) = self
            .build_projected_restore_database(current.value.clone(), &workflow.state)
            .await?;
        if projected != current.value {
            return Ok(None);
        }
        Ok(Some(restore_projection_effect_result_digest(
            &current.value,
            &workflow.state,
        )?))
    }

    async fn failover_promotion_effect_result_if_current(
        &self,
        workflow: &FailoverWorkflow,
    ) -> Result<Option<String>> {
        let current = self
            .load_database_record(workflow.state.database_id.as_str())
            .await?;
        let database = &current.value;
        let current_primary = database
            .replica_topology
            .iter()
            .find(|replica| replica.role == "primary");
        let Some(from_replica) = database
            .replica_topology
            .iter()
            .find(|replica| replica.id == workflow.state.from_replica_id)
        else {
            return Ok(None);
        };
        if current_primary.map(|replica| replica.id.as_str())
            != Some(workflow.state.to_replica_id.as_str())
            || from_replica.role != "replica"
            || database.primary_region != workflow.state.target_region
            || database.lifecycle_state != default_database_state()
        {
            return Ok(None);
        }
        Ok(Some(failover_promotion_effect_result_digest(
            database,
            &workflow.state,
        )?))
    }

    async fn replay_restore_storage_effect_from_ledger(
        &self,
        workflow: &RestoreWorkflow,
    ) -> Result<Option<(RestoreStorageLineage, String)>> {
        let Some(stored) = self
            .load_workflow_effect_ledger(workflow, 1, DATA_RESTORE_STORAGE_EFFECT_KIND)
            .await?
        else {
            return Ok(None);
        };
        let result_digest = stored.value.result_digest.clone();
        let restore_action = self
            .load_restore_storage_action_for_result(&workflow.state, result_digest.as_str())
            .await?;
        let lineage = self
            .build_restore_storage_lineage_for_state(&workflow.state, &restore_action)
            .await?;
        Ok(Some((lineage, result_digest)))
    }

    async fn replay_restore_projection_effect_from_ledger(
        &self,
        workflow: &RestoreWorkflow,
    ) -> Result<Option<String>> {
        let Some(stored) = self
            .load_workflow_effect_ledger(
                workflow,
                DATA_RESTORE_FINAL_STEP_INDEX,
                DATA_RESTORE_PROJECTION_EFFECT_KIND,
            )
            .await?
        else {
            return Ok(None);
        };
        let Some(current_digest) = self
            .restore_projection_effect_result_if_current(workflow)
            .await?
        else {
            return Ok(None);
        };
        if current_digest == stored.value.result_digest {
            return Ok(Some(current_digest));
        }
        Ok(None)
    }

    async fn replay_failover_promotion_effect_from_ledger(
        &self,
        workflow: &FailoverWorkflow,
    ) -> Result<Option<String>> {
        let Some(stored) = self
            .load_workflow_effect_ledger(workflow, 1, DATA_FAILOVER_PROMOTION_EFFECT_KIND)
            .await?
        else {
            return Ok(None);
        };
        let Some(current_digest) = self
            .failover_promotion_effect_result_if_current(workflow)
            .await?
        else {
            return Ok(None);
        };
        if current_digest == stored.value.result_digest {
            return Ok(Some(current_digest));
        }
        Ok(None)
    }

    async fn finish_restore_storage_effect(
        &self,
        workflow_id: &str,
        restore_storage: RestoreStorageLineage,
        result_digest: &str,
        detail: String,
        evidence_detail: &'static str,
        refs: BTreeMap<String, String>,
    ) -> Result<StoredDocument<RestoreWorkflow>> {
        let observed_at = OffsetDateTime::now_utc();
        let stored = self
            .restore_workflows
            .mutate(workflow_id, |workflow| {
                workflow.state.storage_restore = Some(restore_storage.clone());
                workflow.current_step_index = Some(1);
                workflow.set_phase(WorkflowPhase::Running);
                {
                    let step = workflow.step_mut(1).ok_or_else(|| {
                        PlatformError::conflict(
                            "restore workflow storage execution step is missing",
                        )
                    })?;
                    let _effect = step.complete_effect_at(
                        DATA_RESTORE_STORAGE_EFFECT_KIND,
                        Some(result_digest),
                        Some(detail.clone()),
                        observed_at,
                    )?;
                    step.transition(WorkflowStepState::Completed, Some(detail.clone()));
                }
                workflow.current_step_index = Some(DATA_RESTORE_FINAL_STEP_INDEX);
                if let Some(step) = workflow.step_mut(DATA_RESTORE_FINAL_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Active,
                        Some(String::from("applying database restore projection")),
                    );
                }
                push_data_workflow_evidence(
                    &mut workflow.state.evidence,
                    "execute_storage_restore",
                    evidence_detail,
                    refs.clone(),
                );
                Ok(())
            })
            .await?;
        self.sync_restore_job_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn finish_restore_projection_effect(
        &self,
        workflow_id: &str,
        result_digest: &str,
        detail: String,
        evidence_detail: &'static str,
        refs: BTreeMap<String, String>,
    ) -> Result<StoredDocument<RestoreWorkflow>> {
        let observed_at = OffsetDateTime::now_utc();
        let stored = self
            .restore_workflows
            .mutate(workflow_id, |workflow| {
                workflow.current_step_index = Some(DATA_RESTORE_FINAL_STEP_INDEX);
                {
                    let step = workflow
                        .step_mut(DATA_RESTORE_FINAL_STEP_INDEX)
                        .ok_or_else(|| {
                            PlatformError::conflict("restore workflow projection step is missing")
                        })?;
                    let _effect = step.complete_effect_at(
                        DATA_RESTORE_PROJECTION_EFFECT_KIND,
                        Some(result_digest),
                        Some(detail.clone()),
                        observed_at,
                    )?;
                    step.transition(WorkflowStepState::Completed, Some(detail.clone()));
                }
                push_data_workflow_evidence(
                    &mut workflow.state.evidence,
                    "apply_database_restore_projection",
                    evidence_detail,
                    refs.clone(),
                );
                workflow.set_phase(WorkflowPhase::Completed);
                Ok(())
            })
            .await?;
        self.sync_restore_job_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn finish_failover_promotion_effect(
        &self,
        workflow_id: &str,
        result_digest: &str,
        detail: String,
        evidence_detail: &'static str,
        refs: BTreeMap<String, String>,
    ) -> Result<StoredDocument<FailoverWorkflow>> {
        let observed_at = OffsetDateTime::now_utc();
        let stored = self
            .failover_workflows
            .mutate(workflow_id, |workflow| {
                workflow.current_step_index = Some(1);
                workflow.set_phase(WorkflowPhase::Running);
                {
                    let step = workflow.step_mut(1).ok_or_else(|| {
                        PlatformError::conflict("failover workflow promotion step is missing")
                    })?;
                    let _effect = step.complete_effect_at(
                        DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                        Some(result_digest),
                        Some(detail.clone()),
                        observed_at,
                    )?;
                    step.transition(WorkflowStepState::Completed, Some(detail.clone()));
                }
                workflow.current_step_index = Some(DATA_FAILOVER_FINAL_STEP_INDEX);
                if let Some(step) = workflow.step_mut(DATA_FAILOVER_FINAL_STEP_INDEX) {
                    step.transition(
                        WorkflowStepState::Active,
                        Some(String::from("recording failover evidence")),
                    );
                }
                push_data_workflow_evidence(
                    &mut workflow.state.evidence,
                    "promote_target_replica",
                    evidence_detail,
                    refs.clone(),
                );
                Ok(())
            })
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn reconcile_restore_storage_effect_after_controller_death(
        &self,
        workflow: &RestoreWorkflow,
    ) -> Result<Option<(RestoreStorageLineage, String)>> {
        let state = &workflow.state;
        let Some(selected_recovery_point) = state.selected_recovery_point.as_ref() else {
            return Ok(None);
        };
        let database = self.load_database(state.database_id.as_str()).await?;
        let volume = self.ensure_database_storage_volume(&database).await?;
        if volume.id != state.target_volume_id {
            return Ok(None);
        }
        let Some(action_id) = parse_annotation_audit_id(
            &volume.metadata.annotations,
            VOLUME_LAST_RESTORE_ACTION_ID_ANNOTATION,
        ) else {
            return Ok(None);
        };
        let Some(storage_restore) = self
            .storage
            .describe_volume_restore_action(&action_id)
            .await?
        else {
            return Ok(None);
        };
        if storage_restore.state != "completed"
            || storage_restore.volume_id != state.target_volume_id
            || build_restore_storage_recovery_point(&storage_restore) != *selected_recovery_point
        {
            return Ok(None);
        }

        let restore_storage_lineage = build_restore_storage_lineage(
            &volume,
            &storage_restore,
            matches!(
                state.source_mode,
                Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage)
            ),
            state.backup_correlated_recovery_point.as_ref(),
        );
        Ok(Some((
            restore_storage_lineage,
            storage_restore.id.to_string(),
        )))
    }

    async fn reconcile_failover_effect_after_controller_death(
        &self,
        workflow: &FailoverWorkflow,
    ) -> Result<Option<String>> {
        let database = self
            .load_database(workflow.state.database_id.as_str())
            .await?;
        let current_primary = database
            .replica_topology
            .iter()
            .find(|replica| replica.role == "primary");
        let Some(from_replica) = database
            .replica_topology
            .iter()
            .find(|replica| replica.id == workflow.state.from_replica_id)
        else {
            return Ok(None);
        };
        if current_primary.map(|replica| replica.id.as_str())
            != Some(workflow.state.to_replica_id.as_str())
            || from_replica.role != "replica"
            || database.primary_region != workflow.state.target_region
            || database.lifecycle_state != default_database_state()
        {
            return Ok(None);
        }
        Ok(Some(failover_promotion_effect_result_digest(
            &database,
            &workflow.state,
        )?))
    }

    async fn load_backup_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<BackupWorkflow>> {
        let stored = self
            .backup_workflows
            .get(workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("backup workflow does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict("backup workflow has been deleted"));
        }
        Ok(stored)
    }

    async fn load_restore_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<RestoreWorkflow>> {
        let stored = self
            .restore_workflows
            .get(workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("restore workflow does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict("restore workflow has been deleted"));
        }
        Ok(stored)
    }

    async fn load_failover_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<StoredDocument<FailoverWorkflow>> {
        let stored = self
            .failover_workflows
            .get(workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("failover workflow does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::conflict(
                "failover workflow has been deleted",
            ));
        }
        Ok(stored)
    }

    async fn mark_restore_workflow_failed(
        &self,
        workflow_id: &str,
        step_index: usize,
        step_name: &str,
        detail: String,
    ) -> Result<()> {
        let stored = self
            .restore_workflows
            .mutate(workflow_id, |workflow| {
                workflow.current_step_index = Some(step_index);
                if let Some(step) = workflow.step_mut(step_index) {
                    step.transition(WorkflowStepState::Failed, Some(detail.clone()));
                }
                let mut refs = BTreeMap::new();
                refs.insert(String::from("step_index"), step_index.to_string());
                push_data_workflow_evidence(
                    &mut workflow.state.evidence,
                    step_name,
                    detail.clone(),
                    refs,
                );
                workflow.set_phase(WorkflowPhase::Failed);
                Ok(())
            })
            .await?;
        self.sync_restore_job_projection(&stored.value).await
    }

    async fn mark_failover_workflow_failed(
        &self,
        workflow_id: &str,
        step_index: usize,
        step_name: &str,
        detail: String,
    ) -> Result<()> {
        let stored = self
            .failover_workflows
            .mutate(workflow_id, |workflow| {
                workflow.current_step_index = Some(step_index);
                if let Some(step) = workflow.step_mut(step_index) {
                    step.transition(WorkflowStepState::Failed, Some(detail.clone()));
                }
                let mut refs = BTreeMap::new();
                refs.insert(String::from("step_index"), step_index.to_string());
                push_data_workflow_evidence(
                    &mut workflow.state.evidence,
                    step_name,
                    detail.clone(),
                    refs,
                );
                workflow.set_phase(WorkflowPhase::Failed);
                Ok(())
            })
            .await?;
        self.sync_failover_projection(&stored.value).await
    }

    async fn execute_backup_workflow(&self, workflow_id: &str) -> Result<BackupJob> {
        let stored = self.load_backup_workflow(workflow_id).await?;
        if stored.value.phase == WorkflowPhase::Completed {
            self.sync_backup_job_projection(&stored.value).await?;
            return Ok(build_backup_job_from_workflow(&stored.value));
        }
        if matches!(
            stored.value.phase,
            WorkflowPhase::Failed | WorkflowPhase::RolledBack
        ) {
            return Err(PlatformError::conflict("backup workflow is not executable"));
        }

        if matches!(
            data_workflow_step_state(&stored.value, 0),
            Some(WorkflowStepState::Pending)
        ) {
            let stored =
                self.backup_workflows
                    .mutate(workflow_id, |workflow| {
                        let recovery_point = workflow
                            .state
                            .storage_recovery_point
                            .clone()
                            .ok_or_else(|| {
                                PlatformError::conflict(
                                    "backup workflow is missing persisted storage recovery point",
                                )
                            })?;
                        workflow.current_step_index = Some(0);
                        workflow.set_phase(WorkflowPhase::Running);
                        if let Some(step) = workflow.step_mut(0) {
                            step.transition(
                                WorkflowStepState::Completed,
                                Some(format!(
                                    "captured persisted storage recovery point version {}",
                                    recovery_point.version
                                )),
                            );
                        }
                        workflow.current_step_index = Some(1);
                        if let Some(step) = workflow.step_mut(1) {
                            step.transition(
                                WorkflowStepState::Active,
                                Some(String::from("materializing backup snapshot projection")),
                            );
                        }
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("storage_recovery_point_version"),
                            recovery_point.version.to_string(),
                        );
                        refs.insert(
                            String::from("storage_recovery_point_etag"),
                            recovery_point.etag,
                        );
                        push_data_workflow_evidence(
                            &mut workflow.state.evidence,
                            "capture_storage_recovery_point",
                            "captured persisted storage recovery point for backup workflow",
                            refs,
                        );
                        Ok(())
                    })
                    .await?;
            self.sync_backup_job_projection(&stored.value).await?;
        }

        let stored = self.load_backup_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, 1),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let stored = self
                .backup_workflows
                .mutate(workflow_id, |workflow| {
                    let snapshot_uri = workflow.state.snapshot_uri.clone();
                    let checksum = workflow.state.checksum.clone();
                    let backup_artifact_manifest = workflow.state.backup_artifact_manifest.clone();
                    workflow.current_step_index = Some(1);
                    workflow.set_phase(WorkflowPhase::Running);
                    if let Some(step) = workflow.step_mut(1) {
                        step.transition(
                            WorkflowStepState::Completed,
                            Some(format!("materialized backup artifacts at {snapshot_uri}")),
                        );
                    }
                    workflow.current_step_index = Some(DATA_BACKUP_FINAL_STEP_INDEX);
                    if let Some(step) = workflow.step_mut(DATA_BACKUP_FINAL_STEP_INDEX) {
                        step.transition(
                            WorkflowStepState::Active,
                            Some(String::from("recording replayable backup evidence")),
                        );
                    }
                    let mut refs = BTreeMap::new();
                    refs.insert(String::from("snapshot_uri"), snapshot_uri);
                    refs.insert(String::from("checksum"), checksum);
                    if let Some(manifest) = backup_artifact_manifest {
                        refs.insert(
                            String::from("manifest_object_location"),
                            manifest.manifest_object_location,
                        );
                        refs.insert(String::from("manifest_sha256"), manifest.manifest_sha256);
                        if let Some(primary_artifact) = manifest.artifacts.first() {
                            if let Some(key_ref) = primary_artifact.key_ref.clone() {
                                refs.insert(String::from("key_ref"), key_ref);
                            }
                            refs.insert(
                                String::from("verification_state"),
                                format!("{:?}", primary_artifact.verification.state)
                                    .to_ascii_lowercase(),
                            );
                        }
                    }
                    push_data_workflow_evidence(
                        &mut workflow.state.evidence,
                        "materialize_backup_snapshot",
                        "materialized durable backup artifacts, manifest, and checksum evidence",
                        refs,
                    );
                    Ok(())
                })
                .await?;
            self.sync_backup_job_projection(&stored.value).await?;
        }

        let stored = self.load_backup_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, DATA_BACKUP_FINAL_STEP_INDEX),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let stored = self
                .backup_workflows
                .mutate(workflow_id, |workflow| {
                    let mut refs = BTreeMap::new();
                    refs.insert(
                        String::from("requested_by"),
                        workflow.state.requested_by.clone(),
                    );
                    if let Some(reason) = workflow.state.requested_reason.clone() {
                        refs.insert(String::from("reason"), reason);
                    }
                    workflow.current_step_index = Some(DATA_BACKUP_FINAL_STEP_INDEX);
                    if let Some(step) = workflow.step_mut(DATA_BACKUP_FINAL_STEP_INDEX) {
                        step.transition(
                            WorkflowStepState::Completed,
                            Some(String::from("recorded replayable backup evidence")),
                        );
                    }
                    push_data_workflow_evidence(
                        &mut workflow.state.evidence,
                        "record_backup_evidence",
                        "finalized backup workflow evidence and projection",
                        refs,
                    );
                    workflow.set_phase(WorkflowPhase::Completed);
                    Ok(())
                })
                .await?;
            self.sync_backup_job_projection(&stored.value).await?;
        }

        let stored = self.load_backup_workflow(workflow_id).await?;
        self.sync_backup_job_projection(&stored.value).await?;
        Ok(build_backup_job_from_workflow(&stored.value))
    }

    async fn execute_restore_workflow(&self, workflow_id: &str) -> Result<RestoreJob> {
        let stored = self.load_restore_workflow(workflow_id).await?;
        if stored.value.phase == WorkflowPhase::Completed {
            self.sync_restore_job_projection(&stored.value).await?;
            return Ok(build_restore_job_from_workflow(&stored.value));
        }
        if matches!(
            stored.value.phase,
            WorkflowPhase::Failed | WorkflowPhase::RolledBack
        ) {
            return Err(PlatformError::conflict(
                "restore workflow is not executable",
            ));
        }

        if matches!(
            data_workflow_step_state(&stored.value, 0),
            Some(WorkflowStepState::Pending)
        ) {
            let stored = self
                .restore_workflows
                .mutate(workflow_id, |workflow| {
                    let source_mode = workflow
                        .state
                        .source_mode
                        .unwrap_or(RestoreStorageSourceMode::LatestReadyFallback);
                    let selected_recovery_point = workflow
                        .state
                        .selected_recovery_point
                        .clone()
                        .ok_or_else(|| {
                            PlatformError::conflict(
                                "restore workflow is missing selected recovery point",
                            )
                        })?;
                    workflow.current_step_index = Some(0);
                    workflow.set_phase(WorkflowPhase::Running);
                    if let Some(step) = workflow.step_mut(0) {
                        step.transition(
                            WorkflowStepState::Completed,
                            Some(format!(
                                "selected {} storage recovery point version {}",
                                match source_mode {
                                    RestoreStorageSourceMode::BackupCorrelatedStorageLineage => {
                                        "backup-correlated"
                                    }
                                    RestoreStorageSourceMode::LatestReadyFallback => {
                                        "latest-ready fallback"
                                    }
                                },
                                selected_recovery_point.version
                            )),
                        );
                    }
                    workflow.current_step_index = Some(1);
                    if let Some(step) = workflow.step_mut(1) {
                        step.transition(
                            WorkflowStepState::Active,
                            Some(String::from("executing storage restore workflow")),
                        );
                    }
                    let mut refs = BTreeMap::new();
                    refs.insert(
                        String::from("selected_recovery_point_version"),
                        selected_recovery_point.version.to_string(),
                    );
                    refs.insert(
                        String::from("selected_recovery_point_etag"),
                        selected_recovery_point.etag,
                    );
                    push_data_workflow_evidence(
                        &mut workflow.state.evidence,
                        "select_restore_source",
                        "selected deterministic storage recovery point for restore workflow",
                        refs,
                    );
                    Ok(())
                })
                .await?;
            self.sync_restore_job_projection(&stored.value).await?;
        }

        let stored = self.load_restore_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, 1),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let step_result: Result<()> = async {
                let (journaled, effect_execution) =
                    self.begin_restore_storage_effect(workflow_id).await?;
                match effect_execution {
                    WorkflowStepEffectExecution::Replay(effect) => {
                        let result_digest = data_workflow_effect_replay_result_digest(
                            DATA_RESTORE_STORAGE_EFFECT_KIND,
                            effect.result_digest.as_ref(),
                        )?;
                        let restore_action = self
                            .load_restore_storage_action_for_result(
                                &journaled.value.state,
                                result_digest.as_str(),
                            )
                            .await?;
                        let restore_storage = self
                            .build_restore_storage_lineage_for_state(
                                &journaled.value.state,
                                &restore_action,
                            )
                            .await?;
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("storage_restore_action_id"),
                            restore_action.id.to_string(),
                        );
                        refs.insert(
                            String::from("storage_restore_workflow_id"),
                            restore_action.workflow_id.clone(),
                        );
                        refs.insert(
                            String::from("replay_source"),
                            String::from("workflow_journal"),
                        );
                        let _stored = self
                            .finish_restore_storage_effect(
                                workflow_id,
                                restore_storage,
                                result_digest.as_str(),
                                format!(
                                    "reused recorded storage restore action {}",
                                    restore_action.id.as_str()
                                ),
                                "reused recorded storage restore effect result and lineage",
                                refs,
                            )
                            .await?;
                    }
                    WorkflowStepEffectExecution::Execute(_) => {
                        if let Some((restore_storage, result_digest)) = self
                            .replay_restore_storage_effect_from_ledger(&journaled.value)
                            .await?
                        {
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("storage_restore_action_id"),
                                restore_storage.restore_action_id.to_string(),
                            );
                            refs.insert(
                                String::from("storage_restore_workflow_id"),
                                restore_storage.restore_workflow_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("effect_ledger"),
                            );
                            let _stored = self
                                .finish_restore_storage_effect(
                                    workflow_id,
                                    restore_storage.clone(),
                                    result_digest.as_str(),
                                    format!(
                                        "reused recorded storage restore action {}",
                                        restore_storage.restore_action_id.as_str()
                                    ),
                                    "reused recorded storage restore effect result and lineage",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }
                        if let Some((restore_storage, result_digest)) = self
                            .reconcile_restore_storage_effect_after_controller_death(
                                &journaled.value,
                            )
                            .await?
                        {
                            let _ledger = self
                                .persist_workflow_effect_ledger(
                                    &journaled.value,
                                    1,
                                    DATA_RESTORE_STORAGE_EFFECT_KIND,
                                    result_digest.as_str(),
                                    OffsetDateTime::now_utc(),
                                )
                                .await?;
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("storage_restore_action_id"),
                                restore_storage.restore_action_id.to_string(),
                            );
                            refs.insert(
                                String::from("storage_restore_workflow_id"),
                                restore_storage.restore_workflow_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("current_storage_state"),
                            );
                            refs.insert(
                                String::from("reconciled_after"),
                                String::from("controller_death"),
                            );
                            let _stored = self
                                .finish_restore_storage_effect(
                                    workflow_id,
                                    restore_storage.clone(),
                                    result_digest.as_str(),
                                    format!(
                                        "reconciled completed storage restore action {} after controller death",
                                        restore_storage.restore_action_id.as_str()
                                    ),
                                    "reused already-applied storage restore effect after controller death",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }

                        let state = journaled.value.state.clone();
                        let selected_recovery_point =
                            state.selected_recovery_point.clone().ok_or_else(|| {
                                PlatformError::conflict(
                                    "restore workflow is missing selected recovery point",
                                )
                            })?;
                        let storage_restore_action_id = self
                            .storage
                            .restore_volume_from_selected_recovery_point(
                                &state.target_volume_id,
                                selected_recovery_point.version,
                                Some(selected_recovery_point.etag.as_str()),
                                state.reason.clone(),
                            )
                            .await?;
                        let restore_action = self
                            .load_restore_storage_action_for_result(
                                &state,
                                storage_restore_action_id.as_str(),
                            )
                            .await?;
                        let restore_storage = self
                            .build_restore_storage_lineage_for_state(&state, &restore_action)
                            .await?;
                        let result_digest = restore_action.id.to_string();
                        let _ledger = self
                            .persist_workflow_effect_ledger(
                                &journaled.value,
                                1,
                                DATA_RESTORE_STORAGE_EFFECT_KIND,
                                result_digest.as_str(),
                                OffsetDateTime::now_utc(),
                            )
                            .await?;
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("storage_restore_action_id"),
                            restore_action.id.to_string(),
                        );
                        refs.insert(
                            String::from("storage_restore_workflow_id"),
                            restore_action.workflow_id.clone(),
                        );
                        let _stored = self
                            .finish_restore_storage_effect(
                                workflow_id,
                                restore_storage,
                                result_digest.as_str(),
                                format!(
                                    "executed storage restore action {}",
                                    restore_action.id.as_str()
                                ),
                                "executed storage restore workflow and recorded lineage",
                                refs,
                            )
                            .await?;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = step_result {
                self.mark_restore_workflow_failed(
                    workflow_id,
                    1,
                    "execute_storage_restore",
                    format!("storage restore execution failed: {error}"),
                )
                .await?;
                return Err(error);
            }
        }

        let stored = self.load_restore_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, DATA_RESTORE_FINAL_STEP_INDEX),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let step_result: Result<()> = async {
                let (journaled, effect_execution) =
                    self.begin_restore_projection_effect(workflow_id).await?;
                match effect_execution {
                    WorkflowStepEffectExecution::Replay(effect) => {
                        let result_digest = data_workflow_effect_replay_result_digest(
                            DATA_RESTORE_PROJECTION_EFFECT_KIND,
                            effect.result_digest.as_ref(),
                        )?;
                        let Some(current_digest) = self
                            .restore_projection_effect_result_if_current(&journaled.value)
                            .await?
                        else {
                            return Err(PlatformError::conflict(
                                "recorded database restore projection no longer matches current database state",
                            ));
                        };
                        if current_digest != result_digest {
                            return Err(PlatformError::conflict(
                                "recorded database restore projection digest no longer matches current database state",
                            ));
                        }
                        let storage_restore =
                            journaled.value.state.storage_restore.as_ref().ok_or_else(|| {
                                PlatformError::conflict(
                                    "restore workflow is missing storage restore lineage",
                                )
                            })?;
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("storage_restore_action_id"),
                            storage_restore.restore_action_id.to_string(),
                        );
                        refs.insert(
                            String::from("storage_restore_workflow_id"),
                            storage_restore.restore_workflow_id.clone(),
                        );
                        refs.insert(
                            String::from("replay_source"),
                            String::from("workflow_journal"),
                        );
                        let _stored = self
                            .finish_restore_projection_effect(
                                workflow_id,
                                result_digest.as_str(),
                                String::from("applied database restore projection"),
                                "reused recorded database restore projection result",
                                refs,
                            )
                            .await?;
                    }
                    WorkflowStepEffectExecution::Execute(_) => {
                        if let Some(result_digest) = self
                            .replay_restore_projection_effect_from_ledger(&journaled.value)
                            .await?
                        {
                            let storage_restore =
                                journaled.value.state.storage_restore.as_ref().ok_or_else(|| {
                                    PlatformError::conflict(
                                        "restore workflow is missing storage restore lineage",
                                    )
                                })?;
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("storage_restore_action_id"),
                                storage_restore.restore_action_id.to_string(),
                            );
                            refs.insert(
                                String::from("storage_restore_workflow_id"),
                                storage_restore.restore_workflow_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("effect_ledger"),
                            );
                            let _stored = self
                                .finish_restore_projection_effect(
                                    workflow_id,
                                    result_digest.as_str(),
                                    String::from("applied database restore projection"),
                                    "reused recorded database restore projection result",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }
                        if let Some(result_digest) = self
                            .restore_projection_effect_result_if_current(&journaled.value)
                            .await?
                        {
                            let _ledger = self
                                .persist_workflow_effect_ledger(
                                    &journaled.value,
                                    DATA_RESTORE_FINAL_STEP_INDEX,
                                    DATA_RESTORE_PROJECTION_EFFECT_KIND,
                                    result_digest.as_str(),
                                    OffsetDateTime::now_utc(),
                                )
                                .await?;
                            let storage_restore =
                                journaled.value.state.storage_restore.as_ref().ok_or_else(|| {
                                    PlatformError::conflict(
                                        "restore workflow is missing storage restore lineage",
                                    )
                                })?;
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("storage_restore_action_id"),
                                storage_restore.restore_action_id.to_string(),
                            );
                            refs.insert(
                                String::from("storage_restore_workflow_id"),
                                storage_restore.restore_workflow_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("current_database_state"),
                            );
                            refs.insert(
                                String::from("reconciled_after"),
                                String::from("controller_death"),
                            );
                            let _stored = self
                                .finish_restore_projection_effect(
                                    workflow_id,
                                    result_digest.as_str(),
                                    String::from(
                                        "applied database restore projection",
                                    ),
                                    "reused already-applied database restore projection after controller death",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }

                        let current = self
                            .load_database_record(journaled.value.state.database_id.as_str())
                            .await?;
                        let current_database = current.value.clone();
                        let (mut database, storage_changed) = self
                            .build_projected_restore_database(
                                current.value,
                                &journaled.value.state,
                            )
                            .await?;
                        if storage_changed {
                            let storage_restore =
                                journaled.value.state.storage_restore.as_ref().ok_or_else(|| {
                                    PlatformError::conflict(
                                        "restore workflow is missing storage restore lineage",
                                    )
                                })?;
                            let restore_action_summary =
                                build_restore_action_summary_from_lineage(
                                    storage_restore,
                                    "completed",
                                );
                            database.metadata.touch(database_restore_lineage_etag(
                                &database,
                                &journaled.value.state.backup_id,
                                &restore_action_summary,
                            ));
                        } else if database != current_database {
                            database.metadata.touch(sha256_hex(
                                format!(
                                    "{}:database-restore-projection:{}",
                                    database.id.as_str(),
                                    journaled.value.state.restore_id.as_str(),
                                )
                                .as_bytes(),
                            ));
                        }
                        let database_id = database.id.as_str().to_owned();
                        self.databases
                            .upsert(database_id.as_str(), database.clone(), Some(current.version))
                            .await?;
                        let result_digest = restore_projection_effect_result_digest(
                            &database,
                            &journaled.value.state,
                        )?;
                        let _ledger = self
                            .persist_workflow_effect_ledger(
                                &journaled.value,
                                DATA_RESTORE_FINAL_STEP_INDEX,
                                DATA_RESTORE_PROJECTION_EFFECT_KIND,
                                result_digest.as_str(),
                                OffsetDateTime::now_utc(),
                            )
                            .await?;
                        let storage_restore =
                            journaled.value.state.storage_restore.as_ref().ok_or_else(|| {
                                PlatformError::conflict(
                                    "restore workflow is missing storage restore lineage",
                                )
                            })?;
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("storage_restore_action_id"),
                            storage_restore.restore_action_id.to_string(),
                        );
                        refs.insert(
                            String::from("storage_restore_workflow_id"),
                            storage_restore.restore_workflow_id.clone(),
                        );
                        let _stored = self
                            .finish_restore_projection_effect(
                                workflow_id,
                                result_digest.as_str(),
                                String::from("applied database restore projection"),
                                "applied database restore projection and lineage annotations",
                                refs,
                            )
                            .await?;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = step_result {
                self.mark_restore_workflow_failed(
                    workflow_id,
                    DATA_RESTORE_FINAL_STEP_INDEX,
                    "apply_database_restore_projection",
                    format!("database projection update failed: {error}"),
                )
                .await?;
                return Err(error);
            }
        }

        let stored = self.load_restore_workflow(workflow_id).await?;
        self.sync_restore_job_projection(&stored.value).await?;
        Ok(build_restore_job_from_workflow(&stored.value))
    }

    async fn execute_failover_workflow(&self, workflow_id: &str) -> Result<DataFailoverRecord> {
        let stored = self.load_failover_workflow(workflow_id).await?;
        if stored.value.phase == WorkflowPhase::Completed {
            self.sync_failover_projection(&stored.value).await?;
            return Ok(build_failover_record_from_workflow(&stored.value));
        }
        if matches!(
            stored.value.phase,
            WorkflowPhase::Failed | WorkflowPhase::RolledBack
        ) {
            return Err(PlatformError::conflict(
                "failover workflow is not executable",
            ));
        }

        if matches!(
            data_workflow_step_state(&stored.value, 0),
            Some(WorkflowStepState::Pending)
        ) {
            let stored = self
                .failover_workflows
                .mutate(workflow_id, |workflow| {
                    let from_replica_id = workflow.state.from_replica_id.clone();
                    let to_replica_id = workflow.state.to_replica_id.clone();
                    let target_region = workflow.state.target_region.clone();
                    workflow.current_step_index = Some(0);
                    workflow.set_phase(WorkflowPhase::Running);
                    if let Some(step) = workflow.step_mut(0) {
                        step.transition(
                            WorkflowStepState::Completed,
                            Some(format!(
                                "prepared failover from {from_replica_id} to {to_replica_id}"
                            )),
                        );
                    }
                    workflow.current_step_index = Some(1);
                    if let Some(step) = workflow.step_mut(1) {
                        step.transition(
                            WorkflowStepState::Active,
                            Some(String::from("promoting target replica")),
                        );
                    }
                    let mut refs = BTreeMap::new();
                    refs.insert(String::from("from_replica_id"), from_replica_id);
                    refs.insert(String::from("to_replica_id"), to_replica_id);
                    refs.insert(String::from("target_region"), target_region);
                    push_data_workflow_evidence(
                        &mut workflow.state.evidence,
                        "prepare_failover",
                        "prepared deterministic failover target and evidence",
                        refs,
                    );
                    Ok(())
                })
                .await?;
            self.sync_failover_projection(&stored.value).await?;
        }

        let stored = self.load_failover_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, 1),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let step_result: Result<()> = async {
                let (journaled, effect_execution) =
                    self.begin_failover_promotion_effect(workflow_id).await?;
                match effect_execution {
                    WorkflowStepEffectExecution::Replay(effect) => {
                        let result_digest = data_workflow_effect_replay_result_digest(
                            DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                            effect.result_digest.as_ref(),
                        )?;
                        let Some(current_digest) = self
                            .failover_promotion_effect_result_if_current(&journaled.value)
                            .await?
                        else {
                            return Err(PlatformError::conflict(
                                "recorded failover topology no longer matches current database state",
                            ));
                        };
                        if current_digest != result_digest {
                            return Err(PlatformError::conflict(
                                "recorded failover topology digest no longer matches current database state",
                            ));
                        }
                        let mut refs = BTreeMap::new();
                        refs.insert(
                            String::from("target_region"),
                            journaled.value.state.target_region.clone(),
                        );
                        refs.insert(
                            String::from("to_replica_id"),
                            journaled.value.state.to_replica_id.clone(),
                        );
                        refs.insert(
                            String::from("replay_source"),
                            String::from("workflow_journal"),
                        );
                        let _stored = self
                            .finish_failover_promotion_effect(
                                workflow_id,
                                result_digest.as_str(),
                                format!(
                                    "promoted target replica {}",
                                    journaled.value.state.to_replica_id
                                ),
                                "reused recorded failover topology result",
                                refs,
                            )
                            .await?;
                    }
                    WorkflowStepEffectExecution::Execute(_) => {
                        if let Some(result_digest) = self
                            .replay_failover_promotion_effect_from_ledger(&journaled.value)
                            .await?
                        {
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("target_region"),
                                journaled.value.state.target_region.clone(),
                            );
                            refs.insert(
                                String::from("to_replica_id"),
                                journaled.value.state.to_replica_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("effect_ledger"),
                            );
                            let _stored = self
                                .finish_failover_promotion_effect(
                                    workflow_id,
                                    result_digest.as_str(),
                                    format!(
                                        "promoted target replica {}",
                                        journaled.value.state.to_replica_id
                                    ),
                                    "reused recorded failover topology result",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }
                        if let Some(result_digest) = self
                            .reconcile_failover_effect_after_controller_death(&journaled.value)
                            .await?
                        {
                            let _ledger = self
                                .persist_workflow_effect_ledger(
                                    &journaled.value,
                                    1,
                                    DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                                    result_digest.as_str(),
                                    OffsetDateTime::now_utc(),
                                )
                                .await?;
                            let mut refs = BTreeMap::new();
                            refs.insert(
                                String::from("target_region"),
                                journaled.value.state.target_region.clone(),
                            );
                            refs.insert(
                                String::from("to_replica_id"),
                                journaled.value.state.to_replica_id.clone(),
                            );
                            refs.insert(
                                String::from("replay_source"),
                                String::from("current_database_state"),
                            );
                            refs.insert(
                                String::from("reconciled_after"),
                                String::from("controller_death"),
                            );
                            let _stored = self
                                .finish_failover_promotion_effect(
                                    workflow_id,
                                    result_digest.as_str(),
                                    format!(
                                        "reconciled promoted target replica {} after controller death",
                                        journaled.value.state.to_replica_id
                                    ),
                                    "reused already-applied failover topology after controller death",
                                    refs,
                                )
                                .await?;
                            return Ok(());
                        }

                        let state = journaled.value.state.clone();
                        let current = self.load_database_record(state.database_id.as_str()).await?;
                        let current_database = current.value.clone();
                        let mut database = current.value;
                        if database.replica_topology.len() < 2 {
                            return Err(PlatformError::conflict(
                                "database failover requires at least two replicas",
                            ));
                        }
                        let Some(current_primary_idx) = database
                            .replica_topology
                            .iter()
                            .position(|replica| replica.role == "primary")
                        else {
                            return Err(PlatformError::conflict(
                                "database has no primary replica",
                            ));
                        };
                        if database.replica_topology[current_primary_idx].id != state.from_replica_id
                        {
                            return Err(PlatformError::conflict(
                                "database primary replica changed before failover workflow completed",
                            ));
                        }
                        let Some(target_idx) = database
                            .replica_topology
                            .iter()
                            .position(|replica| replica.id == state.to_replica_id)
                        else {
                            return Err(PlatformError::conflict(
                                "database failover target replica no longer exists",
                            ));
                        };
                        if !database.replica_topology[target_idx].healthy {
                            return Err(PlatformError::conflict(
                                "target replica is not healthy",
                            ));
                        }
                        database.lifecycle_state = String::from("failing_over");
                        database.replica_topology[current_primary_idx].role =
                            String::from("replica");
                        database.replica_topology[target_idx].role = String::from("primary");
                        database.primary_region =
                            database.replica_topology[target_idx].region.clone();
                        database.lifecycle_state = default_database_state();
                        if database != current_database {
                            database.metadata.touch(sha256_hex(
                                format!(
                                    "{}:database-failover:{}:{}:{}",
                                    database.id.as_str(),
                                    state.failover_id.as_str(),
                                    state.from_replica_id,
                                    state.to_replica_id,
                                )
                                .as_bytes(),
                            ));
                        }
                        let database_id = database.id.as_str().to_owned();
                        self.databases
                            .upsert(database_id.as_str(), database.clone(), Some(current.version))
                            .await?;
                        let result_digest =
                            failover_promotion_effect_result_digest(&database, &state)?;
                        let _ledger = self
                            .persist_workflow_effect_ledger(
                                &journaled.value,
                                1,
                                DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                                result_digest.as_str(),
                                OffsetDateTime::now_utc(),
                            )
                            .await?;
                        let mut refs = BTreeMap::new();
                        refs.insert(String::from("target_region"), state.target_region.clone());
                        refs.insert(String::from("to_replica_id"), state.to_replica_id.clone());
                        let _stored = self
                            .finish_failover_promotion_effect(
                                workflow_id,
                                result_digest.as_str(),
                                format!("promoted target replica {}", state.to_replica_id),
                                "promoted target replica and updated database topology",
                                refs,
                            )
                            .await?;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = step_result {
                self.mark_failover_workflow_failed(
                    workflow_id,
                    1,
                    "promote_target_replica",
                    format!("database failover persistence failed: {error}"),
                )
                .await?;
                return Err(error);
            }
        }

        let stored = self.load_failover_workflow(workflow_id).await?;
        if matches!(
            data_workflow_step_state(&stored.value, DATA_FAILOVER_FINAL_STEP_INDEX),
            Some(WorkflowStepState::Pending) | Some(WorkflowStepState::Active)
        ) {
            let stored = self
                .failover_workflows
                .mutate(workflow_id, |workflow| {
                    workflow.current_step_index = Some(DATA_FAILOVER_FINAL_STEP_INDEX);
                    if let Some(step) = workflow.step_mut(DATA_FAILOVER_FINAL_STEP_INDEX) {
                        step.transition(
                            WorkflowStepState::Completed,
                            Some(String::from("recorded replayable failover evidence")),
                        );
                    }
                    let mut refs = BTreeMap::new();
                    refs.insert(
                        String::from("from_replica_id"),
                        workflow.state.from_replica_id.clone(),
                    );
                    refs.insert(
                        String::from("to_replica_id"),
                        workflow.state.to_replica_id.clone(),
                    );
                    refs.insert(
                        String::from("target_region"),
                        workflow.state.target_region.clone(),
                    );
                    push_data_workflow_evidence(
                        &mut workflow.state.evidence,
                        "record_failover_evidence",
                        "finalized failover workflow evidence and projection",
                        refs,
                    );
                    workflow.set_phase(WorkflowPhase::Completed);
                    Ok(())
                })
                .await?;
            self.sync_failover_projection(&stored.value).await?;
        }

        let stored = self.load_failover_workflow(workflow_id).await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(build_failover_record_from_workflow(&stored.value))
    }

    async fn create_database(
        &self,
        request: CreateDatabaseRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let engine = normalize_database_engine(&request.engine)?;
        if request.version.trim().is_empty() {
            return Err(PlatformError::invalid("database version may not be empty"));
        }
        let storage_binding = self
            .storage
            .resolve_storage_binding(
                StorageResourceKind::Database,
                request.storage_class_id.as_deref(),
                request.durability_tier_id.as_deref(),
            )
            .await?;
        let id = DatabaseId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate database id")
                .with_detail(error.to_string())
        })?;
        let replicas = request.replicas.max(1);
        let primary_region = request
            .primary_region
            .unwrap_or_else(default_primary_region);
        let mut record = ManagedDatabase {
            id: id.clone(),
            engine,
            version: request.version.trim().to_owned(),
            storage_gb: request.storage_gb.max(1),
            replicas,
            tls_required: request.tls_required,
            storage_binding: Some(storage_binding),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            lifecycle_state: String::from("ready"),
            primary_region: primary_region.clone(),
            replica_topology: build_replica_topology(replicas, &primary_region),
            backup_policy: request.backup_policy.unwrap_or_default(),
            storage_class: None,
            maintenance_mode: false,
            maintenance_reason: None,
            tags: request.tags,
        };
        let volume = self.ensure_database_storage_volume(&record).await?;
        if apply_database_storage_binding_annotations(&mut record, &volume) {
            record
                .metadata
                .touch(database_storage_binding_etag(&record, &volume));
        }
        self.databases.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "data.database.created.v1",
            "database",
            id.as_str(),
            "created",
            serde_json::json!({
                "engine": record.engine,
                "version": record.version,
                "replicas": record.replicas,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_cache(
        &self,
        request: CreateCacheRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = CacheClusterId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate cache id").with_detail(error.to_string())
        })?;
        let record = CacheCluster {
            id: id.clone(),
            engine: normalize_cache_engine(&request.engine),
            memory_mb: request.memory_mb.max(64),
            tls_required: request.tls_required,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.caches.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "data.cache.created.v1",
            "cache",
            id.as_str(),
            "created",
            serde_json::json!({
                "engine": record.engine,
                "memory_mb": record.memory_mb,
                "tls_required": record.tls_required,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_queue(
        &self,
        request: CreateQueueRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = QueueId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate queue id").with_detail(error.to_string())
        })?;
        let record = QueueService {
            id: id.clone(),
            partitions: request.partitions.max(1),
            retention_hours: request.retention_hours.max(1),
            dead_letter_enabled: request.dead_letter_enabled,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.queues.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "data.queue.created.v1",
            "queue",
            id.as_str(),
            "created",
            serde_json::json!({
                "partitions": record.partitions,
                "retention_hours": record.retention_hours,
                "dead_letter_enabled": record.dead_letter_enabled,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_export(
        &self,
        resource_kind: DataTransferResourceKind,
        resource_id: &str,
        request: CreateDataExportRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate export id")
                .with_detail(error.to_string())
        })?;
        let material = self
            .build_export_material(
                resource_kind,
                resource_id,
                &id,
                request.artifact_format.as_deref(),
            )
            .await?;
        let signing_key_ref =
            normalize_signing_key_ref(request.signing_key_ref.as_deref(), resource_kind)?;
        let reason = normalize_optional_string(request.reason);
        let checksum_catalog = build_data_checksum_catalog(material.checksum_entries);
        let now = OffsetDateTime::now_utc();
        let mut signed_manifest = SignedDataTransferManifest {
            manifest_version: 1,
            flow: String::from("export"),
            resource_kind: String::from(resource_kind.as_str()),
            resource_id: resource_id.to_owned(),
            artifact_format: material.artifact_format.clone(),
            artifact_root_uri: material.artifact_root_uri.clone(),
            checksum_catalog_checksum: checksum_catalog.checksum.clone(),
            signing_key_ref,
            signature_scheme: String::from(DATA_TRANSFER_SIGNATURE_SCHEME),
            signature: String::new(),
            signed_at: now,
        };
        signed_manifest.signature = data_transfer_manifest_signature(&signed_manifest);

        let record = DataExportJob {
            id: id.clone(),
            resource_kind: String::from(resource_kind.as_str()),
            resource_id: resource_id.to_owned(),
            state: String::from("completed"),
            requested_by: actor_subject(context),
            created_at: now,
            completed_at: Some(now),
            reason: reason.clone(),
            artifact_root_uri: material.artifact_root_uri.clone(),
            manifest_uri: material.manifest_uri.clone(),
            checksum_catalog_uri: material.checksum_catalog_uri.clone(),
            signed_manifest,
            checksum_catalog,
        };
        self.export_jobs.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "data.export.completed.v1",
            "data_export",
            id.as_str(),
            "completed",
            serde_json::json!({
                "source_resource_kind": record.resource_kind,
                "source_resource_id": record.resource_id,
                "artifact_format": record.signed_manifest.artifact_format,
                "artifact_root_uri": record.artifact_root_uri,
                "manifest_uri": record.manifest_uri,
                "checksum_catalog_uri": record.checksum_catalog_uri,
                "checksum_catalog_checksum": record.checksum_catalog.checksum,
                "reason": reason,
                "resource": material.details,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_import(
        &self,
        resource_kind: DataTransferResourceKind,
        request: CreateDataImportRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let target_resource_id = normalize_optional_string(request.target_resource_id);
        if let Some(target_resource_id) = target_resource_id.as_deref() {
            self.ensure_import_target_exists(resource_kind, target_resource_id)
                .await?;
        }
        let manifest_uri = normalize_optional_string(request.manifest_uri);
        let checksum_catalog_uri = normalize_optional_string(request.checksum_catalog_uri);
        let signed_manifest =
            validate_signed_data_transfer_manifest(request.signed_manifest, resource_kind)?;
        let checksum_catalog = validate_data_checksum_catalog(
            request.checksum_catalog,
            signed_manifest.artifact_root_uri.as_str(),
        )?;
        if signed_manifest.checksum_catalog_checksum != checksum_catalog.checksum {
            return Err(PlatformError::invalid(
                "manifest checksum catalog checksum does not match catalog checksum",
            ));
        }

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate import id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let reason = normalize_optional_string(request.reason);
        let verification_result =
            String::from("manifest signature verified and checksum catalog matched");
        let record = DataImportJob {
            id: id.clone(),
            resource_kind: String::from(resource_kind.as_str()),
            source_resource_id: signed_manifest.resource_id.clone(),
            target_resource_id: target_resource_id.clone(),
            state: String::from("verified"),
            requested_by: actor_subject(context),
            created_at: now,
            completed_at: Some(now),
            reason: reason.clone(),
            manifest_uri: manifest_uri.clone(),
            checksum_catalog_uri: checksum_catalog_uri.clone(),
            verification_result: verification_result.clone(),
            signed_manifest,
            checksum_catalog,
        };
        self.import_jobs.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "data.import.verified.v1",
            "data_import",
            id.as_str(),
            "verified",
            serde_json::json!({
                "resource_kind": record.resource_kind,
                "source_resource_id": record.source_resource_id,
                "target_resource_id": target_resource_id,
                "manifest_uri": manifest_uri,
                "checksum_catalog_uri": checksum_catalog_uri,
                "verification_result": verification_result,
                "checksum_catalog_checksum": record.checksum_catalog.checksum,
                "reason": reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_backup(
        &self,
        database_id: &str,
        request: CreateBackupRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        if database.lifecycle_state == "deleted" {
            return Err(PlatformError::conflict("cannot back up a deleted database"));
        }
        let kind = normalize_backup_kind(request.kind.as_deref().unwrap_or("full"));
        let point_in_time = parse_optional_rfc3339(request.point_in_time_rfc3339.as_deref())?;
        validate_point_in_time(point_in_time)?;
        let now = OffsetDateTime::now_utc();
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate backup id")
                .with_detail(error.to_string())
        })?;
        let requested_by = context
            .actor
            .clone()
            .unwrap_or_else(|| String::from("system"));
        let requested_reason = request.reason.clone();
        let volume = self.ensure_database_storage_volume(&database).await?;
        let storage_recovery_point = self
            .storage
            .describe_ready_volume_recovery_point(&volume.id)
            .await?
            .map(|recovery_point| build_backup_storage_recovery_point(&recovery_point))
            .ok_or_else(|| {
                PlatformError::unavailable("database storage recovery point does not exist")
            })?;
        let backup_artifact_manifest = self
            .persist_backup_artifact_manifest(
                &id,
                &database,
                &kind,
                &requested_by,
                requested_reason.clone(),
                now,
                point_in_time,
                &storage_recovery_point,
            )
            .await?;
        let primary_artifact = backup_artifact_manifest.artifacts.first().ok_or_else(|| {
            PlatformError::unavailable("backup artifact manifest is missing artifacts")
                .with_detail(format!("backup_id={}", id.as_str()))
        })?;
        let snapshot_uri = primary_artifact.object_location.clone();
        let checksum = primary_artifact.sha256.clone();
        let workflow = build_backup_workflow(BackupWorkflowState {
            backup_id: id.clone(),
            database_id: database.id.clone(),
            kind: kind.clone(),
            requested_by: requested_by.clone(),
            snapshot_uri: snapshot_uri.clone(),
            backup_artifact_manifest: Some(backup_artifact_manifest.clone()),
            storage_recovery_point: Some(storage_recovery_point.clone()),
            storage_recovery_point_selection_reason: backup_storage_recovery_point_selection_reason(
            ),
            point_in_time,
            checksum,
            requested_reason: requested_reason.clone(),
            evidence: Vec::new(),
        });
        let started = self.backup_workflows.create(id.as_str(), workflow).await?;
        self.sync_backup_job_projection(&started.value).await?;
        let job = self.execute_backup_workflow(id.as_str()).await?;
        self.append_event(
            "data.database.backup.completed.v1",
            "database_backup",
            id.as_str(),
            "completed",
            serde_json::json!({
                "database_id": database.id,
                "kind": kind,
                "snapshot_uri": snapshot_uri,
                "backup_artifact_manifest_object_location": backup_artifact_manifest.manifest_object_location,
                "backup_artifact_manifest_sha256": backup_artifact_manifest.manifest_sha256,
                "storage_volume_id": volume.id,
                "storage_recovery_point_version": storage_recovery_point.version,
                "storage_recovery_point_execution_count": storage_recovery_point.execution_count,
                "storage_recovery_point_etag": storage_recovery_point.etag,
                "reason": requested_reason,
            }),
            context,
        )
        .await?;
        let reply = self
            .build_backup_job_reply_with_storage_state_reason(&job)
            .await?;
        json_response(StatusCode::CREATED, &reply)
    }

    async fn create_backup_with_idempotency(
        &self,
        database_id: &str,
        request: CreateBackupRequest,
        idempotency_key: Option<&str>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        if database.lifecycle_state == "deleted" {
            return Err(PlatformError::conflict("cannot back up a deleted database"));
        }
        let kind = normalize_backup_kind(request.kind.as_deref().unwrap_or("full"));
        let point_in_time = parse_optional_rfc3339(request.point_in_time_rfc3339.as_deref())?;
        validate_point_in_time(point_in_time)?;
        let request_digest = backup_request_digest(
            database.id.as_str(),
            &kind,
            point_in_time,
            request.reason.as_deref(),
        )?;
        let requested_by = context
            .actor
            .clone()
            .unwrap_or_else(|| String::from("system"));
        let requested_reason = request.reason.clone();
        let mut pending = match self
            .begin_data_mutation_dedupe(
                DataMutationOperation::Backup,
                database.id.as_str(),
                idempotency_key,
                &request_digest,
                context,
            )
            .await?
        {
            DataMutationDedupeBeginOutcome::Proceed(pending) => *pending,
            DataMutationDedupeBeginOutcome::Replay(response) => return Ok(response),
        };

        let result = async {
            let now = OffsetDateTime::now_utc();
            let id = AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate backup id")
                    .with_detail(error.to_string())
            })?;
            let volume = self.ensure_database_storage_volume(&database).await?;
            let storage_recovery_point = self
                .storage
                .describe_ready_volume_recovery_point(&volume.id)
                .await?
                .map(|recovery_point| build_backup_storage_recovery_point(&recovery_point))
                .ok_or_else(|| {
                    PlatformError::unavailable("database storage recovery point does not exist")
                })?;
            let backup_artifact_manifest = self
                .persist_backup_artifact_manifest(
                    &id,
                    &database,
                    &kind,
                    &requested_by,
                    requested_reason.clone(),
                    now,
                    point_in_time,
                    &storage_recovery_point,
                )
                .await?;
            let primary_artifact = backup_artifact_manifest.artifacts.first().ok_or_else(|| {
                PlatformError::unavailable("backup artifact manifest is missing artifacts")
                    .with_detail(format!("backup_id={}", id.as_str()))
            })?;
            let snapshot_uri = primary_artifact.object_location.clone();
            let checksum = primary_artifact.sha256.clone();
            let workflow = build_backup_workflow(BackupWorkflowState {
                backup_id: id.clone(),
                database_id: database.id.clone(),
                kind: kind.clone(),
                requested_by: requested_by.clone(),
                snapshot_uri: snapshot_uri.clone(),
                backup_artifact_manifest: Some(backup_artifact_manifest.clone()),
                storage_recovery_point: Some(storage_recovery_point.clone()),
                storage_recovery_point_selection_reason:
                    backup_storage_recovery_point_selection_reason(),
                point_in_time,
                checksum,
                requested_reason: requested_reason.clone(),
                evidence: Vec::new(),
            });
            let started = self.backup_workflows.create(id.as_str(), workflow).await?;
            self.sync_backup_job_projection(&started.value).await?;
            let job = self.execute_backup_workflow(id.as_str()).await?;
            self.stage_data_mutation_result_reference(
                &mut pending,
                StatusCode::CREATED,
                data_mutation_result_resource_kind(DataMutationOperation::Backup),
                job.id.as_str(),
            )
            .await?;
            let reply = self
                .build_backup_job_reply_with_storage_state_reason(&job)
                .await?;
            let reply_json =
                serialize_response_body(&reply, "backup idempotency replay payload")?;
            self.stage_data_mutation_response(
                &mut pending,
                StatusCode::CREATED,
                &reply_json,
                "database_backup",
                id.as_str(),
            )
            .await?;
            self.append_event(
                "data.database.backup.completed.v1",
                "database_backup",
                id.as_str(),
                "completed",
                serde_json::json!({
                    "database_id": database.id,
                    "kind": kind,
                    "snapshot_uri": snapshot_uri,
                    "backup_artifact_manifest_object_location": backup_artifact_manifest.manifest_object_location,
                    "backup_artifact_manifest_sha256": backup_artifact_manifest.manifest_sha256,
                    "storage_volume_id": volume.id,
                    "storage_recovery_point_version": storage_recovery_point.version,
                    "storage_recovery_point_execution_count": storage_recovery_point.execution_count,
                    "storage_recovery_point_etag": storage_recovery_point.etag,
                    "reason": requested_reason,
                }),
                context,
            )
            .await?;
            self.complete_data_mutation_dedupe(&mut pending).await?;
            json_response(StatusCode::CREATED, &reply)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                self.record_data_mutation_failure(&mut pending, &error)
                    .await?;
                Err(error)
            }
        }
    }

    async fn restore_database(
        &self,
        database_id: &str,
        request: RestoreDatabaseRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        let backup_id = AuditId::parse(&request.backup_id).map_err(|error| {
            PlatformError::invalid("invalid backup_id").with_detail(error.to_string())
        })?;
        let backup = self
            .backup_jobs
            .get(backup_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("backup does not exist"))?;
        if backup.value.database_id != database.id {
            return Err(PlatformError::conflict(
                "backup does not belong to the requested database",
            ));
        }
        if backup.value.state != "completed" {
            return Err(PlatformError::conflict(
                "backup must be completed before restore",
            ));
        }
        self.verify_backup_artifact_manifest(&backup.value).await?;

        let point_in_time = parse_optional_rfc3339(request.point_in_time_rfc3339.as_deref())?;
        validate_point_in_time(point_in_time)?;
        let volume = self.ensure_database_storage_volume(&database).await?;
        let selected_recovery_point = self
            .resolve_backup_storage_recovery_point(&volume, &backup.value)
            .await?;
        let (source_mode, selected_recovery_point) =
            if let Some(recovery_point) = selected_recovery_point {
                (
                    RestoreStorageSourceMode::BackupCorrelatedStorageLineage,
                    build_backup_storage_recovery_point(&recovery_point),
                )
            } else {
                let recovery_point = self
                    .storage
                    .describe_ready_volume_recovery_point(&volume.id)
                    .await?
                    .ok_or_else(|| {
                        PlatformError::unavailable("database storage recovery point does not exist")
                    })?;
                (
                    RestoreStorageSourceMode::LatestReadyFallback,
                    build_backup_storage_recovery_point(&recovery_point),
                )
            };
        let restore_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate restore id")
                .with_detail(error.to_string())
        })?;
        let workflow = build_restore_workflow(RestoreWorkflowState {
            restore_id: restore_id.clone(),
            database_id: database.id.clone(),
            backup_id: backup_id.clone(),
            requested_by: context
                .actor
                .clone()
                .unwrap_or_else(|| String::from("system")),
            point_in_time,
            reason: request.reason.clone(),
            target_volume_id: volume.id.clone(),
            source_mode: Some(source_mode),
            selected_recovery_point: Some(selected_recovery_point.clone()),
            backup_correlated_recovery_point: backup.value.storage_recovery_point.clone(),
            storage_restore: None,
            evidence: Vec::new(),
        });
        let started = self
            .restore_workflows
            .create(restore_id.as_str(), workflow)
            .await?;
        self.sync_restore_job_projection(&started.value).await?;
        let restore = self.execute_restore_workflow(restore_id.as_str()).await?;
        let restore_storage_lineage = restore.storage_restore.clone().ok_or_else(|| {
            PlatformError::unavailable("restore workflow completed without storage lineage")
        })?;

        self.append_event(
            "data.database.restore.completed.v1",
            "database_restore",
            restore_id.as_str(),
            "completed",
            serde_json::json!({
                "database_id": database.id,
                "backup_id": backup_id,
                "point_in_time": point_in_time,
                "reason": request.reason,
                "used_backup_correlated_storage_recovery_point": matches!(
                    source_mode,
                    RestoreStorageSourceMode::BackupCorrelatedStorageLineage
                ),
                "storage_restore_source_mode": restore_storage_lineage.source_mode,
                "storage_volume_id": volume.id,
                "storage_restore_action_id": restore_storage_lineage.restore_action_id,
                "storage_restore_workflow_id": restore_storage_lineage.restore_workflow_id,
                "storage_source_recovery_point_version": restore_storage_lineage.selected_recovery_point.version,
                "storage_source_recovery_point_etag": restore_storage_lineage.selected_recovery_point.etag,
            }),
            context,
        )
        .await?;
        let response = self
            .build_restore_job_reply_with_storage_state_reason(&restore)
            .await?;
        json_response(StatusCode::OK, &response)
    }

    async fn restore_database_with_idempotency(
        &self,
        database_id: &str,
        request: RestoreDatabaseRequest,
        idempotency_key: Option<&str>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        let backup_id = AuditId::parse(&request.backup_id).map_err(|error| {
            PlatformError::invalid("invalid backup_id").with_detail(error.to_string())
        })?;
        let backup = self
            .backup_jobs
            .get(backup_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("backup does not exist"))?;
        if backup.value.database_id != database.id {
            return Err(PlatformError::conflict(
                "backup does not belong to the requested database",
            ));
        }
        if backup.value.state != "completed" {
            return Err(PlatformError::conflict(
                "backup must be completed before restore",
            ));
        }
        self.verify_backup_artifact_manifest(&backup.value).await?;

        let point_in_time = parse_optional_rfc3339(request.point_in_time_rfc3339.as_deref())?;
        validate_point_in_time(point_in_time)?;
        let request_digest = restore_request_digest(
            database.id.as_str(),
            backup_id.as_str(),
            point_in_time,
            request.reason.as_deref(),
        )?;
        let mut pending = match self
            .begin_data_mutation_dedupe(
                DataMutationOperation::Restore,
                database.id.as_str(),
                idempotency_key,
                &request_digest,
                context,
            )
            .await?
        {
            DataMutationDedupeBeginOutcome::Proceed(pending) => *pending,
            DataMutationDedupeBeginOutcome::Replay(response) => return Ok(response),
        };

        let result = async {
            let volume = self.ensure_database_storage_volume(&database).await?;
            let selected_recovery_point = self
                .resolve_backup_storage_recovery_point(&volume, &backup.value)
                .await?;
            let (source_mode, selected_recovery_point) =
                if let Some(recovery_point) = selected_recovery_point {
                    (
                        RestoreStorageSourceMode::BackupCorrelatedStorageLineage,
                        build_backup_storage_recovery_point(&recovery_point),
                    )
                } else {
                    let recovery_point = self
                        .storage
                        .describe_ready_volume_recovery_point(&volume.id)
                        .await?
                        .ok_or_else(|| {
                            PlatformError::unavailable(
                                "database storage recovery point does not exist",
                            )
                        })?;
                    (
                        RestoreStorageSourceMode::LatestReadyFallback,
                        build_backup_storage_recovery_point(&recovery_point),
                    )
                };
            let restore_id = AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate restore id")
                    .with_detail(error.to_string())
            })?;
            let workflow = build_restore_workflow(RestoreWorkflowState {
                restore_id: restore_id.clone(),
                database_id: database.id.clone(),
                backup_id: backup_id.clone(),
                requested_by: context
                    .actor
                    .clone()
                    .unwrap_or_else(|| String::from("system")),
                point_in_time,
                reason: request.reason.clone(),
                target_volume_id: volume.id.clone(),
                source_mode: Some(source_mode),
                selected_recovery_point: Some(selected_recovery_point.clone()),
                backup_correlated_recovery_point: backup.value.storage_recovery_point.clone(),
                storage_restore: None,
                evidence: Vec::new(),
            });
            let started = self
                .restore_workflows
                .create(restore_id.as_str(), workflow)
                .await?;
            self.sync_restore_job_projection(&started.value).await?;
            let restore = self.execute_restore_workflow(restore_id.as_str()).await?;
            let restore_storage_lineage = restore.storage_restore.clone().ok_or_else(|| {
                PlatformError::unavailable("restore workflow completed without storage lineage")
            })?;
            self.stage_data_mutation_result_reference(
                &mut pending,
                StatusCode::OK,
                data_mutation_result_resource_kind(DataMutationOperation::Restore),
                restore.id.as_str(),
            )
            .await?;
            let response = self
                .build_restore_job_reply_with_storage_state_reason(&restore)
                .await?;
            let response_json =
                serialize_response_body(&response, "restore idempotency replay payload")?;
            self.stage_data_mutation_response(
                &mut pending,
                StatusCode::OK,
                &response_json,
                "database_restore",
                restore_id.as_str(),
            )
            .await?;
            self.append_event(
                "data.database.restore.completed.v1",
                "database_restore",
                restore_id.as_str(),
                "completed",
                serde_json::json!({
                    "database_id": database.id,
                    "backup_id": backup_id,
                    "point_in_time": point_in_time,
                    "reason": request.reason,
                    "used_backup_correlated_storage_recovery_point": matches!(
                        source_mode,
                        RestoreStorageSourceMode::BackupCorrelatedStorageLineage
                    ),
                    "storage_restore_source_mode": restore_storage_lineage.source_mode,
                    "storage_volume_id": volume.id,
                    "storage_restore_action_id": restore_storage_lineage.restore_action_id,
                    "storage_restore_workflow_id": restore_storage_lineage.restore_workflow_id,
                    "storage_source_recovery_point_version": restore_storage_lineage.selected_recovery_point.version,
                    "storage_source_recovery_point_etag": restore_storage_lineage.selected_recovery_point.etag,
                }),
                context,
            )
            .await?;
            self.complete_data_mutation_dedupe(&mut pending).await?;
            json_response(StatusCode::OK, &response)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                self.record_data_mutation_failure(&mut pending, &error)
                    .await?;
                Err(error)
            }
        }
    }

    async fn failover_database(
        &self,
        database_id: &str,
        request: FailoverDatabaseRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        if database.replica_topology.len() < 2 {
            return Err(PlatformError::conflict(
                "database failover requires at least two replicas",
            ));
        }

        let current_primary_idx = database
            .replica_topology
            .iter()
            .position(|replica| replica.role == "primary")
            .ok_or_else(|| PlatformError::conflict("database has no primary replica"))?;
        let target_idx = select_failover_target(&database, &request, current_primary_idx)?;
        let from_replica_id = database.replica_topology[current_primary_idx].id.clone();
        let to_replica_id = database.replica_topology[target_idx].id.clone();

        let failover_id = FailoverOperationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate data failover id")
                .with_detail(error.to_string())
        })?;
        let reason = request
            .reason
            .unwrap_or_else(|| String::from("operator initiated failover"));
        let workflow = build_failover_workflow(FailoverWorkflowState {
            failover_id: failover_id.clone(),
            database_id: database.id.clone(),
            from_replica_id: from_replica_id.clone(),
            to_replica_id: to_replica_id.clone(),
            target_region: database.replica_topology[target_idx].region.clone(),
            requested_by: context
                .actor
                .clone()
                .unwrap_or_else(|| String::from("system")),
            reason: reason.clone(),
            evidence: Vec::new(),
        });
        let started = self
            .failover_workflows
            .create(failover_id.as_str(), workflow)
            .await?;
        self.sync_failover_projection(&started.value).await?;
        let record = self.execute_failover_workflow(failover_id.as_str()).await?;

        self.append_event(
            "data.database.failover.completed.v1",
            "database_failover",
            failover_id.as_str(),
            "completed",
            serde_json::json!({
                "database_id": database.id,
                "from_replica_id": from_replica_id,
                "to_replica_id": to_replica_id,
                "reason": reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn failover_database_with_idempotency(
        &self,
        database_id: &str,
        request: FailoverDatabaseRequest,
        idempotency_key: Option<&str>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        if database.replica_topology.len() < 2 {
            return Err(PlatformError::conflict(
                "database failover requires at least two replicas",
            ));
        }

        let reason = request
            .reason
            .clone()
            .unwrap_or_else(|| String::from("operator initiated failover"));
        let request_digest = failover_request_digest(
            database.id.as_str(),
            request.target_replica_id.as_deref(),
            request.target_region.as_deref(),
            reason.as_str(),
        )?;
        let mut pending = match self
            .begin_data_mutation_dedupe(
                DataMutationOperation::Failover,
                database.id.as_str(),
                idempotency_key,
                &request_digest,
                context,
            )
            .await?
        {
            DataMutationDedupeBeginOutcome::Proceed(pending) => *pending,
            DataMutationDedupeBeginOutcome::Replay(response) => return Ok(response),
        };

        let result = async {
            let current_primary_idx = database
                .replica_topology
                .iter()
                .position(|replica| replica.role == "primary")
                .ok_or_else(|| PlatformError::conflict("database has no primary replica"))?;
            let target_idx = select_failover_target(&database, &request, current_primary_idx)?;
            let from_replica_id = database.replica_topology[current_primary_idx].id.clone();
            let to_replica_id = database.replica_topology[target_idx].id.clone();
            let failover_id = FailoverOperationId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate data failover id")
                    .with_detail(error.to_string())
            })?;
            let workflow = build_failover_workflow(FailoverWorkflowState {
                failover_id: failover_id.clone(),
                database_id: database.id.clone(),
                from_replica_id: from_replica_id.clone(),
                to_replica_id: to_replica_id.clone(),
                target_region: database.replica_topology[target_idx].region.clone(),
                requested_by: context
                    .actor
                    .clone()
                    .unwrap_or_else(|| String::from("system")),
                reason: reason.clone(),
                evidence: Vec::new(),
            });
            let started = self
                .failover_workflows
                .create(failover_id.as_str(), workflow)
                .await?;
            self.sync_failover_projection(&started.value).await?;
            let record = self.execute_failover_workflow(failover_id.as_str()).await?;
            self.stage_data_mutation_result_reference(
                &mut pending,
                StatusCode::OK,
                data_mutation_result_resource_kind(DataMutationOperation::Failover),
                record.id.as_str(),
            )
            .await?;
            let record_json =
                serialize_response_body(&record, "failover idempotency replay payload")?;
            self.stage_data_mutation_response(
                &mut pending,
                StatusCode::OK,
                &record_json,
                "database_failover",
                failover_id.as_str(),
            )
            .await?;
            self.append_event(
                "data.database.failover.completed.v1",
                "database_failover",
                failover_id.as_str(),
                "completed",
                serde_json::json!({
                    "database_id": database.id,
                    "from_replica_id": from_replica_id,
                    "to_replica_id": to_replica_id,
                    "reason": reason,
                }),
                context,
            )
            .await?;
            self.complete_data_mutation_dedupe(&mut pending).await?;
            json_response(StatusCode::OK, &record)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                self.record_data_mutation_failure(&mut pending, &error)
                    .await?;
                Err(error)
            }
        }
    }

    async fn set_maintenance(
        &self,
        database_id: &str,
        request: MaintenanceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let mut database = self.load_database(database_id).await?;
        database.maintenance_mode = request.enabled;
        if request.enabled {
            database.lifecycle_state = String::from("maintenance");
            database.maintenance_reason = request.reason.clone();
        } else {
            database.lifecycle_state = String::from("ready");
            database.maintenance_reason = None;
        }

        let current = self
            .databases
            .get(database.id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("database does not exist"))?;
        self.databases
            .upsert(
                database.id.as_str(),
                database.clone(),
                Some(current.version),
            )
            .await?;
        self.append_event(
            "data.database.maintenance.updated.v1",
            "database",
            database.id.as_str(),
            "updated",
            serde_json::json!({
                "enabled": request.enabled,
                "reason": request.reason,
                "state": database.lifecycle_state,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &database)
    }

    async fn create_migration(
        &self,
        database_id: &str,
        request: CreateDataMigrationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let database = self.load_database(database_id).await?;
        if self.has_active_migration(database.id.as_str()).await? {
            return Err(PlatformError::conflict(
                "database already has an active migration workflow",
            ));
        }

        let kind = normalize_migration_kind(&request.kind)?;
        let now = OffsetDateTime::now_utc();
        let id = MigrationJobId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate data migration id")
                .with_detail(error.to_string())
        })?;
        let mut job = DataMigrationJob {
            id: id.clone(),
            database_id: database.id.clone(),
            kind,
            state: String::from(DATA_MIGRATION_STATE_PENDING),
            requested_by: context
                .actor
                .clone()
                .unwrap_or_else(|| String::from("system")),
            created_at: now,
            started_at: None,
            completed_at: None,
            failed_at: None,
            reason: request.reason,
            source_version: None,
            target_version: None,
            source_region: None,
            target_region: None,
            source_replica_id: None,
            target_replica_id: None,
            source_storage_class: None,
            target_storage_class: None,
            failure_reason: None,
        };

        match job.kind.as_str() {
            "major_version_upgrade" => {
                let target_version = normalize_database_version(
                    request.target_version.as_deref().ok_or_else(|| {
                        PlatformError::invalid("major-version migration requires target_version")
                    })?,
                )?;
                validate_major_version_upgrade(&database.version, &target_version)?;
                job.source_version = Some(database.version.clone());
                job.target_version = Some(target_version);
            }
            "region_move" => {
                let target_region =
                    normalize_region(request.target_region.as_deref().ok_or_else(|| {
                        PlatformError::invalid("region migration requires target_region")
                    })?)?;
                if target_region == database.primary_region {
                    return Err(PlatformError::conflict(
                        "region migration target already matches the primary region",
                    ));
                }
                if database
                    .replica_topology
                    .iter()
                    .any(|replica| replica.region == target_region && !replica.healthy)
                {
                    return Err(PlatformError::conflict(
                        "region migration target maps to an unhealthy replica",
                    ));
                }
                job.source_region = Some(database.primary_region.clone());
                job.target_region = Some(target_region);
            }
            "replica_reseed" => {
                let current_primary_idx = primary_replica_index(&database)?;
                let default_source_replica_id =
                    database.replica_topology[current_primary_idx].id.clone();
                let source_replica_id = normalize_replica_id(
                    request
                        .source_replica_id
                        .as_deref()
                        .unwrap_or(default_source_replica_id.as_str()),
                    "source_replica_id",
                )?;
                let target_replica_id = normalize_replica_id(
                    request.target_replica_id.as_deref().ok_or_else(|| {
                        PlatformError::invalid(
                            "replica reseed migration requires target_replica_id",
                        )
                    })?,
                    "target_replica_id",
                )?;
                let source_replica = database
                    .replica_topology
                    .iter()
                    .find(|replica| replica.id == source_replica_id)
                    .ok_or_else(|| {
                        PlatformError::not_found("source replica does not exist for reseed")
                    })?;
                let target_replica = database
                    .replica_topology
                    .iter()
                    .find(|replica| replica.id == target_replica_id)
                    .ok_or_else(|| {
                        PlatformError::not_found("target replica does not exist for reseed")
                    })?;
                if source_replica.id == target_replica.id {
                    return Err(PlatformError::conflict(
                        "replica reseed source and target must differ",
                    ));
                }
                if target_replica.role == "primary" {
                    return Err(PlatformError::conflict(
                        "replica reseed target must be a non-primary replica",
                    ));
                }
                if !source_replica.healthy {
                    return Err(PlatformError::conflict(
                        "replica reseed source must be healthy",
                    ));
                }
                job.source_replica_id = Some(source_replica.id.clone());
                job.target_replica_id = Some(target_replica.id.clone());
            }
            "storage_class_change" => {
                let target_storage_class = normalize_storage_class(
                    request.target_storage_class.as_deref().ok_or_else(|| {
                        PlatformError::invalid(
                            "storage-class migration requires target_storage_class",
                        )
                    })?,
                )?;
                if database.storage_class.as_deref() == Some(target_storage_class.as_str()) {
                    return Err(PlatformError::conflict(
                        "storage-class migration target already matches the database",
                    ));
                }
                job.source_storage_class = database.storage_class.clone();
                job.target_storage_class = Some(target_storage_class);
            }
            _ => {
                return Err(PlatformError::invalid("unsupported data migration kind"));
            }
        }

        self.migrations.create(id.as_str(), job.clone()).await?;
        self.append_event(
            "data.database.migration.requested.v1",
            "database_migration",
            id.as_str(),
            "requested",
            data_migration_event_details(&job),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &job)
    }

    async fn start_migration(
        &self,
        migration_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let current = self.load_migration_record(migration_id).await?;
        let mut migration = current.value;
        if migration.state != DATA_MIGRATION_STATE_PENDING {
            return Err(PlatformError::conflict(
                "data migration must be pending before it can start",
            ));
        }
        let now = OffsetDateTime::now_utc();
        migration.state = String::from(DATA_MIGRATION_STATE_RUNNING);
        migration.started_at = Some(now);
        migration.completed_at = None;
        migration.failed_at = None;
        migration.failure_reason = None;

        self.migrations
            .upsert(
                migration.id.as_str(),
                migration.clone(),
                Some(current.version),
            )
            .await?;
        self.append_event(
            "data.database.migration.started.v1",
            "database_migration",
            migration.id.as_str(),
            "started",
            data_migration_event_details(&migration),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &migration)
    }

    async fn complete_migration(
        &self,
        migration_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let current = self.load_migration_record(migration_id).await?;
        let mut migration = current.value;
        if !matches!(
            migration.state.as_str(),
            DATA_MIGRATION_STATE_PENDING | DATA_MIGRATION_STATE_RUNNING
        ) {
            return Err(PlatformError::conflict(
                "data migration must be pending or running before completion",
            ));
        }

        let database_current = self
            .databases
            .get(migration.database_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("database does not exist"))?;
        if database_current.deleted {
            return Err(PlatformError::not_found("database does not exist"));
        }
        let mut database = database_current.value;
        apply_completed_data_migration(&mut database, &migration)?;
        let database_id = database.id.as_str().to_owned();
        self.databases
            .upsert(
                database_id.as_str(),
                database,
                Some(database_current.version),
            )
            .await?;

        let now = OffsetDateTime::now_utc();
        migration.state = String::from(DATA_MIGRATION_STATE_COMPLETED);
        migration.started_at.get_or_insert(now);
        migration.completed_at = Some(now);
        migration.failed_at = None;
        migration.failure_reason = None;
        self.migrations
            .upsert(
                migration.id.as_str(),
                migration.clone(),
                Some(current.version),
            )
            .await?;
        self.append_event(
            "data.database.migration.completed.v1",
            "database_migration",
            migration.id.as_str(),
            "completed",
            data_migration_event_details(&migration),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &migration)
    }

    async fn fail_migration(
        &self,
        migration_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let current = self.load_migration_record(migration_id).await?;
        let mut migration = current.value;
        if !matches!(
            migration.state.as_str(),
            DATA_MIGRATION_STATE_PENDING | DATA_MIGRATION_STATE_RUNNING
        ) {
            return Err(PlatformError::conflict(
                "data migration must be pending or running before failure",
            ));
        }

        migration.state = String::from(DATA_MIGRATION_STATE_FAILED);
        migration.completed_at = None;
        migration.failed_at = Some(OffsetDateTime::now_utc());
        migration.failure_reason = Some(String::from("operator marked migration failed"));
        self.migrations
            .upsert(
                migration.id.as_str(),
                migration.clone(),
                Some(current.version),
            )
            .await?;
        self.append_event(
            "data.database.migration.failed.v1",
            "database_migration",
            migration.id.as_str(),
            "failed",
            data_migration_event_details(&migration),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &migration)
    }

    async fn load_database_record(
        &self,
        database_id: &str,
    ) -> Result<StoredDocument<ManagedDatabase>> {
        let stored = self
            .databases
            .get(database_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("database does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("database does not exist"));
        }
        Ok(stored)
    }

    async fn load_database(&self, database_id: &str) -> Result<ManagedDatabase> {
        Ok(self.load_database_record(database_id).await?.value)
    }

    async fn load_cache(&self, cache_id: &str) -> Result<CacheCluster> {
        let cache_id = CacheClusterId::parse(cache_id).map_err(|error| {
            PlatformError::invalid("invalid cache_id").with_detail(error.to_string())
        })?;
        let stored = self
            .caches
            .get(cache_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("cache does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("cache does not exist"));
        }
        Ok(stored.value)
    }

    async fn load_queue(&self, queue_id: &str) -> Result<QueueService> {
        let queue_id = QueueId::parse(queue_id).map_err(|error| {
            PlatformError::invalid("invalid queue_id").with_detail(error.to_string())
        })?;
        let stored = self
            .queues
            .get(queue_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("queue does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("queue does not exist"));
        }
        Ok(stored.value)
    }

    async fn ensure_import_target_exists(
        &self,
        resource_kind: DataTransferResourceKind,
        resource_id: &str,
    ) -> Result<()> {
        match resource_kind {
            DataTransferResourceKind::Database => {
                let _ = self.load_database(resource_id).await?;
            }
            DataTransferResourceKind::Cache => {
                let _ = self.load_cache(resource_id).await?;
            }
            DataTransferResourceKind::Queue => {
                let _ = self.load_queue(resource_id).await?;
            }
        }
        Ok(())
    }

    async fn build_export_material(
        &self,
        resource_kind: DataTransferResourceKind,
        resource_id: &str,
        export_id: &AuditId,
        artifact_format: Option<&str>,
    ) -> Result<ExportMaterial> {
        let artifact_format = normalize_export_artifact_format(resource_kind, artifact_format)?;
        let artifact_root_uri = format!(
            "object://data/exports/{}/{}/{}",
            resource_kind.collection_segment(),
            resource_id,
            export_id.as_str(),
        );
        let manifest_uri = format!("{artifact_root_uri}/manifest.json");
        let checksum_catalog_uri = format!("{artifact_root_uri}/checksums.json");

        let (checksum_entries, details) = match resource_kind {
            DataTransferResourceKind::Database => {
                let database = self.load_database(resource_id).await?;
                let schema_uri = format!("{artifact_root_uri}/schema.sql");
                let payload_name = if artifact_format == "physical_snapshot" {
                    "database.snapshot"
                } else {
                    "database.dump"
                };
                let payload_uri = format!("{artifact_root_uri}/{payload_name}");
                let role_uri = format!("{artifact_root_uri}/roles.json");
                let entries = vec![
                    DataChecksumCatalogEntry {
                        artifact_uri: schema_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:database-schema:{}:{}",
                                database.id.as_str(),
                                database.engine,
                                database.version,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: 16 * 1024,
                    },
                    DataChecksumCatalogEntry {
                        artifact_uri: payload_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:database-payload:{}:{}:{}:{}",
                                database.id.as_str(),
                                artifact_format,
                                database.storage_gb,
                                database.replicas,
                                database.metadata.etag,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: u64::from(database.storage_gb)
                            .saturating_mul(1024)
                            .saturating_mul(1024),
                    },
                    DataChecksumCatalogEntry {
                        artifact_uri: role_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:database-roles:{}:{}",
                                database.id.as_str(),
                                database.tls_required,
                                database.primary_region,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: 4 * 1024,
                    },
                ];
                let details = serde_json::json!({
                    "engine": database.engine,
                    "version": database.version,
                    "replicas": database.replicas,
                    "storage_gb": database.storage_gb,
                });
                (entries, details)
            }
            DataTransferResourceKind::Cache => {
                let cache = self.load_cache(resource_id).await?;
                let payload_name = if artifact_format == "append_only_log" {
                    "cache.aof"
                } else {
                    "cache.snapshot"
                };
                let payload_uri = format!("{artifact_root_uri}/{payload_name}");
                let config_uri = format!("{artifact_root_uri}/config.json");
                let entries = vec![
                    DataChecksumCatalogEntry {
                        artifact_uri: payload_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:cache-payload:{}:{}:{}",
                                cache.id.as_str(),
                                artifact_format,
                                cache.engine,
                                cache.memory_mb,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: cache.memory_mb.saturating_mul(1024),
                    },
                    DataChecksumCatalogEntry {
                        artifact_uri: config_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:cache-config:{}:{}",
                                cache.id.as_str(),
                                cache.engine,
                                cache.tls_required,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: 2 * 1024,
                    },
                ];
                let details = serde_json::json!({
                    "engine": cache.engine,
                    "memory_mb": cache.memory_mb,
                    "tls_required": cache.tls_required,
                });
                (entries, details)
            }
            DataTransferResourceKind::Queue => {
                let queue = self.load_queue(resource_id).await?;
                let segment_uri = format!("{artifact_root_uri}/segments.log");
                let consumer_uri = format!("{artifact_root_uri}/consumer-groups.json");
                let mut entries = vec![
                    DataChecksumCatalogEntry {
                        artifact_uri: segment_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:queue-segments:{}:{}:{}",
                                queue.id.as_str(),
                                artifact_format,
                                queue.partitions,
                                queue.retention_hours,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: u64::from(queue.partitions)
                            .saturating_mul(u64::from(queue.retention_hours))
                            .saturating_mul(1024),
                    },
                    DataChecksumCatalogEntry {
                        artifact_uri: consumer_uri,
                        checksum: sha256_hex(
                            format!(
                                "{}:queue-consumers:{}:{}",
                                queue.id.as_str(),
                                queue.partitions,
                                queue.metadata.etag,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: 2 * 1024,
                    },
                ];
                if queue.dead_letter_enabled {
                    entries.push(DataChecksumCatalogEntry {
                        artifact_uri: format!("{artifact_root_uri}/dead-letter.log"),
                        checksum: sha256_hex(
                            format!(
                                "{}:queue-dead-letter:{}",
                                queue.id.as_str(),
                                queue.retention_hours,
                            )
                            .as_bytes(),
                        ),
                        size_bytes: 32 * 1024,
                    });
                }
                let details = serde_json::json!({
                    "partitions": queue.partitions,
                    "retention_hours": queue.retention_hours,
                    "dead_letter_enabled": queue.dead_letter_enabled,
                });
                (entries, details)
            }
        };

        Ok(ExportMaterial {
            artifact_format,
            artifact_root_uri,
            manifest_uri,
            checksum_catalog_uri,
            checksum_entries,
            details,
        })
    }

    async fn load_migration_record(
        &self,
        migration_id: &str,
    ) -> Result<StoredDocument<DataMigrationJob>> {
        let migration_id = MigrationJobId::parse(migration_id).map_err(|error| {
            PlatformError::invalid("invalid migration_id").with_detail(error.to_string())
        })?;
        let stored = self
            .migrations
            .get(migration_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("data migration does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("data migration does not exist"));
        }
        Ok(stored)
    }

    async fn resolve_backup_storage_recovery_point(
        &self,
        volume: &VolumeRecord,
        backup: &BackupJob,
    ) -> Result<Option<VolumeRecoveryPointSummary>> {
        let Some(lineage) = backup.storage_recovery_point.as_ref() else {
            return Ok(None);
        };
        if lineage.volume_id != volume.id {
            return Ok(None);
        }
        self.storage
            .describe_volume_recovery_point(
                &lineage.volume_id,
                lineage.version,
                Some(lineage.etag.as_str()),
            )
            .await
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
                    PlatformError::unavailable("failed to allocate data event id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("data"),
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
        let id = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("data.events.v1", event, Some(&id))
            .await?;
        Ok(())
    }

    async fn list_backup_jobs(
        &self,
        database_filter: Option<&str>,
        state_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BackupJob>> {
        let mut values = active_values(self.backup_jobs.list().await?)
            .into_iter()
            .filter(|entry| database_filter.is_none_or(|value| entry.database_id.as_str() == value))
            .filter(|entry| {
                state_filter
                    .as_ref()
                    .is_none_or(|value| entry.state.to_ascii_lowercase() == *value)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.created_at);
        values.reverse();
        if values.len() > limit {
            values.truncate(limit);
        }
        Ok(values)
    }

    async fn list_export_jobs(
        &self,
        resource_kind_filter: Option<&str>,
        resource_id_filter: Option<&str>,
        state_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DataExportJob>> {
        let mut values = active_values(self.export_jobs.list().await?)
            .into_iter()
            .filter(|entry| {
                resource_kind_filter
                    .is_none_or(|value| entry.resource_kind.eq_ignore_ascii_case(value))
            })
            .filter(|entry| resource_id_filter.is_none_or(|value| entry.resource_id == value))
            .filter(|entry| {
                state_filter
                    .as_ref()
                    .is_none_or(|value| entry.state.to_ascii_lowercase() == *value)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.created_at);
        values.reverse();
        if values.len() > limit {
            values.truncate(limit);
        }
        Ok(values)
    }

    async fn list_import_jobs(
        &self,
        resource_kind_filter: Option<&str>,
        source_resource_id_filter: Option<&str>,
        target_resource_id_filter: Option<&str>,
        state_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DataImportJob>> {
        let mut values = active_values(self.import_jobs.list().await?)
            .into_iter()
            .filter(|entry| {
                resource_kind_filter
                    .is_none_or(|value| entry.resource_kind.eq_ignore_ascii_case(value))
            })
            .filter(|entry| {
                source_resource_id_filter.is_none_or(|value| entry.source_resource_id == value)
            })
            .filter(|entry| {
                target_resource_id_filter
                    .is_none_or(|value| entry.target_resource_id.as_deref() == Some(value))
            })
            .filter(|entry| {
                state_filter
                    .as_ref()
                    .is_none_or(|value| entry.state.to_ascii_lowercase() == *value)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.created_at);
        values.reverse();
        if values.len() > limit {
            values.truncate(limit);
        }
        Ok(values)
    }

    async fn has_active_migration(&self, database_id: &str) -> Result<bool> {
        Ok(active_values(self.migrations.list().await?)
            .into_iter()
            .any(|entry| {
                entry.database_id.as_str() == database_id && is_active_migration_state(&entry.state)
            }))
    }

    async fn list_migration_jobs(
        &self,
        database_filter: Option<&str>,
        kind_filter: Option<&str>,
        state_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DataMigrationJob>> {
        let mut values = active_values(self.migrations.list().await?)
            .into_iter()
            .filter(|entry| database_filter.is_none_or(|value| entry.database_id.as_str() == value))
            .filter(|entry| kind_filter.is_none_or(|value| entry.kind == value))
            .filter(|entry| {
                state_filter
                    .as_ref()
                    .is_none_or(|value| entry.state.to_ascii_lowercase() == *value)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.created_at);
        values.reverse();
        if values.len() > limit {
            values.truncate(limit);
        }
        Ok(values)
    }
}

impl HttpService for DataService {
    fn name(&self) -> &'static str {
        "data"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/data")];
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
                (Method::GET, ["data"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["data", "databases"]) => {
                    let values = active_values(self.databases.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "databases", database_id]) => {
                    let value = self
                        .databases
                        .get(database_id)
                        .await?
                        .filter(|record| !record.deleted)
                        .map(|record| record.value);
                    json_response(StatusCode::OK, &value).map(Some)
                }
                (Method::POST, ["data", "databases"]) => {
                    let body: CreateDatabaseRequest = parse_json(request).await?;
                    self.create_database(body, &context).await.map(Some)
                }
                (Method::POST, ["data", "databases", database_id, "backups"]) => {
                    let idempotency_key = extract_idempotency_key(request.headers())?;
                    let body: CreateBackupRequest = parse_json(request).await?;
                    match idempotency_key.as_deref() {
                        Some(idempotency_key) => self
                            .create_backup_with_idempotency(
                                database_id,
                                body,
                                Some(idempotency_key),
                                &context,
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_backup(database_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::POST, ["data", "databases", database_id, "restore"]) => {
                    let idempotency_key = extract_idempotency_key(request.headers())?;
                    let body: RestoreDatabaseRequest = parse_json(request).await?;
                    match idempotency_key.as_deref() {
                        Some(idempotency_key) => self
                            .restore_database_with_idempotency(
                                database_id,
                                body,
                                Some(idempotency_key),
                                &context,
                            )
                            .await
                            .map(Some),
                        None => self
                            .restore_database(database_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::POST, ["data", "databases", database_id, "failover"]) => {
                    let idempotency_key = extract_idempotency_key(request.headers())?;
                    let body: FailoverDatabaseRequest = parse_json(request).await?;
                    match idempotency_key.as_deref() {
                        Some(idempotency_key) => self
                            .failover_database_with_idempotency(
                                database_id,
                                body,
                                Some(idempotency_key),
                                &context,
                            )
                            .await
                            .map(Some),
                        None => self
                            .failover_database(database_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::POST, ["data", "databases", database_id, "maintenance"]) => {
                    let body: MaintenanceRequest = parse_json(request).await?;
                    self.set_maintenance(database_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["data", "databases", database_id, "migrations"]) => {
                    let body: CreateDataMigrationRequest = parse_json(request).await?;
                    self.create_migration(database_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["data", "databases", database_id, "exports"]) => {
                    let body: CreateDataExportRequest = parse_json(request).await?;
                    self.create_export(
                        DataTransferResourceKind::Database,
                        database_id,
                        body,
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::POST, ["data", "databases", "imports"]) => {
                    let body: CreateDataImportRequest = parse_json(request).await?;
                    self.create_import(DataTransferResourceKind::Database, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["data", "backups"]) => {
                    let database_filter = query.get("database_id").map(String::as_str);
                    let state_filter = query.get("state").map(|value| value.to_ascii_lowercase());
                    let limit = query
                        .get("limit")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(200)
                        .min(5000);
                    let backups = self
                        .list_backup_jobs(database_filter, state_filter.as_deref(), limit)
                        .await?;
                    let mut values = Vec::with_capacity(backups.len());
                    for backup in backups {
                        values.push(
                            self.build_backup_job_reply_with_storage_state_reason(&backup)
                                .await?,
                        );
                    }
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "backups", backup_id, "storage-lineage"]) => {
                    let lineage = self
                        .describe_backup_storage_lineage(backup_id, &context)
                        .await?;
                    json_response(StatusCode::OK, &lineage).map(Some)
                }
                (Method::GET, ["data", "restores"]) => {
                    let restores = active_values(self.restore_jobs.list().await?);
                    let mut values = Vec::with_capacity(restores.len());
                    for restore in restores {
                        values.push(
                            self.build_restore_job_reply_with_storage_state_reason(&restore)
                                .await?,
                        );
                    }
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "restores", restore_id, "storage-lineage"]) => {
                    let lineage = self
                        .describe_restore_storage_lineage(restore_id, &context)
                        .await?;
                    json_response(StatusCode::OK, &lineage).map(Some)
                }
                (Method::GET, ["data", "failovers"]) => {
                    let values = active_values(self.failovers.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "exports"]) => {
                    let resource_kind_filter = query.get("resource_kind").map(String::as_str);
                    let resource_id_filter = query.get("resource_id").map(String::as_str);
                    let state_filter = query.get("state").map(|value| value.to_ascii_lowercase());
                    let limit = query
                        .get("limit")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(200)
                        .min(5000);
                    let values = self
                        .list_export_jobs(
                            resource_kind_filter,
                            resource_id_filter,
                            state_filter.as_deref(),
                            limit,
                        )
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "imports"]) => {
                    let resource_kind_filter = query.get("resource_kind").map(String::as_str);
                    let source_resource_id_filter =
                        query.get("source_resource_id").map(String::as_str);
                    let target_resource_id_filter =
                        query.get("target_resource_id").map(String::as_str);
                    let state_filter = query.get("state").map(|value| value.to_ascii_lowercase());
                    let limit = query
                        .get("limit")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(200)
                        .min(5000);
                    let values = self
                        .list_import_jobs(
                            resource_kind_filter,
                            source_resource_id_filter,
                            target_resource_id_filter,
                            state_filter.as_deref(),
                            limit,
                        )
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["data", "migrations"]) => {
                    let database_filter = query.get("database_id").map(String::as_str);
                    let kind_filter = query.get("kind").map(|value| value.to_ascii_lowercase());
                    let state_filter = query.get("state").map(|value| value.to_ascii_lowercase());
                    let limit = query
                        .get("limit")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(200)
                        .min(5000);
                    let migrations = self
                        .list_migration_jobs(
                            database_filter,
                            kind_filter.as_deref(),
                            state_filter.as_deref(),
                            limit,
                        )
                        .await?;
                    json_response(StatusCode::OK, &migrations).map(Some)
                }
                (Method::GET, ["data", "migrations", migration_id]) => {
                    let value = self
                        .migrations
                        .get(migration_id)
                        .await?
                        .filter(|record| !record.deleted)
                        .map(|record| record.value);
                    json_response(StatusCode::OK, &value).map(Some)
                }
                (Method::POST, ["data", "migrations", migration_id, "start"]) => {
                    self.start_migration(migration_id, &context).await.map(Some)
                }
                (Method::POST, ["data", "migrations", migration_id, "complete"]) => self
                    .complete_migration(migration_id, &context)
                    .await
                    .map(Some),
                (Method::POST, ["data", "migrations", migration_id, "fail"]) => {
                    self.fail_migration(migration_id, &context).await.map(Some)
                }
                (Method::GET, ["data", "caches"]) => {
                    let values = active_values(self.caches.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["data", "caches"]) => {
                    let body: CreateCacheRequest = parse_json(request).await?;
                    self.create_cache(body, &context).await.map(Some)
                }
                (Method::POST, ["data", "caches", cache_id, "exports"]) => {
                    let body: CreateDataExportRequest = parse_json(request).await?;
                    self.create_export(DataTransferResourceKind::Cache, cache_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["data", "caches", "imports"]) => {
                    let body: CreateDataImportRequest = parse_json(request).await?;
                    self.create_import(DataTransferResourceKind::Cache, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["data", "durability-summary"]) => {
                    let summary = self.durability_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["data", "queues"]) => {
                    let values = active_values(self.queues.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["data", "queues"]) => {
                    let body: CreateQueueRequest = parse_json(request).await?;
                    self.create_queue(body, &context).await.map(Some)
                }
                (Method::POST, ["data", "queues", queue_id, "exports"]) => {
                    let body: CreateDataExportRequest = parse_json(request).await?;
                    self.create_export(DataTransferResourceKind::Queue, queue_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["data", "queues", "imports"]) => {
                    let body: CreateDataImportRequest = parse_json(request).await?;
                    self.create_import(DataTransferResourceKind::Queue, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["data", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_database_engine(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "postgres" | "postgresql" => Ok(String::from("postgres")),
        "mysql" => Ok(String::from("mysql")),
        _ => Err(PlatformError::invalid(
            "database engine must be one of postgres/mysql",
        )),
    }
}

fn normalize_cache_engine(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "redis" => String::from("redis"),
        "memcached" => String::from("memcached"),
        _ => String::from("redis"),
    }
}

fn normalize_backup_kind(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "incremental" => String::from("incremental"),
        _ => String::from("full"),
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn normalize_required_string(value: &str, field_name: &'static str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    Ok(trimmed.to_owned())
}

fn normalize_export_artifact_format(
    resource_kind: DataTransferResourceKind,
    value: Option<&str>,
) -> Result<String> {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(resource_kind.default_artifact_format())
        .to_ascii_lowercase();
    let valid = match resource_kind {
        DataTransferResourceKind::Database => {
            matches!(normalized.as_str(), "logical_dump" | "physical_snapshot")
        }
        DataTransferResourceKind::Cache => {
            matches!(normalized.as_str(), "snapshot" | "append_only_log")
        }
        DataTransferResourceKind::Queue => {
            matches!(
                normalized.as_str(),
                "segment_bundle" | "consumer_offsets_bundle"
            )
        }
    };
    if valid {
        Ok(normalized)
    } else {
        Err(PlatformError::invalid(format!(
            "unsupported artifact_format for {}",
            resource_kind.as_str()
        )))
    }
}

fn normalize_signing_key_ref(
    value: Option<&str>,
    resource_kind: DataTransferResourceKind,
) -> Result<String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Ok(value.to_owned()),
        None => Ok(format!(
            "kms://uhost/data/{}/manifest-signing",
            resource_kind.collection_segment()
        )),
    }
}

fn normalize_checksum_algorithm(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == DATA_TRANSFER_CHECKSUM_ALGORITHM {
        Ok(normalized)
    } else {
        Err(PlatformError::invalid("checksum algorithm must be sha256"))
    }
}

fn normalize_signature_scheme(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == DATA_TRANSFER_SIGNATURE_SCHEME {
        Ok(normalized)
    } else {
        Err(PlatformError::invalid(format!(
            "signature_scheme must be {DATA_TRANSFER_SIGNATURE_SCHEME}"
        )))
    }
}

fn normalize_sha256_digest(value: &str, field_name: &'static str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.len() != 64
        || !trimmed
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PlatformError::invalid(format!(
            "{field_name} must be a 64-character hexadecimal sha256 digest"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn build_data_checksum_catalog(entries: Vec<DataChecksumCatalogEntry>) -> DataChecksumCatalog {
    let checksum = data_checksum_catalog_checksum(&entries);
    DataChecksumCatalog {
        algorithm: String::from(DATA_TRANSFER_CHECKSUM_ALGORITHM),
        entries,
        checksum,
    }
}

fn data_checksum_catalog_checksum(entries: &[DataChecksumCatalogEntry]) -> String {
    let mut entries = entries.to_vec();
    entries.sort_by(|left, right| left.artifact_uri.cmp(&right.artifact_uri));
    let mut material = String::from(DATA_TRANSFER_CHECKSUM_ALGORITHM);
    for entry in entries {
        material.push('\n');
        material.push_str(entry.artifact_uri.as_str());
        material.push('|');
        material.push_str(entry.checksum.as_str());
        material.push('|');
        material.push_str(entry.size_bytes.to_string().as_str());
    }
    sha256_hex(material.as_bytes())
}

fn data_transfer_manifest_signature(manifest: &SignedDataTransferManifest) -> String {
    sha256_hex(
        format!(
            "manifest_version={};flow={};resource_kind={};resource_id={};artifact_format={};artifact_root_uri={};checksum_catalog_checksum={};signing_key_ref={};signature_scheme={};signed_at={}",
            manifest.manifest_version,
            manifest.flow,
            manifest.resource_kind,
            manifest.resource_id,
            manifest.artifact_format,
            manifest.artifact_root_uri,
            manifest.checksum_catalog_checksum,
            manifest.signing_key_ref,
            manifest.signature_scheme,
            manifest.signed_at.unix_timestamp_nanos(),
        )
        .as_bytes(),
    )
}

fn validate_signed_data_transfer_manifest(
    manifest: SignedDataTransferManifest,
    expected_resource_kind: DataTransferResourceKind,
) -> Result<SignedDataTransferManifest> {
    if manifest.manifest_version == 0 {
        return Err(PlatformError::invalid(
            "manifest_version must be greater than zero",
        ));
    }
    let flow = normalize_required_string(manifest.flow.as_str(), "flow")?.to_ascii_lowercase();
    if flow != "export" {
        return Err(PlatformError::invalid(
            "data import manifests must be export manifests",
        ));
    }
    let resource_kind =
        normalize_required_string(manifest.resource_kind.as_str(), "resource_kind")?
            .to_ascii_lowercase();
    if resource_kind != expected_resource_kind.as_str() {
        return Err(PlatformError::invalid(
            "manifest resource_kind does not match route",
        ));
    }
    let normalized = SignedDataTransferManifest {
        manifest_version: manifest.manifest_version,
        flow,
        resource_kind,
        resource_id: normalize_required_string(manifest.resource_id.as_str(), "resource_id")?,
        artifact_format: normalize_export_artifact_format(
            expected_resource_kind,
            Some(manifest.artifact_format.as_str()),
        )?,
        artifact_root_uri: normalize_required_string(
            manifest.artifact_root_uri.as_str(),
            "artifact_root_uri",
        )?,
        checksum_catalog_checksum: normalize_sha256_digest(
            manifest.checksum_catalog_checksum.as_str(),
            "checksum_catalog_checksum",
        )?,
        signing_key_ref: normalize_required_string(
            manifest.signing_key_ref.as_str(),
            "signing_key_ref",
        )?,
        signature_scheme: normalize_signature_scheme(manifest.signature_scheme.as_str())?,
        signature: normalize_sha256_digest(manifest.signature.as_str(), "signature")?,
        signed_at: manifest.signed_at,
    };
    let expected_signature = data_transfer_manifest_signature(&normalized);
    if normalized.signature != expected_signature {
        return Err(PlatformError::invalid(
            "manifest signature verification failed",
        ));
    }
    Ok(normalized)
}

fn validate_data_checksum_catalog(
    catalog: DataChecksumCatalog,
    artifact_root_uri: &str,
) -> Result<DataChecksumCatalog> {
    let algorithm = normalize_checksum_algorithm(catalog.algorithm.as_str())?;
    if catalog.entries.is_empty() {
        return Err(PlatformError::invalid(
            "checksum catalog must contain at least one entry",
        ));
    }
    let mut seen_artifacts = BTreeSet::new();
    let mut entries = Vec::with_capacity(catalog.entries.len());
    for entry in catalog.entries {
        let artifact_uri = normalize_required_string(entry.artifact_uri.as_str(), "artifact_uri")?;
        if !artifact_uri.starts_with(artifact_root_uri) {
            return Err(PlatformError::invalid(
                "checksum catalog artifact_uri must be rooted under artifact_root_uri",
            ));
        }
        if entry.size_bytes == 0 {
            return Err(PlatformError::invalid(
                "checksum catalog size_bytes must be greater than zero",
            ));
        }
        if !seen_artifacts.insert(artifact_uri.clone()) {
            return Err(PlatformError::invalid(
                "checksum catalog contains duplicate artifact_uri entries",
            ));
        }
        entries.push(DataChecksumCatalogEntry {
            artifact_uri,
            checksum: normalize_sha256_digest(entry.checksum.as_str(), "checksum")?,
            size_bytes: entry.size_bytes,
        });
    }
    let checksum = normalize_sha256_digest(catalog.checksum.as_str(), "checksum")?;
    let expected_checksum = data_checksum_catalog_checksum(&entries);
    if checksum != expected_checksum {
        return Err(PlatformError::invalid(
            "checksum catalog checksum verification failed",
        ));
    }
    Ok(DataChecksumCatalog {
        algorithm,
        entries,
        checksum,
    })
}

fn actor_subject(context: &RequestContext) -> String {
    context
        .actor
        .clone()
        .unwrap_or_else(|| String::from("system"))
}

fn normalize_database_version(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("database version may not be empty"));
    }
    Ok(normalized.to_owned())
}

fn normalize_migration_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "major_version_upgrade" => Ok(normalized),
        "region_move" => Ok(normalized),
        "replica_reseed" => Ok(normalized),
        "storage_class_change" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "migration kind must be one of major_version_upgrade/region_move/replica_reseed/storage_class_change",
        )),
    }
}

fn normalize_region(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("region may not be empty"));
    }
    Ok(normalized.to_owned())
}

fn normalize_replica_id(value: &str, field_name: &'static str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_storage_class(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("storage class may not be empty"));
    }
    Ok(normalized)
}

fn parse_major_version_component(value: &str) -> Result<u64> {
    let major = value
        .trim()
        .split('.')
        .next()
        .ok_or_else(|| PlatformError::invalid("database version may not be empty"))?;
    major.parse::<u64>().map_err(|error| {
        PlatformError::invalid("database version must start with a numeric major version")
            .with_detail(error.to_string())
    })
}

fn validate_major_version_upgrade(current_version: &str, target_version: &str) -> Result<()> {
    let current_major = parse_major_version_component(current_version)?;
    let target_major = parse_major_version_component(target_version)?;
    if target_major <= current_major {
        return Err(PlatformError::conflict(
            "major-version migration target must increase the database major version",
        ));
    }
    Ok(())
}

fn is_active_migration_state(value: &str) -> bool {
    matches!(
        value,
        DATA_MIGRATION_STATE_PENDING | DATA_MIGRATION_STATE_RUNNING
    )
}

fn data_migration_event_details(migration: &DataMigrationJob) -> serde_json::Value {
    serde_json::json!({
        "database_id": migration.database_id,
        "kind": migration.kind,
        "state": migration.state,
        "reason": migration.reason,
        "source_version": migration.source_version,
        "target_version": migration.target_version,
        "source_region": migration.source_region,
        "target_region": migration.target_region,
        "source_replica_id": migration.source_replica_id,
        "target_replica_id": migration.target_replica_id,
        "source_storage_class": migration.source_storage_class,
        "target_storage_class": migration.target_storage_class,
        "failure_reason": migration.failure_reason,
    })
}

fn primary_replica_index(database: &ManagedDatabase) -> Result<usize> {
    database
        .replica_topology
        .iter()
        .position(|replica| replica.role == "primary")
        .ok_or_else(|| PlatformError::conflict("database has no primary replica"))
}

fn apply_database_region_move(database: &mut ManagedDatabase, target_region: &str) -> Result<()> {
    let current_primary_idx = primary_replica_index(database)?;
    if let Some(target_idx) = database
        .replica_topology
        .iter()
        .position(|replica| replica.region == target_region)
    {
        if !database.replica_topology[target_idx].healthy {
            return Err(PlatformError::conflict(
                "region migration target replica is unhealthy",
            ));
        }
        if target_idx != current_primary_idx {
            database.replica_topology[current_primary_idx].role = String::from("replica");
            database.replica_topology[target_idx].role = String::from("primary");
        }
    } else {
        database.replica_topology[current_primary_idx].region = target_region.to_owned();
    }
    database.primary_region = target_region.to_owned();
    Ok(())
}

fn apply_completed_data_migration(
    database: &mut ManagedDatabase,
    migration: &DataMigrationJob,
) -> Result<()> {
    match migration.kind.as_str() {
        "major_version_upgrade" => {
            let target_version = migration
                .target_version
                .as_ref()
                .ok_or_else(|| PlatformError::conflict("migration is missing a target_version"))?;
            validate_major_version_upgrade(&database.version, target_version)?;
            database.version = target_version.clone();
        }
        "region_move" => {
            let target_region = migration
                .target_region
                .as_deref()
                .ok_or_else(|| PlatformError::conflict("migration is missing a target_region"))?;
            apply_database_region_move(database, target_region)?;
        }
        "replica_reseed" => {
            let source_replica_id = migration.source_replica_id.as_deref().ok_or_else(|| {
                PlatformError::conflict("migration is missing a source_replica_id")
            })?;
            let target_replica_id = migration.target_replica_id.as_deref().ok_or_else(|| {
                PlatformError::conflict("migration is missing a target_replica_id")
            })?;
            let source_replica = database
                .replica_topology
                .iter()
                .find(|replica| replica.id == source_replica_id)
                .ok_or_else(|| {
                    PlatformError::not_found("source replica does not exist for reseed")
                })?;
            if !source_replica.healthy {
                return Err(PlatformError::conflict(
                    "replica reseed source must remain healthy for completion",
                ));
            }
            let target_replica = database
                .replica_topology
                .iter_mut()
                .find(|replica| replica.id == target_replica_id)
                .ok_or_else(|| {
                    PlatformError::not_found("target replica does not exist for reseed")
                })?;
            if target_replica.role == "primary" {
                return Err(PlatformError::conflict(
                    "replica reseed target must remain non-primary",
                ));
            }
            target_replica.healthy = true;
            target_replica.lag_seconds = 0;
        }
        "storage_class_change" => {
            let target_storage_class =
                migration.target_storage_class.as_ref().ok_or_else(|| {
                    PlatformError::conflict("migration is missing a target_storage_class")
                })?;
            database.storage_class = Some(target_storage_class.clone());
        }
        _ => {
            return Err(PlatformError::invalid("unsupported data migration kind"));
        }
    }

    database.metadata.touch(sha256_hex(
        format!(
            "{}:data-migration:{}:{}",
            database.id.as_str(),
            migration.id.as_str(),
            migration.kind,
        )
        .as_bytes(),
    ));
    Ok(())
}

fn parse_optional_rfc3339(value: Option<&str>) -> Result<Option<OffsetDateTime>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|error| {
            PlatformError::invalid("invalid RFC3339 timestamp").with_detail(error.to_string())
        })
}

fn build_replica_topology(replicas: u16, primary_region: &str) -> Vec<DatabaseReplica> {
    let count = replicas.max(1);
    (0..count)
        .map(|index| {
            let id = format!("replica-{}", index + 1);
            let role = if index == 0 { "primary" } else { "replica" };
            let region = if index == 0 {
                primary_region.to_owned()
            } else {
                format!("{primary_region}-dr{}", index)
            };
            DatabaseReplica {
                id,
                role: String::from(role),
                region,
                healthy: true,
                lag_seconds: 0,
            }
        })
        .collect::<Vec<_>>()
}

fn active_values<T>(records: Vec<(String, StoredDocument<T>)>) -> Vec<T> {
    records
        .into_iter()
        .filter(|(_, record)| !record.deleted)
        .map(|(_, record)| record.value)
        .collect()
}

fn latest_timestamp(left: OffsetDateTime, right: OffsetDateTime) -> OffsetDateTime {
    if left >= right { left } else { right }
}

fn parse_annotation_audit_id(
    annotations: &BTreeMap<String, String>,
    key: &'static str,
) -> Option<AuditId> {
    annotations
        .get(key)
        .and_then(|raw| AuditId::parse(raw).ok())
}

fn restore_sort_key(restore: &RestoreJob) -> OffsetDateTime {
    restore.completed_at.unwrap_or(restore.created_at)
}

fn restore_uses_backup_correlated_storage_lineage(
    backup: &BackupJob,
    restore_action: &VolumeRestoreActionSummary,
) -> bool {
    backup
        .storage_recovery_point
        .as_ref()
        .is_some_and(|recovery_point| {
            recovery_point == &build_restore_storage_recovery_point(restore_action)
        })
}

fn build_restore_action_summary_from_lineage(
    lineage: &RestoreStorageLineage,
    state: &str,
) -> VolumeRestoreActionSummary {
    let lifecycle = match state {
        "completed" => "ready",
        "failed" => "failed",
        _ => "pending",
    };
    VolumeRestoreActionSummary {
        id: lineage.restore_action_id.clone(),
        workflow_id: lineage.restore_workflow_id.clone(),
        volume_id: lineage.storage_volume_id.clone(),
        state: state.to_owned(),
        source_recovery_point_volume_id: lineage.selected_recovery_point.volume_id.clone(),
        source_recovery_point_version: lineage.selected_recovery_point.version,
        source_recovery_point_execution_count: lineage.selected_recovery_point.execution_count,
        source_recovery_point_etag: lineage.selected_recovery_point.etag.clone(),
        source_recovery_point_captured_at: lineage.selected_recovery_point.captured_at,
        recovery_class: String::from("scheduled_snapshot"),
        requested_reason: None,
        requested_at: lineage.selected_recovery_point.captured_at,
        started_at: Some(lineage.selected_recovery_point.captured_at),
        completed_at: (state == "completed").then_some(lineage.selected_recovery_point.captured_at),
        lifecycle: String::from(lifecycle),
    }
}

fn build_outbox_event_signature(
    event_type: &str,
    resource_kind: &str,
    resource_id: &str,
    action: &str,
) -> (String, String, String, String) {
    (
        event_type.to_owned(),
        resource_kind.to_owned(),
        resource_id.to_owned(),
        action.to_owned(),
    )
}

fn outbox_event_signature(event: &PlatformEvent) -> Option<(String, String, String, String)> {
    let EventPayload::Service(service_event) = &event.payload else {
        return None;
    };
    Some(build_outbox_event_signature(
        &event.header.event_type,
        &service_event.resource_kind,
        &service_event.resource_id,
        &service_event.action,
    ))
}

fn backup_completed_event_details(backup: &BackupJob) -> serde_json::Value {
    serde_json::json!({
        "database_id": backup.database_id,
        "kind": backup.kind,
        "snapshot_uri": backup.snapshot_uri,
        "backup_artifact_manifest_object_location": backup
            .backup_artifact_manifest
            .as_ref()
            .map(|manifest| manifest.manifest_object_location.clone()),
        "backup_artifact_manifest_sha256": backup
            .backup_artifact_manifest
            .as_ref()
            .map(|manifest| manifest.manifest_sha256.clone()),
        "storage_volume_id": backup
            .storage_recovery_point
            .as_ref()
            .map(|recovery_point| recovery_point.volume_id.clone()),
        "storage_recovery_point_version": backup
            .storage_recovery_point
            .as_ref()
            .map(|recovery_point| recovery_point.version),
        "storage_recovery_point_execution_count": backup
            .storage_recovery_point
            .as_ref()
            .map(|recovery_point| recovery_point.execution_count),
        "storage_recovery_point_etag": backup
            .storage_recovery_point
            .as_ref()
            .map(|recovery_point| recovery_point.etag.clone()),
        "reason": serde_json::Value::Null,
    })
}

fn restore_completed_event_details(restore: &RestoreJob) -> serde_json::Value {
    serde_json::json!({
        "database_id": restore.database_id,
        "backup_id": restore.backup_id,
        "point_in_time": restore.point_in_time,
        "reason": restore.reason,
        "used_backup_correlated_storage_recovery_point": restore
            .storage_restore
            .as_ref()
            .map(|lineage| matches!(
                lineage.source_mode,
                RestoreStorageSourceMode::BackupCorrelatedStorageLineage
            )),
        "storage_restore_source_mode": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.source_mode),
        "storage_volume_id": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.storage_volume_id.clone()),
        "storage_restore_action_id": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.restore_action_id.clone()),
        "storage_restore_workflow_id": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.restore_workflow_id.clone()),
        "storage_source_recovery_point_version": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.selected_recovery_point.version),
        "storage_source_recovery_point_etag": restore
            .storage_restore
            .as_ref()
            .map(|lineage| lineage.selected_recovery_point.etag.clone()),
    })
}

fn failover_completed_event_details(failover: &DataFailoverRecord) -> serde_json::Value {
    serde_json::json!({
        "database_id": failover.database_id,
        "from_replica_id": failover.from_replica_id,
        "to_replica_id": failover.to_replica_id,
        "reason": failover.reason,
    })
}

async fn sync_document_projection<T>(store: &DocumentStore<T>, key: &str, value: T) -> Result<()>
where
    T: Clone + DeserializeOwned + Serialize + PartialEq + Eq + Send + Sync + 'static,
{
    match store.get(key).await? {
        Some(stored) if !stored.deleted && stored.value == value => Ok(()),
        Some(stored) => {
            store.upsert(key, value, Some(stored.version)).await?;
            Ok(())
        }
        None => match store.create(key, value.clone()).await {
            Ok(_) => Ok(()),
            Err(error) if error.code == ErrorCode::Conflict => {
                let stored = store.get(key).await?.ok_or_else(|| {
                    PlatformError::conflict(format!(
                        "document projection `{key}` conflicted but could not be reloaded",
                    ))
                })?;
                store.upsert(key, value, Some(stored.version)).await?;
                Ok(())
            }
            Err(error) => Err(error),
        },
    }
}

async fn sync_workflow_projection<T>(
    store: &WorkflowCollection<T>,
    key: &str,
    workflow: WorkflowInstance<T>,
) -> Result<()>
where
    T: Clone + DeserializeOwned + Serialize + PartialEq + Eq + Send + Sync + 'static,
{
    match store.get(key).await? {
        Some(stored) if !stored.deleted && stored.value == workflow => Ok(()),
        Some(stored) => {
            store.upsert(key, workflow, Some(stored.version)).await?;
            Ok(())
        }
        None => match store.create(key, workflow.clone()).await {
            Ok(_) => Ok(()),
            Err(error) if error.code == ErrorCode::Conflict => {
                let stored = store.get(key).await?.ok_or_else(|| {
                    PlatformError::conflict(format!(
                        "workflow projection `{key}` conflicted but could not be reloaded",
                    ))
                })?;
                store.upsert(key, workflow, Some(stored.version)).await?;
                Ok(())
            }
            Err(error) => Err(error),
        },
    }
}

fn select_failover_target(
    database: &ManagedDatabase,
    request: &FailoverDatabaseRequest,
    current_primary_idx: usize,
) -> Result<usize> {
    if let Some(target_replica_id) = request.target_replica_id.as_deref() {
        let Some(index) = database
            .replica_topology
            .iter()
            .position(|replica| replica.id == target_replica_id)
        else {
            return Err(PlatformError::not_found(
                "requested failover target replica does not exist",
            ));
        };
        if index == current_primary_idx {
            return Err(PlatformError::conflict(
                "requested failover target is already primary",
            ));
        }
        if !database.replica_topology[index].healthy {
            return Err(PlatformError::conflict(
                "requested failover target replica is unhealthy",
            ));
        }
        return Ok(index);
    }
    if let Some(target_region) = request.target_region.as_deref() {
        let Some(index) = database.replica_topology.iter().position(|replica| {
            replica.region == target_region && replica.role != "primary" && replica.healthy
        }) else {
            return Err(PlatformError::not_found(
                "requested failover target region has no promotable replica",
            ));
        };
        return Ok(index);
    }
    database
        .replica_topology
        .iter()
        .enumerate()
        .find(|(index, replica)| *index != current_primary_idx && replica.healthy)
        .map(|(index, _)| index)
        .ok_or_else(|| PlatformError::conflict("no healthy replica available for failover"))
}

fn validate_point_in_time(point_in_time: Option<OffsetDateTime>) -> Result<()> {
    if let Some(point_in_time) = point_in_time
        && point_in_time > OffsetDateTime::now_utc()
    {
        return Err(PlatformError::invalid(
            "point-in-time recovery timestamp may not be in the future",
        ));
    }
    Ok(())
}

fn extract_idempotency_key(headers: &HeaderMap) -> Result<Option<String>> {
    let mut values = headers
        .get_all("idempotency-key")
        .iter()
        .chain(headers.get_all("x-idempotency-key").iter());
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let first = parse_idempotency_key_header_value(first)?;
    for value in values {
        let value = parse_idempotency_key_header_value(value)?;
        if value != first {
            return Err(PlatformError::invalid(
                "Idempotency-Key header may not be supplied multiple times with different values",
            ));
        }
    }
    Ok(Some(first))
}

fn parse_idempotency_key_header_value(value: &http::HeaderValue) -> Result<String> {
    let value = value.to_str().map_err(|error| {
        PlatformError::invalid("Idempotency-Key header must be valid ASCII")
            .with_detail(error.to_string())
    })?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "Idempotency-Key header may not be empty",
        ));
    }
    if value != trimmed {
        return Err(PlatformError::invalid(
            "Idempotency-Key header may not include leading or trailing whitespace",
        ));
    }
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid(
            "Idempotency-Key header may not exceed 128 characters",
        ));
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(PlatformError::invalid(
            "Idempotency-Key header may contain only visible ASCII without whitespace",
        ));
    }
    Ok(trimmed.to_owned())
}

fn data_mutation_dedupe_key(
    operation: DataMutationOperation,
    subject_id: &str,
    idempotency_key: &str,
) -> String {
    sha256_hex(
        format!(
            "data-mutation-idempotency:v1|{}|{}|{subject_id}|{idempotency_key}",
            operation.as_str(),
            DATA_MUTATION_SUBJECT_KIND_DATABASE,
        )
        .as_bytes(),
    )
}

fn validate_data_mutation_dedupe_identity(
    record: &DataMutationDedupeRecord,
    operation: DataMutationOperation,
    subject_id: &str,
    idempotency_key: &str,
    context: &RequestContext,
) -> Result<()> {
    if record.operation != operation
        || record.subject_kind != DATA_MUTATION_SUBJECT_KIND_DATABASE
        || record.subject_id != subject_id
        || record.idempotency_key != idempotency_key
    {
        return Err(
            PlatformError::unavailable(
                "data idempotency record identity does not match the requested operation or database subject",
            )
            .with_detail(format!(
                "expected_operation={}, actual_operation={}, expected_subject_kind={}, actual_subject_kind={}, expected_subject_id={}, actual_subject_id={}, expected_idempotency_key={}, actual_idempotency_key={}",
                operation.as_str(),
                record.operation.as_str(),
                DATA_MUTATION_SUBJECT_KIND_DATABASE,
                record.subject_kind,
                subject_id,
                record.subject_id,
                idempotency_key,
                record.idempotency_key,
            ))
            .with_correlation_id(context.correlation_id.clone()),
        );
    }
    Ok(())
}

fn validate_data_mutation_result_subject(
    operation: DataMutationOperation,
    subject_kind: &str,
    subject_id: &str,
    actual_database_id: &DatabaseId,
    result_resource_id: &str,
    context: &RequestContext,
) -> Result<()> {
    if subject_kind != DATA_MUTATION_SUBJECT_KIND_DATABASE {
        return Err(PlatformError::unavailable(
            "data idempotency record uses an unsupported subject kind",
        )
        .with_detail(format!(
            "operation={}, result_resource_id={}, subject_kind={subject_kind}",
            operation.as_str(),
            result_resource_id,
        ))
        .with_correlation_id(context.correlation_id.clone()));
    }
    if actual_database_id.as_str() != subject_id {
        return Err(PlatformError::unavailable(
            "data idempotency result resource does not match the recorded database subject",
        )
        .with_detail(format!(
            "operation={}, result_resource_id={}, expected_database_id={}, actual_database_id={}",
            operation.as_str(),
            result_resource_id,
            subject_id,
            actual_database_id.as_str(),
        ))
        .with_correlation_id(context.correlation_id.clone()));
    }
    Ok(())
}

fn serialize_response_body<T: Serialize>(
    response: &T,
    purpose: &'static str,
) -> Result<serde_json::Value> {
    serde_json::to_value(response)
        .map_err(|error| PlatformError::unavailable(purpose).with_detail(error.to_string()))
}

fn build_idempotency_request_digest<T: Serialize>(
    namespace: &'static str,
    payload: &T,
) -> Result<String> {
    let payload = serde_json::to_vec(payload).map_err(|error| {
        PlatformError::unavailable("failed to serialize idempotency request")
            .with_detail(error.to_string())
    })?;
    let mut digest_input = namespace.as_bytes().to_vec();
    digest_input.push(b'|');
    digest_input.extend(payload);
    Ok(sha256_hex(&digest_input))
}

fn backup_request_digest(
    database_id: &str,
    kind: &str,
    point_in_time: Option<OffsetDateTime>,
    reason: Option<&str>,
) -> Result<String> {
    build_idempotency_request_digest(
        "data-backup-idempotency-request:v1",
        &BackupIdempotencyDigest {
            database_id,
            kind,
            point_in_time_unix_nanos: point_in_time.map(OffsetDateTime::unix_timestamp_nanos),
            reason,
        },
    )
}

fn restore_request_digest(
    database_id: &str,
    backup_id: &str,
    point_in_time: Option<OffsetDateTime>,
    reason: Option<&str>,
) -> Result<String> {
    build_idempotency_request_digest(
        "data-restore-idempotency-request:v1",
        &RestoreIdempotencyDigest {
            database_id,
            backup_id,
            point_in_time_unix_nanos: point_in_time.map(OffsetDateTime::unix_timestamp_nanos),
            reason,
        },
    )
}

fn failover_request_digest(
    database_id: &str,
    target_replica_id: Option<&str>,
    target_region: Option<&str>,
    reason: &str,
) -> Result<String> {
    build_idempotency_request_digest(
        "data-failover-idempotency-request:v1",
        &FailoverIdempotencyDigest {
            database_id,
            target_replica_id,
            target_region,
            reason,
        },
    )
}

fn replay_data_mutation_response(
    record: &DataMutationDedupeRecord,
) -> Result<http::Response<ApiBody>> {
    let status = record.response_status.ok_or_else(|| {
        PlatformError::unavailable("data idempotency record is missing response status")
    })?;
    let body = record.response_body.as_ref().ok_or_else(|| {
        PlatformError::unavailable("data idempotency record is missing response body")
    })?;
    let status = StatusCode::from_u16(status).map_err(|error| {
        PlatformError::unavailable("data idempotency record stored an invalid HTTP status")
            .with_detail(error.to_string())
    })?;
    json_response(status, body)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{BackupPolicy, default_database_state, default_primary_region};
    use http::{HeaderMap, HeaderValue};
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};
    use uhost_core::{ErrorCode, RequestContext, sha256_hex};
    use uhost_store::workflow::WorkflowStepEffectExecution;
    use uhost_store::{
        DocumentCollection, WorkflowPhase, WorkflowStepEffectState, WorkflowStepState,
    };
    use uhost_types::{
        AuditId, CacheClusterId, DatabaseId, EventPayload, FailoverOperationId, MigrationJobId,
        OwnershipScope, PrincipalIdentity, PrincipalKind, QueueId, ResourceMetadata, VolumeId,
    };

    use super::{
        BackupJob, CacheCluster, CreateBackupRequest, CreateDataExportRequest,
        CreateDataImportRequest, CreateDataMigrationRequest, CreateDatabaseRequest,
        DATA_MIGRATION_STATE_COMPLETED, DATA_MIGRATION_STATE_FAILED, DATA_MIGRATION_STATE_PENDING,
        DATA_MIGRATION_STATE_RUNNING, DATABASE_BACKING_VOLUME_ID_ANNOTATION,
        DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION, DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION,
        DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION, DataExportJob,
        DataFailoverRecord, DataImportJob, DataMigrationJob, DataService, DataTransferResourceKind,
        FailoverDatabaseRequest, MaintenanceRequest, ManagedDatabase, QueueService,
        RestoreDatabaseRequest, RestoreJob, RestoreStorageSourceMode,
    };

    async fn mutate_persisted_data_state_and_reopen<Fut>(
        state_root: &std::path::Path,
        mutation: Fut,
    ) -> DataService
    where
        Fut: std::future::Future<Output = ()>,
    {
        mutation.await;
        reopen_data_service(state_root).await
    }

    async fn advance_persisted_volume_recovery_point(
        state_root: &std::path::Path,
        volume_id: &VolumeId,
    ) {
        let path = state_root.join("storage/volume_recovery_points.json");
        let raw = tokio::fs::read(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut collection: DocumentCollection<serde_json::Value> =
            serde_json::from_slice(&raw).unwrap_or_else(|error| panic!("{error}"));
        let record = collection
            .records
            .get_mut(volume_id.as_str())
            .unwrap_or_else(|| panic!("missing persisted recovery point"));
        record.version += 1;
        let captured_at = time::OffsetDateTime::now_utc() + Duration::minutes(30);
        let interval_minutes = record.value["interval_minutes"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing interval_minutes"));
        let execution_count = record.value["execution_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing execution_count"))
            + 1;
        record.updated_at = captured_at;
        record.value["execution_count"] = serde_json::json!(execution_count);
        record.value["latest_snapshot_at"] = serde_json::json!(captured_at);
        record.value["next_snapshot_after"] =
            serde_json::json!(captured_at + Duration::minutes(interval_minutes as i64));
        record.value["metadata"]["etag"] = serde_json::json!(sha256_hex(
            format!("{}:recovery-point:{}", volume_id.as_str(), record.version).as_bytes(),
        ));
        record.value["metadata"]["updated_at"] = serde_json::json!(captured_at);
        let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(path, payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn advance_persisted_volume_recovery_point_and_reopen(
        state_root: &std::path::Path,
        volume_id: &VolumeId,
    ) -> DataService {
        mutate_persisted_data_state_and_reopen(
            state_root,
            advance_persisted_volume_recovery_point(state_root, volume_id),
        )
        .await
    }

    async fn remove_persisted_volume_recovery_point_revision(
        state_root: &std::path::Path,
        volume_id: &VolumeId,
        recovery_point_version: u64,
    ) {
        let path = state_root.join("storage/volume_recovery_point_revisions.json");
        let raw = tokio::fs::read(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut collection: DocumentCollection<serde_json::Value> =
            serde_json::from_slice(&raw).unwrap_or_else(|error| panic!("{error}"));
        let key = format!("{}:{recovery_point_version}", volume_id.as_str());
        collection
            .records
            .remove(&key)
            .unwrap_or_else(|| panic!("missing persisted recovery point revision"));
        let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(path, payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn remove_persisted_volume_recovery_point_revision_and_reopen(
        state_root: &std::path::Path,
        volume_id: &VolumeId,
        recovery_point_version: u64,
    ) -> DataService {
        mutate_persisted_data_state_and_reopen(
            state_root,
            remove_persisted_volume_recovery_point_revision(
                state_root,
                volume_id,
                recovery_point_version,
            ),
        )
        .await
    }

    async fn remove_persisted_outbox_service_event(
        state_root: &std::path::Path,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
    ) {
        let path = state_root.join("data/outbox.json");
        let raw = tokio::fs::read(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut collection: DocumentCollection<serde_json::Value> =
            serde_json::from_slice(&raw).unwrap_or_else(|error| panic!("{error}"));
        let removed = collection
            .records
            .iter()
            .filter(|(_, record)| {
                let event_payload = &record.value["payload"]["payload"];
                let service_payload = if event_payload["kind"] == serde_json::json!("service") {
                    &event_payload["data"]
                } else {
                    event_payload
                };
                record.value["payload"]["header"]["event_type"] == serde_json::json!(event_type)
                    && service_payload["resource_kind"] == serde_json::json!(resource_kind)
                    && service_payload["resource_id"] == serde_json::json!(resource_id)
                    && service_payload["action"] == serde_json::json!(action)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        assert!(
            !removed.is_empty(),
            "missing persisted outbox service event for {event_type}/{resource_kind}/{resource_id}/{action}",
        );
        for key in removed {
            collection.records.remove(&key);
        }
        let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(path, payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn remove_persisted_outbox_service_event_and_reopen(
        state_root: &std::path::Path,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
    ) -> DataService {
        mutate_persisted_data_state_and_reopen(
            state_root,
            remove_persisted_outbox_service_event(
                state_root,
                event_type,
                resource_kind,
                resource_id,
                action,
            ),
        )
        .await
    }

    async fn remove_backup_payload_artifact(
        state_root: &std::path::Path,
        database_id: &DatabaseId,
        backup_id: &AuditId,
    ) {
        let path =
            super::backup_payload_artifact_path(&state_root.join("data"), database_id, backup_id);
        tokio::fs::remove_file(&path)
            .await
            .unwrap_or_else(|error| panic!("failed to remove backup payload artifact: {error}"));
    }

    async fn remove_backup_payload_artifact_and_reopen(
        state_root: &std::path::Path,
        database_id: &DatabaseId,
        backup_id: &AuditId,
    ) -> DataService {
        mutate_persisted_data_state_and_reopen(
            state_root,
            remove_backup_payload_artifact(state_root, database_id, backup_id),
        )
        .await
    }

    async fn create_database_backup_and_restore(
        service: &DataService,
    ) -> (ManagedDatabase, BackupJob, RestoreJob) {
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 96,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: ManagedDatabase =
            serde_json::from_slice(&created_payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));

        let restore = service
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("operator restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restore.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_reply: serde_json::Value =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        let restore_id = restore_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing restore id"));
        let restore_job = service
            .restore_jobs
            .get(restore_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted restore job"))
            .value;

        (database, backup_job, restore_job)
    }

    fn operator_context(subject: &str, credential_id: &str) -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(
                PrincipalIdentity::new(PrincipalKind::Operator, subject)
                    .with_credential_id(credential_id),
            )
    }

    async fn reopen_data_service(state_root: &std::path::Path) -> DataService {
        DataService::open(state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn create_database_for_test(
        service: &DataService,
        context: &RequestContext,
    ) -> ManagedDatabase {
        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 64,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("us-east-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn mark_dedupe_as_aborted_without_response(service: &DataService, key: &str) {
        rewrite_dedupe_record(service, key, |record| {
            assert!(
                record.result_resource_kind.is_some() && record.result_resource_id.is_some(),
                "recovery tests require persisted result references",
            );
            record.state = super::DataMutationDedupeState::Aborted;
            record.response_body = None;
            record.completed_at = None;
            record.error_message = Some(String::from(
                "simulated crash after persisting the result reference",
            ));
        })
        .await;
    }

    async fn rewrite_dedupe_record<F>(service: &DataService, key: &str, mut rewrite: F)
    where
        F: FnMut(&mut super::DataMutationDedupeRecord),
    {
        let stored = service
            .mutation_dedupes
            .get(key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing data mutation dedupe record"));
        let mut record = stored.value;
        rewrite(&mut record);
        service
            .mutation_dedupes
            .upsert(key, record, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn create_cache_for_test(
        service: &DataService,
        context: &RequestContext,
    ) -> CacheCluster {
        let created = service
            .create_cache(
                super::CreateCacheRequest {
                    engine: String::from("redis"),
                    memory_mb: 512,
                    tls_required: true,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn create_queue_for_test(
        service: &DataService,
        context: &RequestContext,
    ) -> QueueService {
        let created = service
            .create_queue(
                super::CreateQueueRequest {
                    partitions: 3,
                    retention_hours: 48,
                    dead_letter_enabled: true,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn export_flows_emit_signed_manifests_for_all_resource_kinds() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("data.exporter");

        let database = create_database_for_test(&service, &context).await;
        let cache = create_cache_for_test(&service, &context).await;
        let queue = create_queue_for_test(&service, &context).await;

        for (resource_kind, resource_id, artifact_format, expected_kind) in [
            (
                DataTransferResourceKind::Database,
                database.id.to_string(),
                Some(String::from("physical_snapshot")),
                "database",
            ),
            (
                DataTransferResourceKind::Cache,
                cache.id.to_string(),
                Some(String::from("append_only_log")),
                "cache",
            ),
            (
                DataTransferResourceKind::Queue,
                queue.id.to_string(),
                None,
                "queue",
            ),
        ] {
            let response = service
                .create_export(
                    resource_kind,
                    resource_id.as_str(),
                    CreateDataExportRequest {
                        artifact_format,
                        signing_key_ref: None,
                        reason: Some(String::from("cross-region transfer")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let payload = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            let export_job: DataExportJob =
                serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(export_job.resource_kind, expected_kind);
            assert_eq!(export_job.resource_id, resource_id);
            assert_eq!(export_job.state, "completed");
            assert_eq!(
                export_job.signed_manifest.signature,
                super::data_transfer_manifest_signature(&export_job.signed_manifest)
            );
            assert_eq!(
                export_job.checksum_catalog.checksum,
                super::data_checksum_catalog_checksum(&export_job.checksum_catalog.entries)
            );
            assert!(
                !export_job.checksum_catalog.entries.is_empty(),
                "export flow should record at least one artifact"
            );
            for entry in &export_job.checksum_catalog.entries {
                assert!(
                    entry
                        .artifact_uri
                        .starts_with(export_job.artifact_root_uri.as_str()),
                    "artifact {} should be rooted under {}",
                    entry.artifact_uri,
                    export_job.artifact_root_uri
                );
            }
        }
    }

    #[tokio::test]
    async fn import_flows_verify_signed_manifest_and_checksum_catalog() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("data.importer");

        let queue = create_queue_for_test(&service, &context).await;
        let export_response = service
            .create_export(
                DataTransferResourceKind::Queue,
                queue.id.as_str(),
                CreateDataExportRequest {
                    artifact_format: Some(String::from("segment_bundle")),
                    signing_key_ref: Some(String::from("kms://example/queue-signing")),
                    reason: Some(String::from("seed remote queue import")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let export_payload = http_body_util::BodyExt::collect(export_response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let export_job: DataExportJob =
            serde_json::from_slice(&export_payload).unwrap_or_else(|error| panic!("{error}"));

        let import_response = service
            .create_import(
                DataTransferResourceKind::Queue,
                CreateDataImportRequest {
                    signed_manifest: export_job.signed_manifest.clone(),
                    checksum_catalog: export_job.checksum_catalog.clone(),
                    target_resource_id: Some(queue.id.to_string()),
                    manifest_uri: Some(export_job.manifest_uri.clone()),
                    checksum_catalog_uri: Some(export_job.checksum_catalog_uri.clone()),
                    reason: Some(String::from("stage verified import")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let import_payload = http_body_util::BodyExt::collect(import_response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let import_job: DataImportJob =
            serde_json::from_slice(&import_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(import_job.resource_kind, "queue");
        assert_eq!(import_job.source_resource_id, queue.id.as_str());
        assert_eq!(
            import_job.target_resource_id.as_deref(),
            Some(queue.id.as_str())
        );
        assert_eq!(import_job.state, "verified");
        assert_eq!(
            import_job.verification_result,
            "manifest signature verified and checksum catalog matched"
        );

        let imports = service
            .list_import_jobs(
                Some("queue"),
                Some(queue.id.as_str()),
                Some(queue.id.as_str()),
                Some("verified"),
                10,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].id, import_job.id);
    }

    #[tokio::test]
    async fn import_rejects_manifest_signature_drift() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("data.importer");

        let cache = create_cache_for_test(&service, &context).await;
        let export_response = service
            .create_export(
                DataTransferResourceKind::Cache,
                cache.id.as_str(),
                CreateDataExportRequest {
                    artifact_format: None,
                    signing_key_ref: None,
                    reason: Some(String::from("tamper test")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let export_payload = http_body_util::BodyExt::collect(export_response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let export_job: DataExportJob =
            serde_json::from_slice(&export_payload).unwrap_or_else(|error| panic!("{error}"));

        let mut tampered_manifest = export_job.signed_manifest.clone();
        tampered_manifest.signature = "0".repeat(64);
        let error = service
            .create_import(
                DataTransferResourceKind::Cache,
                CreateDataImportRequest {
                    signed_manifest: tampered_manifest,
                    checksum_catalog: export_job.checksum_catalog.clone(),
                    target_resource_id: Some(cache.id.to_string()),
                    manifest_uri: Some(export_job.manifest_uri.clone()),
                    checksum_catalog_uri: Some(export_job.checksum_catalog_uri.clone()),
                    reason: Some(String::from("expect failure")),
                },
                &context,
            )
            .await
            .expect_err("tampered manifest signature should be rejected");
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(error.message, "manifest signature verification failed");
    }

    #[tokio::test]
    async fn create_database_populates_replica_topology() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.2"),
                    storage_gb: 200,
                    replicas: 3,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("us-east-1")),
                    backup_policy: None,
                    tags: BTreeMap::from([(String::from("tier"), String::from("prod"))]),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(database.engine, "postgres");
        assert_eq!(database.replica_topology.len(), 3);
        assert_eq!(database.replica_topology[0].role, "primary");
        assert!(database.storage_binding.is_some());
    }

    #[tokio::test]
    async fn create_database_persists_storage_binding_without_restore_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 120,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        let database_storage_binding = database
            .storage_binding
            .clone()
            .unwrap_or_else(|| panic!("missing database storage binding"));
        let backing_volume_id = database
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        assert!(
            !database
                .metadata
                .annotations
                .contains_key(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
        );
        let backing_volume_id =
            VolumeId::parse(backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let recovery_point = service
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing ready recovery point"));
        assert_eq!(recovery_point.volume_id, backing_volume_id);

        let stored_immediately = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored database"));
        let stored_immediate_backing_volume_id = stored_immediately
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing immediate backing volume annotation"))
            .clone();
        assert!(
            !stored_immediately
                .value
                .metadata
                .annotations
                .contains_key(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
        );
        let stored_immediate_backing_volume_id =
            VolumeId::parse(stored_immediate_backing_volume_id)
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stored_immediate_backing_volume_id, backing_volume_id);
        assert_eq!(
            stored_immediately.value.storage_binding,
            Some(database_storage_binding.clone())
        );

        let reopened = reopen_data_service(temp.path()).await;
        let stored = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        let stored_backing_volume_id = stored
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        assert!(
            !stored
                .value
                .metadata
                .annotations
                .contains_key(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
        );

        let stored_backing_volume_id =
            VolumeId::parse(stored_backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&stored_backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing ready recovery point"));
        assert_eq!(stored_backing_volume_id, backing_volume_id);
        assert_eq!(recovery_point.volume_id, stored_backing_volume_id);
        assert_eq!(stored.value.storage_binding, Some(database_storage_binding));
    }

    #[tokio::test]
    async fn backup_restore_flow_creates_records_and_binds_storage_restore_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("mysql"),
                    version: String::from("8.4"),
                    storage_gb: 80,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        let backing_volume_id = stored_database
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        let backing_volume_id =
            VolumeId::parse(backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let initial_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        let backup = reopened
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(backup_job.state, "completed");
        let backup_storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage recovery point lineage"));
        assert_eq!(backup_storage_recovery_point.volume_id, backing_volume_id);
        assert_eq!(
            backup_storage_recovery_point.version,
            initial_recovery_point.version
        );
        assert_eq!(
            backup_storage_recovery_point.etag,
            initial_recovery_point.etag
        );

        let reopened =
            advance_persisted_volume_recovery_point_and_reopen(temp.path(), &backing_volume_id)
                .await;
        let latest_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing latest recovery point"));
        assert!(latest_recovery_point.version > initial_recovery_point.version);
        assert_ne!(latest_recovery_point.etag, initial_recovery_point.etag);

        let restored = reopened
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restored.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_response: serde_json::Value =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            restore_response.get("storage_restore").is_none(),
            "restore response should not expose internal storage lineage"
        );
        assert_eq!(
            restore_response["storage_restore_selection_reason"],
            serde_json::json!(
                "selected backup-correlated storage recovery point recorded by the originating backup"
            )
        );
        assert_eq!(
            restore_response["storage_restore_selected_recovery_point"],
            serde_json::to_value(&backup_storage_recovery_point)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            restore_response["storage_restore_backup_correlated_recovery_point"],
            serde_json::to_value(&backup_storage_recovery_point)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            restore_response["storage_restore_source_mode"],
            serde_json::json!("backup_correlated_storage_lineage")
        );
        let expected_restore_reply_state_reason =
            super::historical_restore_selected_recovery_point_state_reason();
        assert_eq!(
            restore_response["storage_restore_selected_recovery_point_state_reason"],
            serde_json::json!(expected_restore_reply_state_reason.clone())
        );
        let restore_reply: super::RestoreJobReply =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restore_reply.state, "completed");
        assert_eq!(
            restore_reply.storage_restore_source_mode,
            Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage)
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point
                .as_ref(),
            Some(&backup_storage_recovery_point)
        );
        assert_eq!(
            restore_reply
                .storage_restore_backup_correlated_recovery_point
                .as_ref(),
            Some(&backup_storage_recovery_point)
        );
        assert_eq!(
            restore_reply.storage_restore_selection_reason.as_deref(),
            Some(
                "selected backup-correlated storage recovery point recorded by the originating backup"
            )
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point_state_reason
                .as_deref(),
            Some(expected_restore_reply_state_reason.as_str())
        );

        let persisted_restore_job = reopened
            .restore_jobs
            .get(restore_reply.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted restore job"));
        let restore_storage_lineage = persisted_restore_job
            .value
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing restore storage lineage"));
        assert_eq!(
            restore_storage_lineage.source_mode,
            RestoreStorageSourceMode::BackupCorrelatedStorageLineage
        );
        assert_eq!(restore_storage_lineage.storage_volume_id, backing_volume_id);
        assert_eq!(
            restore_storage_lineage.backup_correlated_recovery_point,
            Some(backup_storage_recovery_point.clone())
        );
        assert_eq!(
            restore_storage_lineage.selected_recovery_point,
            backup_storage_recovery_point.clone()
        );

        let inspected_lineage = reopened
            .describe_restore_storage_lineage(
                restore_reply.id.as_str(),
                &operator_context("operator:restore-inspector", "cred_restore_inspector"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(inspected_lineage.restore_id, restore_reply.id);
        assert_eq!(
            inspected_lineage.source_mode,
            restore_storage_lineage.source_mode
        );
        assert_eq!(
            inspected_lineage.storage_volume_id,
            restore_storage_lineage.storage_volume_id
        );
        assert_eq!(
            inspected_lineage.restore_action_id,
            restore_storage_lineage.restore_action_id
        );
        assert_eq!(
            inspected_lineage.restore_workflow_id,
            restore_storage_lineage.restore_workflow_id
        );
        assert_eq!(
            inspected_lineage.selected_recovery_point,
            restore_storage_lineage.selected_recovery_point
        );
        assert_eq!(
            inspected_lineage.backup_correlated_recovery_point,
            restore_storage_lineage.backup_correlated_recovery_point
        );
        assert_eq!(
            inspected_lineage.selection_reason,
            "selected backup-correlated storage recovery point recorded by the originating backup"
        );
        assert_eq!(
            inspected_lineage.selected_recovery_point_state_reason,
            super::historical_restore_selected_recovery_point_state_reason()
        );

        let restored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored database"));
        let restore_action_id = restored_database
            .value
            .metadata
            .annotations
            .get(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing storage restore action annotation"))
            .clone();
        let expected_recovery_point_version = initial_recovery_point.version.to_string();
        let expected_recovery_point_captured_at = initial_recovery_point
            .captured_at
            .unix_timestamp()
            .to_string();
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
                .map(String::as_str),
            Some(backing_volume_id.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION)
                .map(String::as_str),
            Some(backup_job.id.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION)
                .map(String::as_str),
            Some(expected_recovery_point_version.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION)
                .map(String::as_str),
            Some(initial_recovery_point.etag.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION)
                .map(String::as_str),
            Some(expected_recovery_point_captured_at.as_str())
        );

        let restore_action_id =
            AuditId::parse(restore_action_id).unwrap_or_else(|error| panic!("{error}"));
        let storage_restore = reopened
            .storage
            .describe_volume_restore_action(&restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing storage restore action"));
        assert_eq!(storage_restore.state, "completed");
        assert_eq!(storage_restore.volume_id, backing_volume_id);
        assert_eq!(
            restore_storage_lineage.restore_action_id,
            storage_restore.id
        );
        assert_eq!(
            restore_storage_lineage.restore_workflow_id,
            storage_restore.workflow_id
        );
        assert_eq!(
            storage_restore.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            storage_restore.source_recovery_point_execution_count,
            initial_recovery_point.execution_count
        );
        assert_eq!(
            storage_restore.source_recovery_point_etag,
            initial_recovery_point.etag
        );
        assert_ne!(
            storage_restore.source_recovery_point_version,
            latest_recovery_point.version
        );
        assert_ne!(
            storage_restore.source_recovery_point_etag,
            latest_recovery_point.etag
        );

        let reopened_after_restore = reopen_data_service(temp.path()).await;
        let persisted_restore_job = reopened_after_restore
            .restore_jobs
            .get(restore_reply.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted restore job"));
        assert_eq!(
            persisted_restore_job.value.storage_restore,
            Some(restore_storage_lineage.clone())
        );
        let persisted_database = reopened_after_restore
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted restored database"));
        assert_eq!(
            persisted_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
                .map(String::as_str),
            Some(restore_action_id.as_str())
        );

        let reopened_after_revision_loss =
            remove_persisted_volume_recovery_point_revision_and_reopen(
                temp.path(),
                &backing_volume_id,
                initial_recovery_point.version,
            )
            .await;
        let inspected_lineage_after_revision_loss = reopened_after_revision_loss
            .describe_restore_storage_lineage(
                restore_reply.id.as_str(),
                &operator_context(
                    "operator:restore-revision-loss-inspector",
                    "cred_restore_revision_loss_inspector",
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            inspected_lineage_after_revision_loss.selected_recovery_point_state_reason,
            super::unavailable_restore_selected_recovery_point_state_reason()
        );
    }

    #[tokio::test]
    async fn storage_lineage_assertions_remain_stable_after_multiple_recovery_point_mutations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let reopened = reopen_data_service(temp.path()).await;
        let stored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        let backing_volume_id = stored_database
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        let backing_volume_id =
            VolumeId::parse(backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let initial_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        let backup = reopened
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("multi-mutation lineage drill")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let backup_storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage recovery point lineage"));
        assert_eq!(
            backup_storage_recovery_point.version,
            initial_recovery_point.version
        );
        assert_eq!(
            backup_storage_recovery_point.etag,
            initial_recovery_point.etag
        );

        let reopened_after_first_advance =
            advance_persisted_volume_recovery_point_and_reopen(temp.path(), &backing_volume_id)
                .await;
        let first_advanced_recovery_point = reopened_after_first_advance
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first advanced recovery point"));
        assert!(first_advanced_recovery_point.version > initial_recovery_point.version);
        assert!(
            first_advanced_recovery_point.execution_count > initial_recovery_point.execution_count
        );

        let reopened_after_second_advance =
            advance_persisted_volume_recovery_point_and_reopen(temp.path(), &backing_volume_id)
                .await;
        let latest_recovery_point = reopened_after_second_advance
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing latest recovery point"));
        assert!(latest_recovery_point.version > first_advanced_recovery_point.version);
        assert!(
            latest_recovery_point.execution_count > first_advanced_recovery_point.execution_count
        );
        assert_ne!(
            latest_recovery_point.etag,
            first_advanced_recovery_point.etag
        );

        let expected_backup_state_reason =
            super::historical_backup_storage_recovery_point_state_reason();
        let inspected_backup_lineage = reopened_after_second_advance
            .describe_backup_storage_lineage(
                backup_job.id.as_str(),
                &operator_context(
                    "operator:backup-multi-mutation-inspector",
                    "cred_backup_multi_mutation_inspector",
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(inspected_backup_lineage.backup_id, backup_job.id);
        assert_eq!(
            inspected_backup_lineage.recovery_point,
            backup_storage_recovery_point
        );
        assert_eq!(
            inspected_backup_lineage.recovery_point_state_reason,
            expected_backup_state_reason
        );

        let restored = reopened_after_second_advance
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("multi-mutation restore drill")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restored.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_reply: super::RestoreJobReply =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        let expected_restore_state_reason =
            super::historical_restore_selected_recovery_point_state_reason();
        assert_eq!(
            restore_reply.storage_restore_source_mode,
            Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage)
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point
                .as_ref(),
            Some(&backup_storage_recovery_point)
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point_state_reason
                .as_deref(),
            Some(expected_restore_state_reason.as_str())
        );

        let reopened_after_restore = reopen_data_service(temp.path()).await;
        let persisted_restore_job = reopened_after_restore
            .restore_jobs
            .get(restore_reply.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted restore job"));
        let restore_storage_lineage = persisted_restore_job
            .value
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing restore storage lineage"));
        assert_eq!(
            restore_storage_lineage.selected_recovery_point,
            backup_storage_recovery_point
        );
        let inspected_restore_lineage = reopened_after_restore
            .describe_restore_storage_lineage(
                restore_reply.id.as_str(),
                &operator_context(
                    "operator:restore-multi-mutation-inspector",
                    "cred_restore_multi_mutation_inspector",
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            inspected_restore_lineage.selected_recovery_point,
            restore_storage_lineage.selected_recovery_point
        );
        assert_eq!(
            inspected_restore_lineage.selected_recovery_point_state_reason,
            expected_restore_state_reason
        );

        let storage_restore = reopened_after_restore
            .storage
            .describe_volume_restore_action(&restore_storage_lineage.restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing storage restore action"));
        assert_eq!(
            storage_restore.source_recovery_point_version,
            initial_recovery_point.version
        );
        assert_eq!(
            storage_restore.source_recovery_point_etag,
            initial_recovery_point.etag
        );
        assert_ne!(
            storage_restore.source_recovery_point_version,
            latest_recovery_point.version
        );
        assert_ne!(
            storage_restore.source_recovery_point_etag,
            latest_recovery_point.etag
        );
    }

    #[tokio::test]
    async fn restore_record_marks_latest_ready_fallback_when_backup_lineage_is_unavailable() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.3"),
                    storage_gb: 72,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened = reopen_data_service(temp.path()).await;
        let stored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        let backing_volume_id = stored_database
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        let backing_volume_id =
            VolumeId::parse(backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let initial_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        let backup = reopened
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("pre-drill")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let backup_storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage recovery point lineage"));

        let reopened =
            advance_persisted_volume_recovery_point_and_reopen(temp.path(), &backing_volume_id)
                .await;
        let latest_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing latest recovery point"));
        let reopened = remove_persisted_volume_recovery_point_revision_and_reopen(
            temp.path(),
            &backing_volume_id,
            initial_recovery_point.version,
        )
        .await;

        let restored = reopened
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("fallback drill")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restored.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_response: serde_json::Value =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            restore_response.get("storage_restore").is_none(),
            "restore response should not expose internal storage lineage"
        );
        assert_eq!(
            restore_response["storage_restore_selection_reason"],
            serde_json::json!(
                "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point"
            )
        );
        let expected_selected_recovery_point =
            super::build_backup_storage_recovery_point(&latest_recovery_point);
        assert_eq!(
            restore_response["storage_restore_selected_recovery_point"],
            serde_json::to_value(&expected_selected_recovery_point)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            restore_response["storage_restore_backup_correlated_recovery_point"],
            serde_json::to_value(&backup_storage_recovery_point)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            restore_response["storage_restore_source_mode"],
            serde_json::json!("latest_ready_fallback")
        );
        let expected_restore_reply_state_reason =
            super::current_restore_selected_recovery_point_state_reason();
        assert_eq!(
            restore_response["storage_restore_selected_recovery_point_state_reason"],
            serde_json::json!(expected_restore_reply_state_reason.clone())
        );
        let restore_reply: super::RestoreJobReply =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restore_reply.state, "completed");
        assert_eq!(
            restore_reply.storage_restore_source_mode,
            Some(RestoreStorageSourceMode::LatestReadyFallback)
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point
                .as_ref(),
            Some(&expected_selected_recovery_point)
        );
        assert_eq!(
            restore_reply
                .storage_restore_backup_correlated_recovery_point
                .as_ref(),
            Some(&backup_storage_recovery_point)
        );
        assert_eq!(
            restore_reply.storage_restore_selection_reason.as_deref(),
            Some(
                "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point"
            )
        );
        assert_eq!(
            restore_reply
                .storage_restore_selected_recovery_point_state_reason
                .as_deref(),
            Some(expected_restore_reply_state_reason.as_str())
        );

        let persisted_restore_job = reopened
            .restore_jobs
            .get(restore_reply.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted fallback restore job"));
        let restore_storage_lineage = persisted_restore_job
            .value
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing fallback storage lineage"));
        assert_eq!(
            restore_storage_lineage.source_mode,
            RestoreStorageSourceMode::LatestReadyFallback
        );
        assert_eq!(restore_storage_lineage.storage_volume_id, backing_volume_id);
        assert_eq!(
            restore_storage_lineage.backup_correlated_recovery_point,
            Some(backup_storage_recovery_point.clone())
        );
        assert_eq!(
            restore_storage_lineage.selected_recovery_point.volume_id,
            backing_volume_id
        );
        assert_eq!(
            restore_storage_lineage.selected_recovery_point.version,
            latest_recovery_point.version
        );
        assert_eq!(
            restore_storage_lineage
                .selected_recovery_point
                .execution_count,
            latest_recovery_point.execution_count
        );
        assert_eq!(
            restore_storage_lineage.selected_recovery_point.etag,
            latest_recovery_point.etag
        );
        assert_eq!(
            restore_storage_lineage.selected_recovery_point.captured_at,
            latest_recovery_point.captured_at
        );
        assert_ne!(
            restore_storage_lineage.selected_recovery_point.version,
            initial_recovery_point.version
        );
        assert_ne!(
            restore_storage_lineage.selected_recovery_point.etag,
            initial_recovery_point.etag
        );

        let inspected_lineage = reopened
            .describe_restore_storage_lineage(
                restore_reply.id.as_str(),
                &operator_context("operator:fallback-inspector", "cred_fallback_inspector"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(inspected_lineage.restore_id, restore_reply.id);
        assert_eq!(
            inspected_lineage.source_mode,
            restore_storage_lineage.source_mode
        );
        assert_eq!(
            inspected_lineage.storage_volume_id,
            restore_storage_lineage.storage_volume_id
        );
        assert_eq!(
            inspected_lineage.restore_action_id,
            restore_storage_lineage.restore_action_id
        );
        assert_eq!(
            inspected_lineage.restore_workflow_id,
            restore_storage_lineage.restore_workflow_id
        );
        assert_eq!(
            inspected_lineage.selected_recovery_point,
            restore_storage_lineage.selected_recovery_point
        );
        assert_eq!(
            inspected_lineage.backup_correlated_recovery_point,
            restore_storage_lineage.backup_correlated_recovery_point
        );
        assert_eq!(
            inspected_lineage.selection_reason,
            "backup-correlated storage recovery point was unavailable during restore; fell back to the latest ready storage recovery point"
        );
        assert_eq!(
            inspected_lineage.selected_recovery_point_state_reason,
            super::current_restore_selected_recovery_point_state_reason()
        );

        let restored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restored database"));
        let expected_latest_recovery_point_version = latest_recovery_point.version.to_string();
        let expected_latest_recovery_point_captured_at = latest_recovery_point
            .captured_at
            .unix_timestamp()
            .to_string();
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION)
                .map(String::as_str),
            Some(backup_job.id.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION)
                .map(String::as_str),
            Some(expected_latest_recovery_point_version.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION)
                .map(String::as_str),
            Some(latest_recovery_point.etag.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION)
                .map(String::as_str),
            Some(expected_latest_recovery_point_captured_at.as_str())
        );

        let storage_restore = reopened
            .storage
            .describe_volume_restore_action(&restore_storage_lineage.restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing fallback storage restore action"));
        assert_eq!(
            storage_restore.id,
            restore_storage_lineage.restore_action_id
        );
        assert_eq!(
            storage_restore.workflow_id,
            restore_storage_lineage.restore_workflow_id
        );
        assert_eq!(storage_restore.state, "completed");
        assert_eq!(storage_restore.volume_id, backing_volume_id);
        assert_eq!(
            storage_restore.source_recovery_point_version,
            latest_recovery_point.version
        );
        assert_eq!(
            storage_restore.source_recovery_point_execution_count,
            latest_recovery_point.execution_count
        );
        assert_eq!(
            storage_restore.source_recovery_point_etag,
            latest_recovery_point.etag
        );

        let reopened_after_post_restore_drift =
            advance_persisted_volume_recovery_point_and_reopen(temp.path(), &backing_volume_id)
                .await;
        let post_restore_recovery_point = reopened_after_post_restore_drift
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing post-restore recovery point"));
        assert!(post_restore_recovery_point.version > latest_recovery_point.version);

        let persisted_restore_job = reopened_after_post_restore_drift
            .restore_jobs
            .get(restore_reply.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted fallback restore job"));
        assert_eq!(
            persisted_restore_job.value.storage_restore,
            Some(restore_storage_lineage.clone())
        );
        assert_ne!(
            persisted_restore_job
                .value
                .storage_restore
                .as_ref()
                .unwrap_or_else(|| panic!("missing persisted fallback storage lineage"))
                .selected_recovery_point
                .version,
            post_restore_recovery_point.version
        );
    }

    #[tokio::test]
    async fn backup_job_persists_storage_recovery_point_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.2"),
                    storage_gb: 96,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored database"));
        let backing_volume_id = stored_database
            .value
            .metadata
            .annotations
            .get(DATABASE_BACKING_VOLUME_ID_ANNOTATION)
            .unwrap_or_else(|| panic!("missing backing volume annotation"))
            .clone();
        let backing_volume_id =
            VolumeId::parse(backing_volume_id).unwrap_or_else(|error| panic!("{error}"));
        let initial_recovery_point = reopened
            .storage
            .describe_ready_volume_recovery_point(&backing_volume_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial recovery point"));

        let backup = reopened
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_response: serde_json::Value =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            backup_response["storage_recovery_point_state_reason"],
            serde_json::json!(super::current_backup_storage_recovery_point_state_reason())
        );
        let backup_job: super::BackupJob =
            serde_json::from_value(backup_response).unwrap_or_else(|error| panic!("{error}"));
        let storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage lineage"));
        let backup_artifact_manifest = backup_job
            .backup_artifact_manifest
            .clone()
            .unwrap_or_else(|| panic!("missing backup artifact manifest"));
        assert_eq!(storage_recovery_point.volume_id, backing_volume_id);
        assert_eq!(
            storage_recovery_point.version,
            initial_recovery_point.version
        );
        assert_eq!(
            storage_recovery_point.execution_count,
            initial_recovery_point.execution_count
        );
        assert_eq!(storage_recovery_point.etag, initial_recovery_point.etag);
        assert_eq!(
            storage_recovery_point.captured_at,
            initial_recovery_point.captured_at
        );
        assert_eq!(
            backup_job.storage_recovery_point_selection_reason,
            super::backup_storage_recovery_point_selection_reason()
        );
        assert_eq!(
            backup_artifact_manifest.schema_version,
            super::BACKUP_ARTIFACT_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(backup_artifact_manifest.artifacts.len(), 1);
        assert_eq!(
            backup_artifact_manifest.manifest_verification.state,
            super::BackupArtifactVerificationState::Verified
        );
        let primary_artifact = backup_artifact_manifest
            .artifacts
            .first()
            .unwrap_or_else(|| panic!("missing primary backup artifact"));
        assert_eq!(
            primary_artifact.kind,
            super::BackupArtifactKind::SnapshotBundle
        );
        assert_eq!(
            primary_artifact.verification.state,
            super::BackupArtifactVerificationState::Verified
        );
        let expected_key_ref = format!(
            "key://data/databases/{}/backups/default",
            database.id.as_str()
        );
        assert_eq!(
            primary_artifact.key_ref.as_deref(),
            Some(expected_key_ref.as_str())
        );
        assert_eq!(backup_job.snapshot_uri, primary_artifact.object_location);
        assert_eq!(backup_job.checksum, primary_artifact.sha256);

        let payload_path =
            super::backup_payload_artifact_path(&reopened.state_root, &database.id, &backup_job.id);
        let payload_bytes = tokio::fs::read(&payload_path)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to read persisted backup payload artifact: {error}")
            });
        assert_eq!(sha256_hex(&payload_bytes), primary_artifact.sha256);
        let persisted_payload: super::PersistedBackupPayload =
            serde_json::from_slice(&payload_bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(persisted_payload.backup_id, backup_job.id);
        assert_eq!(persisted_payload.database_id, database.id);
        assert_eq!(
            persisted_payload.storage_recovery_point,
            storage_recovery_point
        );

        let manifest_path = super::backup_manifest_artifact_path(
            &reopened.state_root,
            &database.id,
            &backup_job.id,
        );
        let manifest_bytes = tokio::fs::read(&manifest_path)
            .await
            .unwrap_or_else(|error| {
                panic!("failed to read persisted backup manifest artifact: {error}")
            });
        assert_eq!(
            sha256_hex(&manifest_bytes),
            backup_artifact_manifest.manifest_sha256
        );
        let persisted_manifest: super::PersistedBackupArtifactManifest =
            serde_json::from_slice(&manifest_bytes).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(persisted_manifest.backup_id, backup_job.id);
        assert_eq!(persisted_manifest.database_id, database.id);
        assert_eq!(
            persisted_manifest.artifacts,
            backup_artifact_manifest.artifacts
        );

        let persisted = reopened
            .backup_jobs
            .get(backup_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted backup job"));
        assert_eq!(
            persisted.value.storage_recovery_point,
            Some(storage_recovery_point)
        );
        assert_eq!(
            persisted.value.storage_recovery_point_selection_reason,
            super::backup_storage_recovery_point_selection_reason()
        );
        assert_eq!(
            persisted.value.backup_artifact_manifest,
            Some(backup_artifact_manifest)
        );
    }

    #[tokio::test]
    async fn restore_rejects_missing_backup_payload_artifact() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 48,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup = reopened
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("artifact-loss-drill")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened =
            remove_backup_payload_artifact_and_reopen(temp.path(), &database.id, &backup_job.id)
                .await;

        let error = reopened
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("restore-after-artifact-loss")),
                },
                &context,
            )
            .await
            .expect_err("restore should fail when the backup payload artifact is missing");
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "backup payload artifact does not exist");
    }

    #[test]
    fn backup_job_deserialization_defaults_storage_recovery_point_selection_reason() {
        let backup_job = super::BackupJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: DatabaseId::generate().unwrap_or_else(|error| panic!("{error}")),
            kind: String::from("full"),
            state: String::from("completed"),
            requested_by: String::from("db.operator"),
            created_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            snapshot_uri: String::from("object://data/backups/example/example.bak"),
            backup_artifact_manifest: None,
            storage_recovery_point: None,
            storage_recovery_point_selection_reason:
                super::backup_storage_recovery_point_selection_reason(),
            point_in_time: None,
            checksum: String::from("deadbeef"),
        };
        let mut raw = serde_json::to_value(&backup_job).unwrap_or_else(|error| panic!("{error}"));
        raw.as_object_mut()
            .unwrap_or_else(|| panic!("backup job should serialize to a JSON object"))
            .remove("backup_artifact_manifest");
        raw.as_object_mut()
            .unwrap_or_else(|| panic!("backup job should serialize to a JSON object"))
            .remove("storage_recovery_point_selection_reason");

        let legacy_job: super::BackupJob =
            serde_json::from_value(raw).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(legacy_job.backup_artifact_manifest, None);
        assert_eq!(
            legacy_job.storage_recovery_point_selection_reason,
            super::backup_storage_recovery_point_selection_reason()
        );
    }

    #[test]
    fn backup_job_reply_omits_storage_recovery_point_state_reason_without_persisted_lineage() {
        let backup = super::BackupJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: DatabaseId::generate().unwrap_or_else(|error| panic!("{error}")),
            kind: String::from("full"),
            state: String::from("completed"),
            requested_by: String::from("db.operator"),
            created_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            snapshot_uri: String::from("object://data/backups/example/example.bak"),
            backup_artifact_manifest: None,
            storage_recovery_point: None,
            storage_recovery_point_selection_reason:
                super::backup_storage_recovery_point_selection_reason(),
            point_in_time: None,
            checksum: String::from("deadbeef"),
        };

        let reply = super::build_backup_job_reply(&backup);
        assert_eq!(reply.storage_recovery_point_state_reason, None);

        let raw = serde_json::to_value(&reply).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            raw.get("storage_recovery_point_state_reason").is_none(),
            "backup reply should omit storage recovery point state reason when lineage was not persisted"
        );
    }

    #[tokio::test]
    async fn backup_job_reply_reports_historical_storage_recovery_point_state_reason_when_current_advances()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.3"),
                    storage_gb: 80,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("reply history check")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage lineage"));

        let reopened = advance_persisted_volume_recovery_point_and_reopen(
            temp.path(),
            &storage_recovery_point.volume_id,
        )
        .await;
        let persisted = reopened
            .backup_jobs
            .get(backup_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted backup job"));
        let reply = reopened
            .build_backup_job_reply_with_storage_state_reason(&persisted.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let expected_reason = super::historical_backup_storage_recovery_point_state_reason();
        assert_eq!(
            reply.storage_recovery_point_state_reason.as_deref(),
            Some(expected_reason.as_str())
        );

        let raw = serde_json::to_value(&reply).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            raw["storage_recovery_point_state_reason"],
            serde_json::json!(expected_reason)
        );
    }

    #[test]
    fn restore_job_reply_omits_storage_selection_reason_without_persisted_lineage() {
        let restore = super::RestoreJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: DatabaseId::generate().unwrap_or_else(|error| panic!("{error}")),
            backup_id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            state: String::from("completed"),
            requested_by: String::from("db.operator"),
            created_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            point_in_time: None,
            reason: Some(String::from("legacy restore")),
            storage_restore: None,
        };

        let reply = super::build_restore_job_reply(&restore);
        assert_eq!(reply.storage_restore_source_mode, None);
        assert_eq!(reply.storage_restore_selected_recovery_point, None);
        assert_eq!(reply.storage_restore_backup_correlated_recovery_point, None);
        assert_eq!(reply.storage_restore_selection_reason, None);
        assert_eq!(
            reply.storage_restore_selected_recovery_point_state_reason,
            None
        );

        let raw = serde_json::to_value(&reply).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            raw.get("storage_restore_source_mode").is_none(),
            "restore reply should omit storage source mode when lineage was not persisted"
        );
        assert!(
            raw.get("storage_restore_selection_reason").is_none(),
            "restore reply should omit storage selection reason when lineage was not persisted"
        );
        assert!(
            raw.get("storage_restore_selected_recovery_point").is_none(),
            "restore reply should omit storage selected recovery point when lineage was not persisted"
        );
        assert!(
            raw.get("storage_restore_backup_correlated_recovery_point")
                .is_none(),
            "restore reply should omit backup-correlated storage recovery point when lineage was not persisted"
        );
        assert!(
            raw.get("storage_restore_selected_recovery_point_state_reason")
                .is_none(),
            "restore reply should omit storage selected recovery point state reason when lineage was not persisted"
        );
    }

    #[test]
    fn restore_job_reply_omits_backup_correlated_recovery_point_when_not_persisted() {
        let selected_recovery_point = super::BackupStorageRecoveryPoint {
            volume_id: VolumeId::parse("vol_cccccccccccccccccccccccccc")
                .unwrap_or_else(|error| panic!("{error}")),
            version: 7,
            execution_count: 3,
            etag: String::from("etag_selected"),
            captured_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(5),
        };
        let restore = super::RestoreJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: DatabaseId::generate().unwrap_or_else(|error| panic!("{error}")),
            backup_id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            state: String::from("completed"),
            requested_by: String::from("db.operator"),
            created_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            point_in_time: None,
            reason: Some(String::from("legacy restore without backup lineage")),
            storage_restore: Some(super::RestoreStorageLineage {
                source_mode: RestoreStorageSourceMode::LatestReadyFallback,
                storage_volume_id: selected_recovery_point.volume_id.clone(),
                restore_action_id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
                restore_workflow_id: String::from("workflow_restore_legacy"),
                selected_recovery_point: selected_recovery_point.clone(),
                backup_correlated_recovery_point: None,
            }),
        };

        let reply = super::build_restore_job_reply(&restore);
        assert_eq!(
            reply.storage_restore_source_mode,
            Some(RestoreStorageSourceMode::LatestReadyFallback)
        );
        assert_eq!(
            reply.storage_restore_selected_recovery_point.as_ref(),
            Some(&selected_recovery_point)
        );
        assert_eq!(reply.storage_restore_backup_correlated_recovery_point, None);
        assert_eq!(
            reply.storage_restore_selection_reason.as_deref(),
            Some(
                "backup did not record storage recovery lineage; restored from the latest ready storage recovery point"
            )
        );

        let raw = serde_json::to_value(&reply).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            raw["storage_restore_selected_recovery_point"],
            serde_json::to_value(&selected_recovery_point)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert!(
            raw.get("storage_restore_backup_correlated_recovery_point")
                .is_none(),
            "restore reply should omit backup-correlated storage recovery point when none was persisted"
        );
    }

    #[tokio::test]
    async fn backup_lineage_inspection_projects_persisted_recovery_point() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.3"),
                    storage_gb: 80,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("inspection check")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage lineage"));

        let reopened = reopen_data_service(temp.path()).await;
        let inspected_lineage = reopened
            .describe_backup_storage_lineage(
                backup_job.id.as_str(),
                &operator_context(
                    "operator:backup-lineage-inspector",
                    "cred_backup_lineage_inspector",
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(inspected_lineage.backup_id, backup_job.id);
        assert_eq!(
            inspected_lineage.storage_volume_id,
            storage_recovery_point.volume_id
        );
        assert_eq!(inspected_lineage.recovery_point, storage_recovery_point);
        assert_eq!(
            inspected_lineage.selection_reason,
            backup_job.storage_recovery_point_selection_reason
        );
        assert_eq!(
            inspected_lineage.recovery_point_state_reason,
            super::current_backup_storage_recovery_point_state_reason()
        );
    }

    #[tokio::test]
    async fn backup_lineage_inspection_reports_unavailable_recovery_point_when_revision_is_missing()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 64,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("inspection drift check")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let storage_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup storage lineage"));

        let _reopened_after_advance = advance_persisted_volume_recovery_point_and_reopen(
            temp.path(),
            &storage_recovery_point.volume_id,
        )
        .await;
        let reopened = remove_persisted_volume_recovery_point_revision_and_reopen(
            temp.path(),
            &storage_recovery_point.volume_id,
            storage_recovery_point.version,
        )
        .await;
        let inspected_lineage = reopened
            .describe_backup_storage_lineage(
                backup_job.id.as_str(),
                &operator_context(
                    "operator:backup-drift-inspector",
                    "cred_backup_drift_inspector",
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(inspected_lineage.backup_id, backup_job.id);
        assert_eq!(inspected_lineage.recovery_point, storage_recovery_point);
        assert_eq!(
            inspected_lineage.recovery_point_state_reason,
            super::unavailable_backup_storage_recovery_point_state_reason()
        );
    }

    #[tokio::test]
    async fn backup_lineage_inspection_requires_operator_principal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 64,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("inspection check")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));

        let viewer_context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.viewer");
        let error = service
            .describe_backup_storage_lineage(backup_job.id.as_str(), &viewer_context)
            .await
            .expect_err("backup lineage inspection should require operator principal");
        assert_eq!(error.code, ErrorCode::Forbidden);
        assert_eq!(
            error.message,
            "backup lineage inspection requires operator principal"
        );
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(viewer_context.correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn restore_lineage_inspection_requires_operator_principal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 64,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("inspection check")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));

        let restored = service
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("inspection regression")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restored.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_reply: super::RestoreJobReply =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));

        let viewer_context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.viewer");
        let error = service
            .describe_restore_storage_lineage(restore_reply.id.as_str(), &viewer_context)
            .await
            .expect_err("restore lineage inspection should require operator principal");
        assert_eq!(error.code, ErrorCode::Forbidden);
        assert_eq!(
            error.message,
            "restore lineage inspection requires operator principal"
        );
        assert_eq!(
            error.correlation_id.as_deref(),
            Some(viewer_context.correlation_id.as_str())
        );
    }

    #[tokio::test]
    async fn backup_listing_ignores_soft_deleted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("mysql"),
                    version: String::from("8.4"),
                    storage_gb: 80,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: super::BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));

        let backup_version = service
            .backup_jobs
            .get(backup_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing backup job after creation"))
            .version;
        service
            .backup_jobs
            .soft_delete(backup_job.id.as_str(), Some(backup_version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let backups = service
            .list_backup_jobs(Some(database.id.as_str()), None, 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(backups.is_empty());
    }

    #[tokio::test]
    async fn failover_promotes_replica_and_records_operation() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.1"),
                    storage_gb: 60,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("eu-west-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let failover = service
            .failover_database(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failover_payload = http_body_util::BodyExt::collect(failover.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let record: super::DataFailoverRecord =
            serde_json::from_slice(&failover_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(record.state, "completed");
        assert_eq!(record.to_replica_id, "replica-2");
    }

    #[tokio::test]
    async fn failover_rejects_unhealthy_target_replica() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.1"),
                    storage_gb: 60,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("eu-west-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let mut database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        database.replica_topology[1].healthy = false;
        service
            .databases
            .upsert(database.id.as_str(), database.clone(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failure = service
            .failover_database(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                &context,
            )
            .await;
        assert!(failure.is_err());
    }

    #[test]
    fn extract_idempotency_key_rejects_surrounding_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_static(" backup-idem-1 "),
        );

        let error = super::extract_idempotency_key(&headers)
            .expect_err("surrounding whitespace should be rejected");
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(
            error.message,
            "Idempotency-Key header may not include leading or trailing whitespace"
        );
    }

    #[test]
    fn extract_idempotency_key_rejects_internal_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("Idempotency-Key", HeaderValue::from_static("backup idem 1"));

        let error = super::extract_idempotency_key(&headers)
            .expect_err("internal whitespace should be rejected");
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(
            error.message,
            "Idempotency-Key header may contain only visible ASCII without whitespace"
        );
    }

    #[test]
    fn extract_idempotency_key_rejects_conflicting_duplicate_values() {
        let mut headers = HeaderMap::new();
        headers.append("Idempotency-Key", HeaderValue::from_static("backup-idem-1"));
        headers.append(
            "X-Idempotency-Key",
            HeaderValue::from_static("backup-idem-2"),
        );

        let error = super::extract_idempotency_key(&headers)
            .expect_err("conflicting duplicate idempotency headers should be rejected");
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(
            error.message,
            "Idempotency-Key header may not be supplied multiple times with different values"
        );
    }

    #[tokio::test]
    async fn backup_idempotency_rejects_tampered_subject_record_identity() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let first_database = create_database_for_test(&service, &context).await;
        let second_database = create_database_for_test(&service, &context).await;

        service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-subject-tamper"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Backup,
            first_database.id.as_str(),
            "backup-idem-subject-tamper",
        );
        rewrite_dedupe_record(&service, dedupe_key.as_str(), |record| {
            record.subject_id = second_database.id.to_string();
        })
        .await;

        let error = service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-subject-tamper"),
                &context,
            )
            .await
            .expect_err("tampered dedupe subject identity should be rejected");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.message.contains("record identity"));
    }

    #[tokio::test]
    async fn backup_idempotency_rejects_cross_subject_result_reference_recovery() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let first_database = create_database_for_test(&service, &context).await;
        let second_database = create_database_for_test(&service, &context).await;

        service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-cross-subject"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = service
            .create_backup(
                second_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_payload = http_body_util::BodyExt::collect(second.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_reply: serde_json::Value =
            serde_json::from_slice(&second_payload).unwrap_or_else(|error| panic!("{error}"));
        let second_backup_id = second_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second backup id"))
            .to_owned();
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Backup,
            first_database.id.as_str(),
            "backup-idem-cross-subject",
        );
        rewrite_dedupe_record(&service, dedupe_key.as_str(), |record| {
            record.state = super::DataMutationDedupeState::Aborted;
            record.response_body = None;
            record.completed_at = None;
            record.result_resource_kind = Some(String::from("database_backup"));
            record.result_resource_id = Some(second_backup_id.clone());
            record.error_message = Some(String::from(
                "simulated crash with cross-subject result reference",
            ));
        })
        .await;

        let error = service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-cross-subject"),
                &context,
            )
            .await
            .expect_err("cross-subject backup result recovery should be rejected");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.message.contains("database subject"));
    }

    #[tokio::test]
    async fn restore_idempotency_rejects_cross_subject_result_reference_recovery() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let first_database = create_database_for_test(&service, &context).await;
        let second_database = create_database_for_test(&service, &context).await;

        let first_backup = service
            .create_backup(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("restore-prep")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_backup_payload = http_body_util::BodyExt::collect(first_backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_backup_reply: serde_json::Value =
            serde_json::from_slice(&first_backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let first_backup_id = first_backup_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing first backup id"))
            .to_owned();

        service
            .restore_database_with_idempotency(
                first_database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: first_backup_id.clone(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-cross-subject"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_backup = service
            .create_backup(
                second_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("restore-prep")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_backup_payload = http_body_util::BodyExt::collect(second_backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_backup_reply: serde_json::Value = serde_json::from_slice(&second_backup_payload)
            .unwrap_or_else(|error| panic!("{error}"));
        let second_restore = service
            .restore_database(
                second_database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: second_backup_reply["id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("missing second backup id"))
                        .to_owned(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_restore_payload = http_body_util::BodyExt::collect(second_restore.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_restore_reply: serde_json::Value =
            serde_json::from_slice(&second_restore_payload)
                .unwrap_or_else(|error| panic!("{error}"));
        let second_restore_id = second_restore_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second restore id"))
            .to_owned();
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Restore,
            first_database.id.as_str(),
            "restore-idem-cross-subject",
        );
        rewrite_dedupe_record(&service, dedupe_key.as_str(), |record| {
            record.state = super::DataMutationDedupeState::Aborted;
            record.response_body = None;
            record.completed_at = None;
            record.result_resource_kind = Some(String::from("database_restore"));
            record.result_resource_id = Some(second_restore_id.clone());
            record.error_message = Some(String::from(
                "simulated crash with cross-subject restore reference",
            ));
        })
        .await;

        let error = service
            .restore_database_with_idempotency(
                first_database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: first_backup_id,
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-cross-subject"),
                &context,
            )
            .await
            .expect_err("cross-subject restore result recovery should be rejected");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.message.contains("database subject"));
    }

    #[tokio::test]
    async fn failover_idempotency_rejects_cross_subject_result_reference_recovery() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let first_database = create_database_for_test(&service, &context).await;
        let second_database = create_database_for_test(&service, &context).await;

        service
            .failover_database_with_idempotency(
                first_database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-cross-subject"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = service
            .failover_database(
                second_database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_payload = http_body_util::BodyExt::collect(second.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_record: super::DataFailoverRecord =
            serde_json::from_slice(&second_payload).unwrap_or_else(|error| panic!("{error}"));
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Failover,
            first_database.id.as_str(),
            "failover-idem-cross-subject",
        );
        rewrite_dedupe_record(&service, dedupe_key.as_str(), |record| {
            record.state = super::DataMutationDedupeState::Aborted;
            record.response_body = None;
            record.completed_at = None;
            record.result_resource_kind = Some(String::from("database_failover"));
            record.result_resource_id = Some(second_record.id.to_string());
            record.error_message = Some(String::from(
                "simulated crash with cross-subject failover reference",
            ));
        })
        .await;

        let error = service
            .failover_database_with_idempotency(
                first_database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-cross-subject"),
                &context,
            )
            .await
            .expect_err("cross-subject failover result recovery should be rejected");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.message.contains("database subject"));
    }

    #[tokio::test]
    async fn backup_idempotency_recovers_aborted_dedupe_from_result_reference() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let first = service
            .create_backup_with_idempotency(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_reply: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Backup,
            database.id.as_str(),
            "backup-idem-recover",
        );
        mark_dedupe_as_aborted_without_response(&service, dedupe_key.as_str()).await;

        let replayed = service
            .create_backup_with_idempotency(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_reply: serde_json::Value =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_reply["id"], first_reply["id"]);

        let dedupe = service
            .mutation_dedupes
            .get(dedupe_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovered dedupe record"));
        assert_eq!(
            dedupe.value.state,
            super::DataMutationDedupeState::Completed
        );
        assert_eq!(dedupe.value.attempt_count, 2);
        assert!(dedupe.value.response_body.is_some());

        let backups = super::active_values(
            service
                .backup_jobs
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(backups.len(), 1);
    }

    #[tokio::test]
    async fn restore_idempotency_recovers_aborted_dedupe_from_result_reference() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("restore-prep")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_reply: serde_json::Value =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let backup_id = backup_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing backup id"))
            .to_owned();

        let first = service
            .restore_database_with_idempotency(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_id.clone(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_reply: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Restore,
            database.id.as_str(),
            "restore-idem-recover",
        );
        mark_dedupe_as_aborted_without_response(&service, dedupe_key.as_str()).await;

        let replayed = service
            .restore_database_with_idempotency(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id,
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_reply: serde_json::Value =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_reply["id"], first_reply["id"]);

        let dedupe = service
            .mutation_dedupes
            .get(dedupe_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovered dedupe record"));
        assert_eq!(
            dedupe.value.state,
            super::DataMutationDedupeState::Completed
        );
        assert_eq!(dedupe.value.attempt_count, 2);
        assert!(dedupe.value.response_body.is_some());

        let restores = super::active_values(
            service
                .restore_jobs
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(restores.len(), 1);
    }

    #[tokio::test]
    async fn failover_idempotency_recovers_aborted_dedupe_from_result_reference() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let first = service
            .failover_database_with_idempotency(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_reply: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        let dedupe_key = super::data_mutation_dedupe_key(
            super::DataMutationOperation::Failover,
            database.id.as_str(),
            "failover-idem-recover",
        );
        mark_dedupe_as_aborted_without_response(&service, dedupe_key.as_str()).await;

        let replayed = service
            .failover_database_with_idempotency(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-recover"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_reply: serde_json::Value =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_reply["id"], first_reply["id"]);

        let dedupe = service
            .mutation_dedupes
            .get(dedupe_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovered dedupe record"));
        assert_eq!(
            dedupe.value.state,
            super::DataMutationDedupeState::Completed
        );
        assert_eq!(dedupe.value.attempt_count, 2);
        assert!(dedupe.value.response_body.is_some());

        let failovers = super::active_values(
            service
                .failovers
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(failovers.len(), 1);
    }

    #[tokio::test]
    async fn backup_idempotency_replays_only_within_one_database_subject() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let replay_context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("different-operator");
        let first_database = create_database_for_test(&service, &context).await;
        let second_database = create_database_for_test(&service, &context).await;

        let first = service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-1"),
                &replay_context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_reply: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));

        let replayed = service
            .create_backup_with_idempotency(
                first_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_reply: serde_json::Value =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_reply["id"], first_reply["id"]);

        let second = service
            .create_backup_with_idempotency(
                second_database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_payload = http_body_util::BodyExt::collect(second.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_reply: serde_json::Value =
            serde_json::from_slice(&second_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_ne!(second_reply["id"], first_reply["id"]);

        let backups = service
            .list_backup_jobs(None, None, 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(backups.len(), 2);
        let dedupes = service
            .mutation_dedupes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            dedupes
                .into_iter()
                .filter(|(_, record)| !record.deleted)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn backup_idempotency_rejects_same_key_for_different_request() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let database = create_database_for_test(&service, &context).await;

        service
            .create_backup_with_idempotency(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-conflict"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_backup_with_idempotency(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("incremental")),
                    reason: Some(String::from("nightly")),
                    point_in_time_rfc3339: None,
                },
                Some("backup-idem-conflict"),
                &context,
            )
            .await
            .expect_err("backup idempotency key should reject a different request");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(error.message.contains("different request"));
    }

    #[tokio::test]
    async fn restore_idempotency_replays_completed_restore() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("restore-prep")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_reply: serde_json::Value =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let backup_id = backup_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing backup id"))
            .to_owned();

        let first = service
            .restore_database_with_idempotency(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_id.clone(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_reply: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));

        let replayed = service
            .restore_database_with_idempotency(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id,
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("drill")),
                },
                Some("restore-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_reply: serde_json::Value =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_reply["id"], first_reply["id"]);

        let restores = super::active_values(
            service
                .restore_jobs
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(restores.len(), 1);
    }

    #[tokio::test]
    async fn failover_idempotency_replays_completed_failover() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let database = create_database_for_test(&service, &context).await;

        let first = service
            .failover_database_with_idempotency(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_record: super::DataFailoverRecord =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));

        let replayed = service
            .failover_database_with_idempotency(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("simulated primary failure")),
                },
                Some("failover-idem-1"),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_payload = http_body_util::BodyExt::collect(replayed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replayed_record: super::DataFailoverRecord =
            serde_json::from_slice(&replayed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed_record.id, first_record.id);

        let failovers = super::active_values(
            service
                .failovers
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(failovers.len(), 1);
    }

    #[tokio::test]
    async fn maintenance_mode_toggles_lifecycle_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("mysql"),
                    version: String::from("8.4"),
                    storage_gb: 120,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let enabled = service
            .set_maintenance(
                database.id.as_str(),
                MaintenanceRequest {
                    enabled: true,
                    reason: Some(String::from("kernel upgrade")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let enabled_payload = http_body_util::BodyExt::collect(enabled.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let enabled_db: super::ManagedDatabase =
            serde_json::from_slice(&enabled_payload).unwrap_or_else(|error| panic!("{error}"));
        assert!(enabled_db.maintenance_mode);
        assert_eq!(enabled_db.lifecycle_state, "maintenance");

        let disabled = service
            .set_maintenance(
                database.id.as_str(),
                MaintenanceRequest {
                    enabled: false,
                    reason: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let disabled_payload = http_body_util::BodyExt::collect(disabled.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let disabled_db: super::ManagedDatabase =
            serde_json::from_slice(&disabled_payload).unwrap_or_else(|error| panic!("{error}"));
        assert!(!disabled_db.maintenance_mode);
        assert_eq!(disabled_db.lifecycle_state, "ready");
    }

    #[tokio::test]
    async fn backup_rejects_future_point_in_time_requests() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("mysql"),
                    version: String::from("8.4"),
                    storage_gb: 120,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: None,
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: super::ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let future = (time::OffsetDateTime::now_utc() + Duration::minutes(5))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|error| panic!("{error}"));
        let failure = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("ad-hoc")),
                    point_in_time_rfc3339: Some(future),
                },
                &context,
            )
            .await;
        assert!(failure.is_err());
    }

    #[tokio::test]
    async fn major_version_migration_workflow_updates_database_version() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("15.6"),
                    storage_gb: 100,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("us-east-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let migration = service
            .create_migration(
                database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("major_version_upgrade"),
                    target_version: Some(String::from("16.2")),
                    target_region: None,
                    source_replica_id: None,
                    target_replica_id: None,
                    target_storage_class: None,
                    reason: Some(String::from("major upgrade")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_payload = http_body_util::BodyExt::collect(migration.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let migration_job: DataMigrationJob =
            serde_json::from_slice(&migration_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migration_job.state, DATA_MIGRATION_STATE_PENDING);
        assert_eq!(migration_job.source_version.as_deref(), Some("15.6"));
        assert_eq!(migration_job.target_version.as_deref(), Some("16.2"));

        let started = service
            .start_migration(migration_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let started_payload = http_body_util::BodyExt::collect(started.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let started_job: DataMigrationJob =
            serde_json::from_slice(&started_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started_job.state, DATA_MIGRATION_STATE_RUNNING);
        assert!(started_job.started_at.is_some());

        let completed = service
            .complete_migration(migration_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let completed_payload = http_body_util::BodyExt::collect(completed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let completed_job: DataMigrationJob =
            serde_json::from_slice(&completed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed_job.state, DATA_MIGRATION_STATE_COMPLETED);
        assert!(completed_job.completed_at.is_some());

        let stored_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated database"));
        assert_eq!(stored_database.value.version, "16.2");
    }

    #[tokio::test]
    async fn region_move_and_replica_reseed_migrations_update_topology() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.4"),
                    storage_gb: 80,
                    replicas: 3,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("us-east-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let region_move = service
            .create_migration(
                database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("region_move"),
                    target_version: None,
                    target_region: Some(String::from("us-east-1-dr1")),
                    source_replica_id: None,
                    target_replica_id: None,
                    target_storage_class: None,
                    reason: Some(String::from("promote regional replica")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let region_move_payload = http_body_util::BodyExt::collect(region_move.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let region_move_job: DataMigrationJob =
            serde_json::from_slice(&region_move_payload).unwrap_or_else(|error| panic!("{error}"));
        let completed_region_move = service
            .complete_migration(region_move_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let completed_region_move_payload =
            http_body_util::BodyExt::collect(completed_region_move.into_body())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
        let completed_region_move_job: DataMigrationJob =
            serde_json::from_slice(&completed_region_move_payload)
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            completed_region_move_job.state,
            DATA_MIGRATION_STATE_COMPLETED
        );

        let moved_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing region-moved database"));
        assert_eq!(moved_database.value.primary_region, "us-east-1-dr1");
        assert_eq!(moved_database.value.replica_topology[1].role, "primary");
        assert_eq!(moved_database.value.replica_topology[0].role, "replica");

        let mut reseed_database = moved_database.value;
        reseed_database.replica_topology[0].healthy = false;
        reseed_database.replica_topology[0].lag_seconds = 300;
        service
            .databases
            .upsert(
                reseed_database.id.as_str(),
                reseed_database.clone(),
                Some(moved_database.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reseed = service
            .create_migration(
                reseed_database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("replica_reseed"),
                    target_version: None,
                    target_region: None,
                    source_replica_id: Some(String::from("replica-2")),
                    target_replica_id: Some(String::from("replica-1")),
                    target_storage_class: None,
                    reason: Some(String::from("reseed stale replica")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reseed_payload = http_body_util::BodyExt::collect(reseed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let reseed_job: DataMigrationJob =
            serde_json::from_slice(&reseed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reseed_job.source_replica_id.as_deref(), Some("replica-2"));
        assert_eq!(reseed_job.target_replica_id.as_deref(), Some("replica-1"));

        service
            .complete_migration(reseed_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reseeded_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reseeded database"));
        assert!(reseeded_database.value.replica_topology[0].healthy);
        assert_eq!(reseeded_database.value.replica_topology[0].lag_seconds, 0);
    }

    #[tokio::test]
    async fn storage_class_migrations_support_failure_and_active_guard() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("mysql"),
                    version: String::from("8.4"),
                    storage_gb: 120,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("eu-west-1")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        let stored_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing storage-class database"));
        let mut seeded_database = stored_database.value;
        seeded_database.storage_class = Some(String::from("general-purpose"));
        service
            .databases
            .upsert(
                seeded_database.id.as_str(),
                seeded_database.clone(),
                Some(stored_database.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migration = service
            .create_migration(
                database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("storage_class_change"),
                    target_version: None,
                    target_region: None,
                    source_replica_id: None,
                    target_replica_id: None,
                    target_storage_class: Some(String::from("archival")),
                    reason: Some(String::from("cost optimization")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_payload = http_body_util::BodyExt::collect(migration.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let migration_job: DataMigrationJob =
            serde_json::from_slice(&migration_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            migration_job.source_storage_class.as_deref(),
            Some("general-purpose")
        );
        assert_eq!(
            migration_job.target_storage_class.as_deref(),
            Some("archival")
        );

        let active_conflict = service
            .create_migration(
                database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("major_version_upgrade"),
                    target_version: Some(String::from("9.0")),
                    target_region: None,
                    source_replica_id: None,
                    target_replica_id: None,
                    target_storage_class: None,
                    reason: Some(String::from("should be blocked")),
                },
                &context,
            )
            .await
            .expect_err("active migration should block a second request");
        assert_eq!(active_conflict.code, ErrorCode::Conflict);

        let failed = service
            .fail_migration(migration_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failed_payload = http_body_util::BodyExt::collect(failed.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let failed_job: DataMigrationJob =
            serde_json::from_slice(&failed_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed_job.state, DATA_MIGRATION_STATE_FAILED);
        assert_eq!(
            failed_job.failure_reason.as_deref(),
            Some("operator marked migration failed")
        );

        let retry = service
            .create_migration(
                database.id.as_str(),
                CreateDataMigrationRequest {
                    kind: String::from("storage_class_change"),
                    target_version: None,
                    target_region: None,
                    source_replica_id: None,
                    target_replica_id: None,
                    target_storage_class: Some(String::from("archival")),
                    reason: Some(String::from("retry storage-class migration")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let retry_payload = http_body_util::BodyExt::collect(retry.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let retry_job: DataMigrationJob =
            serde_json::from_slice(&retry_payload).unwrap_or_else(|error| panic!("{error}"));

        service
            .complete_migration(retry_job.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let completed_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing completed storage-class database"));
        assert_eq!(
            completed_database.value.storage_class.as_deref(),
            Some("archival")
        );
    }

    async fn new_metadata(id: &str) -> ResourceMetadata {
        ResourceMetadata::new(
            OwnershipScope::Tenant,
            Some(id.to_owned()),
            sha256_hex(id.as_bytes()),
        )
    }

    async fn insert_sample_resources(service: &DataService) {
        let db_id = DatabaseId::generate().unwrap_or_else(|error| panic!("{error}"));
        let database = ManagedDatabase {
            id: db_id.clone(),
            engine: String::from("postgres"),
            version: String::from("16"),
            storage_gb: 64,
            replicas: 2,
            tls_required: true,
            storage_binding: None,
            metadata: new_metadata(db_id.as_str()).await,
            lifecycle_state: default_database_state(),
            primary_region: default_primary_region(),
            replica_topology: Vec::new(),
            backup_policy: BackupPolicy::default(),
            storage_class: Some(String::from("general-purpose")),
            maintenance_mode: true,
            maintenance_reason: Some(String::from("upgrade")),
            tags: BTreeMap::new(),
        };
        service
            .databases
            .create(db_id.as_str(), database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let cache_id = CacheClusterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let cache = CacheCluster {
            id: cache_id.clone(),
            engine: String::from("redis"),
            memory_mb: 2048,
            tls_required: true,
            metadata: new_metadata(cache_id.as_str()).await,
        };
        service
            .caches
            .create(cache_id.as_str(), cache)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let queue_id = QueueId::generate().unwrap_or_else(|error| panic!("{error}"));
        let queue = QueueService {
            id: queue_id.clone(),
            partitions: 3,
            retention_hours: 48,
            dead_letter_enabled: true,
            metadata: new_metadata(queue_id.as_str()).await,
        };
        service
            .queues
            .create(queue_id.as_str(), queue)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let backup_job = BackupJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: db_id.clone(),
            kind: String::from("manual"),
            state: String::from("completed"),
            requested_by: String::from("ops"),
            created_at: OffsetDateTime::now_utc(),
            completed_at: Some(OffsetDateTime::now_utc()),
            snapshot_uri: String::from("file:///snapshot"),
            backup_artifact_manifest: None,
            storage_recovery_point: None,
            storage_recovery_point_selection_reason: String::from("initial"),
            point_in_time: None,
            checksum: String::from("checksum"),
        };
        service
            .backup_jobs
            .create(backup_job.id.as_str(), backup_job.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restore_job = RestoreJob {
            id: AuditId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: db_id.clone(),
            backup_id: backup_job.id.clone(),
            state: String::from("pending"),
            requested_by: String::from("ops"),
            created_at: OffsetDateTime::now_utc(),
            completed_at: None,
            point_in_time: None,
            reason: None,
            storage_restore: None,
        };
        let restore_job_id = restore_job.id.clone();
        service
            .restore_jobs
            .create(restore_job_id.as_str(), restore_job)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failover = DataFailoverRecord {
            id: FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: db_id.clone(),
            from_replica_id: String::from("replica-1"),
            to_replica_id: String::from("replica-2"),
            state: String::from("completed"),
            reason: String::from("test"),
            created_at: OffsetDateTime::now_utc(),
            completed_at: None,
        };
        let failover_id = failover.id.clone();
        service
            .failovers
            .create(failover_id.as_str(), failover)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migration = DataMigrationJob {
            id: MigrationJobId::generate().unwrap_or_else(|error| panic!("{error}")),
            database_id: db_id.clone(),
            kind: String::from("region_move"),
            state: String::from(DATA_MIGRATION_STATE_PENDING),
            requested_by: String::from("ops"),
            created_at: OffsetDateTime::now_utc(),
            started_at: None,
            completed_at: None,
            failed_at: None,
            reason: Some(String::from("relocate primary")),
            source_version: None,
            target_version: None,
            source_region: Some(String::from("region-a")),
            target_region: Some(String::from("region-b")),
            source_replica_id: None,
            target_replica_id: None,
            source_storage_class: Some(String::from("general-purpose")),
            target_storage_class: Some(String::from("archival")),
            failure_reason: None,
        };
        let migration_id = migration.id.clone();
        service
            .migrations
            .create(migration_id.as_str(), migration)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("ops");
        let export = service
            .create_export(
                DataTransferResourceKind::Database,
                db_id.as_str(),
                CreateDataExportRequest {
                    artifact_format: Some(String::from("logical_dump")),
                    signing_key_ref: None,
                    reason: Some(String::from("seed summary export")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let export_payload = http_body_util::BodyExt::collect(export.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let export_job: DataExportJob =
            serde_json::from_slice(&export_payload).unwrap_or_else(|error| panic!("{error}"));
        service
            .create_import(
                DataTransferResourceKind::Database,
                CreateDataImportRequest {
                    signed_manifest: export_job.signed_manifest,
                    checksum_catalog: export_job.checksum_catalog,
                    target_resource_id: Some(db_id.to_string()),
                    manifest_uri: Some(export_job.manifest_uri),
                    checksum_catalog_uri: Some(export_job.checksum_catalog_uri),
                    reason: Some(String::from("seed summary import")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn legacy_data_jobs_backfill_into_operation_workflows_on_open() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        insert_sample_resources(&service).await;

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let backup_workflows = reopened
            .backup_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_workflows = reopened
            .restore_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failover_workflows = reopened
            .failover_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(backup_workflows.len(), 1);
        assert_eq!(restore_workflows.len(), 1);
        assert_eq!(failover_workflows.len(), 1);
        assert_eq!(backup_workflows[0].1.value.phase, WorkflowPhase::Completed);
        assert_eq!(restore_workflows[0].1.value.phase, WorkflowPhase::Pending);
        assert_eq!(
            failover_workflows[0].1.value.phase,
            WorkflowPhase::Completed
        );
        assert!(
            !backup_workflows[0].1.value.state.evidence.is_empty(),
            "backfilled backup workflow should retain replayable evidence"
        );
        assert!(
            !restore_workflows[0].1.value.state.evidence.is_empty(),
            "backfilled restore workflow should retain replayable evidence"
        );
        assert!(
            !failover_workflows[0].1.value.state.evidence.is_empty(),
            "backfilled failover workflow should retain replayable evidence"
        );
    }

    #[tokio::test]
    async fn data_mutations_persist_completed_workflows_and_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_database(
                CreateDatabaseRequest {
                    engine: String::from("postgres"),
                    version: String::from("16.2"),
                    storage_gb: 80,
                    replicas: 2,
                    tls_required: true,
                    storage_class_id: None,
                    durability_tier_id: None,
                    primary_region: Some(String::from("region-a")),
                    backup_policy: None,
                    tags: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let database: ManagedDatabase =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("workflow verification")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let backup_workflow = service
            .backup_workflows
            .get(backup_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing backup workflow"));
        assert_eq!(backup_workflow.value.phase, WorkflowPhase::Completed);
        assert!(backup_workflow.value.state.evidence.len() >= 3);
        assert_eq!(
            backup_workflow.value.state.snapshot_uri,
            backup_job.snapshot_uri
        );

        let restored = service
            .restore_database(
                database.id.as_str(),
                RestoreDatabaseRequest {
                    backup_id: backup_job.id.to_string(),
                    point_in_time_rfc3339: None,
                    reason: Some(String::from("workflow restore verification")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_payload = http_body_util::BodyExt::collect(restored.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let restore_reply: serde_json::Value =
            serde_json::from_slice(&restore_payload).unwrap_or_else(|error| panic!("{error}"));
        let restore_id = restore_reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing restore id"));
        let restore_workflow = service
            .restore_workflows
            .get(restore_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restore workflow"));
        assert_eq!(restore_workflow.value.phase, WorkflowPhase::Completed);
        assert!(restore_workflow.value.state.evidence.len() >= 3);
        assert!(restore_workflow.value.state.source_mode.is_some());
        assert!(
            restore_workflow
                .value
                .state
                .selected_recovery_point
                .is_some()
        );
        assert!(restore_workflow.value.state.storage_restore.is_some());

        let failover = service
            .failover_database(
                database.id.as_str(),
                FailoverDatabaseRequest {
                    target_replica_id: Some(String::from("replica-2")),
                    target_region: None,
                    reason: Some(String::from("workflow failover verification")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failover_payload = http_body_util::BodyExt::collect(failover.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let failover_record: DataFailoverRecord =
            serde_json::from_slice(&failover_payload).unwrap_or_else(|error| panic!("{error}"));
        let failover_workflow = service
            .failover_workflows
            .get(failover_record.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing failover workflow"));
        assert_eq!(failover_workflow.value.phase, WorkflowPhase::Completed);
        assert!(failover_workflow.value.state.evidence.len() >= 3);
        assert_eq!(failover_workflow.value.state.to_replica_id, "replica-2");
    }

    #[tokio::test]
    async fn restore_crash_reconciler_rebuilds_restore_job_workflow_and_outbox_from_annotations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (database, _backup_job, restore_job) =
            create_database_backup_and_restore(&service).await;
        let restore_lineage = restore_job
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing restore lineage"));

        let stored_restore = service
            .restore_jobs
            .get(restore_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored restore job"));
        service
            .restore_jobs
            .soft_delete(restore_job.id.as_str(), Some(stored_restore.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored_workflow = service
            .restore_workflows
            .get(restore_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored restore workflow"));
        service
            .restore_workflows
            .soft_delete(restore_job.id.as_str(), Some(stored_workflow.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened = remove_persisted_outbox_service_event_and_reopen(
            temp.path(),
            "data.database.restore.completed.v1",
            "database_restore",
            restore_job.id.as_str(),
            "completed",
        )
        .await;
        let restored_job = reopened
            .restore_jobs
            .get(restore_lineage.restore_action_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled restore job"));
        assert_eq!(restored_job.value.database_id, database.id);
        assert_eq!(
            restored_job.value.requested_by,
            super::DATA_RECONCILER_ACTOR
        );
        assert_eq!(
            restored_job.value.reason.as_deref(),
            Some(super::RECONCILED_RESTORE_REASON)
        );
        assert_eq!(
            restored_job.value.storage_restore,
            Some(restore_lineage.clone())
        );

        let restored_workflow = reopened
            .restore_workflows
            .get(restore_lineage.restore_action_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled restore workflow"));
        assert_eq!(restored_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            restored_workflow.value.state.restore_id,
            restore_lineage.restore_action_id
        );
        assert_eq!(
            restored_workflow.value.state.storage_restore,
            Some(restore_lineage.clone())
        );

        let messages = reopened
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(messages.iter().any(|message| {
            message.payload.header.event_type == "data.database.restore.completed.v1"
                && matches!(
                    &message.payload.payload,
                    EventPayload::Service(service_event)
                        if service_event.resource_kind == "database_restore"
                            && service_event.resource_id
                                == restore_lineage.restore_action_id.as_str()
                            && service_event.action == "completed"
                )
        }));
    }

    #[tokio::test]
    async fn reconcile_restore_workflows_backfill_missing_workflow_and_database_projection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (database, _backup_job, restore_job) =
            create_database_backup_and_restore(&service).await;
        let restore_lineage = restore_job
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing restore lineage"));

        let stored_workflow = service
            .restore_workflows
            .get(restore_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored restore workflow"));
        service
            .restore_workflows
            .soft_delete(restore_job.id.as_str(), Some(stored_workflow.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored database"));
        let mut degraded_database = stored_database.value;
        degraded_database.lifecycle_state = String::from("maintenance");
        degraded_database.maintenance_mode = true;
        degraded_database.maintenance_reason = Some(String::from("controller crash"));
        degraded_database
            .metadata
            .annotations
            .remove(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION);
        degraded_database
            .metadata
            .annotations
            .remove(DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION);
        degraded_database
            .metadata
            .annotations
            .remove(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_VERSION_ANNOTATION);
        degraded_database
            .metadata
            .annotations
            .remove(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_ETAG_ANNOTATION);
        degraded_database
            .metadata
            .annotations
            .remove(DATABASE_LAST_RESTORE_SOURCE_RECOVERY_POINT_CAPTURED_AT_ANNOTATION);
        service
            .databases
            .upsert(
                database.id.as_str(),
                degraded_database,
                Some(stored_database.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restored_workflow = reopened
            .restore_workflows
            .get(restore_job.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled restore workflow"));
        assert_eq!(restored_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            restored_workflow.value.state.storage_restore,
            Some(restore_lineage.clone())
        );

        let restored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        assert_eq!(restored_database.value.lifecycle_state, "ready");
        assert!(!restored_database.value.maintenance_mode);
        assert_eq!(restored_database.value.maintenance_reason, None);
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
                .map(String::as_str),
            Some(restore_lineage.restore_action_id.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION)
                .map(String::as_str),
            Some(restore_job.backup_id.as_str())
        );
    }

    #[tokio::test]
    async fn open_migrates_paused_pre_ledger_restore_storage_effect_before_retry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("pre-ledger restore storage migration")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let selected_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup recovery point lineage"));
        let volume = service
            .ensure_database_storage_volume(&database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restore_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_restore_workflow(super::RestoreWorkflowState {
            restore_id: restore_id.clone(),
            database_id: database.id.clone(),
            backup_id: backup_job.id.clone(),
            requested_by: String::from("db.operator"),
            point_in_time: None,
            reason: Some(String::from("paused pre-ledger restore storage migration")),
            target_volume_id: volume.id.clone(),
            source_mode: Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage),
            selected_recovery_point: Some(selected_recovery_point.clone()),
            backup_correlated_recovery_point: Some(selected_recovery_point),
            storage_restore: None,
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Paused);
        workflow.current_step_index = Some(1);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing restore workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "selected deterministic storage recovery point",
                )),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing restore workflow step 1"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("executing storage restore workflow")),
            );
        let started = service
            .restore_workflows
            .create(restore_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            started
                .value
                .step(1)
                .and_then(|step| step.effect(super::DATA_RESTORE_STORAGE_EFFECT_KIND))
                .is_none(),
            "setup should start from a pre-ledger restore workflow",
        );
        service
            .sync_restore_job_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = reopen_data_service(temp.path()).await;
        let migrated = reopened
            .restore_workflows
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated restore workflow"));
        assert_eq!(migrated.value.phase, WorkflowPhase::Paused);
        let effect = migrated
            .value
            .step(1)
            .and_then(|step| step.effect(super::DATA_RESTORE_STORAGE_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing migrated restore storage effect"));
        assert_eq!(effect.state, WorkflowStepEffectState::Pending);
        assert_eq!(
            effect.idempotency_key,
            super::restore_storage_effect_idempotency_key(&migrated.value.state)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            effect.detail.as_deref(),
            Some(
                super::restore_storage_effect_detail(&migrated.value.state)
                    .unwrap_or_else(|error| panic!("{error}"))
                    .as_str()
            )
        );
    }

    #[tokio::test]
    async fn open_migrates_paused_pre_ledger_restore_projection_effect_before_retry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("pre-ledger restore projection migration")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let selected_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup recovery point lineage"));
        let volume = service
            .ensure_database_storage_volume(&database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let storage_restore_action_id = service
            .storage
            .restore_volume_from_selected_recovery_point(
                &volume.id,
                selected_recovery_point.version,
                Some(selected_recovery_point.etag.as_str()),
                Some(String::from(
                    "paused pre-ledger restore projection migration",
                )),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let storage_restore_action = service
            .storage
            .describe_volume_restore_action(&storage_restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing storage restore action"));
        let storage_restore_lineage = super::build_restore_storage_lineage(
            &volume,
            &storage_restore_action,
            true,
            Some(&selected_recovery_point),
        );

        let restore_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_restore_workflow(super::RestoreWorkflowState {
            restore_id: restore_id.clone(),
            database_id: database.id.clone(),
            backup_id: backup_job.id.clone(),
            requested_by: String::from("db.operator"),
            point_in_time: None,
            reason: Some(String::from(
                "paused pre-ledger restore projection migration",
            )),
            target_volume_id: volume.id.clone(),
            source_mode: Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage),
            selected_recovery_point: Some(selected_recovery_point.clone()),
            backup_correlated_recovery_point: Some(selected_recovery_point),
            storage_restore: Some(storage_restore_lineage.clone()),
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Paused);
        workflow.current_step_index = Some(super::DATA_RESTORE_FINAL_STEP_INDEX);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing restore workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "selected deterministic storage recovery point",
                )),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing restore workflow step 1"))
            .transition(
                WorkflowStepState::Completed,
                Some(format!(
                    "executed storage restore action {}",
                    storage_restore_action_id.as_str()
                )),
            );
        workflow
            .step_mut(super::DATA_RESTORE_FINAL_STEP_INDEX)
            .unwrap_or_else(|| panic!("missing restore workflow final step"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("applying database restore projection")),
            );
        let started = service
            .restore_workflows
            .create(restore_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            started
                .value
                .step(super::DATA_RESTORE_FINAL_STEP_INDEX)
                .and_then(|step| step.effect(super::DATA_RESTORE_PROJECTION_EFFECT_KIND))
                .is_none(),
            "setup should start from a pre-ledger restore projection workflow",
        );
        service
            .sync_restore_job_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = reopen_data_service(temp.path()).await;
        let migrated = reopened
            .restore_workflows
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated restore workflow"));
        assert_eq!(migrated.value.phase, WorkflowPhase::Paused);
        let effect = migrated
            .value
            .step(super::DATA_RESTORE_FINAL_STEP_INDEX)
            .and_then(|step| step.effect(super::DATA_RESTORE_PROJECTION_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing migrated restore projection effect"));
        assert_eq!(effect.state, WorkflowStepEffectState::Pending);
        assert_eq!(
            effect.idempotency_key,
            super::restore_projection_effect_idempotency_key(&migrated.value.state)
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(
            effect.detail.as_deref(),
            Some(
                super::restore_projection_effect_detail(&migrated.value.state)
                    .unwrap_or_else(|error| panic!("{error}"))
                    .as_str()
            )
        );
    }

    #[tokio::test]
    async fn open_migrates_paused_pre_ledger_failover_promotion_effect_before_retry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;
        let stored_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored database"));
        let from_replica_id = stored_database.value.replica_topology[0].id.clone();
        let to_replica_id = stored_database.value.replica_topology[1].id.clone();
        let target_region = stored_database.value.replica_topology[1].region.clone();

        let failover_id = FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_failover_workflow(super::FailoverWorkflowState {
            failover_id: failover_id.clone(),
            database_id: database.id.clone(),
            from_replica_id: from_replica_id.clone(),
            to_replica_id: to_replica_id.clone(),
            target_region: target_region.clone(),
            requested_by: String::from("db.operator"),
            reason: String::from("paused pre-ledger failover migration"),
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Paused);
        workflow.current_step_index = Some(1);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing failover workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from("prepared deterministic failover target")),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing failover workflow step 1"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("promoting target replica")),
            );
        let started = service
            .failover_workflows
            .create(failover_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            started
                .value
                .step(1)
                .and_then(|step| step.effect(super::DATA_FAILOVER_PROMOTION_EFFECT_KIND))
                .is_none(),
            "setup should start from a pre-ledger failover workflow",
        );
        service
            .sync_failover_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = reopen_data_service(temp.path()).await;
        let migrated = reopened
            .failover_workflows
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated failover workflow"));
        assert_eq!(migrated.value.phase, WorkflowPhase::Paused);
        let effect = migrated
            .value
            .step(1)
            .and_then(|step| step.effect(super::DATA_FAILOVER_PROMOTION_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing migrated failover effect"));
        assert_eq!(effect.state, WorkflowStepEffectState::Pending);
        assert_eq!(
            effect.idempotency_key,
            super::failover_promotion_effect_idempotency_key(&migrated.value.state)
        );
        assert_eq!(
            effect.detail.as_deref(),
            Some(super::failover_promotion_effect_detail(&migrated.value.state).as_str())
        );
    }

    #[tokio::test]
    async fn open_resumes_pending_backup_workflow_after_controller_death() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;
        let volume = service
            .ensure_database_storage_volume(&database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let recovery_point = service
            .storage
            .describe_ready_volume_recovery_point(&volume.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing ready recovery point"));
        let backup_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();
        let storage_recovery_point = super::build_backup_storage_recovery_point(&recovery_point);
        let manifest = service
            .persist_backup_artifact_manifest(
                &backup_id,
                &database,
                "full",
                "db.operator",
                Some(String::from("resume-after-crash")),
                created_at,
                None,
                &storage_recovery_point,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let primary_artifact = manifest
            .artifacts
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("missing backup artifact"));
        let workflow = super::build_backup_workflow(super::BackupWorkflowState {
            backup_id: backup_id.clone(),
            database_id: database.id.clone(),
            kind: String::from("full"),
            requested_by: String::from("db.operator"),
            snapshot_uri: primary_artifact.object_location.clone(),
            backup_artifact_manifest: Some(manifest),
            storage_recovery_point: Some(storage_recovery_point),
            storage_recovery_point_selection_reason:
                super::backup_storage_recovery_point_selection_reason(),
            point_in_time: None,
            checksum: primary_artifact.sha256.clone(),
            requested_reason: Some(String::from("resume-after-crash")),
            evidence: Vec::new(),
        });
        let started = service
            .backup_workflows
            .create(backup_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .sync_backup_job_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = reopened
            .backup_workflows
            .get(backup_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resumed backup workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert!(workflow.value.completed_at.is_some());

        let backup = reopened
            .backup_jobs
            .get(backup_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resumed backup job"));
        assert_eq!(backup.value.state, "completed");
        assert!(backup.value.completed_at.is_some());
    }

    #[tokio::test]
    async fn open_reconciles_restore_after_storage_effect_already_applied() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("pre-restore")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let selected_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup recovery point lineage"));
        let volume = service
            .ensure_database_storage_volume(&database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let storage_restore_action_id = service
            .storage
            .restore_volume_from_selected_recovery_point(
                &volume.id,
                selected_recovery_point.version,
                Some(selected_recovery_point.etag.as_str()),
                Some(String::from("restore crash window")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let restore_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_restore_workflow(super::RestoreWorkflowState {
            restore_id: restore_id.clone(),
            database_id: database.id.clone(),
            backup_id: backup_job.id.clone(),
            requested_by: String::from("db.operator"),
            point_in_time: None,
            reason: Some(String::from("restore crash window")),
            target_volume_id: volume.id.clone(),
            source_mode: Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage),
            selected_recovery_point: Some(selected_recovery_point.clone()),
            backup_correlated_recovery_point: Some(selected_recovery_point.clone()),
            storage_restore: None,
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Running);
        workflow.current_step_index = Some(1);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing restore workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "selected deterministic storage recovery point",
                )),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing restore workflow step 1"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("executing storage restore workflow")),
            );
        let started = service
            .restore_workflows
            .create(restore_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .sync_restore_job_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (journaled, effect_execution) = service
            .begin_restore_storage_effect(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first restore storage effect should execute")
            }
        };
        let _ledger = service
            .persist_workflow_effect_ledger(
                &journaled.value,
                1,
                super::DATA_RESTORE_STORAGE_EFFECT_KIND,
                storage_restore_action_id.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = reopened
            .restore_workflows
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled restore workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        let storage_restore = workflow
            .value
            .state
            .storage_restore
            .clone()
            .unwrap_or_else(|| panic!("missing reconciled storage restore lineage"));
        assert_eq!(storage_restore.restore_action_id, storage_restore_action_id);
        let restore_effect = workflow
            .value
            .step(1)
            .and_then(|step| step.effect(super::DATA_RESTORE_STORAGE_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing reconciled restore storage effect"));
        assert_eq!(
            restore_effect.result_digest.as_deref(),
            Some(storage_restore_action_id.as_str())
        );

        let restore = reopened
            .restore_jobs
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled restore job"));
        assert_eq!(restore.value.state, "completed");
        assert_eq!(
            restore
                .value
                .storage_restore
                .as_ref()
                .map(|lineage| lineage.restore_action_id.clone()),
            Some(storage_restore_action_id.clone())
        );

        let restored_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_BACKUP_ID_ANNOTATION)
                .map(String::as_str),
            Some(backup_job.id.as_str())
        );
        assert_eq!(
            restored_database
                .value
                .metadata
                .annotations
                .get(DATABASE_LAST_RESTORE_ACTION_ID_ANNOTATION)
                .map(String::as_str),
            Some(storage_restore_action_id.as_str())
        );
        let inspection_context = operator_context("db.operator", "cred_restore_inspect");
        let restore_actions = reopened
            .storage
            .list_volume_restore_actions(volume.id.as_str(), &inspection_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            restore_actions.len(),
            1,
            "controller restart should not duplicate the already-applied storage restore",
        );
    }

    #[tokio::test]
    async fn open_reconciles_restore_after_database_projection_ledger_was_persisted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;

        let backup = service
            .create_backup(
                database.id.as_str(),
                CreateBackupRequest {
                    kind: Some(String::from("full")),
                    reason: Some(String::from("projection crash window")),
                    point_in_time_rfc3339: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let backup_payload = http_body_util::BodyExt::collect(backup.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let backup_job: BackupJob =
            serde_json::from_slice(&backup_payload).unwrap_or_else(|error| panic!("{error}"));
        let selected_recovery_point = backup_job
            .storage_recovery_point
            .clone()
            .unwrap_or_else(|| panic!("missing backup recovery point lineage"));
        let volume = service
            .ensure_database_storage_volume(&database)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let storage_restore_action_id = service
            .storage
            .restore_volume_from_selected_recovery_point(
                &volume.id,
                selected_recovery_point.version,
                Some(selected_recovery_point.etag.as_str()),
                Some(String::from("projection crash window")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let storage_restore_action = service
            .storage
            .describe_volume_restore_action(&storage_restore_action_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing storage restore action"));
        let storage_restore_lineage = super::build_restore_storage_lineage(
            &volume,
            &storage_restore_action,
            true,
            Some(&selected_recovery_point),
        );
        let restore_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_restore_workflow(super::RestoreWorkflowState {
            restore_id: restore_id.clone(),
            database_id: database.id.clone(),
            backup_id: backup_job.id.clone(),
            requested_by: String::from("db.operator"),
            point_in_time: None,
            reason: Some(String::from("projection crash window")),
            target_volume_id: volume.id.clone(),
            source_mode: Some(RestoreStorageSourceMode::BackupCorrelatedStorageLineage),
            selected_recovery_point: Some(selected_recovery_point.clone()),
            backup_correlated_recovery_point: Some(selected_recovery_point.clone()),
            storage_restore: Some(storage_restore_lineage.clone()),
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Running);
        workflow.current_step_index = Some(super::DATA_RESTORE_FINAL_STEP_INDEX);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing restore workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from(
                    "selected deterministic storage recovery point",
                )),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing restore workflow step 1"))
            .transition(
                WorkflowStepState::Completed,
                Some(format!(
                    "executed storage restore action {}",
                    storage_restore_action_id.as_str()
                )),
            );
        workflow
            .step_mut(super::DATA_RESTORE_FINAL_STEP_INDEX)
            .unwrap_or_else(|| panic!("missing restore workflow final step"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("applying database restore projection")),
            );
        let started = service
            .restore_workflows
            .create(restore_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .sync_restore_job_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (journaled, effect_execution) = service
            .begin_restore_projection_effect(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first restore projection effect should execute")
            }
        };
        let current = service
            .load_database_record(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let current_database = current.value.clone();
        let (mut projected_database, storage_changed) = service
            .build_projected_restore_database(current.value, &journaled.value.state)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        if storage_changed {
            let restore_action_summary = super::build_restore_action_summary_from_lineage(
                journaled
                    .value
                    .state
                    .storage_restore
                    .as_ref()
                    .unwrap_or_else(|| panic!("missing restore lineage")),
                "completed",
            );
            projected_database
                .metadata
                .touch(super::database_restore_lineage_etag(
                    &projected_database,
                    &journaled.value.state.backup_id,
                    &restore_action_summary,
                ));
        } else if projected_database != current_database {
            projected_database.metadata.touch(sha256_hex(
                format!(
                    "{}:database-restore-projection:{}",
                    projected_database.id.as_str(),
                    journaled.value.state.restore_id.as_str(),
                )
                .as_bytes(),
            ));
        }
        service
            .databases
            .upsert(
                projected_database.id.as_str(),
                projected_database.clone(),
                Some(current.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projection_result_digest = super::restore_projection_effect_result_digest(
            &projected_database,
            &journaled.value.state,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let _ledger = service
            .persist_workflow_effect_ledger(
                &journaled.value,
                super::DATA_RESTORE_FINAL_STEP_INDEX,
                super::DATA_RESTORE_PROJECTION_EFFECT_KIND,
                projection_result_digest.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = reopened
            .restore_workflows
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resumed restore workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        let projection_effect = workflow
            .value
            .step(super::DATA_RESTORE_FINAL_STEP_INDEX)
            .and_then(|step| step.effect(super::DATA_RESTORE_PROJECTION_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing reconciled restore projection effect"));
        assert_eq!(
            projection_effect.result_digest.as_deref(),
            Some(projection_result_digest.as_str())
        );

        let restore = reopened
            .restore_jobs
            .get(restore_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resumed restore job"));
        assert_eq!(restore.value.state, "completed");
        assert_eq!(
            restore
                .value
                .storage_restore
                .as_ref()
                .map(|lineage| lineage.restore_action_id.clone()),
            Some(storage_restore_action_id)
        );
    }

    #[tokio::test]
    async fn open_reconciles_failover_after_topology_was_already_promoted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("db.operator");
        let database = create_database_for_test(&service, &context).await;
        let stored_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored database"));
        let mut promoted_database = stored_database.value;
        let from_replica_id = promoted_database.replica_topology[0].id.clone();
        let to_replica_id = promoted_database.replica_topology[1].id.clone();
        let target_region = promoted_database.replica_topology[1].region.clone();
        promoted_database.replica_topology[0].role = String::from("replica");
        promoted_database.replica_topology[1].role = String::from("primary");
        promoted_database.primary_region = target_region.clone();
        service
            .databases
            .upsert(
                database.id.as_str(),
                promoted_database,
                Some(stored_database.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failover_id = FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut workflow = super::build_failover_workflow(super::FailoverWorkflowState {
            failover_id: failover_id.clone(),
            database_id: database.id.clone(),
            from_replica_id: from_replica_id.clone(),
            to_replica_id: to_replica_id.clone(),
            target_region: target_region.clone(),
            requested_by: String::from("db.operator"),
            reason: String::from("failover crash window"),
            evidence: Vec::new(),
        });
        workflow.set_phase(WorkflowPhase::Running);
        workflow.current_step_index = Some(1);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing failover workflow step 0"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from("prepared deterministic failover target")),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing failover workflow step 1"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("promoting target replica")),
            );
        let started = service
            .failover_workflows
            .create(failover_id.as_str(), workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .sync_failover_projection(&started.value)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (journaled, effect_execution) = service
            .begin_failover_promotion_effect(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first failover promotion effect should execute")
            }
        };
        let promoted_database = service
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing promoted database after rewrite"));
        let promotion_result_digest = super::failover_promotion_effect_result_digest(
            &promoted_database.value,
            &journaled.value.state,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let _ledger = service
            .persist_workflow_effect_ledger(
                &journaled.value,
                1,
                super::DATA_FAILOVER_PROMOTION_EFFECT_KIND,
                promotion_result_digest.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = reopened
            .failover_workflows
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled failover workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        let promotion_effect = workflow
            .value
            .step(1)
            .and_then(|step| step.effect(super::DATA_FAILOVER_PROMOTION_EFFECT_KIND))
            .unwrap_or_else(|| panic!("missing reconciled failover promotion effect"));
        assert_eq!(
            promotion_effect.result_digest.as_deref(),
            Some(promotion_result_digest.as_str())
        );

        let failover = reopened
            .failovers
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled failover projection"));
        assert_eq!(failover.value.state, "completed");

        let reconciled_database = reopened
            .databases
            .get(database.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled database"));
        assert_eq!(reconciled_database.value.primary_region, target_region);
        assert_eq!(
            reconciled_database.value.replica_topology[0].role,
            "replica"
        );
        assert_eq!(
            reconciled_database.value.replica_topology[1].role,
            "primary"
        );
    }

    #[tokio::test]
    async fn durability_summary_counts_entries() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = DataService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        insert_sample_resources(&service).await;

        let summary = service
            .durability_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.database_count, 1);
        assert_eq!(summary.cache_count, 1);
        assert_eq!(summary.queue_count, 1);
        assert_eq!(summary.backup_job_count, 1);
        assert_eq!(summary.restore_job_count, 1);
        assert_eq!(summary.failover_count, 1);
        assert_eq!(summary.migration_job_count, 1);
        assert_eq!(summary.export_job_count, 1);
        assert_eq!(summary.import_job_count, 1);
        assert_eq!(summary.maintenance_mode_databases, 1);
        assert!(summary.backup_job_state_counts.contains_key("completed"));
        assert!(summary.restore_job_state_counts.contains_key("pending"));
        assert!(summary.failover_state_counts.contains_key("completed"));
        assert!(summary.migration_job_state_counts.contains_key("pending"));
        assert!(summary.export_job_state_counts.contains_key("completed"));
        assert!(summary.import_job_state_counts.contains_key("verified"));
    }
}
