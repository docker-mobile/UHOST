//! Upgrade, migration, rollout, and repair service.
//!
//! This bounded context owns schema/config migration execution metadata,
//! compatibility windows, rollout plan orchestration metadata, maintenance-mode
//! declarations, and workflow-backed dead-letter repair tooling.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::fs;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{
    BackgroundTaskContract, CompatibilityPolicy, ErrorCode, EventSubscription, MigrationManifest,
    PlatformError, RequestContext, Result, find_migration_manifest, load_migration_manifests,
    sha256_hex, validate_manifest_against_policy, validate_migration_manifest_chain,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    AuditLog, DocumentStore, DurableOutbox, StoredDocument, WorkflowCollection, WorkflowInstance,
    WorkflowPhase, WorkflowStep, WorkflowStepState,
};
use uhost_types::{
    AuditActor, AuditId, ChangeRequestId, DeadLetterId, EventHeader, EventPayload, MigrationJobId,
    OwnershipScope, PlatformEvent, PluginId, RepairJobId, ResourceMetadata, RolloutPlanId,
    ServiceEvent,
};

/// Migration scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationScope {
    /// Persistent schema migration.
    Schema,
    /// Configuration shape migration.
    Config,
}

/// Migration state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// Recorded but not yet applied.
    Pending,
    /// Successfully applied.
    Applied,
    /// Failed and requires repair.
    Failed,
}

/// Applied migration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Migration identifier.
    pub id: MigrationJobId,
    /// Scope.
    pub scope: MigrationScope,
    /// Expected source version.
    pub from_version: u32,
    /// Target version.
    pub to_version: u32,
    /// Migration name.
    pub name: String,
    /// Migration checksum used for idempotency.
    pub checksum: String,
    /// Current state.
    pub state: MigrationState,
    /// Timestamp when applied.
    pub applied_at: Option<OffsetDateTime>,
    /// Compatibility window end timestamp.
    pub compatibility_window_until: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Rollout plan record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPlanRecord {
    /// Rollout identifier.
    pub id: RolloutPlanId,
    /// Target service.
    pub service: String,
    /// Release channel (`stable`, `canary`, `preview`).
    pub channel: String,
    /// Canary percentages in ascending order.
    pub canary_steps: Vec<u8>,
    /// Compatibility window in days.
    pub compatibility_window_days: u32,
    /// Current rollout phase.
    pub phase: String,
    /// Index of the active canary step.
    pub current_step_index: usize,
    /// Currently routed traffic percentage for this rollout.
    pub current_traffic_percent: u8,
    /// Optional operator reason for pause/rollback.
    pub status_reason: Option<String>,
    /// Last mutation kind applied to this rollout.
    #[serde(default)]
    pub last_mutation_kind: Option<String>,
    /// Optional idempotency key associated with the last mutation.
    #[serde(default)]
    pub last_mutation_idempotency_key: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Maintenance-mode declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceRecord {
    /// Service key under maintenance.
    pub service: String,
    /// Whether maintenance mode is enabled.
    pub enabled: bool,
    /// Operator reason.
    pub reason: String,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

/// Dead-letter message record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetterRecord {
    /// Dead-letter identifier.
    pub id: DeadLetterId,
    /// Topic name.
    pub topic: String,
    /// Opaque payload.
    pub payload: serde_json::Value,
    /// Error detail.
    pub error: String,
    /// Number of attempts seen before dead-lettering.
    pub attempts: u32,
    /// Replay state.
    pub replayed: bool,
    /// Active repair job currently responsible for downstream replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_job_id: Option<RepairJobId>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Timestamp when a repair job most recently claimed this dead letter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_requested_at: Option<OffsetDateTime>,
    /// Replay timestamp if replayed.
    pub replayed_at: Option<OffsetDateTime>,
}

/// Repair job record produced by dead-letter replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairJobRecord {
    /// Repair job identifier.
    pub id: RepairJobId,
    /// Job type.
    pub job_type: String,
    /// Job status.
    pub status: String,
    /// Number of records considered.
    pub scanned: u64,
    /// Number of records replayed.
    pub replayed: u64,
    /// Number of records that failed replay.
    pub failed: u64,
    /// Dead-letter identifiers targeted by this repair job.
    #[serde(default)]
    pub dead_letter_ids: Vec<DeadLetterId>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Completion timestamp.
    pub completed_at: Option<OffsetDateTime>,
    /// Optional downstream confirmation detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_detail: Option<String>,
    /// Timestamp when the downstream outcome was confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Plugin registration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRecord {
    /// Plugin identifier.
    pub id: PluginId,
    /// Plugin name.
    pub name: String,
    /// Plugin implementation version.
    pub version: String,
    /// Minimum supported extension API version.
    pub min_api_version: u16,
    /// Maximum supported extension API version.
    pub max_api_version: u16,
    /// Whether plugin is enabled.
    pub enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Versioned event subscription record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionSubscriptionRecord {
    /// Record identifier.
    pub id: AuditId,
    /// Owning plugin id.
    pub plugin_id: PluginId,
    /// Subscribed topic.
    pub topic: String,
    /// Delivery mode.
    pub delivery_mode: String,
    /// Whether retries are enabled.
    pub retries_enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Background task contract registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundTaskRecord {
    /// Record identifier.
    pub id: AuditId,
    /// Owning plugin id.
    pub plugin_id: PluginId,
    /// Task identifier.
    pub task: String,
    /// Timeout budget for one task run.
    pub timeout_seconds: u32,
    /// Maximum concurrency.
    pub max_concurrency: u16,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateMigrationRequest {
    scope: String,
    from_version: u32,
    to_version: u32,
    name: String,
    checksum: String,
    compatibility_window_days: Option<u32>,
    change_request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRolloutRequest {
    service: String,
    channel: String,
    canary_steps: Vec<u8>,
    compatibility_window_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RolloutActionRequest {
    reason: Option<String>,
    idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SetMaintenanceRequest {
    service: String,
    enabled: bool,
    reason: String,
    change_request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceChangeRequestMirror {
    id: ChangeRequestId,
    state: String,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleIntegrityReport {
    valid: bool,
    migration_count: usize,
    duplicate_target_conflicts: usize,
    ordering_violations: usize,
    unreplayed_dead_letters: usize,
    details: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDeadLetterRequest {
    topic: String,
    payload: serde_json::Value,
    error: String,
    attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplayDeadLetterRequest {
    limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConfirmRepairJobRequest {
    success: bool,
    detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisterPluginRequest {
    plugin_id: String,
    name: String,
    version: String,
    min_api_version: u16,
    max_api_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisterSubscriptionRequest {
    plugin_id: String,
    topic: String,
    delivery_mode: String,
    retries_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisterBackgroundTaskRequest {
    plugin_id: String,
    task: String,
    timeout_seconds: u32,
    max_concurrency: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleSummary {
    rollouts: LifecycleRolloutSummary,
    migrations: LifecycleMigrationSummary,
    maintenance: LifecycleMaintenanceSummary,
    dead_letters: LifecycleDeadLetterSummary,
    repair_jobs: LifecycleRepairJobSummary,
    extensions: LifecycleExtensionSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleRolloutSummary {
    total: usize,
    by_phase: Vec<NamedCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleMigrationSummary {
    total: usize,
    pending: usize,
    applied: usize,
    failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleMaintenanceSummary {
    total: usize,
    enabled: usize,
    disabled: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleDeadLetterSummary {
    total: usize,
    pending_replay: usize,
    replayed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleRepairJobSummary {
    total: usize,
    completed: usize,
    failed: usize,
    active: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LifecycleExtensionSummary {
    plugins_total: usize,
    plugins_enabled: usize,
    event_subscriptions_total: usize,
    background_tasks_total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamedCount {
    name: String,
    count: usize,
}

/// Lifecycle service.
#[derive(Debug, Clone)]
pub struct LifecycleService {
    migrations: DocumentStore<MigrationRecord>,
    governance_change_requests: DocumentStore<GovernanceChangeRequestMirror>,
    rollouts: DocumentStore<RolloutPlanRecord>,
    rollout_workflows: WorkflowCollection<RolloutPlanRecord>,
    maintenance: DocumentStore<MaintenanceRecord>,
    dead_letters: DocumentStore<DeadLetterRecord>,
    repair_jobs: DocumentStore<RepairJobRecord>,
    repair_job_workflows: WorkflowCollection<RepairJobRecord>,
    plugins: DocumentStore<PluginRecord>,
    extension_subscriptions: DocumentStore<ExtensionSubscriptionRecord>,
    background_tasks: DocumentStore<BackgroundTaskRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    platform_state_root: PathBuf,
    state_root: PathBuf,
    migration_manifest_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RolloutMutationKind {
    Start,
    Advance,
    Pause,
    Resume,
    Rollback,
}

impl RolloutMutationKind {
    fn event_type(self) -> &'static str {
        match self {
            Self::Start => "lifecycle.rollout.started.v1",
            Self::Advance => "lifecycle.rollout.advanced.v1",
            Self::Pause => "lifecycle.rollout.paused.v1",
            Self::Resume => "lifecycle.rollout.resumed.v1",
            Self::Rollback => "lifecycle.rollout.rolled_back.v1",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Advance => "advance",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Rollback => "rollback",
        }
    }
}

const ROLLOUT_WORKFLOW_KIND: &str = "lifecycle.rollout";
const ROLLOUT_WORKFLOW_SUBJECT_KIND: &str = "rollout_plan";
const ROLLOUT_RECONCILER_RUNNER_ID: &str = "lifecycle:rollout-reconciler";
const REPAIR_JOB_WORKFLOW_KIND: &str = "lifecycle.repair";
const REPAIR_JOB_WORKFLOW_SUBJECT_KIND: &str = "repair_job";
const REPAIR_JOB_STEP_CLAIM_TARGETS: &str = "claim_dead_letters";
const REPAIR_JOB_STEP_AWAIT_CONFIRMATION: &str = "await_downstream_confirmation";
const REPAIR_JOB_STEP_FINALIZE_OUTCOME: &str = "finalize_repair_outcome";
const REPAIR_JOB_TYPE_DEAD_LETTER_REPLAY: &str = "dead_letter_replay";
const REPAIR_JOB_STATUS_PENDING_CONFIRMATION: &str = "pending_confirmation";
const REPAIR_JOB_STATUS_COMPLETED: &str = "completed";
const REPAIR_JOB_STATUS_FAILED: &str = "failed";

type RolloutWorkflow = WorkflowInstance<RolloutPlanRecord>;
type RepairJobWorkflow = WorkflowInstance<RepairJobRecord>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairJobDeadLetterTrackingMode {
    StrictOwnership,
    PreserveNewerClaims,
}

fn repair_job_status_is_completed(status: &str) -> bool {
    status
        .trim()
        .eq_ignore_ascii_case(REPAIR_JOB_STATUS_COMPLETED)
}

fn repair_job_status_is_pending_confirmation(status: &str) -> bool {
    status
        .trim()
        .eq_ignore_ascii_case(REPAIR_JOB_STATUS_PENDING_CONFIRMATION)
}

fn repair_job_status_is_failed(status: &str) -> bool {
    status.trim().eq_ignore_ascii_case(REPAIR_JOB_STATUS_FAILED)
}

fn repair_job_status_is_terminal(status: &str) -> bool {
    repair_job_status_is_completed(status) || repair_job_status_is_failed(status)
}

fn normalize_optional_detail(detail: Option<String>) -> Option<String> {
    detail
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

impl LifecycleService {
    /// Open lifecycle state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let platform_state_root = state_root.as_ref().to_path_buf();
        let root = platform_state_root.join("lifecycle");
        let service = Self {
            migrations: DocumentStore::open(root.join("migrations.json")).await?,
            governance_change_requests: DocumentStore::open(
                platform_state_root
                    .join("governance")
                    .join("change_requests.json"),
            )
            .await?,
            rollouts: DocumentStore::open(root.join("rollouts.json")).await?,
            rollout_workflows: WorkflowCollection::open_local(root.join("rollout_workflows.json"))
                .await?,
            maintenance: DocumentStore::open(root.join("maintenance.json")).await?,
            dead_letters: DocumentStore::open(root.join("dead_letters.json")).await?,
            repair_jobs: DocumentStore::open(root.join("repair_jobs.json")).await?,
            repair_job_workflows: WorkflowCollection::open_local(
                root.join("repair_job_workflows.json"),
            )
            .await?,
            plugins: DocumentStore::open(root.join("plugins.json")).await?,
            extension_subscriptions: DocumentStore::open(root.join("extension_subscriptions.json"))
                .await?,
            background_tasks: DocumentStore::open(root.join("background_tasks.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            platform_state_root: platform_state_root.clone(),
            state_root: root,
            migration_manifest_root: discover_migration_manifest_root(&platform_state_root),
        };
        service.reconcile_rollout_workflows().await?;
        service.reconcile_repair_job_workflows().await?;
        Ok(service)
    }

    async fn reconcile_rollout_workflows(&self) -> Result<()> {
        // `rollouts.json` is a derived projection once any durable rollout workflow exists.
        // Bootstrap from legacy projection metadata only for first-open upgrades.
        let has_authoritative_workflows = self
            .rollout_workflows
            .list()
            .await?
            .into_iter()
            .any(|(_, stored)| !stored.deleted);
        if !has_authoritative_workflows {
            let legacy_rollouts = self.rollouts.list().await?;
            for (key, stored) in legacy_rollouts {
                if stored.deleted {
                    continue;
                }

                let workflow = build_rollout_workflow(stored.value);
                if let Err(error) = self.rollout_workflows.create(&key, workflow).await
                    && error.code != ErrorCode::Conflict
                {
                    return Err(error);
                }
            }
        }

        let workflows = self.rollout_workflows.list().await?;
        for (key, stored) in workflows {
            if stored.deleted {
                continue;
            }

            let stored = self
                .reconcile_rollout_workflow_primitives(&key, stored)
                .await?;
            if stored.deleted {
                continue;
            }
            self.sync_rollout_projection(&stored.value).await?;
        }
        Ok(())
    }

    async fn reconcile_rollout_workflow_primitives(
        &self,
        key: &str,
        mut stored: StoredDocument<RolloutWorkflow>,
    ) -> Result<StoredDocument<RolloutWorkflow>> {
        loop {
            let mut workflow = stored.value.clone();
            let observed_at = OffsetDateTime::now_utc();
            if !apply_rollout_reconciliation_primitives(&mut workflow, observed_at)? {
                return Ok(stored);
            }

            match self
                .rollout_workflows
                .upsert(key, workflow, Some(stored.version))
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(error) if error.code == ErrorCode::Conflict => {
                    stored = self.rollout_workflows.get(key).await?.ok_or_else(|| {
                        PlatformError::not_found(
                            "rollout workflow disappeared during reconciliation",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn load_rollout_workflow(
        &self,
        rollout_id: &RolloutPlanId,
    ) -> Result<StoredDocument<RolloutWorkflow>> {
        self.rollout_workflows
            .get(rollout_id.as_str())
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("rollout plan does not exist").with_detail(
                    "rollout workflows are authoritative; projection metadata alone is ignored",
                )
            })
    }

    async fn sync_rollout_projection(&self, workflow: &RolloutWorkflow) -> Result<()> {
        let rollout = workflow.state.clone();
        let rollout_id = rollout.id.to_string();
        loop {
            match self.rollouts.get(&rollout_id).await? {
                Some(existing) if !existing.deleted && existing.value == rollout => return Ok(()),
                Some(existing) => {
                    match self
                        .rollouts
                        .upsert(&rollout_id, rollout.clone(), Some(existing.version))
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self.rollouts.create(&rollout_id, rollout.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                },
            }
        }
    }

    async fn reconcile_repair_job_workflows(&self) -> Result<()> {
        let has_authoritative_workflows = self
            .repair_job_workflows
            .list()
            .await?
            .into_iter()
            .any(|(_, stored)| !stored.deleted);
        if !has_authoritative_workflows {
            let legacy_repair_jobs = self.repair_jobs.list().await?;
            for (key, stored) in legacy_repair_jobs {
                if stored.deleted {
                    continue;
                }

                let workflow = build_repair_job_workflow(stored.value);
                if let Err(error) = self.repair_job_workflows.create(&key, workflow).await
                    && error.code != ErrorCode::Conflict
                {
                    return Err(error);
                }
            }
        }

        let workflows = self.repair_job_workflows.list().await?;
        for (key, stored) in workflows {
            if stored.deleted {
                continue;
            }

            let stored = self
                .reconcile_repair_job_workflow_primitives(&key, stored)
                .await?;
            if stored.deleted {
                continue;
            }
            self.reconcile_repair_job_dead_letters(&stored.value.state)
                .await?;
            self.sync_repair_job_projection(&stored.value).await?;
        }
        Ok(())
    }

    async fn reconcile_repair_job_workflow_primitives(
        &self,
        key: &str,
        mut stored: StoredDocument<RepairJobWorkflow>,
    ) -> Result<StoredDocument<RepairJobWorkflow>> {
        loop {
            let mut workflow = stored.value.clone();
            if !apply_repair_job_reconciliation_primitives(&mut workflow) {
                return Ok(stored);
            }

            match self
                .repair_job_workflows
                .upsert(key, workflow, Some(stored.version))
                .await
            {
                Ok(updated) => return Ok(updated),
                Err(error) if error.code == ErrorCode::Conflict => {
                    stored = self.repair_job_workflows.get(key).await?.ok_or_else(|| {
                        PlatformError::not_found(
                            "repair job workflow disappeared during reconciliation",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn sync_repair_job_projection(&self, workflow: &RepairJobWorkflow) -> Result<()> {
        let repair_job = workflow.state.clone();
        let repair_job_id = repair_job.id.to_string();
        loop {
            match self.repair_jobs.get(&repair_job_id).await? {
                Some(existing) if !existing.deleted && existing.value == repair_job => {
                    return Ok(());
                }
                Some(existing) => {
                    match self
                        .repair_jobs
                        .upsert(&repair_job_id, repair_job.clone(), Some(existing.version))
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self
                    .repair_jobs
                    .create(&repair_job_id, repair_job.clone())
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                },
            }
        }
    }

    async fn load_repair_job_workflow(
        &self,
        repair_job_id: &RepairJobId,
    ) -> Result<StoredDocument<RepairJobWorkflow>> {
        self.repair_job_workflows
            .get(repair_job_id.as_str())
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("repair job does not exist").with_detail(
                    "repair job workflows are authoritative; projection metadata alone is ignored",
                )
            })
    }

    async fn list_repair_job_states(&self) -> Result<Vec<RepairJobRecord>> {
        Ok(self
            .repair_job_workflows
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.state)
            .collect::<Vec<_>>())
    }

    async fn reconcile_repair_job_dead_letters(&self, repair_job: &RepairJobRecord) -> Result<()> {
        let tracking_mode = if repair_job_status_is_terminal(&repair_job.status) {
            RepairJobDeadLetterTrackingMode::PreserveNewerClaims
        } else {
            RepairJobDeadLetterTrackingMode::StrictOwnership
        };
        let tracked_dead_letters = self
            .tracked_dead_letters_for_job(repair_job, tracking_mode)
            .await?;
        for (key, stored) in tracked_dead_letters {
            let mut dead_letter = stored.value.clone();
            let changed = if repair_job_status_is_completed(&repair_job.status) {
                apply_completed_repair_job_dead_letter_state(&mut dead_letter, repair_job)
            } else if repair_job_status_is_failed(&repair_job.status) {
                apply_failed_repair_job_dead_letter_state(&mut dead_letter)
            } else {
                apply_pending_repair_job_dead_letter_state(&mut dead_letter, repair_job)
            };
            if changed {
                self.dead_letters
                    .upsert(&key, dead_letter, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    fn load_verified_migration_manifests(&self) -> Result<Vec<MigrationManifest>> {
        let manifest_root = self.migration_manifest_root.as_ref().ok_or_else(|| {
            PlatformError::not_found("migration manifest root not found")
                .with_detail(self.platform_state_root.display().to_string())
        })?;
        let manifests = load_migration_manifests(manifest_root)?;
        validate_migration_manifest_chain(&manifests)?;
        Ok(manifests)
    }

    fn resolve_migration_manifest(
        &self,
        request: &CreateMigrationRequest,
    ) -> Result<MigrationManifest> {
        let manifests = self.load_verified_migration_manifests()?;
        let manifest = find_migration_manifest(
            &manifests,
            request.scope.trim(),
            request.from_version,
            request.to_version,
            request.name.trim(),
        )
        .cloned()
        .ok_or_else(|| {
            PlatformError::not_found("migration manifest does not exist").with_detail(format!(
                "{}:{}->{}:{}",
                request.scope.trim(),
                request.from_version,
                request.to_version,
                request.name.trim()
            ))
        })?;

        if request.checksum != manifest.checksum {
            return Err(PlatformError::conflict(
                "migration checksum does not match canonical manifest",
            )
            .with_detail(manifest.source.display().to_string()));
        }

        if let Some(requested_days) = request.compatibility_window_days
            && Some(requested_days) != manifest.compatibility_window_days
        {
            return Err(PlatformError::conflict(
                "compatibility_window_days does not match canonical manifest",
            )
            .with_detail(manifest.source.display().to_string()));
        }

        Ok(manifest)
    }

    async fn materialize_manifest_transform(
        &self,
        scope: &MigrationScope,
        manifest: &MigrationManifest,
    ) -> Result<bool> {
        let current_version = self.current_scope_version(scope).await?;
        if current_version == manifest.to_version {
            return Ok(false);
        }
        if current_version != manifest.from_version {
            return Err(PlatformError::conflict(
                "migration chain violation: requested step is not next",
            )
            .with_detail(format!(
                "scope {} is currently at version {}, but {} expects {}",
                scope_key(scope),
                current_version,
                manifest.name,
                manifest.from_version
            )));
        }

        self.apply_manifest_transform(manifest).await?;
        self.refresh_transform_touched_store_caches(manifest)
            .await?;
        Ok(true)
    }

    async fn current_scope_version(&self, scope: &MigrationScope) -> Result<u32> {
        match scope {
            MigrationScope::Schema => self.current_schema_version().await,
            MigrationScope::Config => self.current_config_version().await,
        }
    }

    async fn current_schema_version(&self) -> Result<u32> {
        read_json_collection_schema_version(&self.state_root.join("migrations.json")).await
    }

    async fn current_config_version(&self) -> Result<u32> {
        let config_files = self.matching_config_files().await?;
        if config_files.is_empty() {
            return Err(PlatformError::not_found(
                "no runtime config matched the current state directory",
            )
            .with_detail(self.platform_state_root.display().to_string()));
        }

        let mut versions = BTreeSet::new();
        let mut matched_paths = Vec::new();
        for path in config_files {
            let raw = fs::read_to_string(&path).await.map_err(|error| {
                PlatformError::unavailable("failed to read runtime config file")
                    .with_detail(format!("{}: {}", path.display(), error))
            })?;
            let value: toml::Value =
                toml::from_str(&raw).map_err(|error| {
                    PlatformError::invalid("failed to parse runtime config file")
                        .with_detail(format!("{}: {}", path.display(), error))
                })?;
            let version = value
                .get("schema")
                .and_then(|schema| schema.get("schema_version"))
                .and_then(toml::Value::as_integer)
                .and_then(|version| u32::try_from(version).ok())
                .ok_or_else(|| {
                    PlatformError::invalid("runtime config is missing schema.schema_version")
                        .with_detail(path.display().to_string())
                })?;
            versions.insert(version);
            matched_paths.push(path.display().to_string());
        }

        if versions.len() != 1 {
            return Err(PlatformError::conflict(
                "matched runtime config files do not agree on schema version",
            )
            .with_detail(matched_paths.join(", ")));
        }

        versions
            .into_iter()
            .next()
            .ok_or_else(|| PlatformError::invalid("no config schema versions were discovered"))
    }

    async fn matching_config_files(&self) -> Result<Vec<PathBuf>> {
        let expected_state_root = match fs::canonicalize(&self.platform_state_root).await {
            Ok(path) => path,
            Err(_) => self.platform_state_root.clone(),
        };
        let current_dir = std::env::current_dir().ok();
        let mut matches = BTreeSet::new();
        for root in workspace_root_candidates(&self.platform_state_root) {
            let config_root = root.join("configs");
            if !config_root.is_dir() {
                continue;
            }

            let mut files = Vec::new();
            collect_named_files(&config_root, "all-in-one.toml", &mut files)?;
            for file in files {
                if config_targets_state_root(&file, &expected_state_root, current_dir.as_deref())
                    .await?
                {
                    matches.insert(file);
                }
            }
        }

        Ok(matches.into_iter().collect::<Vec<_>>())
    }

    async fn apply_manifest_transform(&self, manifest: &MigrationManifest) -> Result<()> {
        let target_version = u16::try_from(manifest.to_version).map_err(|error| {
            PlatformError::invalid("migration target version exceeds store schema range")
                .with_detail(error.to_string())
        })?;

        match (manifest.scope.as_str(), manifest.name.as_str()) {
            ("schema", "lifecycle_extension_registry") => {
                for relative_path in [
                    "lifecycle/migrations.json",
                    "lifecycle/plugins.json",
                    "lifecycle/extension_subscriptions.json",
                    "lifecycle/background_tasks.json",
                ] {
                    set_json_collection_schema_version(
                        &self.platform_state_root.join(relative_path),
                        target_version,
                    )
                    .await?;
                }
                Ok(())
            }
            ("schema", "governance_audit_chain") => {
                for relative_path in [
                    "lifecycle/migrations.json",
                    "governance/change_approvals.json",
                    "governance/audit_checkpoints.json",
                    "governance/audit_chain_head.json",
                ] {
                    set_json_collection_schema_version(
                        &self.platform_state_root.join(relative_path),
                        target_version,
                    )
                    .await?;
                }
                Ok(())
            }
            ("config", "observe_otlp_defaults") => {
                self.apply_observe_otlp_defaults_transform(manifest).await
            }
            _ => Err(
                PlatformError::not_found("migration transform is not implemented").with_detail(
                    format!(
                        "{}:{}->{}:{}",
                        manifest.scope, manifest.from_version, manifest.to_version, manifest.name
                    ),
                ),
            ),
        }
    }

    async fn refresh_transform_touched_store_caches(
        &self,
        manifest: &MigrationManifest,
    ) -> Result<()> {
        match (manifest.scope.as_str(), manifest.name.as_str()) {
            ("schema", "lifecycle_extension_registry") => {
                self.migrations.reload_from_disk().await?;
                self.plugins.reload_from_disk().await?;
                self.extension_subscriptions.reload_from_disk().await?;
                self.background_tasks.reload_from_disk().await?;
            }
            ("schema", "governance_audit_chain") => {
                self.migrations.reload_from_disk().await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn apply_observe_otlp_defaults_transform(
        &self,
        manifest: &MigrationManifest,
    ) -> Result<()> {
        let add_signal_defaults = manifest
            .changes
            .get("add_signal_defaults")
            .and_then(toml::Value::as_bool)
            .ok_or_else(|| {
                PlatformError::invalid("config migration manifest is missing add_signal_defaults")
                    .with_detail(manifest.source.display().to_string())
            })?;
        let default_retry_policy = manifest
            .changes
            .get("default_retry_policy")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                PlatformError::invalid("config migration manifest is missing default_retry_policy")
                    .with_detail(manifest.source.display().to_string())
            })?;

        let config_files = self.matching_config_files().await?;
        if config_files.is_empty() {
            return Err(PlatformError::not_found(
                "no runtime config matched the current state directory",
            )
            .with_detail(self.platform_state_root.display().to_string()));
        }

        for path in config_files {
            let raw = fs::read_to_string(&path).await.map_err(|error| {
                PlatformError::unavailable("failed to read runtime config file")
                    .with_detail(format!("{}: {}", path.display(), error))
            })?;
            let mut value: toml::Value =
                toml::from_str(&raw).map_err(|error| {
                    PlatformError::invalid("failed to parse runtime config file")
                        .with_detail(format!("{}: {}", path.display(), error))
                })?;

            let root = value.as_table_mut().ok_or_else(|| {
                PlatformError::invalid("runtime config root must be a table")
                    .with_detail(path.display().to_string())
            })?;
            let schema = root
                .entry(String::from("schema"))
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
            let schema_table = schema.as_table_mut().ok_or_else(|| {
                PlatformError::invalid("runtime config schema section must be a table")
                    .with_detail(path.display().to_string())
            })?;
            schema_table.insert(
                String::from("schema_version"),
                toml::Value::Integer(i64::from(manifest.to_version)),
            );

            let observe = root
                .entry(String::from("observe"))
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
            let observe_table = observe.as_table_mut().ok_or_else(|| {
                PlatformError::invalid("runtime config observe section must be a table")
                    .with_detail(path.display().to_string())
            })?;
            let otlp = observe_table
                .entry(String::from("otlp"))
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
            let otlp_table = otlp.as_table_mut().ok_or_else(|| {
                PlatformError::invalid("runtime config observe.otlp section must be a table")
                    .with_detail(path.display().to_string())
            })?;
            otlp_table.insert(
                String::from("add_signal_defaults"),
                toml::Value::Boolean(add_signal_defaults),
            );
            otlp_table.insert(
                String::from("default_retry_policy"),
                toml::Value::String(default_retry_policy.clone()),
            );

            let rendered = toml::to_string_pretty(&value).map_err(|error| {
                PlatformError::invalid("failed to render migrated runtime config")
                    .with_detail(format!("{}: {}", path.display(), error))
            })?;
            fs::write(&path, rendered).await.map_err(|error| {
                PlatformError::unavailable("failed to write migrated runtime config")
                    .with_detail(format!("{}: {}", path.display(), error))
            })?;
        }

        Ok(())
    }

    async fn record_migration(
        &self,
        request: CreateMigrationRequest,
        context: &RequestContext,
        apply: bool,
    ) -> Result<Response<ApiBody>> {
        let now = OffsetDateTime::now_utc();
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        if request.to_version <= request.from_version {
            return Err(PlatformError::invalid(
                "to_version must be greater than from_version",
            ));
        }
        if request.checksum.trim().is_empty() {
            return Err(PlatformError::invalid("checksum may not be empty"));
        }
        let change_request_id = if apply {
            let raw = request.change_request_id.as_deref().ok_or_else(|| {
                PlatformError::conflict("change_request_id is required when applying migrations")
            })?;
            Some(self.validate_governance_gate(raw, true).await?)
        } else {
            if let Some(raw) = request.change_request_id.as_deref() {
                Some(self.validate_governance_gate(raw, false).await?)
            } else {
                None
            }
        };
        let manifest = self.resolve_migration_manifest(&request)?;
        let scope = parse_scope(&manifest.scope)?;
        let scope_name = scope_key(&scope);
        let compatibility_window_until = manifest
            .compatibility_window_days
            .filter(|days| *days > 0)
            .map(|days| now + Duration::days(i64::from(days)));

        let existing = self
            .migrations
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .filter(|(_, stored)| scope_key(&stored.value.scope) == scope_name)
            .collect::<Vec<_>>();

        if let Some((key, stored)) = existing.iter().find(|(_, stored)| {
            stored.value.to_version == manifest.to_version
                && stored.value.checksum == manifest.checksum
        }) {
            let found = &stored.value;
            if found.from_version != manifest.from_version || found.name != manifest.name {
                return Err(PlatformError::conflict(
                    "migration target version already exists with different definition",
                ));
            }
            if apply {
                let _ = self
                    .materialize_manifest_transform(&scope, &manifest)
                    .await?;
                if found.state != MigrationState::Applied {
                    let mut applied = found.clone();
                    applied.state = MigrationState::Applied;
                    applied.applied_at = Some(now);
                    applied.compatibility_window_until = compatibility_window_until;
                    self.migrations
                        .upsert(key, applied.clone(), Some(stored.version))
                        .await?;
                    self.append_event(
                        "lifecycle.migration.applied.v1",
                        "migration",
                        applied.id.as_str(),
                        "applied",
                        serde_json::json!({
                            "scope": scope_name,
                            "from_version": applied.from_version,
                            "to_version": applied.to_version,
                            "change_request_id": change_request_id.map(|id| id.to_string()),
                        }),
                        context,
                    )
                    .await?;
                    return json_response(StatusCode::OK, &applied);
                }
                return json_response(StatusCode::OK, found);
            }
            return json_response(StatusCode::OK, found);
        }

        if existing.iter().any(|(_, stored)| {
            stored.value.to_version == manifest.to_version
                && stored.value.checksum != manifest.checksum
        }) {
            return Err(PlatformError::conflict(
                "migration target version already exists with different checksum",
            ));
        }

        if existing.iter().any(|(_, stored)| {
            stored.value.state == MigrationState::Applied
                && stored.value.to_version > manifest.from_version
        }) {
            return Err(PlatformError::conflict(
                "migration ordering violation: from_version is behind applied history",
            ));
        }

        if apply {
            let _ = self
                .materialize_manifest_transform(&scope, &manifest)
                .await?;
        }

        let id = MigrationJobId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate migration id")
                .with_detail(error.to_string())
        })?;
        let applied_at = apply.then_some(now);
        let record = MigrationRecord {
            id: id.clone(),
            scope,
            from_version: manifest.from_version,
            to_version: manifest.to_version,
            name: manifest.name,
            checksum: manifest.checksum,
            state: if apply {
                MigrationState::Applied
            } else {
                MigrationState::Pending
            },
            applied_at,
            compatibility_window_until,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.migrations.create(id.as_str(), record.clone()).await?;
        self.append_event(
            if apply {
                "lifecycle.migration.applied.v1"
            } else {
                "lifecycle.migration.recorded.v1"
            },
            "migration",
            id.as_str(),
            if apply { "applied" } else { "recorded" },
            serde_json::json!({
                "scope": scope_name,
                "from_version": record.from_version,
                "to_version": record.to_version,
                "change_request_id": change_request_id.map(|id| id.to_string()),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_rollout_plan(
        &self,
        request: CreateRolloutRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.service.trim().is_empty() {
            return Err(PlatformError::invalid("service may not be empty"));
        }
        if request.compatibility_window_days == 0 {
            return Err(PlatformError::invalid(
                "compatibility_window_days must be greater than zero",
            ));
        }
        validate_canary_steps(&request.canary_steps)?;
        let channel = normalize_rollout_channel(&request.channel)?;

        let id = RolloutPlanId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate rollout plan id")
                .with_detail(error.to_string())
        })?;
        let record = RolloutPlanRecord {
            id: id.clone(),
            service: request.service,
            channel,
            canary_steps: request.canary_steps,
            compatibility_window_days: request.compatibility_window_days,
            phase: String::from("planned"),
            current_step_index: 0,
            current_traffic_percent: 0,
            status_reason: None,
            last_mutation_kind: None,
            last_mutation_idempotency_key: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let workflow = build_rollout_workflow(record.clone());
        self.rollout_workflows
            .create(id.as_str(), workflow.clone())
            .await?;
        self.sync_rollout_projection(&workflow).await?;
        self.append_event(
            "lifecycle.rollout.created.v1",
            "rollout_plan",
            id.as_str(),
            "created",
            serde_json::json!({
                "service": record.service,
                "channel": record.channel,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn set_maintenance(
        &self,
        request: SetMaintenanceRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let service = request.service.trim().to_ascii_lowercase();
        if service.is_empty() {
            return Err(PlatformError::invalid("service may not be empty"));
        }
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let change_request_id = request.change_request_id.as_deref().ok_or_else(|| {
            PlatformError::conflict("change_request_id is required for maintenance mutations")
        })?;
        let change_request_id = self
            .validate_governance_gate(change_request_id, true)
            .await?;
        let existing = self.maintenance.get(&service).await?;
        let record = MaintenanceRecord {
            service: service.clone(),
            enabled: request.enabled,
            reason: request.reason,
            updated_at: OffsetDateTime::now_utc(),
        };
        self.maintenance
            .upsert(
                &service,
                record.clone(),
                existing.map(|stored| stored.version),
            )
            .await?;
        self.append_event(
            "lifecycle.maintenance.updated.v1",
            "maintenance",
            &service,
            "updated",
            serde_json::json!({
                "enabled": record.enabled,
                "change_request_id": change_request_id,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn mutate_rollout_plan(
        &self,
        rollout_id: &str,
        request: RolloutActionRequest,
        mutation: RolloutMutationKind,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let RolloutActionRequest {
            reason,
            idempotency_key,
        } = request;
        let normalized_reason = normalize_optional_reason(reason.clone())?;
        let rollout_id = RolloutPlanId::parse(rollout_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid rollout plan id").with_detail(error.to_string())
        })?;
        let stored = self.load_rollout_workflow(&rollout_id).await?;
        let mut workflow = stored.value;
        let mut rollout = workflow.state.clone();
        let previous_phase = rollout.phase.clone();
        let idempotency_key = normalize_optional_idempotency_key(idempotency_key)?;
        if let Some(key) = idempotency_key.as_deref()
            && rollout.last_mutation_kind.as_deref() == Some(mutation.action())
            && rollout.last_mutation_idempotency_key.as_deref() == Some(key)
        {
            return json_response(StatusCode::OK, &rollout);
        }

        match mutation {
            RolloutMutationKind::Start => {
                if rollout.phase != "planned" {
                    return Err(PlatformError::conflict(
                        "rollout start requires phase=planned",
                    ));
                }
                rollout.phase = String::from("in_progress");
                rollout.current_step_index = 0;
                rollout.current_traffic_percent = rollout.canary_steps[0];
                rollout.status_reason = normalized_reason.clone();
            }
            RolloutMutationKind::Advance => {
                if rollout.phase == "completed" {
                    return json_response(StatusCode::OK, &rollout);
                }
                if rollout.phase != "in_progress" {
                    return Err(PlatformError::conflict(
                        "rollout advance requires phase=in_progress",
                    ));
                }
                let next_step = rollout.current_step_index.saturating_add(1);
                if next_step >= rollout.canary_steps.len() {
                    rollout.current_step_index = rollout.canary_steps.len().saturating_sub(1);
                    rollout.current_traffic_percent = 100;
                    rollout.phase = String::from("completed");
                    rollout.status_reason = normalized_reason.clone();
                } else {
                    rollout.current_step_index = next_step;
                    rollout.current_traffic_percent = rollout.canary_steps[next_step];
                    if rollout.current_traffic_percent == 100 {
                        rollout.phase = String::from("completed");
                    }
                    rollout.status_reason = normalized_reason.clone();
                }
            }
            RolloutMutationKind::Pause => {
                if rollout.phase != "in_progress" {
                    return Err(PlatformError::conflict(
                        "rollout pause requires phase=in_progress",
                    ));
                }
                rollout.phase = String::from("paused");
                rollout.status_reason = normalized_reason.clone();
            }
            RolloutMutationKind::Resume => {
                if rollout.phase != "paused" {
                    return Err(PlatformError::conflict(
                        "rollout resume requires phase=paused",
                    ));
                }
                rollout.phase = String::from("in_progress");
                rollout.status_reason = normalized_reason.clone();
            }
            RolloutMutationKind::Rollback => {
                if !matches!(rollout.phase.as_str(), "planned" | "in_progress" | "paused") {
                    return Err(PlatformError::conflict(
                        "rollout rollback is allowed only for planned/in_progress/paused phases",
                    ));
                }
                let reason = reason
                    .ok_or_else(|| PlatformError::invalid("rollback requires non-empty reason"))?;
                if reason.trim().is_empty() {
                    return Err(PlatformError::invalid("rollback requires non-empty reason"));
                }
                rollout.phase = String::from("rolled_back");
                rollout.current_step_index = 0;
                rollout.current_traffic_percent = 0;
                rollout.status_reason = Some(reason.trim().to_owned());
            }
        }

        rollout.last_mutation_kind = Some(mutation.action().to_owned());
        rollout.last_mutation_idempotency_key = idempotency_key;
        rollout
            .metadata
            .touch(sha256_hex(rollout.id.as_str().as_bytes()));
        apply_rollout_mutation_to_workflow(&mut workflow, &rollout, mutation);
        workflow.state = rollout.clone();
        self.rollout_workflows
            .upsert(rollout.id.as_str(), workflow.clone(), Some(stored.version))
            .await?;
        self.sync_rollout_projection(&workflow).await?;
        self.append_event(
            mutation.event_type(),
            "rollout_plan",
            rollout.id.as_str(),
            mutation.action(),
            serde_json::json!({
                "service": rollout.service,
                "channel": rollout.channel,
                "from_phase": previous_phase,
                "to_phase": rollout.phase,
                "current_step_index": rollout.current_step_index,
                "current_traffic_percent": rollout.current_traffic_percent,
                "reason": rollout.status_reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &rollout)
    }

    async fn create_dead_letter(
        &self,
        request: CreateDeadLetterRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.topic.trim().is_empty() || request.error.trim().is_empty() {
            return Err(PlatformError::invalid("topic and error may not be empty"));
        }

        let id = DeadLetterId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate dead letter id")
                .with_detail(error.to_string())
        })?;
        let record = DeadLetterRecord {
            id: id.clone(),
            topic: request.topic,
            payload: request.payload,
            error: request.error,
            attempts: request.attempts.max(1),
            replayed: false,
            repair_job_id: None,
            created_at: OffsetDateTime::now_utc(),
            repair_requested_at: None,
            replayed_at: None,
        };
        self.dead_letters
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "lifecycle.dead_letter.recorded.v1",
            "dead_letter",
            id.as_str(),
            "recorded",
            serde_json::json!({ "topic": record.topic }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn active_repair_target_ids(&self) -> Result<BTreeSet<String>> {
        let mut targeted = BTreeSet::new();
        for repair_job in self.list_repair_job_states().await? {
            if repair_job_status_is_terminal(&repair_job.status) {
                continue;
            }
            for dead_letter_id in &repair_job.dead_letter_ids {
                let _ = targeted.insert(dead_letter_id.to_string());
            }
        }
        Ok(targeted)
    }

    async fn tracked_dead_letters_for_job(
        &self,
        repair_job: &RepairJobRecord,
        mode: RepairJobDeadLetterTrackingMode,
    ) -> Result<Vec<(String, StoredDocument<DeadLetterRecord>)>> {
        let targeted_ids = repair_job
            .dead_letter_ids
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut tracked = Vec::new();
        let mut observed_targeted_ids = BTreeSet::new();
        let mut conflicting_claims = Vec::new();
        for (key, stored) in self.dead_letters.list().await? {
            if stored.deleted {
                continue;
            }

            let dead_letter_id = stored.value.id.to_string();
            let is_targeted = targeted_ids.contains(dead_letter_id.as_str());
            let claimed_by_this_job = stored
                .value
                .repair_job_id
                .as_ref()
                .is_some_and(|repair_job_id| repair_job_id == &repair_job.id);
            let conflicting_owner = stored
                .value
                .repair_job_id
                .as_ref()
                .filter(|repair_job_id| *repair_job_id != &repair_job.id)
                .cloned();

            if !is_targeted && !claimed_by_this_job {
                continue;
            }

            if is_targeted {
                let _ = observed_targeted_ids.insert(dead_letter_id);
            }

            if is_targeted && let Some(owner) = conflicting_owner {
                match mode {
                    RepairJobDeadLetterTrackingMode::StrictOwnership => {
                        conflicting_claims.push(format!(
                            "{} is already claimed by {}",
                            stored.value.id, owner
                        ));
                    }
                    RepairJobDeadLetterTrackingMode::PreserveNewerClaims => {}
                }
                continue;
            }

            tracked.push((key, stored));
        }
        tracked.sort_by_key(|(_, stored)| stored.value.created_at);

        if !conflicting_claims.is_empty() {
            return Err(PlatformError::conflict(
                "repair job target is already claimed by another job",
            )
            .with_detail(conflicting_claims.join(", ")));
        }

        let missing_targeted_ids = targeted_ids
            .difference(&observed_targeted_ids)
            .cloned()
            .collect::<Vec<_>>();
        if !missing_targeted_ids.is_empty() {
            return Err(PlatformError::conflict(
                "repair job lost one or more targeted dead letters",
            )
            .with_detail(missing_targeted_ids.join(", ")));
        }

        Ok(tracked)
    }

    async fn replay_dead_letters(
        &self,
        request: ReplayDeadLetterRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.reconcile_repair_job_workflows().await?;
        let limit = request.limit.unwrap_or(100).clamp(1, 10_000);
        let active_targets = self.active_repair_target_ids().await?;
        let mut candidates = self
            .dead_letters
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| {
                !stored.deleted
                    && !stored.value.replayed
                    && !active_targets.contains(stored.value.id.as_str())
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(_, stored)| stored.value.created_at);
        if candidates.len() > limit {
            candidates.truncate(limit);
        }

        let job_id = RepairJobId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate repair job id")
                .with_detail(error.to_string())
        })?;
        let now = OffsetDateTime::now_utc();
        let dead_letter_ids = candidates
            .iter()
            .map(|(_, stored)| stored.value.id.clone())
            .collect::<Vec<_>>();
        let completed_immediately = dead_letter_ids.is_empty();
        let mut job = RepairJobRecord {
            id: job_id.clone(),
            job_type: String::from(REPAIR_JOB_TYPE_DEAD_LETTER_REPLAY),
            status: String::from(if completed_immediately {
                REPAIR_JOB_STATUS_COMPLETED
            } else {
                REPAIR_JOB_STATUS_PENDING_CONFIRMATION
            }),
            scanned: candidates.len() as u64,
            replayed: 0,
            failed: 0,
            dead_letter_ids: dead_letter_ids.clone(),
            created_at: now,
            completed_at: completed_immediately.then_some(now),
            confirmation_detail: None,
            confirmed_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(job_id.to_string()),
                String::new(),
            ),
        };
        job.metadata.touch(repair_job_etag(&job));
        let workflow = build_repair_job_workflow(job.clone());
        let stored_workflow = self
            .repair_job_workflows
            .create(job_id.as_str(), workflow)
            .await?;
        self.reconcile_repair_job_dead_letters(&stored_workflow.value.state)
            .await?;
        self.sync_repair_job_projection(&stored_workflow.value)
            .await?;

        if completed_immediately {
            self.append_event(
                "lifecycle.repair.completed.v1",
                "repair_job",
                job_id.as_str(),
                "completed",
                serde_json::json!({
                    "scanned": job.scanned,
                    "replayed": job.replayed,
                    "detail": "no eligible dead letters remained",
                }),
                context,
            )
            .await?;
        } else {
            self.append_event(
                "lifecycle.repair.queued.v1",
                "repair_job",
                job_id.as_str(),
                "queued",
                serde_json::json!({
                    "scanned": job.scanned,
                    "dead_letter_ids": dead_letter_ids,
                }),
                context,
            )
            .await?;
        }
        json_response(StatusCode::OK, &job)
    }

    async fn confirm_repair_job(
        &self,
        repair_job_id: &str,
        request: ConfirmRepairJobRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.reconcile_repair_job_workflows().await?;
        let repair_job_id = RepairJobId::parse(repair_job_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid repair_job_id").with_detail(error.to_string())
        })?;
        let stored_workflow = self.load_repair_job_workflow(&repair_job_id).await?;
        let mut job = stored_workflow.value.state;
        if repair_job_status_is_terminal(&job.status) {
            let confirmed_success = repair_job_status_is_completed(&job.status);
            if confirmed_success == request.success {
                return json_response(StatusCode::OK, &job);
            }
            return Err(PlatformError::conflict(
                "repair job already has a different terminal outcome",
            ));
        }

        let tracked_dead_letters = self
            .tracked_dead_letters_for_job(&job, RepairJobDeadLetterTrackingMode::StrictOwnership)
            .await?;
        if job.scanned > 0 && tracked_dead_letters.is_empty() {
            return Err(PlatformError::conflict(
                "repair job has no tracked dead letters to confirm",
            ));
        }

        let now = OffsetDateTime::now_utc();
        let detail = normalize_optional_detail(request.detail);
        let mut affected = 0_u64;
        for (key, stored) in tracked_dead_letters {
            let mut dead_letter = stored.value;
            if request.success {
                dead_letter.replayed = true;
                dead_letter.replayed_at = Some(now);
                dead_letter.repair_job_id = Some(job.id.clone());
                dead_letter.repair_requested_at =
                    Some(dead_letter.repair_requested_at.unwrap_or(now));
            } else {
                dead_letter.repair_job_id = None;
                dead_letter.repair_requested_at = None;
            }
            self.dead_letters
                .upsert(&key, dead_letter, Some(stored.version))
                .await?;
            affected = affected.saturating_add(1);
        }

        if request.success {
            job.status = String::from(REPAIR_JOB_STATUS_COMPLETED);
            job.replayed = affected;
            job.failed = 0;
        } else {
            job.status = String::from(REPAIR_JOB_STATUS_FAILED);
            job.replayed = 0;
            job.failed = affected;
        }
        job.completed_at = Some(now);
        job.confirmation_detail = detail.clone();
        job.confirmed_at = Some(now);
        job.metadata.touch(repair_job_etag(&job));
        let updated_workflow = self
            .repair_job_workflows
            .mutate(job.id.as_str(), |workflow| {
                workflow.state = job.clone();
                let _ = apply_repair_job_reconciliation_primitives(workflow);
                Ok(())
            })
            .await?;
        self.sync_repair_job_projection(&updated_workflow.value)
            .await?;
        let updated_job = updated_workflow.value.state;
        if request.success {
            self.append_event(
                "lifecycle.repair.completed.v1",
                "repair_job",
                updated_job.id.as_str(),
                "completed",
                serde_json::json!({
                    "scanned": updated_job.scanned,
                    "replayed": updated_job.replayed,
                    "detail": detail,
                }),
                context,
            )
            .await?;
        } else {
            self.append_event(
                "lifecycle.repair.failed.v1",
                "repair_job",
                updated_job.id.as_str(),
                "failed",
                serde_json::json!({
                    "scanned": updated_job.scanned,
                    "failed": updated_job.failed,
                    "detail": detail,
                }),
                context,
            )
            .await?;
        }
        json_response(StatusCode::OK, &updated_job)
    }

    async fn register_plugin(
        &self,
        request: RegisterPluginRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.name.trim().is_empty() || request.version.trim().is_empty() {
            return Err(PlatformError::invalid("name and version may not be empty"));
        }
        let plugin_id = PluginId::parse(request.plugin_id).map_err(|error| {
            PlatformError::invalid("invalid plugin_id").with_detail(error.to_string())
        })?;
        let manifest = uhost_core::PluginManifest {
            plugin_id: plugin_id.to_string(),
            name: request.name.clone(),
            version: request.version.clone(),
            min_api_version: request.min_api_version,
            max_api_version: request.max_api_version,
            subscriptions: Vec::<EventSubscription>::new(),
            background_tasks: Vec::<BackgroundTaskContract>::new(),
        };
        if !validate_manifest_against_policy(&manifest, &extension_policy()) {
            return Err(PlatformError::conflict(
                "plugin manifest is outside the supported compatibility window",
            ));
        }

        let key = plugin_id.to_string();
        let existing = self.plugins.get(&key).await?;
        let record = PluginRecord {
            id: plugin_id,
            name: request.name,
            version: request.version,
            min_api_version: request.min_api_version,
            max_api_version: request.max_api_version,
            enabled: true,
            metadata: existing
                .as_ref()
                .map(|stored| {
                    let mut metadata = stored.value.metadata.clone();
                    metadata.touch(sha256_hex(key.as_bytes()));
                    metadata
                })
                .unwrap_or_else(|| {
                    ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(key.clone()),
                        sha256_hex(key.as_bytes()),
                    )
                }),
        };
        self.plugins
            .upsert(&key, record.clone(), existing.map(|stored| stored.version))
            .await?;
        self.append_event(
            "lifecycle.extension.plugin.registered.v1",
            "plugin",
            &key,
            "registered",
            serde_json::json!({
                "version": record.version,
                "min_api_version": record.min_api_version,
                "max_api_version": record.max_api_version,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn register_event_subscription(
        &self,
        request: RegisterSubscriptionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.topic.trim().is_empty() {
            return Err(PlatformError::invalid("topic may not be empty"));
        }
        let plugin_id = PluginId::parse(request.plugin_id).map_err(|error| {
            PlatformError::invalid("invalid plugin_id").with_detail(error.to_string())
        })?;
        let _ = self
            .plugins
            .get(plugin_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("plugin does not exist"))?;
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate subscription id")
                .with_detail(error.to_string())
        })?;
        let delivery_mode = parse_delivery_mode(&request.delivery_mode)?;
        let record = ExtensionSubscriptionRecord {
            id: id.clone(),
            plugin_id,
            topic: request.topic,
            delivery_mode,
            retries_enabled: request.retries_enabled,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.extension_subscriptions
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "lifecycle.extension.subscription.registered.v1",
            "extension_subscription",
            id.as_str(),
            "registered",
            serde_json::json!({
                "topic": record.topic,
                "delivery_mode": record.delivery_mode,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn register_background_task(
        &self,
        request: RegisterBackgroundTaskRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.task.trim().is_empty() {
            return Err(PlatformError::invalid("task may not be empty"));
        }
        let plugin_id = PluginId::parse(request.plugin_id).map_err(|error| {
            PlatformError::invalid("invalid plugin_id").with_detail(error.to_string())
        })?;
        let _ = self
            .plugins
            .get(plugin_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("plugin does not exist"))?;
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate background task id")
                .with_detail(error.to_string())
        })?;
        let record = BackgroundTaskRecord {
            id: id.clone(),
            plugin_id,
            task: request.task,
            timeout_seconds: request.timeout_seconds.clamp(1, 86_400),
            max_concurrency: request.max_concurrency.max(1),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.background_tasks
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "lifecycle.extension.background_task.registered.v1",
            "background_task",
            id.as_str(),
            "registered",
            serde_json::json!({
                "task": record.task,
                "timeout_seconds": record.timeout_seconds,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn validate_governance_gate(
        &self,
        change_request_id: &str,
        require_approved: bool,
    ) -> Result<ChangeRequestId> {
        let change_request_id =
            ChangeRequestId::parse(change_request_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid change_request_id").with_detail(error.to_string())
            })?;
        let stored = self
            .governance_change_requests
            .get(change_request_id.as_str())
            .await?
            .ok_or_else(|| {
                PlatformError::not_found("change_request_id does not exist in governance")
            })?;
        if require_approved {
            let state = stored.value.state.trim().to_ascii_lowercase();
            if state != "approved" && state != "applied" {
                return Err(PlatformError::conflict(
                    "change_request_id is not approved/applied in governance",
                ));
            }
        }
        Ok(change_request_id)
    }

    async fn integrity_report(&self) -> Result<Response<ApiBody>> {
        let migrations = self
            .migrations
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let dead_letters = self
            .dead_letters
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();

        let mut duplicate_target_conflicts = 0_usize;
        let mut ordering_violations = 0_usize;
        let mut details = Vec::new();

        for scope in [MigrationScope::Schema, MigrationScope::Config] {
            let mut scoped = migrations
                .iter()
                .filter(|record| record.scope == scope)
                .collect::<Vec<_>>();
            scoped.sort_by_key(|record| {
                (
                    record.to_version,
                    record.from_version,
                    record.id.to_string(),
                )
            });

            let mut previous_to = 0_u32;
            let mut version_checksum = std::collections::BTreeMap::<u32, String>::new();
            for record in scoped {
                if let Some(existing_checksum) = version_checksum.get(&record.to_version) {
                    if existing_checksum != &record.checksum {
                        duplicate_target_conflicts = duplicate_target_conflicts.saturating_add(1);
                        details.push(format!(
                            "scope {} has conflicting checksum for target version {}",
                            scope_key(&scope),
                            record.to_version
                        ));
                    }
                } else {
                    version_checksum.insert(record.to_version, record.checksum.clone());
                }
                if record.from_version < previous_to {
                    ordering_violations = ordering_violations.saturating_add(1);
                    details.push(format!(
                        "scope {} ordering violation: from_version {} behind previous target {}",
                        scope_key(&scope),
                        record.from_version,
                        previous_to
                    ));
                }
                previous_to = previous_to.max(record.to_version);
            }
        }

        let unreplayed_dead_letters = dead_letters
            .iter()
            .filter(|record| !record.replayed)
            .count();
        if unreplayed_dead_letters > 0 {
            details.push(format!(
                "{} unreplayed dead letters pending repair",
                unreplayed_dead_letters
            ));
        }

        let report = LifecycleIntegrityReport {
            valid: duplicate_target_conflicts == 0 && ordering_violations == 0,
            migration_count: migrations.len(),
            duplicate_target_conflicts,
            ordering_violations,
            unreplayed_dead_letters,
            details,
        };
        json_response(StatusCode::OK, &report)
    }

    async fn summary_report(&self) -> Result<Response<ApiBody>> {
        let rollouts = self
            .rollout_workflows
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.state)
            .collect::<Vec<_>>();
        let mut rollout_phase_counts = BTreeMap::<String, usize>::new();
        for rollout in &rollouts {
            *rollout_phase_counts
                .entry(rollout.phase.clone())
                .or_default() += 1;
        }

        let migrations = self
            .migrations
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let migration_pending = migrations
            .iter()
            .filter(|record| matches!(record.state, MigrationState::Pending))
            .count();
        let migration_applied = migrations
            .iter()
            .filter(|record| matches!(record.state, MigrationState::Applied))
            .count();
        let migration_failed = migrations
            .iter()
            .filter(|record| matches!(record.state, MigrationState::Failed))
            .count();

        let maintenance = self
            .maintenance
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let maintenance_enabled = maintenance.iter().filter(|record| record.enabled).count();

        let dead_letters = self
            .dead_letters
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let dead_letters_replayed = dead_letters.iter().filter(|record| record.replayed).count();

        let repair_jobs = self.list_repair_job_states().await?;
        let repair_completed = repair_jobs
            .iter()
            .filter(|record| record.status.trim().eq_ignore_ascii_case("completed"))
            .count();
        let repair_failed = repair_jobs
            .iter()
            .filter(|record| record.status.trim().eq_ignore_ascii_case("failed"))
            .count();

        let plugins = self
            .plugins
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let plugins_enabled = plugins.iter().filter(|record| record.enabled).count();
        let extension_subscriptions = self
            .extension_subscriptions
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        let background_tasks = self
            .background_tasks
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();

        let summary = LifecycleSummary {
            rollouts: LifecycleRolloutSummary {
                total: rollouts.len(),
                by_phase: map_named_counts(rollout_phase_counts),
            },
            migrations: LifecycleMigrationSummary {
                total: migrations.len(),
                pending: migration_pending,
                applied: migration_applied,
                failed: migration_failed,
            },
            maintenance: LifecycleMaintenanceSummary {
                total: maintenance.len(),
                enabled: maintenance_enabled,
                disabled: maintenance.len().saturating_sub(maintenance_enabled),
            },
            dead_letters: LifecycleDeadLetterSummary {
                total: dead_letters.len(),
                pending_replay: dead_letters.len().saturating_sub(dead_letters_replayed),
                replayed: dead_letters_replayed,
            },
            repair_jobs: LifecycleRepairJobSummary {
                total: repair_jobs.len(),
                completed: repair_completed,
                failed: repair_failed,
                active: repair_jobs
                    .len()
                    .saturating_sub(repair_completed.saturating_add(repair_failed)),
            },
            extensions: LifecycleExtensionSummary {
                plugins_total: plugins.len(),
                plugins_enabled,
                event_subscriptions_total: extension_subscriptions,
                background_tasks_total: background_tasks,
            },
        };
        json_response(StatusCode::OK, &summary)
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
                source_service: String::from("lifecycle"),
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
        let idempotency = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("lifecycle.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for LifecycleService {
    fn name(&self) -> &'static str {
        "lifecycle"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/lifecycle")];
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

            match (method, segments.as_slice()) {
                (Method::GET, ["lifecycle"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["lifecycle", "migrations"]) => {
                    let values = self
                        .migrations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "migrations"]) => {
                    let body: CreateMigrationRequest = parse_json(request).await?;
                    self.record_migration(body, &context, false).await.map(Some)
                }
                (Method::POST, ["lifecycle", "migrations", "apply"]) => {
                    let body: CreateMigrationRequest = parse_json(request).await?;
                    self.record_migration(body, &context, true).await.map(Some)
                }
                (Method::GET, ["lifecycle", "integrity"]) => {
                    self.integrity_report().await.map(Some)
                }
                (Method::GET, ["lifecycle", "summary"]) => self.summary_report().await.map(Some),
                (Method::GET, ["lifecycle", "rollout-plans"]) => {
                    let values = self
                        .rollout_workflows
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value.state)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans"]) => {
                    let body: CreateRolloutRequest = parse_json(request).await?;
                    self.create_rollout_plan(body, &context).await.map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans", rollout_id, "start"]) => {
                    let body: RolloutActionRequest = parse_json(request).await?;
                    self.mutate_rollout_plan(rollout_id, body, RolloutMutationKind::Start, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans", rollout_id, "advance"]) => {
                    let body: RolloutActionRequest = parse_json(request).await?;
                    self.mutate_rollout_plan(
                        rollout_id,
                        body,
                        RolloutMutationKind::Advance,
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans", rollout_id, "pause"]) => {
                    let body: RolloutActionRequest = parse_json(request).await?;
                    self.mutate_rollout_plan(rollout_id, body, RolloutMutationKind::Pause, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans", rollout_id, "resume"]) => {
                    let body: RolloutActionRequest = parse_json(request).await?;
                    self.mutate_rollout_plan(
                        rollout_id,
                        body,
                        RolloutMutationKind::Resume,
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::POST, ["lifecycle", "rollout-plans", rollout_id, "rollback"]) => {
                    let body: RolloutActionRequest = parse_json(request).await?;
                    self.mutate_rollout_plan(
                        rollout_id,
                        body,
                        RolloutMutationKind::Rollback,
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::GET, ["lifecycle", "maintenance"]) => {
                    let values = self
                        .maintenance
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "maintenance"]) => {
                    let body: SetMaintenanceRequest = parse_json(request).await?;
                    self.set_maintenance(body, &context).await.map(Some)
                }
                (Method::GET, ["lifecycle", "repair-jobs"]) => {
                    let values = self.list_repair_job_states().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "repair-jobs", repair_job_id, "confirm"]) => {
                    let body: ConfirmRepairJobRequest = parse_json(request).await?;
                    self.confirm_repair_job(repair_job_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["lifecycle", "plugins"]) => {
                    let values = self
                        .plugins
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "plugins"]) => {
                    let body: RegisterPluginRequest = parse_json(request).await?;
                    self.register_plugin(body, &context).await.map(Some)
                }
                (Method::GET, ["lifecycle", "event-subscriptions"]) => {
                    let values = self
                        .extension_subscriptions
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "event-subscriptions"]) => {
                    let body: RegisterSubscriptionRequest = parse_json(request).await?;
                    self.register_event_subscription(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["lifecycle", "background-tasks"]) => {
                    let values = self
                        .background_tasks
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "background-tasks"]) => {
                    let body: RegisterBackgroundTaskRequest = parse_json(request).await?;
                    self.register_background_task(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["lifecycle", "compatibility-policy"]) => {
                    json_response(StatusCode::OK, &extension_policy()).map(Some)
                }
                (Method::GET, ["lifecycle", "dead-letters"]) => {
                    let values = self
                        .dead_letters
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["lifecycle", "dead-letters"]) => {
                    let body: CreateDeadLetterRequest = parse_json(request).await?;
                    self.create_dead_letter(body, &context).await.map(Some)
                }
                (Method::POST, ["lifecycle", "dead-letter", "replay"]) => {
                    let body: ReplayDeadLetterRequest = parse_json(request).await?;
                    self.replay_dead_letters(body, &context).await.map(Some)
                }
                (Method::GET, ["lifecycle", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn discover_migration_manifest_root(platform_state_root: &Path) -> Option<PathBuf> {
    workspace_root_candidates(platform_state_root)
        .into_iter()
        .map(|root| root.join("migrations"))
        .find(|candidate| candidate.join("schema").is_dir() || candidate.join("config").is_dir())
}

fn workspace_root_candidates(platform_state_root: &Path) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    for ancestor in platform_state_root.ancestors() {
        roots.insert(ancestor.to_path_buf());
    }
    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors() {
            roots.insert(ancestor.to_path_buf());
        }
    }
    roots.into_iter().collect::<Vec<_>>()
}

fn collect_named_files(root: &Path, file_name: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(root).map_err(|error| {
        PlatformError::unavailable("failed to read config directory").with_detail(format!(
            "{}: {}",
            root.display(),
            error
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            PlatformError::unavailable("failed to enumerate config directory")
                .with_detail(error.to_string())
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            PlatformError::unavailable("failed to read config path type").with_detail(format!(
                "{}: {}",
                path.display(),
                error
            ))
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_named_files(&path, file_name, output)?;
            continue;
        }
        if path
            .file_name()
            .is_some_and(|candidate| candidate == std::ffi::OsStr::new(file_name))
        {
            output.push(path);
        }
    }

    Ok(())
}

async fn config_targets_state_root(
    config_path: &Path,
    expected_state_root: &Path,
    current_dir: Option<&Path>,
) -> Result<bool> {
    let raw = fs::read_to_string(config_path).await.map_err(|error| {
        PlatformError::unavailable("failed to read runtime config file").with_detail(format!(
            "{}: {}",
            config_path.display(),
            error
        ))
    })?;
    let value: toml::Value = toml::from_str(&raw).map_err(|error| {
        PlatformError::invalid("failed to parse runtime config file").with_detail(format!(
            "{}: {}",
            config_path.display(),
            error
        ))
    })?;
    let Some(state_dir) = value.get("state_dir").and_then(toml::Value::as_str) else {
        return Ok(false);
    };

    let mut candidates = BTreeSet::new();
    if let Some(current_dir) = current_dir {
        candidates.insert(current_dir.join(state_dir));
    }
    if let Some(parent) = config_path.parent() {
        candidates.insert(parent.join(state_dir));
    }

    for candidate in candidates {
        let resolved = match fs::canonicalize(&candidate).await {
            Ok(path) => path,
            Err(_) => continue,
        };
        if resolved == expected_state_root {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn read_json_collection_schema_version(path: &Path) -> Result<u32> {
    if fs::metadata(path).await.is_err() {
        return Ok(1);
    }

    let raw = fs::read_to_string(path).await.map_err(|error| {
        PlatformError::unavailable("failed to read collection file").with_detail(format!(
            "{}: {}",
            path.display(),
            error
        ))
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        PlatformError::invalid("failed to parse collection file").with_detail(format!(
            "{}: {}",
            path.display(),
            error
        ))
    })?;
    value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            PlatformError::invalid("collection file is missing schema_version")
                .with_detail(path.display().to_string())
        })
}

async fn set_json_collection_schema_version(path: &Path, schema_version: u16) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|error| {
            PlatformError::unavailable("failed to create collection directory")
                .with_detail(format!("{}: {}", parent.display(), error))
        })?;
    }

    let mut value =
        if fs::metadata(path).await.is_ok() {
            let raw =
                fs::read_to_string(path).await.map_err(|error| {
                    PlatformError::unavailable("failed to read collection file")
                        .with_detail(format!("{}: {}", path.display(), error))
                })?;
            serde_json::from_str::<serde_json::Value>(&raw).map_err(|error| {
                PlatformError::invalid("failed to parse collection file").with_detail(format!(
                    "{}: {}",
                    path.display(),
                    error
                ))
            })?
        } else {
            serde_json::json!({
                "schema_version": schema_version,
                "revision": 0,
                "records": {},
                "changes": [],
            })
        };

    let object = value.as_object_mut().ok_or_else(|| {
        PlatformError::invalid("collection file root must be an object")
            .with_detail(path.display().to_string())
    })?;
    object.insert(
        String::from("schema_version"),
        serde_json::Value::from(u64::from(schema_version)),
    );
    object
        .entry(String::from("revision"))
        .or_insert_with(|| serde_json::Value::from(0_u64));
    object
        .entry(String::from("records"))
        .or_insert_with(|| serde_json::json!({}));
    object
        .entry(String::from("changes"))
        .or_insert_with(|| serde_json::json!([]));

    let rendered =
        serde_json::to_vec(&value).map_err(|error| {
            PlatformError::invalid("failed to encode migrated collection file")
                .with_detail(format!("{}: {}", path.display(), error))
        })?;
    fs::write(path, rendered).await.map_err(|error| {
        PlatformError::unavailable("failed to write migrated collection file").with_detail(format!(
            "{}: {}",
            path.display(),
            error
        ))
    })?;

    Ok(())
}

fn map_named_counts(counts: BTreeMap<String, usize>) -> Vec<NamedCount> {
    counts
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect::<Vec<_>>()
}

fn parse_scope(raw: &str) -> Result<MigrationScope> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "schema" => Ok(MigrationScope::Schema),
        "config" => Ok(MigrationScope::Config),
        _ => Err(PlatformError::invalid("scope must be `schema` or `config`")),
    }
}

fn scope_key(scope: &MigrationScope) -> &'static str {
    match scope {
        MigrationScope::Schema => "schema",
        MigrationScope::Config => "config",
    }
}

fn validate_canary_steps(steps: &[u8]) -> Result<()> {
    if steps.is_empty() {
        return Err(PlatformError::invalid("canary_steps may not be empty"));
    }
    let mut previous = 0_u8;
    for value in steps {
        if *value == 0 || *value > 100 {
            return Err(PlatformError::invalid(
                "canary_steps values must be between 1 and 100",
            ));
        }
        if *value <= previous {
            return Err(PlatformError::invalid(
                "canary_steps must be in strictly ascending order",
            ));
        }
        previous = *value;
    }
    if previous != 100 {
        return Err(PlatformError::invalid(
            "canary_steps must end with 100 to ensure full rollout",
        ));
    }
    Ok(())
}

fn normalize_rollout_channel(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "stable" | "canary" | "preview" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "channel must be stable, canary, or preview",
        )),
    }
}

fn extension_policy() -> CompatibilityPolicy {
    CompatibilityPolicy {
        current_api_version: 1,
        minimum_supported_api_version: 1,
        effective_at: OffsetDateTime::now_utc(),
    }
}

fn parse_delivery_mode(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "best_effort" | "at_least_once" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "delivery_mode must be best_effort or at_least_once",
        )),
    }
}

fn normalize_optional_reason(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 512 {
        return Err(PlatformError::invalid(
            "reason may not exceed 512 characters",
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

fn normalize_optional_idempotency_key(value: Option<String>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("idempotency_key may not be empty"));
    }
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid(
            "idempotency_key may not exceed 128 characters",
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

fn repair_job_workflow_steps() -> Vec<WorkflowStep> {
    vec![
        WorkflowStep::new(REPAIR_JOB_STEP_CLAIM_TARGETS, 0),
        WorkflowStep::new(REPAIR_JOB_STEP_AWAIT_CONFIRMATION, 1),
        WorkflowStep::new(REPAIR_JOB_STEP_FINALIZE_OUTCOME, 2),
    ]
}

fn repair_job_confirmation_observed_at(repair_job: &RepairJobRecord) -> OffsetDateTime {
    repair_job
        .confirmed_at
        .or(repair_job.completed_at)
        .unwrap_or(repair_job.created_at)
}

fn repair_job_requested_at(repair_job: &RepairJobRecord) -> OffsetDateTime {
    repair_job.created_at
}

fn repair_job_etag(repair_job: &RepairJobRecord) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{}:{:?}:{:?}:{:?}",
            repair_job.id,
            repair_job.job_type,
            repair_job.status,
            repair_job.scanned,
            repair_job.replayed,
            repair_job.failed,
            repair_job.completed_at,
            repair_job.confirmed_at
        )
        .as_bytes(),
    )
}

fn build_repair_job_workflow(record: RepairJobRecord) -> RepairJobWorkflow {
    let created_at = record.created_at;
    let updated_at = record.metadata.updated_at;
    let mut steps = repair_job_workflow_steps();
    for step in &mut steps {
        step.updated_at = created_at;
    }

    let claimed_detail = Some(format!(
        "claimed {} dead letters for downstream repair",
        record.dead_letter_ids.len()
    ));
    steps[0].transition(WorkflowStepState::Completed, claimed_detail);
    steps[0].updated_at = updated_at;

    let mut workflow = RepairJobWorkflow {
        id: record.id.to_string(),
        workflow_kind: String::from(REPAIR_JOB_WORKFLOW_KIND),
        subject_kind: String::from(REPAIR_JOB_WORKFLOW_SUBJECT_KIND),
        subject_id: record.id.to_string(),
        phase: WorkflowPhase::Pending,
        current_step_index: Some(1),
        steps,
        created_at,
        updated_at,
        completed_at: None,
        next_attempt_at: None,
        runner_claim: None,
        state: record,
    };

    if repair_job_status_is_pending_confirmation(&workflow.state.status) {
        workflow.phase = WorkflowPhase::Running;
        workflow.current_step_index = Some(1);
        workflow.steps[1].transition(
            WorkflowStepState::Active,
            Some(String::from("awaiting downstream confirmation")),
        );
        workflow.steps[1].updated_at = updated_at;
        return workflow;
    }

    let confirmation_detail = workflow.state.confirmation_detail.clone();
    workflow.current_step_index = Some(2);
    workflow.steps[1].transition(
        WorkflowStepState::Completed,
        confirmation_detail
            .clone()
            .or_else(|| Some(String::from("downstream outcome confirmed"))),
    );
    workflow.steps[1].updated_at = updated_at;

    if repair_job_status_is_completed(&workflow.state.status) {
        workflow.phase = WorkflowPhase::Completed;
        workflow.steps[2].transition(
            WorkflowStepState::Completed,
            confirmation_detail.or_else(|| Some(String::from("repair completed"))),
        );
    } else if repair_job_status_is_failed(&workflow.state.status) {
        workflow.phase = WorkflowPhase::Failed;
        workflow.steps[2].transition(
            WorkflowStepState::Failed,
            confirmation_detail.or_else(|| Some(String::from("repair failed"))),
        );
    } else {
        workflow.phase = WorkflowPhase::Running;
        workflow.current_step_index = Some(1);
        workflow.steps[1].transition(
            WorkflowStepState::Active,
            Some(String::from("awaiting downstream confirmation")),
        );
        workflow.steps[1].updated_at = updated_at;
        return workflow;
    }

    workflow.steps[2].updated_at = updated_at;
    workflow.completed_at = workflow.state.completed_at.or(workflow.state.confirmed_at);
    workflow
}

fn apply_repair_job_reconciliation_primitives(workflow: &mut RepairJobWorkflow) -> bool {
    let desired = build_repair_job_workflow(workflow.state.clone());
    let changed = workflow.phase != desired.phase
        || workflow.current_step_index != desired.current_step_index
        || workflow.steps != desired.steps
        || workflow.completed_at != desired.completed_at
        || workflow.updated_at != desired.updated_at;
    if changed {
        workflow.phase = desired.phase;
        workflow.current_step_index = desired.current_step_index;
        workflow.steps = desired.steps;
        workflow.completed_at = desired.completed_at;
        workflow.updated_at = desired.updated_at;
    }
    changed
}

fn apply_pending_repair_job_dead_letter_state(
    dead_letter: &mut DeadLetterRecord,
    repair_job: &RepairJobRecord,
) -> bool {
    let mut changed = false;
    if dead_letter.replayed {
        dead_letter.replayed = false;
        changed = true;
    }
    if dead_letter.replayed_at.is_some() {
        dead_letter.replayed_at = None;
        changed = true;
    }
    if dead_letter.repair_job_id.as_ref() != Some(&repair_job.id) {
        dead_letter.repair_job_id = Some(repair_job.id.clone());
        changed = true;
    }
    let requested_at = Some(
        dead_letter
            .repair_requested_at
            .unwrap_or_else(|| repair_job_requested_at(repair_job)),
    );
    if dead_letter.repair_requested_at != requested_at {
        dead_letter.repair_requested_at = requested_at;
        changed = true;
    }
    changed
}

fn apply_completed_repair_job_dead_letter_state(
    dead_letter: &mut DeadLetterRecord,
    repair_job: &RepairJobRecord,
) -> bool {
    let mut changed = false;
    if !dead_letter.replayed {
        dead_letter.replayed = true;
        changed = true;
    }
    if dead_letter.repair_job_id.as_ref() != Some(&repair_job.id) {
        dead_letter.repair_job_id = Some(repair_job.id.clone());
        changed = true;
    }
    let requested_at = Some(
        dead_letter
            .repair_requested_at
            .unwrap_or_else(|| repair_job_requested_at(repair_job)),
    );
    if dead_letter.repair_requested_at != requested_at {
        dead_letter.repair_requested_at = requested_at;
        changed = true;
    }
    let replayed_at = Some(
        dead_letter
            .replayed_at
            .unwrap_or_else(|| repair_job_confirmation_observed_at(repair_job)),
    );
    if dead_letter.replayed_at != replayed_at {
        dead_letter.replayed_at = replayed_at;
        changed = true;
    }
    changed
}

fn apply_failed_repair_job_dead_letter_state(dead_letter: &mut DeadLetterRecord) -> bool {
    let mut changed = false;
    if dead_letter.replayed {
        dead_letter.replayed = false;
        changed = true;
    }
    if dead_letter.replayed_at.is_some() {
        dead_letter.replayed_at = None;
        changed = true;
    }
    if dead_letter.repair_job_id.is_some() {
        dead_letter.repair_job_id = None;
        changed = true;
    }
    if dead_letter.repair_requested_at.is_some() {
        dead_letter.repair_requested_at = None;
        changed = true;
    }
    changed
}

fn build_rollout_workflow(record: RolloutPlanRecord) -> RolloutWorkflow {
    let created_at = record.metadata.created_at;
    let updated_at = record.metadata.updated_at;
    let current_step_index = rollout_current_step_index(&record);
    let mut steps = rollout_workflow_steps(&record)
        .into_iter()
        .map(|mut step| {
            step.updated_at = created_at;
            step
        })
        .collect::<Vec<_>>();

    match record.phase.as_str() {
        "in_progress" | "paused" | "completed" => {
            if let Some(current_step_index) = current_step_index {
                for (index, step) in steps.iter_mut().enumerate() {
                    if index < current_step_index {
                        step.state = WorkflowStepState::Completed;
                        step.updated_at = updated_at;
                    } else if index == current_step_index {
                        step.state = if record.phase == "completed" {
                            WorkflowStepState::Completed
                        } else {
                            WorkflowStepState::Active
                        };
                        step.detail = record.status_reason.clone();
                        step.updated_at = updated_at;
                    }
                }
            }
        }
        "rolled_back" => {
            if let Some(current_step_index) = current_step_index {
                for step in steps.iter_mut().take(current_step_index.saturating_add(1)) {
                    step.state = WorkflowStepState::RolledBack;
                    step.detail = record.status_reason.clone();
                    step.updated_at = updated_at;
                }
            } else if let Some(step) = steps.first_mut() {
                step.state = WorkflowStepState::RolledBack;
                step.detail = record.status_reason.clone();
                step.updated_at = updated_at;
            }
        }
        _ => {}
    }

    let completed_at = match record.phase.as_str() {
        "completed" | "rolled_back" => Some(updated_at),
        _ => None,
    };
    RolloutWorkflow {
        id: record.id.to_string(),
        workflow_kind: String::from(ROLLOUT_WORKFLOW_KIND),
        subject_kind: String::from(ROLLOUT_WORKFLOW_SUBJECT_KIND),
        subject_id: record.id.to_string(),
        phase: workflow_phase_from_rollout_phase(record.phase.as_str()),
        current_step_index,
        steps,
        created_at,
        updated_at,
        completed_at,
        next_attempt_at: None,
        runner_claim: None,
        state: record,
    }
}

fn apply_rollout_mutation_to_workflow(
    workflow: &mut RolloutWorkflow,
    rollout: &RolloutPlanRecord,
    mutation: RolloutMutationKind,
) {
    ensure_rollout_workflow_shape(workflow, rollout);
    let detail = rollout.status_reason.clone();

    match mutation {
        RolloutMutationKind::Start => {
            workflow.current_step_index = Some(0);
            workflow.set_phase(WorkflowPhase::Running);
            if let Some(step) = workflow.step_mut(0) {
                set_rollout_step_state(step, WorkflowStepState::Active, detail);
            }
        }
        RolloutMutationKind::Advance => {
            let previous_step_index = workflow
                .current_step_index
                .or_else(|| rollout_current_step_index(rollout))
                .unwrap_or(0);
            if let Some(step) = workflow.step_mut(previous_step_index) {
                set_rollout_step_state(step, WorkflowStepState::Completed, detail.clone());
            }

            if let Some(current_step_index) = rollout_current_step_index(rollout) {
                workflow.current_step_index = Some(current_step_index);
                if rollout.phase == "completed" {
                    if let Some(step) = workflow.step_mut(current_step_index) {
                        set_rollout_step_state(step, WorkflowStepState::Completed, detail);
                    }
                    workflow.set_phase(WorkflowPhase::Completed);
                } else {
                    if let Some(step) = workflow.step_mut(current_step_index) {
                        set_rollout_step_state(step, WorkflowStepState::Active, detail);
                    }
                    workflow.set_phase(WorkflowPhase::Running);
                }
            } else {
                workflow.set_phase(WorkflowPhase::Completed);
            }
        }
        RolloutMutationKind::Pause => {
            workflow.current_step_index = workflow
                .current_step_index
                .or_else(|| rollout_current_step_index(rollout));
            workflow.set_phase(WorkflowPhase::Paused);
            if let Some(current_step_index) = workflow.current_step_index
                && let Some(step) = workflow.step_mut(current_step_index)
            {
                set_rollout_step_state(step, WorkflowStepState::Active, detail);
            }
        }
        RolloutMutationKind::Resume => {
            workflow.current_step_index = workflow
                .current_step_index
                .or_else(|| rollout_current_step_index(rollout));
            workflow.set_phase(WorkflowPhase::Running);
            if let Some(current_step_index) = workflow.current_step_index
                && let Some(step) = workflow.step_mut(current_step_index)
            {
                set_rollout_step_state(step, WorkflowStepState::Active, detail);
            }
        }
        RolloutMutationKind::Rollback => {
            let mut rolled_back_any = false;
            for step in &mut workflow.steps {
                if matches!(
                    step.state,
                    WorkflowStepState::Active | WorkflowStepState::Completed
                ) {
                    set_rollout_step_state(step, WorkflowStepState::RolledBack, detail.clone());
                    rolled_back_any = true;
                }
            }

            if !rolled_back_any {
                let current_step_index = workflow
                    .current_step_index
                    .or_else(|| rollout_current_step_index(rollout))
                    .or_else(|| (!workflow.steps.is_empty()).then_some(0));
                if let Some(current_step_index) = current_step_index {
                    workflow.current_step_index = Some(current_step_index);
                    if let Some(step) = workflow.step_mut(current_step_index) {
                        set_rollout_step_state(step, WorkflowStepState::RolledBack, detail);
                    }
                }
            }

            workflow.set_phase(WorkflowPhase::RolledBack);
        }
    }

    workflow.state = rollout.clone();
    workflow.subject_id = rollout.id.to_string();
}

fn ensure_rollout_workflow_shape(workflow: &mut RolloutWorkflow, rollout: &RolloutPlanRecord) {
    workflow.workflow_kind = String::from(ROLLOUT_WORKFLOW_KIND);
    workflow.subject_kind = String::from(ROLLOUT_WORKFLOW_SUBJECT_KIND);
    workflow.subject_id = rollout.id.to_string();
    if workflow.steps.len() != rollout.canary_steps.len() {
        workflow.steps = rollout_workflow_steps(rollout);
        return;
    }

    for (step, (index, traffic_percent)) in workflow
        .steps
        .iter_mut()
        .zip(rollout.canary_steps.iter().enumerate())
    {
        step.name = rollout_workflow_step_name(*traffic_percent);
        step.index = index;
    }
}

fn rollout_workflow_steps(rollout: &RolloutPlanRecord) -> Vec<WorkflowStep> {
    rollout
        .canary_steps
        .iter()
        .enumerate()
        .map(|(index, traffic_percent)| {
            WorkflowStep::new(rollout_workflow_step_name(*traffic_percent), index)
        })
        .collect::<Vec<_>>()
}

fn rollout_workflow_step_name(traffic_percent: u8) -> String {
    format!("shift_{traffic_percent}_percent")
}

fn rollout_current_step_index(rollout: &RolloutPlanRecord) -> Option<usize> {
    if rollout.phase == "planned" || rollout.canary_steps.is_empty() {
        return None;
    }

    Some(
        rollout
            .current_step_index
            .min(rollout.canary_steps.len().saturating_sub(1)),
    )
}

fn workflow_phase_from_rollout_phase(phase: &str) -> WorkflowPhase {
    match phase {
        "planned" => WorkflowPhase::Pending,
        "in_progress" => WorkflowPhase::Running,
        "paused" => WorkflowPhase::Paused,
        "completed" => WorkflowPhase::Completed,
        "rolled_back" => WorkflowPhase::RolledBack,
        _ => WorkflowPhase::Failed,
    }
}

fn rollout_reconciliation_lease_duration() -> Duration {
    Duration::minutes(5)
}

fn rollout_workflow_requires_reconciliation(workflow: &RolloutWorkflow) -> bool {
    workflow.phase == WorkflowPhase::Running
}

fn apply_rollout_reconciliation_primitives(
    workflow: &mut RolloutWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    let desired_next_attempt_at =
        rollout_workflow_requires_reconciliation(workflow).then_some(observed_at);
    let active_claim = workflow
        .runner_claim
        .clone()
        .filter(|claim| claim.is_active_at(observed_at));

    if active_claim
        .as_ref()
        .is_some_and(|claim| claim.runner_id != ROLLOUT_RECONCILER_RUNNER_ID)
    {
        return Ok(false);
    }

    let mut changed = false;
    if desired_next_attempt_at.is_some() {
        if let Some(active_claim) = active_claim.as_ref() {
            let fencing_token = active_claim.fencing_token.clone();
            workflow.heartbeat_runner_at(
                ROLLOUT_RECONCILER_RUNNER_ID,
                fencing_token.as_str(),
                rollout_reconciliation_lease_duration(),
                observed_at,
            )?;
        } else {
            workflow.claim_runner_at(
                ROLLOUT_RECONCILER_RUNNER_ID,
                rollout_reconciliation_lease_duration(),
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

fn set_rollout_step_state(
    step: &mut WorkflowStep,
    state: WorkflowStepState,
    detail: Option<String>,
) {
    if step.state != state || step.detail != detail {
        step.transition(state, detail);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use http_body_util::BodyExt;
    use proptest::prelude::*;
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;

    use super::{
        BackgroundTaskRecord, ConfirmRepairJobRequest, CreateDeadLetterRequest,
        CreateMigrationRequest, CreateRolloutRequest, DeadLetterRecord,
        ExtensionSubscriptionRecord, LifecycleService, MigrationRecord, MigrationScope,
        MigrationState, PluginRecord, RegisterPluginRequest, RepairJobRecord,
        ReplayDeadLetterRequest, RolloutActionRequest, SetMaintenanceRequest,
    };
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_store::{DocumentStore, WorkflowPhase, WorkflowStepState};
    use uhost_types::{
        ChangeRequestId, DeadLetterId, MigrationJobId, OwnershipScope, PluginId, RepairJobId,
        ResourceMetadata, RolloutPlanId,
    };

    const LIFECYCLE_EXTENSION_REGISTRY_CHECKSUM: &str =
        "eae471336f91281a3587df5311b9ccd1ac523849fd89fb20053d3d2a444450f5";
    const GOVERNANCE_AUDIT_CHAIN_CHECKSUM: &str =
        "c25c1be6c75cddad6fce128799a95e1ff06996600faf271feafacff11c65cf74";
    const OBSERVE_OTLP_DEFAULTS_CHECKSUM: &str =
        "19cd3cb320003da40958b681b735592a6d240c27684011b20a0c8b2c616622b5";

    async fn seed_governance_change_request(
        state_root: &Path,
        state: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let store =
            DocumentStore::open(state_root.join("governance").join("change_requests.json")).await?;
        let id = ChangeRequestId::generate()?;
        let record = super::GovernanceChangeRequestMirror {
            id: id.clone(),
            state: state.to_owned(),
            extra: std::collections::BTreeMap::new(),
        };
        let _ = store.create(id.as_str(), record).await?;
        Ok(id.to_string())
    }

    async fn read_json<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn migration_apply_is_idempotent_for_same_checksum() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(temp.path(), "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let request = CreateMigrationRequest {
            scope: String::from("schema"),
            from_version: 1,
            to_version: 2,
            name: String::from("lifecycle_extension_registry"),
            checksum: String::from(LIFECYCLE_EXTENSION_REGISTRY_CHECKSUM),
            compatibility_window_days: Some(30),
            change_request_id: Some(change_request_id),
        };

        let first = service
            .record_migration(request.clone(), &context, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), http::StatusCode::CREATED);

        let second = service
            .record_migration(request, &context, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), http::StatusCode::OK);
        let all = service
            .migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1.value.state, MigrationState::Applied);
        assert!(all[0].1.value.applied_at.is_some());
    }

    #[tokio::test]
    async fn migration_apply_rejects_checksum_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(temp.path(), "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 1,
                    to_version: 2,
                    name: String::from("lifecycle_extension_registry"),
                    checksum: String::from("wrong-checksum"),
                    compatibility_window_days: Some(30),
                    change_request_id: Some(change_request_id),
                },
                &context,
                true,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected checksum mismatch to fail"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn migration_apply_rejects_non_contiguous_step() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(temp.path(), "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 2,
                    to_version: 3,
                    name: String::from("governance_audit_chain"),
                    checksum: String::from(GOVERNANCE_AUDIT_CHAIN_CHECKSUM),
                    compatibility_window_days: Some(30),
                    change_request_id: Some(change_request_id),
                },
                &context,
                true,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-contiguous migration to fail"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(
            error
                .detail
                .unwrap_or_default()
                .contains("currently at version 1")
        );
    }

    #[tokio::test]
    async fn migration_apply_materializes_schema_transforms() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(temp.path(), "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 1,
                    to_version: 2,
                    name: String::from("lifecycle_extension_registry"),
                    checksum: String::from(LIFECYCLE_EXTENSION_REGISTRY_CHECKSUM),
                    compatibility_window_days: Some(30),
                    change_request_id: Some(change_request_id.clone()),
                },
                &context,
                true,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            super::read_json_collection_schema_version(
                &temp.path().join("lifecycle").join("plugins.json")
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            2
        );

        let _ = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 2,
                    to_version: 3,
                    name: String::from("governance_audit_chain"),
                    checksum: String::from(GOVERNANCE_AUDIT_CHAIN_CHECKSUM),
                    compatibility_window_days: Some(30),
                    change_request_id: Some(change_request_id),
                },
                &context,
                true,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            super::read_json_collection_schema_version(
                &temp.path().join("lifecycle").join("migrations.json")
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            3
        );
        assert_eq!(
            super::read_json_collection_schema_version(
                &temp.path().join("governance").join("audit_chain_head.json")
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            3
        );
        assert!(
            temp.path()
                .join("governance")
                .join("audit_checkpoints.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn migration_apply_updates_matching_runtime_config_files() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let state_root = temp.path().join("state").join("dev");
        fs::create_dir_all(temp.path().join("configs").join("dev"))
            .unwrap_or_else(|error| panic!("{error}"));
        let config_path = temp
            .path()
            .join("configs")
            .join("dev")
            .join("all-in-one.toml");
        fs::write(
            &config_path,
            r#"listen = "127.0.0.1:9080"
state_dir = "../../state/dev"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "migration-test-node"
"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let service = LifecycleService::open(&state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(&state_root, "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("config"),
                    from_version: 1,
                    to_version: 2,
                    name: String::from("observe_otlp_defaults"),
                    checksum: String::from(OBSERVE_OTLP_DEFAULTS_CHECKSUM),
                    compatibility_window_days: None,
                    change_request_id: Some(change_request_id),
                },
                &context,
                true,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migrated = fs::read_to_string(&config_path).unwrap_or_else(|error| panic!("{error}"));
        let config: toml::Value =
            toml::from_str(&migrated).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config["schema"]["schema_version"].as_integer(), Some(2));
        assert_eq!(
            config["observe"]["otlp"]["add_signal_defaults"].as_bool(),
            Some(true)
        );
        assert_eq!(
            config["observe"]["otlp"]["default_retry_policy"].as_str(),
            Some("exponential_jitter")
        );
    }

    #[tokio::test]
    async fn replay_dead_letters_creates_pending_confirmation_repair_job() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_dead_letter(
                CreateDeadLetterRequest {
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-1"}),
                    error: String::from("sink timeout"),
                    attempts: 3,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .replay_dead_letters(ReplayDeadLetterRequest { limit: Some(10) }, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let repair_job: RepairJobRecord = read_json(response).await;
        assert_eq!(repair_job.status, "pending_confirmation");
        assert_eq!(repair_job.scanned, 1);
        assert_eq!(repair_job.replayed, 0);
        assert_eq!(repair_job.dead_letter_ids.len(), 1);

        let jobs = service
            .repair_jobs
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].1.value.status, "pending_confirmation");

        let workflows = service
            .repair_job_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workflows.len(), 1);
        assert_eq!(workflows[0].1.value.phase, WorkflowPhase::Running);
        assert_eq!(workflows[0].1.value.current_step_index, Some(1));
        assert_eq!(
            workflows[0].1.value.steps[0].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            workflows[0].1.value.steps[1].state,
            WorkflowStepState::Active
        );
        assert_eq!(
            workflows[0].1.value.state.id.to_string(),
            repair_job.id.to_string()
        );

        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
        assert!(!dead_letters[0].1.value.replayed);
        assert_eq!(
            dead_letters[0]
                .1
                .value
                .repair_job_id
                .as_ref()
                .map(ToString::to_string),
            Some(repair_job.id.to_string())
        );
    }

    #[tokio::test]
    async fn confirm_repair_job_marks_dead_letters_replayed_after_success() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_dead_letter(
                CreateDeadLetterRequest {
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-1"}),
                    error: String::from("sink timeout"),
                    attempts: 3,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repair_job: RepairJobRecord = read_json(
            service
                .replay_dead_letters(ReplayDeadLetterRequest { limit: Some(10) }, &context)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let confirmed: RepairJobRecord = read_json(
            service
                .confirm_repair_job(
                    repair_job.id.as_str(),
                    ConfirmRepairJobRequest {
                        success: true,
                        detail: Some(String::from("downstream replay verified")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(confirmed.status, "completed");
        assert_eq!(confirmed.replayed, 1);
        assert_eq!(
            confirmed.confirmation_detail.as_deref(),
            Some("downstream replay verified")
        );

        let workflows = service
            .repair_job_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workflows.len(), 1);
        assert_eq!(workflows[0].1.value.phase, WorkflowPhase::Completed);
        assert_eq!(workflows[0].1.value.current_step_index, Some(2));
        assert_eq!(
            workflows[0].1.value.steps[2].state,
            WorkflowStepState::Completed
        );

        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
        assert!(dead_letters[0].1.value.replayed);
        assert!(dead_letters[0].1.value.replayed_at.is_some());
    }

    #[tokio::test]
    async fn failed_repair_confirmation_releases_dead_letters_for_retry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_dead_letter(
                CreateDeadLetterRequest {
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-1"}),
                    error: String::from("sink timeout"),
                    attempts: 3,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repair_job: RepairJobRecord = read_json(
            service
                .replay_dead_letters(ReplayDeadLetterRequest { limit: Some(10) }, &context)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let failed: RepairJobRecord = read_json(
            service
                .confirm_repair_job(
                    repair_job.id.as_str(),
                    ConfirmRepairJobRequest {
                        success: false,
                        detail: Some(String::from("downstream replay still failing")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.failed, 1);

        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
        assert!(!dead_letters[0].1.value.replayed);
        assert!(dead_letters[0].1.value.repair_job_id.is_none());

        let workflows = service
            .repair_job_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workflows.len(), 1);
        assert_eq!(workflows[0].1.value.phase, WorkflowPhase::Failed);
        assert_eq!(workflows[0].1.value.current_step_index, Some(2));
        assert_eq!(
            workflows[0].1.value.steps[2].state,
            WorkflowStepState::Failed
        );
    }

    #[tokio::test]
    async fn failed_repair_reconciliation_preserves_newer_pending_claims() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let now = time::OffsetDateTime::now_utc();
        let dead_letter_id = DeadLetterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let pending_job_id =
            RepairJobId::parse(String::from("rpj_aaaa")).unwrap_or_else(|error| panic!("{error}"));
        let failed_job_id =
            RepairJobId::parse(String::from("rpj_zzzz")).unwrap_or_else(|error| panic!("{error}"));

        let metadata = |seed: &str| {
            ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(seed.to_owned()),
                uhost_core::sha256_hex(seed.as_bytes()),
            )
        };

        service
            .dead_letters
            .create(
                dead_letter_id.as_str(),
                DeadLetterRecord {
                    id: dead_letter_id.clone(),
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-1"}),
                    error: String::from("sink timeout"),
                    attempts: 3,
                    replayed: false,
                    repair_job_id: Some(pending_job_id.clone()),
                    created_at: now,
                    repair_requested_at: Some(now),
                    replayed_at: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut pending_job = RepairJobRecord {
            id: pending_job_id.clone(),
            job_type: String::from("dead_letter_replay"),
            status: String::from("pending_confirmation"),
            scanned: 1,
            replayed: 0,
            failed: 0,
            dead_letter_ids: vec![dead_letter_id.clone()],
            created_at: now,
            completed_at: None,
            confirmation_detail: None,
            confirmed_at: None,
            metadata: metadata("repair-pending"),
        };
        pending_job
            .metadata
            .touch(super::repair_job_etag(&pending_job));
        service
            .repair_job_workflows
            .create(
                pending_job_id.as_str(),
                super::build_repair_job_workflow(pending_job),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut failed_job = RepairJobRecord {
            id: failed_job_id.clone(),
            job_type: String::from("dead_letter_replay"),
            status: String::from("failed"),
            scanned: 1,
            replayed: 0,
            failed: 1,
            dead_letter_ids: vec![dead_letter_id.clone()],
            created_at: now,
            completed_at: Some(now),
            confirmation_detail: Some(String::from("previous retry failed")),
            confirmed_at: Some(now),
            metadata: metadata("repair-failed"),
        };
        failed_job
            .metadata
            .touch(super::repair_job_etag(&failed_job));
        service
            .repair_job_workflows
            .create(
                failed_job_id.as_str(),
                super::build_repair_job_workflow(failed_job),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .reconcile_repair_job_workflows()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letter = service
            .dead_letters
            .get(dead_letter_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing repaired dead letter"))
            .value;
        assert_eq!(
            dead_letter.repair_job_id.as_ref().map(ToString::to_string),
            Some(pending_job_id.to_string())
        );
        assert!(dead_letter.repair_requested_at.is_some());
        assert!(!dead_letter.replayed);
    }

    #[tokio::test]
    async fn reopening_service_reasserts_pending_repair_job_claims_from_workflow_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let initial_service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = initial_service
            .create_dead_letter(
                CreateDeadLetterRequest {
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-1"}),
                    error: String::from("sink timeout"),
                    attempts: 3,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repair_job: RepairJobRecord = read_json(
            initial_service
                .replay_dead_letters(ReplayDeadLetterRequest { limit: Some(10) }, &context)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let mut dead_letters = initial_service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
        let dead_letter_key = dead_letters[0].0.clone();
        let dead_letter_version = dead_letters[0].1.version;
        let mut interrupted_dead_letter = dead_letters.remove(0).1.value;
        interrupted_dead_letter.repair_job_id = None;
        interrupted_dead_letter.repair_requested_at = None;
        initial_service
            .dead_letters
            .upsert(
                dead_letter_key.as_str(),
                interrupted_dead_letter,
                Some(dead_letter_version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened_service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflows = reopened_service
            .repair_job_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workflows.len(), 1);
        assert_eq!(
            workflows[0].1.value.state.id.to_string(),
            repair_job.id.to_string()
        );
        assert_eq!(workflows[0].1.value.phase, WorkflowPhase::Running);
        assert_eq!(workflows[0].1.value.current_step_index, Some(1));
        assert_eq!(
            workflows[0].1.value.steps[1].state,
            WorkflowStepState::Active
        );

        let repaired_dead_letters = reopened_service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(repaired_dead_letters.len(), 1);
        assert_eq!(
            repaired_dead_letters[0]
                .1
                .value
                .repair_job_id
                .as_ref()
                .map(ToString::to_string),
            Some(repair_job.id.to_string())
        );
        assert!(
            repaired_dead_letters[0]
                .1
                .value
                .repair_requested_at
                .is_some()
        );

        let confirmed: RepairJobRecord = read_json(
            reopened_service
                .confirm_repair_job(
                    repair_job.id.as_str(),
                    ConfirmRepairJobRequest {
                        success: true,
                        detail: Some(String::from("downstream repair confirmed after restart")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(confirmed.status, "completed");
    }

    #[tokio::test]
    async fn plugin_registration_accepts_compatible_manifest() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let plugin_id = PluginId::generate().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .register_plugin(
                RegisterPluginRequest {
                    plugin_id: plugin_id.to_string(),
                    name: String::from("audit-forwarder"),
                    version: String::from("1.0.0"),
                    min_api_version: 1,
                    max_api_version: 1,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn apply_migration_requires_governance_gate() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let blocked = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 2,
                    to_version: 3,
                    name: String::from("governance_audit_chain"),
                    checksum: String::from(GOVERNANCE_AUDIT_CHAIN_CHECKSUM),
                    compatibility_window_days: Some(30),
                    change_request_id: None,
                },
                &context,
                true,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected governance gate enforcement"));
        assert_eq!(blocked.code, uhost_core::ErrorCode::Conflict);

        let pending_change = seed_governance_change_request(temp.path(), "pending")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let blocked_pending = service
            .record_migration(
                CreateMigrationRequest {
                    scope: String::from("schema"),
                    from_version: 2,
                    to_version: 3,
                    name: String::from("governance_audit_chain"),
                    checksum: String::from(GOVERNANCE_AUDIT_CHAIN_CHECKSUM),
                    compatibility_window_days: Some(30),
                    change_request_id: Some(pending_change),
                },
                &context,
                true,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected pending governance gate rejection"));
        assert_eq!(blocked_pending.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn maintenance_requires_approved_governance_change() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let missing = service
            .set_maintenance(
                SetMaintenanceRequest {
                    service: String::from("scheduler"),
                    enabled: true,
                    reason: String::from("schema patch"),
                    change_request_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected missing governance gate rejection"));
        assert_eq!(missing.code, uhost_core::ErrorCode::Conflict);

        let approved_change = seed_governance_change_request(temp.path(), "approved")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let applied = service
            .set_maintenance(
                SetMaintenanceRequest {
                    service: String::from("scheduler"),
                    enabled: true,
                    reason: String::from("schema patch"),
                    change_request_id: Some(approved_change),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(applied.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn lifecycle_integrity_reports_unreplayed_dead_letters() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_dead_letter(
                CreateDeadLetterRequest {
                    topic: String::from("control.events.v1"),
                    payload: serde_json::json!({"id":"evt-2"}),
                    error: String::from("timeout"),
                    attempts: 2,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .integrity_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn lifecycle_summary_reports_document_backed_totals() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let metadata = |seed: &str| {
            ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(seed.to_owned()),
                uhost_core::sha256_hex(seed.as_bytes()),
            )
        };

        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("ingress"),
                    channel: String::from("stable"),
                    canary_steps: vec![10, 100],
                    compatibility_window_days: 14,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollout_a = service
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));
        let _ = service
            .mutate_rollout_plan(
                rollout_a.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .mutate_rollout_plan(
                rollout_a.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("awaiting validation")),
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Pause,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("scheduler"),
                    channel: String::from("canary"),
                    canary_steps: vec![5, 50, 100],
                    compatibility_window_days: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migration_pending_id =
            MigrationJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .migrations
            .create(
                migration_pending_id.as_str(),
                MigrationRecord {
                    id: migration_pending_id.clone(),
                    scope: MigrationScope::Schema,
                    from_version: 1,
                    to_version: 2,
                    name: String::from("pending-schema"),
                    checksum: String::from("m-pending"),
                    state: MigrationState::Pending,
                    applied_at: None,
                    compatibility_window_until: None,
                    metadata: metadata("migration-pending"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_applied_id =
            MigrationJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .migrations
            .create(
                migration_applied_id.as_str(),
                MigrationRecord {
                    id: migration_applied_id.clone(),
                    scope: MigrationScope::Config,
                    from_version: 2,
                    to_version: 3,
                    name: String::from("applied-config"),
                    checksum: String::from("m-applied"),
                    state: MigrationState::Applied,
                    applied_at: Some(time::OffsetDateTime::now_utc()),
                    compatibility_window_until: None,
                    metadata: metadata("migration-applied"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migration_failed_id =
            MigrationJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .migrations
            .create(
                migration_failed_id.as_str(),
                MigrationRecord {
                    id: migration_failed_id.clone(),
                    scope: MigrationScope::Schema,
                    from_version: 3,
                    to_version: 4,
                    name: String::from("failed-schema"),
                    checksum: String::from("m-failed"),
                    state: MigrationState::Failed,
                    applied_at: None,
                    compatibility_window_until: None,
                    metadata: metadata("migration-failed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .maintenance
            .create(
                "ingress",
                super::MaintenanceRecord {
                    service: String::from("ingress"),
                    enabled: true,
                    reason: String::from("upgrade"),
                    updated_at: time::OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .maintenance
            .create(
                "scheduler",
                super::MaintenanceRecord {
                    service: String::from("scheduler"),
                    enabled: false,
                    reason: String::from("done"),
                    updated_at: time::OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letter_pending_id =
            DeadLetterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .dead_letters
            .create(
                dead_letter_pending_id.as_str(),
                DeadLetterRecord {
                    id: dead_letter_pending_id.clone(),
                    topic: String::from("lifecycle.events.v1"),
                    payload: serde_json::json!({"kind":"migration"}),
                    error: String::from("timeout"),
                    attempts: 1,
                    replayed: false,
                    repair_job_id: None,
                    created_at: time::OffsetDateTime::now_utc(),
                    repair_requested_at: None,
                    replayed_at: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dead_letter_replayed_id =
            DeadLetterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .dead_letters
            .create(
                dead_letter_replayed_id.as_str(),
                DeadLetterRecord {
                    id: dead_letter_replayed_id.clone(),
                    topic: String::from("lifecycle.events.v1"),
                    payload: serde_json::json!({"kind":"rollout"}),
                    error: String::from("retry"),
                    attempts: 2,
                    replayed: true,
                    repair_job_id: None,
                    created_at: time::OffsetDateTime::now_utc(),
                    repair_requested_at: None,
                    replayed_at: Some(time::OffsetDateTime::now_utc()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair_active_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .repair_jobs
            .create(
                repair_active_id.as_str(),
                RepairJobRecord {
                    id: repair_active_id.clone(),
                    job_type: String::from("dead_letter_replay"),
                    status: String::from("running"),
                    scanned: 10,
                    replayed: 3,
                    failed: 0,
                    dead_letter_ids: Vec::new(),
                    created_at: time::OffsetDateTime::now_utc(),
                    completed_at: None,
                    confirmation_detail: None,
                    confirmed_at: None,
                    metadata: metadata("repair-active"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repair_completed_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .repair_jobs
            .create(
                repair_completed_id.as_str(),
                RepairJobRecord {
                    id: repair_completed_id.clone(),
                    job_type: String::from("dead_letter_replay"),
                    status: String::from("completed"),
                    scanned: 8,
                    replayed: 8,
                    failed: 0,
                    dead_letter_ids: Vec::new(),
                    created_at: time::OffsetDateTime::now_utc(),
                    completed_at: Some(time::OffsetDateTime::now_utc()),
                    confirmation_detail: None,
                    confirmed_at: None,
                    metadata: metadata("repair-completed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repair_failed_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .repair_jobs
            .create(
                repair_failed_id.as_str(),
                RepairJobRecord {
                    id: repair_failed_id.clone(),
                    job_type: String::from("dead_letter_replay"),
                    status: String::from("failed"),
                    scanned: 5,
                    replayed: 2,
                    failed: 3,
                    dead_letter_ids: Vec::new(),
                    created_at: time::OffsetDateTime::now_utc(),
                    completed_at: Some(time::OffsetDateTime::now_utc()),
                    confirmation_detail: None,
                    confirmed_at: None,
                    metadata: metadata("repair-failed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .reconcile_repair_job_workflows()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let plugin_alpha = PluginId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .plugins
            .create(
                plugin_alpha.as_str(),
                PluginRecord {
                    id: plugin_alpha.clone(),
                    name: String::from("alpha"),
                    version: String::from("1.0.0"),
                    min_api_version: 1,
                    max_api_version: 1,
                    enabled: true,
                    metadata: metadata("plugin-alpha"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let plugin_beta = PluginId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .plugins
            .create(
                plugin_beta.as_str(),
                PluginRecord {
                    id: plugin_beta.clone(),
                    name: String::from("beta"),
                    version: String::from("1.0.0"),
                    min_api_version: 1,
                    max_api_version: 1,
                    enabled: false,
                    metadata: metadata("plugin-beta"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let subscription_id =
            uhost_types::AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .extension_subscriptions
            .create(
                subscription_id.as_str(),
                ExtensionSubscriptionRecord {
                    id: subscription_id.clone(),
                    plugin_id: plugin_alpha,
                    topic: String::from("lifecycle.rollout.advanced.v1"),
                    delivery_mode: String::from("at_least_once"),
                    retries_enabled: true,
                    metadata: metadata("subscription"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let task_id = uhost_types::AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .background_tasks
            .create(
                task_id.as_str(),
                BackgroundTaskRecord {
                    id: task_id.clone(),
                    plugin_id: plugin_beta,
                    task: String::from("sweep"),
                    timeout_seconds: 30,
                    max_concurrency: 2,
                    metadata: metadata("task"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .summary_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let summary: serde_json::Value = read_json(response).await;

        assert_eq!(summary["rollouts"]["total"], 2);
        assert_eq!(summary["migrations"]["total"], 3);
        assert_eq!(summary["migrations"]["pending"], 1);
        assert_eq!(summary["migrations"]["applied"], 1);
        assert_eq!(summary["migrations"]["failed"], 1);
        assert_eq!(summary["maintenance"]["total"], 2);
        assert_eq!(summary["maintenance"]["enabled"], 1);
        assert_eq!(summary["maintenance"]["disabled"], 1);
        assert_eq!(summary["dead_letters"]["total"], 2);
        assert_eq!(summary["dead_letters"]["pending_replay"], 1);
        assert_eq!(summary["dead_letters"]["replayed"], 1);
        assert_eq!(summary["repair_jobs"]["total"], 3);
        assert_eq!(summary["repair_jobs"]["completed"], 1);
        assert_eq!(summary["repair_jobs"]["failed"], 1);
        assert_eq!(summary["repair_jobs"]["active"], 1);
        assert_eq!(summary["extensions"]["plugins_total"], 2);
        assert_eq!(summary["extensions"]["plugins_enabled"], 1);
        assert_eq!(summary["extensions"]["event_subscriptions_total"], 1);
        assert_eq!(summary["extensions"]["background_tasks_total"], 1);

        let rollout_by_phase = summary["rollouts"]["by_phase"]
            .as_array()
            .unwrap_or_else(|| panic!("rollouts.by_phase should be an array"));
        let paused_count = rollout_by_phase
            .iter()
            .find(|entry| entry["name"] == "paused");
        assert_eq!(
            paused_count
                .and_then(|entry| entry["count"].as_u64())
                .unwrap_or(0),
            1
        );
        let planned_count = rollout_by_phase
            .iter()
            .find(|entry| entry["name"] == "planned");
        assert_eq!(
            planned_count
                .and_then(|entry| entry["count"].as_u64())
                .unwrap_or(0),
            1
        );
    }

    #[tokio::test]
    async fn rollout_plan_progresses_to_completed() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("ingress"),
                    channel: String::from("stable"),
                    canary_steps: vec![10, 50, 100],
                    compatibility_window_days: 14,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);
        let rollout_id = service
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));

        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let advanced = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("final ramp")),
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(advanced.status(), http::StatusCode::OK);

        let stored = service
            .rollouts
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout"));
        assert_eq!(stored.value.phase, "completed");
        assert_eq!(stored.value.current_traffic_percent, 100);

        let workflow = service
            .rollout_workflows
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.value.current_step_index, Some(2));
        assert!(
            workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );
    }

    #[tokio::test]
    async fn legacy_rollout_plans_are_backfilled_into_workflow_store() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let legacy_rollouts = DocumentStore::<super::RolloutPlanRecord>::open(
            temp.path().join("lifecycle").join("rollouts.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let rollout_id = RolloutPlanId::generate().unwrap_or_else(|error| panic!("{error}"));
        let record = super::RolloutPlanRecord {
            id: rollout_id.clone(),
            service: String::from("scheduler"),
            channel: String::from("canary"),
            canary_steps: vec![10, 50, 100],
            compatibility_window_days: 14,
            phase: String::from("paused"),
            current_step_index: 1,
            current_traffic_percent: 50,
            status_reason: Some(String::from("waiting for metrics")),
            last_mutation_kind: Some(String::from("pause")),
            last_mutation_idempotency_key: None,
            metadata: uhost_types::ResourceMetadata::new(
                uhost_types::OwnershipScope::Platform,
                Some(rollout_id.to_string()),
                uhost_core::sha256_hex(rollout_id.as_str().as_bytes()),
            ),
        };
        let _ = legacy_rollouts
            .create(rollout_id.as_str(), record.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflow = service
            .rollout_workflows
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow"));
        assert_eq!(workflow.value.phase, WorkflowPhase::Paused);
        assert_eq!(workflow.value.state, record);
        assert_eq!(workflow.value.current_step_index, Some(1));
        assert_eq!(workflow.value.steps[0].state, WorkflowStepState::Completed);
        assert_eq!(workflow.value.steps[1].state, WorkflowStepState::Active);
    }

    #[tokio::test]
    async fn rollout_projection_records_do_not_rehydrate_workflows_after_bootstrap() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("ingress"),
                    channel: String::from("stable"),
                    canary_steps: vec![10, 100],
                    compatibility_window_days: 14,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let legacy_projection_id =
            RolloutPlanId::generate().unwrap_or_else(|error| panic!("{error}"));
        let legacy_projection = super::RolloutPlanRecord {
            id: legacy_projection_id.clone(),
            service: String::from("scheduler"),
            channel: String::from("canary"),
            canary_steps: vec![25, 100],
            compatibility_window_days: 7,
            phase: String::from("planned"),
            current_step_index: 0,
            current_traffic_percent: 0,
            status_reason: None,
            last_mutation_kind: None,
            last_mutation_idempotency_key: None,
            metadata: uhost_types::ResourceMetadata::new(
                uhost_types::OwnershipScope::Platform,
                Some(legacy_projection_id.to_string()),
                uhost_core::sha256_hex(legacy_projection_id.as_str().as_bytes()),
            ),
        };
        let _ = service
            .rollouts
            .create(legacy_projection_id.as_str(), legacy_projection.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow_count = reopened
            .rollout_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        assert_eq!(workflow_count, 1);
        assert!(
            reopened
                .rollout_workflows
                .get(legacy_projection_id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none(),
            "projection-only rollout should not recreate durable workflow state",
        );

        let error = reopened
            .mutate_rollout_plan(
                legacy_projection_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| {
                panic!("projection-only rollout metadata should not be treated as executable state")
            });
        assert_eq!(error.code, uhost_core::ErrorCode::NotFound);

        let projection = reopened
            .rollouts
            .get(legacy_projection_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout projection"));
        assert_eq!(projection.value, legacy_projection);
    }

    #[tokio::test]
    async fn rollout_workflow_updates_reject_stale_versions_across_handles() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service_a = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service_a
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("ingress"),
                    channel: String::from("stable"),
                    canary_steps: vec![25, 100],
                    compatibility_window_days: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollout_id = service_a
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));

        let service_b = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_a = service_a
            .rollout_workflows
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow"));
        let stored_b = service_b
            .rollout_workflows
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow"));

        let mut updated_by_b = stored_b.value.clone();
        updated_by_b.touch();
        updated_by_b.state.status_reason = Some(String::from("updated by handle b"));
        let updated = service_b
            .rollout_workflows
            .upsert(rollout_id.as_str(), updated_by_b, Some(stored_b.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(updated.version, stored_b.version + 1);

        let mut stale_write = stored_a.value.clone();
        stale_write.touch();
        stale_write.state.status_reason = Some(String::from("stale write"));
        let error = service_a
            .rollout_workflows
            .upsert(rollout_id.as_str(), stale_write, Some(stored_a.version))
            .await
            .expect_err("stale workflow version should fail");
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn running_rollout_reconciliation_sets_due_attempt_and_heartbeats_claims() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created: super::RolloutPlanRecord = read_json(
            service
                .create_rollout_plan(
                    CreateRolloutRequest {
                        service: String::from("ingress"),
                        channel: String::from("stable"),
                        canary_steps: vec![10, 50, 100],
                        compatibility_window_days: 14,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        service
            .mutate_rollout_plan(
                created.id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("resume after restart")),
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first = reopened
            .rollout_workflows
            .get(created.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow after reconciliation"));
        assert_eq!(first.value.phase, WorkflowPhase::Running);
        let first_claim = first
            .value
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing rollout reconciler claim"));
        assert_eq!(first_claim.runner_id, super::ROLLOUT_RECONCILER_RUNNER_ID);
        assert_eq!(
            first.value.next_attempt_at,
            Some(first_claim.last_heartbeat_at)
        );

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let reopened_again = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = reopened_again
            .rollout_workflows
            .get(created.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout workflow after heartbeat"));
        let second_claim = second
            .value
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing heartbeated rollout claim"));
        assert_eq!(second_claim.runner_id, super::ROLLOUT_RECONCILER_RUNNER_ID);
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
    async fn rollout_plan_rejects_unknown_channel_and_duplicate_steps() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let blocked = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("ingress"),
                    channel: String::from("beta"),
                    canary_steps: vec![10, 50, 100],
                    compatibility_window_days: 14,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected invalid channel rejection"));
        assert_eq!(blocked.code, uhost_core::ErrorCode::InvalidInput);

        let duplicate_steps = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("scheduler"),
                    channel: String::from("stable"),
                    canary_steps: vec![10, 10, 100],
                    compatibility_window_days: 7,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate canary step rejection"));
        assert_eq!(duplicate_steps.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn paused_rollout_rejects_advance_until_resumed() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("scheduler"),
                    channel: String::from("canary"),
                    canary_steps: vec![5, 25, 100],
                    compatibility_window_days: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollout_id = service
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));

        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("waiting for metrics")),
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Pause,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let blocked = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected paused rollout advance rejection"));
        assert_eq!(blocked.code, uhost_core::ErrorCode::Conflict);
        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Resume,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let resumed_advance = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resumed_advance.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn rollout_advance_is_idempotent_with_same_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("scheduler"),
                    channel: String::from("canary"),
                    canary_steps: vec![5, 25, 100],
                    compatibility_window_days: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollout_id = service
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));

        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Start,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_advance = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("canary step")),
                    idempotency_key: Some(String::from("adv-1")),
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_advance.status(), http::StatusCode::OK);
        let after_first = service
            .rollouts
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout"));

        let second_advance = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("canary step")),
                    idempotency_key: Some(String::from("adv-1")),
                },
                super::RolloutMutationKind::Advance,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_advance.status(), http::StatusCode::OK);
        let after_second = service
            .rollouts
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout"));

        assert_eq!(
            after_first.value.current_step_index,
            after_second.value.current_step_index
        );
        assert_eq!(
            after_first.value.current_traffic_percent,
            after_second.value.current_traffic_percent
        );
    }

    #[tokio::test]
    async fn rollback_requires_reason_and_sets_zero_traffic() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = LifecycleService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_rollout_plan(
                CreateRolloutRequest {
                    service: String::from("netsec"),
                    channel: String::from("preview"),
                    canary_steps: vec![20, 100],
                    compatibility_window_days: 5,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollout_id = service
            .rollouts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing rollout plan"));

        let missing_reason = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: None,
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Rollback,
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected missing rollback reason rejection"));
        assert_eq!(missing_reason.code, uhost_core::ErrorCode::InvalidInput);

        let _ = service
            .mutate_rollout_plan(
                rollout_id.as_str(),
                RolloutActionRequest {
                    reason: Some(String::from("rollback due to elevated error rate")),
                    idempotency_key: None,
                },
                super::RolloutMutationKind::Rollback,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored = service
            .rollouts
            .get(rollout_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing rollout"));
        assert_eq!(stored.value.phase, "rolled_back");
        assert_eq!(stored.value.current_traffic_percent, 0);
    }

    proptest! {
        #[test]
        fn validate_canary_steps_accepts_sorted_sequences(mut values in proptest::collection::vec(1_u8..100_u8, 1..10)) {
            values.sort_unstable();
            values.dedup();
            if *values.last().unwrap_or(&100_u8) != 100 {
                values.push(100);
            }
            let result = super::validate_canary_steps(&values);
            prop_assert!(result.is_ok());
        }
    }
}
