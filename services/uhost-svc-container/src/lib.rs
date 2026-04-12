//! Container-family orchestration service.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use getrandom::fill as fill_random;
use http::header::{HeaderMap, HeaderName, HeaderValue, IF_MATCH};
use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tokio::fs;
use uhost_api::{ApiBody, empty_response, json_response, parse_json, path_segments, with_etag};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex, validate_slug};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, OutboxMessage, StoredDocument};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, NodeId, OwnershipScope, PlatformEvent,
    ProjectId, ResourceLifecycleState, ResourceMetadata, ServiceEvent, WorkloadId,
};

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const RECORD_VERSION_HEADER: HeaderName = HeaderName::from_static("x-record-version");
const CONTAINER_EVENTS_TOPIC: &str = "container.events.v1";
const CONTAINER_RECONCILED_EVENT_TYPE: &str = "container.workload.reconciled.v1";
const CONTAINER_RETIRED_EVENT_TYPE: &str = "container.workload.reconciliation_retired.v1";
const RECONCILE_SYSTEM_CORRELATION_ID: &str = "container.reconciler.system";
const LEGACY_CLUSTER_NODE_POOL_ANNOTATION: &str = "container.cluster_legacy_id";
const DEFAULT_SCHEDULER_POOL: &str = "general";

/// Reconciliation status derived from the current container intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadReconciliationState {
    /// The workload is admitted and ready for downstream scheduler placement.
    Planned,
    /// The workload cannot currently be handed to a scheduler safely.
    Blocked,
}

impl WorkloadReconciliationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Blocked => "blocked",
        }
    }

    fn metadata_lifecycle(self) -> ResourceLifecycleState {
        match self {
            Self::Planned => ResourceLifecycleState::Ready,
            Self::Blocked => ResourceLifecycleState::Failed,
        }
    }
}

/// Local identifier for one admitted container cluster.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerClusterId(String);

impl ContainerClusterId {
    /// Stable prefix used by cluster identifiers.
    pub const PREFIX: &'static str = "cls";

    /// Generate a new identifier.
    pub fn generate() -> std::result::Result<Self, ContainerClusterIdError> {
        let mut random = [0_u8; 10];
        fill_random(&mut random)
            .map_err(|error| ContainerClusterIdError::RandomnessUnavailable(error.to_string()))?;

        let timestamp = OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_le_bytes();
        let mut combined = [0_u8; 18];
        combined[..8].copy_from_slice(&timestamp[..8]);
        combined[8..].copy_from_slice(&random);

        Ok(Self(format!(
            "{}_{}",
            Self::PREFIX,
            encode_base32(&combined)
        )))
    }

    /// Parse and validate an existing cluster identifier.
    pub fn parse(value: impl Into<String>) -> std::result::Result<Self, ContainerClusterIdError> {
        Self::try_from(value.into())
    }

    /// Borrow the stable string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ContainerClusterId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContainerClusterId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<ContainerClusterId> for String {
    fn from(value: ContainerClusterId) -> Self {
        value.0
    }
}

impl TryFrom<String> for ContainerClusterId {
    type Error = ContainerClusterIdError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let Some((prefix, body)) = value.split_once('_') else {
            return Err(ContainerClusterIdError::InvalidShape(value));
        };
        if prefix != Self::PREFIX {
            return Err(ContainerClusterIdError::InvalidPrefix {
                expected: Self::PREFIX,
                actual: value,
            });
        }
        if body.is_empty() {
            return Err(ContainerClusterIdError::InvalidShape(format!("{prefix}_")));
        }
        for character in body.chars() {
            if !character.is_ascii_lowercase()
                && !matches!(character, '2' | '3' | '4' | '5' | '6' | '7')
            {
                return Err(ContainerClusterIdError::InvalidCharacter(character));
            }
        }
        Ok(Self(format!("{prefix}_{body}")))
    }
}

/// Failure modes for local cluster identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerClusterIdError {
    /// Prefix did not match `cls`.
    InvalidPrefix {
        /// Expected stable prefix.
        expected: &'static str,
        /// Original input value.
        actual: String,
    },
    /// Identifier did not match the `<prefix>_<body>` shape.
    InvalidShape(String),
    /// Identifier body used unsupported characters.
    InvalidCharacter(char),
    /// Secure randomness was unavailable from the host.
    RandomnessUnavailable(String),
}

impl fmt::Display for ContainerClusterIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix { expected, actual } => {
                write!(formatter, "expected id prefix `{expected}`, got `{actual}`")
            }
            Self::InvalidShape(value) => write!(formatter, "invalid identifier shape `{value}`"),
            Self::InvalidCharacter(character) => {
                write!(formatter, "invalid identifier character `{character}`")
            }
            Self::RandomnessUnavailable(message) => {
                write!(formatter, "randomness unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for ContainerClusterIdError {}

/// Local identifier for one durable container node pool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerNodePoolId(String);

impl ContainerNodePoolId {
    /// Stable prefix used by node-pool identifiers.
    pub const PREFIX: &'static str = "cnp";

    /// Generate a new identifier.
    pub fn generate() -> std::result::Result<Self, ContainerClusterIdError> {
        let mut random = [0_u8; 10];
        fill_random(&mut random)
            .map_err(|error| ContainerClusterIdError::RandomnessUnavailable(error.to_string()))?;

        let timestamp = OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_le_bytes();
        let mut combined = [0_u8; 18];
        combined[..8].copy_from_slice(&timestamp[..8]);
        combined[8..].copy_from_slice(&random);

        Ok(Self(format!(
            "{}_{}",
            Self::PREFIX,
            encode_base32(&combined)
        )))
    }

    /// Parse and validate an existing node-pool identifier.
    pub fn parse(value: impl Into<String>) -> std::result::Result<Self, ContainerClusterIdError> {
        Self::try_from(value.into())
    }

    /// Borrow the stable string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ContainerNodePoolId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContainerNodePoolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<ContainerNodePoolId> for String {
    fn from(value: ContainerNodePoolId) -> Self {
        value.0
    }
}

impl TryFrom<String> for ContainerNodePoolId {
    type Error = ContainerClusterIdError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let Some((prefix, body)) = value.split_once('_') else {
            return Err(ContainerClusterIdError::InvalidShape(value));
        };
        if prefix != Self::PREFIX {
            return Err(ContainerClusterIdError::InvalidPrefix {
                expected: Self::PREFIX,
                actual: value,
            });
        }
        if body.is_empty() {
            return Err(ContainerClusterIdError::InvalidShape(format!("{prefix}_")));
        }
        for character in body.chars() {
            if !character.is_ascii_lowercase()
                && !matches!(character, '2' | '3' | '4' | '5' | '6' | '7')
            {
                return Err(ContainerClusterIdError::InvalidCharacter(character));
            }
        }
        Ok(Self(format!("{prefix}_{body}")))
    }
}

/// Durable placement pool for container clusters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePoolRecord {
    pub id: ContainerNodePoolId,
    pub project_id: ProjectId,
    pub name: String,
    pub region: String,
    pub scheduler_pool: String,
    pub min_nodes: u16,
    pub desired_nodes: u16,
    pub max_nodes: u16,
    pub metadata: ResourceMetadata,
}

/// One container cluster admitted into the local control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRecord {
    pub id: ContainerClusterId,
    pub project_id: ProjectId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pool_id: Option<ContainerNodePoolId>,
    pub region: String,
    pub scheduler_pool: String,
    pub desired_nodes: u16,
    pub metadata: ResourceMetadata,
}

/// Execution shape for a container workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerExecutionClass {
    /// Long-lived service workloads.
    Service,
    /// Finite run-to-completion job workloads.
    Job,
}

impl ContainerExecutionClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Job => "job",
        }
    }
}

/// One container workload bound to a cluster declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerWorkloadRecord {
    pub id: WorkloadId,
    pub cluster_id: ContainerClusterId,
    pub project_id: ProjectId,
    pub name: String,
    pub image: String,
    pub desired_replicas: u32,
    pub execution_class: ContainerExecutionClass,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    pub metadata: ResourceMetadata,
}

/// Durable reconciliation record for one container workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadReconciliationRecord {
    pub workload_id: WorkloadId,
    pub cluster_id: ContainerClusterId,
    pub project_id: ProjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pool_id: Option<ContainerNodePoolId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pool_name: Option<String>,
    pub workload_name: String,
    pub image: String,
    pub desired_replicas: u32,
    pub execution_class: ContainerExecutionClass,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_pool: Option<String>,
    pub state: WorkloadReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub reconcile_digest: String,
    pub event_idempotency_key: String,
    pub reconciled_at: OffsetDateTime,
    pub metadata: ResourceMetadata,
}

/// Generic tally entry used by summary responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotalByValue {
    pub value: String,
    pub count: usize,
}

/// Per-cluster workload rollup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterWorkloadSummary {
    pub cluster_id: ContainerClusterId,
    pub project_id: ProjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pool_id: Option<ContainerNodePoolId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_pool_name: Option<String>,
    pub region: String,
    pub scheduler_pool: String,
    pub min_nodes: u16,
    pub desired_nodes: u16,
    pub max_nodes: u16,
    pub workload_count: usize,
    pub total_desired_replicas: u64,
}

/// Per-node-pool workload rollup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePoolWorkloadSummary {
    pub node_pool_id: ContainerNodePoolId,
    pub project_id: ProjectId,
    pub name: String,
    pub region: String,
    pub scheduler_pool: String,
    pub min_nodes: u16,
    pub desired_nodes: u16,
    pub max_nodes: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<ContainerClusterId>,
    pub workload_count: usize,
    pub total_desired_replicas: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchedulerNodeInventorySnapshot {
    id: NodeId,
    region: String,
    #[serde(default = "default_scheduler_pool")]
    scheduler_pool: String,
    cpu_millis: u32,
    memory_mb: u64,
    free_cpu_millis: u32,
    free_memory_mb: u64,
    #[serde(default)]
    drained: bool,
    metadata: ResourceMetadata,
}

/// Top-level container-family summary response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub node_pool_count: usize,
    pub cluster_count: usize,
    pub workload_count: usize,
    pub total_min_nodes: u64,
    pub total_desired_nodes: u64,
    pub total_max_nodes: u64,
    pub total_desired_replicas: u64,
    pub active_project_count: usize,
    pub execution_class_totals: Vec<TotalByValue>,
    pub region_totals: Vec<TotalByValue>,
    pub node_pool_summaries: Vec<NodePoolWorkloadSummary>,
    pub cluster_summaries: Vec<ClusterWorkloadSummary>,
}

/// Result of one reconciler pass over the current container workload set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ContainerReconcileSummary {
    pub reconciled_workloads: usize,
    pub created_records: usize,
    pub updated_records: usize,
    pub replayed_records: usize,
    pub retired_records: usize,
    pub blocked_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateClusterRequest {
    project_id: String,
    name: String,
    node_pool_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNodePoolRequest {
    project_id: String,
    name: String,
    region: String,
    scheduler_pool: String,
    min_nodes: u16,
    desired_nodes: u16,
    max_nodes: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateWorkloadRequest {
    cluster_id: String,
    project_id: String,
    name: String,
    image: String,
    desired_replicas: u32,
    #[serde(default)]
    execution_class: Option<ContainerExecutionClass>,
    #[serde(default)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileRecordChange {
    Created,
    Updated,
    Replayed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileWorkloadOutcome {
    change: ReconcileRecordChange,
    record: WorkloadReconciliationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesiredWorkloadReconciliation {
    workload_id: WorkloadId,
    cluster_id: ContainerClusterId,
    project_id: ProjectId,
    node_pool_id: Option<ContainerNodePoolId>,
    node_pool_name: Option<String>,
    workload_name: String,
    image: String,
    desired_replicas: u32,
    execution_class: ContainerExecutionClass,
    command: Vec<String>,
    region: Option<String>,
    scheduler_pool: Option<String>,
    state: WorkloadReconciliationState,
    detail: Option<String>,
    reconcile_digest: String,
    event_idempotency_key: String,
}

#[derive(Debug, Clone)]
struct ResolvedClusterPlacement {
    node_pool_id: Option<ContainerNodePoolId>,
    node_pool_name: Option<String>,
    region: String,
    scheduler_pool: String,
    min_nodes: u16,
    desired_nodes: u16,
    max_nodes: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchedulerPoolAvailability {
    scheduler_inventory_present: bool,
    matching_active_node_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconciliationEventKind {
    Reconciled,
    Retired,
}

impl ReconciliationEventKind {
    fn action(self) -> &'static str {
        match self {
            Self::Reconciled => "reconciled",
            Self::Retired => "retired",
        }
    }

    fn detail_key(self) -> &'static str {
        match self {
            Self::Reconciled => "event_idempotency_key",
            Self::Retired => "retired_idempotency_key",
        }
    }

    fn event_type(self) -> &'static str {
        match self {
            Self::Reconciled => CONTAINER_RECONCILED_EVENT_TYPE,
            Self::Retired => CONTAINER_RETIRED_EVENT_TYPE,
        }
    }

    fn idempotency_key(self, record: &WorkloadReconciliationRecord) -> String {
        match self {
            Self::Reconciled => record.event_idempotency_key.clone(),
            Self::Retired => retired_reconciliation_idempotency_key(record),
        }
    }
}

impl DesiredWorkloadReconciliation {
    fn from_records(
        workload: &ContainerWorkloadRecord,
        cluster: Option<&ClusterRecord>,
        node_pool: Option<&NodePoolRecord>,
        scheduler_pool_availability: Option<SchedulerPoolAvailability>,
    ) -> Self {
        let (state, detail, node_pool_id, node_pool_name, region, scheduler_pool) = match cluster {
            Some(cluster) if cluster.project_id != workload.project_id => (
                WorkloadReconciliationState::Blocked,
                Some(String::from(
                    "workload project_id does not match the active cluster project",
                )),
                cluster.node_pool_id.clone(),
                node_pool.map(|pool| pool.name.clone()),
                Some(cluster.region.clone()),
                Some(cluster.scheduler_pool.clone()),
            ),
            Some(cluster) => match (cluster.node_pool_id.as_ref(), node_pool) {
                (Some(pool_id), Some(pool)) if pool.project_id != cluster.project_id => (
                    WorkloadReconciliationState::Blocked,
                    Some(String::from(
                        "cluster node_pool project_id does not match the cluster project",
                    )),
                    Some(pool_id.clone()),
                    Some(pool.name.clone()),
                    Some(pool.region.clone()),
                    Some(pool.scheduler_pool.clone()),
                ),
                (Some(pool_id), Some(pool))
                    if scheduler_pool_availability.is_some_and(|availability| {
                        availability.scheduler_inventory_present
                            && availability.matching_active_node_count
                                < usize::from(pool.desired_nodes)
                    }) =>
                {
                    let availability = scheduler_pool_availability
                        .unwrap_or_else(|| panic!("scheduler availability should be present"));
                    (
                        WorkloadReconciliationState::Blocked,
                        Some(format!(
                            "node pool {} in region {} via scheduler pool {} requires {} active scheduler node(s) but only {} matching node(s) are registered",
                            pool.id,
                            pool.region,
                            pool.scheduler_pool,
                            pool.desired_nodes,
                            availability.matching_active_node_count
                        )),
                        Some(pool_id.clone()),
                        Some(pool.name.clone()),
                        Some(pool.region.clone()),
                        Some(pool.scheduler_pool.clone()),
                    )
                }
                (Some(pool_id), Some(pool)) => (
                    WorkloadReconciliationState::Planned,
                    Some(format!(
                        "workload is admitted to cluster {} on node pool {} in region {} via scheduler pool {}",
                        cluster.id, pool.id, pool.region, pool.scheduler_pool
                    )),
                    Some(pool_id.clone()),
                    Some(pool.name.clone()),
                    Some(pool.region.clone()),
                    Some(pool.scheduler_pool.clone()),
                ),
                (Some(pool_id), None) => (
                    WorkloadReconciliationState::Blocked,
                    Some(String::from(
                        "cluster references a missing or deleted node pool",
                    )),
                    Some(pool_id.clone()),
                    None,
                    Some(cluster.region.clone()),
                    Some(cluster.scheduler_pool.clone()),
                ),
                (None, _) => (
                    WorkloadReconciliationState::Blocked,
                    Some(String::from(
                        "cluster is not bound to a container node pool",
                    )),
                    None,
                    None,
                    Some(cluster.region.clone()),
                    Some(cluster.scheduler_pool.clone()),
                ),
            },
            None => (
                WorkloadReconciliationState::Blocked,
                Some(String::from(
                    "workload references a missing or deleted cluster",
                )),
                None,
                None,
                None,
                None,
            ),
        };
        let command_digest = sha256_hex(workload.command.join("\n").as_bytes());
        let reconcile_digest = sha256_hex(
            format!(
                "container-reconcile:v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                workload.id,
                workload.cluster_id,
                workload.project_id,
                node_pool_id
                    .as_ref()
                    .map(ContainerNodePoolId::as_str)
                    .unwrap_or("-"),
                node_pool_name.as_deref().unwrap_or("-"),
                workload.name,
                workload.image,
                workload.desired_replicas,
                workload.execution_class.as_str(),
                command_digest,
                state.as_str(),
                region.as_deref().unwrap_or("-"),
                scheduler_pool.as_deref().unwrap_or("-"),
            )
            .as_bytes(),
        );
        let event_idempotency_key =
            reconcile_event_idempotency_key(workload.id.as_str(), reconcile_digest.as_str());
        Self {
            workload_id: workload.id.clone(),
            cluster_id: workload.cluster_id.clone(),
            project_id: workload.project_id.clone(),
            node_pool_id,
            node_pool_name,
            workload_name: workload.name.clone(),
            image: workload.image.clone(),
            desired_replicas: workload.desired_replicas,
            execution_class: workload.execution_class,
            command: workload.command.clone(),
            region,
            scheduler_pool,
            state,
            detail,
            reconcile_digest,
            event_idempotency_key,
        }
    }

    fn into_record(
        self,
        existing: Option<&WorkloadReconciliationRecord>,
    ) -> WorkloadReconciliationRecord {
        let mut metadata = existing
            .map(|record| record.metadata.clone())
            .unwrap_or_else(|| {
                ResourceMetadata::new(
                    OwnershipScope::Project,
                    Some(self.workload_id.to_string()),
                    self.reconcile_digest.clone(),
                )
            });
        metadata.deleted_at = None;
        metadata.lifecycle = self.state.metadata_lifecycle();
        metadata.touch(self.reconcile_digest.clone());

        WorkloadReconciliationRecord {
            workload_id: self.workload_id,
            cluster_id: self.cluster_id,
            project_id: self.project_id,
            node_pool_id: self.node_pool_id,
            node_pool_name: self.node_pool_name,
            workload_name: self.workload_name,
            image: self.image,
            desired_replicas: self.desired_replicas,
            execution_class: self.execution_class,
            command: self.command,
            region: self.region,
            scheduler_pool: self.scheduler_pool,
            state: self.state,
            detail: self.detail,
            reconcile_digest: self.reconcile_digest,
            event_idempotency_key: self.event_idempotency_key,
            reconciled_at: OffsetDateTime::now_utc(),
            metadata,
        }
    }
}

/// File-backed service for the container workload family.
#[derive(Debug, Clone)]
pub struct ContainerService {
    node_pools: DocumentStore<NodePoolRecord>,
    clusters: DocumentStore<ClusterRecord>,
    workloads: DocumentStore<ContainerWorkloadRecord>,
    reconciliations: DocumentStore<WorkloadReconciliationRecord>,
    scheduler_nodes: DocumentStore<SchedulerNodeInventorySnapshot>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl ContainerService {
    /// Open or create the service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("container");
        let service = Self {
            node_pools: DocumentStore::open(root.join("node_pools.json")).await?,
            clusters: DocumentStore::open(root.join("clusters.json")).await?,
            workloads: DocumentStore::open(root.join("workloads.json")).await?,
            reconciliations: DocumentStore::open(root.join("reconciliations.json")).await?,
            scheduler_nodes: DocumentStore::open(
                state_root.as_ref().join("scheduler").join("nodes.json"),
            )
            .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.normalize_cluster_node_pools().await?;
        let _replayed = service.reconcile_all(None).await?;
        Ok(service)
    }

    async fn create_node_pool(&self, request: CreateNodePoolRequest) -> Result<Response<ApiBody>> {
        let project_id = parse_project_id(request.project_id, "project_id")?;
        let name = normalize_name(&request.name, "name")?;
        let region = normalize_slug_field(&request.region, "region")?;
        let scheduler_pool = normalize_slug_field(&request.scheduler_pool, "scheduler_pool")?;
        validate_node_pool_capacity(request.min_nodes, request.desired_nodes, request.max_nodes)?;

        if self
            .node_pools
            .list()
            .await?
            .into_iter()
            .any(|(_, stored)| {
                !stored.deleted
                    && stored.value.project_id == project_id
                    && stored.value.name.eq_ignore_ascii_case(&name)
            })
        {
            return Err(PlatformError::conflict(
                "node pool name already exists in project",
            ));
        }

        let id = ContainerNodePoolId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate node pool id")
                .with_detail(error.to_string())
        })?;
        let node_pool = NodePoolRecord {
            id: id.clone(),
            project_id,
            name,
            region,
            scheduler_pool,
            min_nodes: request.min_nodes,
            desired_nodes: request.desired_nodes,
            max_nodes: request.max_nodes,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let stored = self
            .node_pools
            .create(id.as_str(), node_pool.clone())
            .await?;
        entity_response(
            StatusCode::CREATED,
            &node_pool,
            &node_pool.metadata,
            stored.version,
        )
    }

    async fn create_cluster(&self, request: CreateClusterRequest) -> Result<Response<ApiBody>> {
        let project_id = parse_project_id(request.project_id, "project_id")?;
        let name = normalize_name(&request.name, "name")?;
        let node_pool_id = parse_node_pool_id(request.node_pool_id, "node_pool_id")?;

        if self.clusters.list().await?.into_iter().any(|(_, stored)| {
            !stored.deleted
                && stored.value.project_id == project_id
                && stored.value.name.eq_ignore_ascii_case(&name)
        }) {
            return Err(PlatformError::conflict(
                "cluster name already exists in project",
            ));
        }

        let node_pool = self.require_active_node_pool(&node_pool_id).await?;
        if node_pool.value.project_id != project_id {
            return Err(PlatformError::conflict(
                "cluster project_id does not match owning node pool",
            ));
        }
        if self.clusters.list().await?.into_iter().any(|(_, stored)| {
            !stored.deleted && stored.value.node_pool_id.as_ref() == Some(&node_pool_id)
        }) {
            return Err(PlatformError::conflict(
                "node pool is already attached to an active cluster",
            ));
        }

        let id = ContainerClusterId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate cluster id")
                .with_detail(error.to_string())
        })?;
        let cluster = ClusterRecord {
            id: id.clone(),
            project_id,
            name,
            node_pool_id: Some(node_pool_id),
            region: node_pool.value.region.clone(),
            scheduler_pool: node_pool.value.scheduler_pool.clone(),
            desired_nodes: node_pool.value.desired_nodes,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let stored = self.clusters.create(id.as_str(), cluster.clone()).await?;
        entity_response(
            StatusCode::CREATED,
            &cluster,
            &cluster.metadata,
            stored.version,
        )
    }

    async fn create_workload(
        &self,
        request: CreateWorkloadRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let cluster_id = parse_cluster_id(request.cluster_id, "cluster_id")?;
        let project_id = parse_project_id(request.project_id, "project_id")?;
        let name = normalize_name(&request.name, "name")?;
        let image = normalize_nonempty_trimmed(&request.image, "image")?;
        if request.desired_replicas == 0 {
            return Err(PlatformError::invalid(
                "desired_replicas must be greater than zero",
            ));
        }

        let cluster = self
            .clusters
            .get(cluster_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("cluster does not exist"))?;
        if cluster.value.project_id != project_id {
            return Err(PlatformError::conflict(
                "workload project_id does not match owning cluster",
            ));
        }
        if self.workloads.list().await?.into_iter().any(|(_, stored)| {
            !stored.deleted
                && stored.value.cluster_id == cluster_id
                && stored.value.name.eq_ignore_ascii_case(&name)
        }) {
            return Err(PlatformError::conflict(
                "workload name already exists in cluster",
            ));
        }

        let id = WorkloadId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate workload id")
                .with_detail(error.to_string())
        })?;
        let workload = ContainerWorkloadRecord {
            id: id.clone(),
            cluster_id,
            project_id,
            name,
            image,
            desired_replicas: request.desired_replicas,
            execution_class: request
                .execution_class
                .unwrap_or(ContainerExecutionClass::Service),
            command: normalize_command(request.command)?,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let stored = self.workloads.create(id.as_str(), workload.clone()).await?;
        let _reconciled = self
            .reconcile_workload(&stored.value, Some(context))
            .await?;
        entity_response(
            StatusCode::CREATED,
            &workload,
            &workload.metadata,
            stored.version,
        )
    }

    async fn list_active_node_pools(&self) -> Result<Vec<NodePoolRecord>> {
        Ok(self
            .node_pools
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect())
    }

    async fn list_active_clusters(&self) -> Result<Vec<ClusterRecord>> {
        Ok(self
            .clusters
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect())
    }

    async fn list_active_workloads(&self) -> Result<Vec<ContainerWorkloadRecord>> {
        Ok(self
            .workloads
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect())
    }

    async fn list_active_reconciliations(&self) -> Result<Vec<WorkloadReconciliationRecord>> {
        Ok(self
            .reconciliations
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect())
    }

    async fn list_outbox_messages(&self) -> Result<Vec<OutboxMessage<PlatformEvent>>> {
        self.outbox.list_all().await
    }

    async fn scheduler_pool_availability(
        &self,
        node_pool: &NodePoolRecord,
    ) -> Result<SchedulerPoolAvailability> {
        let scheduler_nodes = self.scheduler_nodes.list().await?;
        let scheduler_inventory_present = scheduler_nodes.iter().any(|(_, stored)| !stored.deleted);
        let matching_active_node_count = scheduler_nodes
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|node| !node.drained)
            .filter(|node| node.free_cpu_millis > 0)
            .filter(|node| node.free_memory_mb > 0)
            .filter(|node| node.region == node_pool.region)
            .filter(|node| node.scheduler_pool == node_pool.scheduler_pool)
            .count();
        Ok(SchedulerPoolAvailability {
            scheduler_inventory_present,
            matching_active_node_count,
        })
    }

    async fn require_active_node_pool(
        &self,
        node_pool_id: &ContainerNodePoolId,
    ) -> Result<StoredDocument<NodePoolRecord>> {
        self.node_pools
            .get(node_pool_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("node pool does not exist"))
    }

    async fn normalize_cluster_node_pools(&self) -> Result<()> {
        for (key, stored) in self.clusters.list().await? {
            if stored.deleted {
                continue;
            }
            let mut cluster = stored.value;
            let node_pool = match cluster.node_pool_id.as_ref() {
                Some(node_pool_id) => match self
                    .node_pools
                    .get(node_pool_id.as_str())
                    .await?
                    .filter(|stored| !stored.deleted)
                {
                    Some(stored) => stored.value,
                    None => self.build_legacy_node_pool_record(&cluster).await?,
                },
                None => self.build_legacy_node_pool_record(&cluster).await?,
            };

            let node_pool = self.ensure_node_pool_record(node_pool).await?;
            let mut changed = false;
            if cluster.node_pool_id.as_ref() != Some(&node_pool.id) {
                cluster.node_pool_id = Some(node_pool.id.clone());
                changed = true;
            }
            if cluster.region != node_pool.region {
                cluster.region = node_pool.region.clone();
                changed = true;
            }
            if cluster.scheduler_pool != node_pool.scheduler_pool {
                cluster.scheduler_pool = node_pool.scheduler_pool.clone();
                changed = true;
            }
            if cluster.desired_nodes != node_pool.desired_nodes {
                cluster.desired_nodes = node_pool.desired_nodes;
                changed = true;
            }

            if changed {
                cluster.metadata.touch(cluster_binding_etag(&cluster));
                let _updated = self
                    .clusters
                    .upsert(&key, cluster, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn ensure_node_pool_record(&self, candidate: NodePoolRecord) -> Result<NodePoolRecord> {
        if let Some(existing) = self
            .node_pools
            .get(candidate.id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
        {
            return Ok(existing.value);
        }

        if let Some(existing) = self
            .node_pools
            .list()
            .await?
            .into_iter()
            .find_map(|(_, stored)| {
                (!stored.deleted
                    && stored
                        .value
                        .metadata
                        .annotations
                        .get(LEGACY_CLUSTER_NODE_POOL_ANNOTATION)
                        == candidate
                            .metadata
                            .annotations
                            .get(LEGACY_CLUSTER_NODE_POOL_ANNOTATION))
                .then_some(stored.value)
            })
        {
            return Ok(existing);
        }

        let _created = self
            .node_pools
            .upsert(candidate.id.as_str(), candidate.clone(), None)
            .await?;
        Ok(candidate)
    }

    async fn build_legacy_node_pool_record(
        &self,
        cluster: &ClusterRecord,
    ) -> Result<NodePoolRecord> {
        let id = match cluster.node_pool_id.clone() {
            Some(node_pool_id) => node_pool_id,
            None => ContainerNodePoolId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate migrated node pool id")
                    .with_detail(error.to_string())
            })?,
        };
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            sha256_hex(id.as_str().as_bytes()),
        );
        metadata.annotations.insert(
            String::from(LEGACY_CLUSTER_NODE_POOL_ANNOTATION),
            cluster.id.to_string(),
        );
        Ok(NodePoolRecord {
            id,
            project_id: cluster.project_id.clone(),
            name: derived_legacy_node_pool_name(cluster),
            region: cluster.region.clone(),
            scheduler_pool: cluster.scheduler_pool.clone(),
            min_nodes: cluster.desired_nodes,
            desired_nodes: cluster.desired_nodes,
            max_nodes: cluster.desired_nodes,
            metadata,
        })
    }

    async fn get_node_pool(&self, node_pool_id: &str) -> Result<Response<ApiBody>> {
        let node_pool_id = parse_node_pool_id(node_pool_id.to_owned(), "node_pool_id")?;
        let stored = self.require_active_node_pool(&node_pool_id).await?;
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn read_audit_events(&self) -> Result<Vec<PlatformEvent>> {
        let audit_path = self.state_root.join("audit.log");
        let payload = match fs::read(&audit_path).await {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to read container audit log")
                        .with_detail(error.to_string()),
                );
            }
        };

        let mut events = Vec::new();
        for line in payload.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_slice::<PlatformEvent>(line).map_err(|error| {
                PlatformError::unavailable("failed to decode container audit log record")
                    .with_detail(error.to_string())
            })?;
            events.push(event);
        }
        Ok(events)
    }

    async fn get_cluster(&self, cluster_id: &str) -> Result<Response<ApiBody>> {
        let cluster_id = parse_cluster_id(cluster_id.to_owned(), "cluster_id")?;
        let stored = self
            .clusters
            .get(cluster_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("cluster does not exist"))?;
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn get_workload(&self, workload_id: &str) -> Result<Response<ApiBody>> {
        let workload_id = WorkloadId::parse(workload_id.trim().to_owned()).map_err(|error| {
            PlatformError::invalid("invalid workload_id").with_detail(error.to_string())
        })?;
        let stored = self
            .workloads
            .get(workload_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("workload does not exist"))?;
        entity_response(
            StatusCode::OK,
            &stored.value,
            &stored.value.metadata,
            stored.version,
        )
    }

    async fn delete_node_pool(
        &self,
        node_pool_id: &str,
        headers: &HeaderMap,
    ) -> Result<Response<ApiBody>> {
        let node_pool_id = parse_node_pool_id(node_pool_id.to_owned(), "node_pool_id")?;
        let stored = self.require_active_node_pool(&node_pool_id).await?;
        assert_matches_concurrency(headers, &stored)?;

        if self.clusters.list().await?.into_iter().any(|(_, cluster)| {
            !cluster.deleted && cluster.value.node_pool_id.as_ref() == Some(&node_pool_id)
        }) {
            return Err(PlatformError::conflict(
                "node pool is still attached to an active cluster",
            ));
        }

        let updated = mark_deleted_node_pool(stored.value.clone(), node_pool_id.as_str());
        let updated = self
            .node_pools
            .upsert(node_pool_id.as_str(), updated, Some(stored.version))
            .await?;
        self.node_pools
            .soft_delete(node_pool_id.as_str(), Some(updated.version))
            .await?;
        empty_response(StatusCode::NO_CONTENT)
    }

    async fn delete_cluster(
        &self,
        cluster_id: &str,
        headers: &HeaderMap,
    ) -> Result<Response<ApiBody>> {
        let cluster_id = parse_cluster_id(cluster_id.to_owned(), "cluster_id")?;
        let stored = self
            .clusters
            .get(cluster_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("cluster does not exist"))?;
        assert_matches_concurrency(headers, &stored)?;

        if self
            .workloads
            .list()
            .await?
            .into_iter()
            .any(|(_, workload)| !workload.deleted && workload.value.cluster_id == cluster_id)
        {
            return Err(PlatformError::conflict(
                "cluster still has active workloads attached",
            ));
        }

        let updated = mark_deleted_cluster(stored.value.clone(), cluster_id.as_str());
        let updated = self
            .clusters
            .upsert(cluster_id.as_str(), updated, Some(stored.version))
            .await?;
        self.clusters
            .soft_delete(cluster_id.as_str(), Some(updated.version))
            .await?;
        empty_response(StatusCode::NO_CONTENT)
    }

    async fn delete_workload(
        &self,
        workload_id: &str,
        headers: &HeaderMap,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let workload_id = WorkloadId::parse(workload_id.trim().to_owned()).map_err(|error| {
            PlatformError::invalid("invalid workload_id").with_detail(error.to_string())
        })?;
        let stored = self
            .workloads
            .get(workload_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("workload does not exist"))?;
        assert_matches_concurrency(headers, &stored)?;

        let updated = mark_deleted_workload(stored.value.clone(), workload_id.as_str());
        let updated = self
            .workloads
            .upsert(workload_id.as_str(), updated, Some(stored.version))
            .await?;
        self.workloads
            .soft_delete(workload_id.as_str(), Some(updated.version))
            .await?;
        self.retire_reconciliation_for_workload(workload_id.as_str(), Some(context))
            .await?;
        empty_response(StatusCode::NO_CONTENT)
    }

    async fn summary(&self) -> Result<ContainerSummary> {
        let node_pools = self.list_active_node_pools().await?;
        let clusters = self.list_active_clusters().await?;
        let workloads = self.list_active_workloads().await?;
        let node_pools_by_id = node_pools
            .iter()
            .map(|node_pool| (node_pool.id.clone(), node_pool))
            .collect::<BTreeMap<_, _>>();

        let mut projects = BTreeSet::new();
        let mut region_totals = BTreeMap::<String, usize>::new();
        for node_pool in &node_pools {
            projects.insert(node_pool.project_id.clone());
            *region_totals.entry(node_pool.region.clone()).or_default() += 1;
        }
        for cluster in &clusters {
            projects.insert(cluster.project_id.clone());
        }

        let mut execution_class_totals = BTreeMap::<String, usize>::new();
        let mut workloads_by_cluster =
            BTreeMap::<ContainerClusterId, Vec<&ContainerWorkloadRecord>>::new();
        let mut total_desired_replicas = 0_u64;
        for workload in &workloads {
            projects.insert(workload.project_id.clone());
            *execution_class_totals
                .entry(workload.execution_class.as_str().to_owned())
                .or_default() += 1;
            workloads_by_cluster
                .entry(workload.cluster_id.clone())
                .or_default()
                .push(workload);
            total_desired_replicas =
                total_desired_replicas.saturating_add(u64::from(workload.desired_replicas));
        }

        let cluster_by_node_pool = clusters
            .iter()
            .filter_map(|cluster| {
                cluster
                    .node_pool_id
                    .as_ref()
                    .map(|node_pool_id| (node_pool_id.clone(), cluster))
            })
            .collect::<BTreeMap<_, _>>();

        let total_min_nodes = node_pools
            .iter()
            .fold(0_u64, |total, pool| total + u64::from(pool.min_nodes));
        let total_desired_nodes = node_pools
            .iter()
            .fold(0_u64, |total, pool| total + u64::from(pool.desired_nodes));
        let total_max_nodes = node_pools
            .iter()
            .fold(0_u64, |total, pool| total + u64::from(pool.max_nodes));

        let mut node_pool_summaries = Vec::new();
        for node_pool in &node_pools {
            let attached_cluster = cluster_by_node_pool.get(&node_pool.id).copied();
            let cluster_workloads = attached_cluster
                .and_then(|cluster| workloads_by_cluster.get(&cluster.id))
                .cloned()
                .unwrap_or_default();
            let replicas = cluster_workloads.iter().fold(0_u64, |total, workload| {
                total.saturating_add(u64::from(workload.desired_replicas))
            });
            node_pool_summaries.push(NodePoolWorkloadSummary {
                node_pool_id: node_pool.id.clone(),
                project_id: node_pool.project_id.clone(),
                name: node_pool.name.clone(),
                region: node_pool.region.clone(),
                scheduler_pool: node_pool.scheduler_pool.clone(),
                min_nodes: node_pool.min_nodes,
                desired_nodes: node_pool.desired_nodes,
                max_nodes: node_pool.max_nodes,
                cluster_id: attached_cluster.map(|cluster| cluster.id.clone()),
                workload_count: cluster_workloads.len(),
                total_desired_replicas: replicas,
            });
        }

        let mut cluster_summaries = Vec::new();
        for cluster in &clusters {
            let placement = cluster
                .node_pool_id
                .as_ref()
                .and_then(|node_pool_id| node_pools_by_id.get(node_pool_id))
                .map_or_else(
                    || ResolvedClusterPlacement {
                        node_pool_id: cluster.node_pool_id.clone(),
                        node_pool_name: None,
                        region: cluster.region.clone(),
                        scheduler_pool: cluster.scheduler_pool.clone(),
                        min_nodes: cluster.desired_nodes,
                        desired_nodes: cluster.desired_nodes,
                        max_nodes: cluster.desired_nodes,
                    },
                    |node_pool| ResolvedClusterPlacement {
                        node_pool_id: Some(node_pool.id.clone()),
                        node_pool_name: Some(node_pool.name.clone()),
                        region: node_pool.region.clone(),
                        scheduler_pool: node_pool.scheduler_pool.clone(),
                        min_nodes: node_pool.min_nodes,
                        desired_nodes: node_pool.desired_nodes,
                        max_nodes: node_pool.max_nodes,
                    },
                );
            let Some(cluster_workloads) = workloads_by_cluster.get(&cluster.id) else {
                cluster_summaries.push(ClusterWorkloadSummary {
                    cluster_id: cluster.id.clone(),
                    project_id: cluster.project_id.clone(),
                    node_pool_id: placement.node_pool_id,
                    node_pool_name: placement.node_pool_name,
                    region: placement.region,
                    scheduler_pool: placement.scheduler_pool,
                    min_nodes: placement.min_nodes,
                    desired_nodes: placement.desired_nodes,
                    max_nodes: placement.max_nodes,
                    workload_count: 0,
                    total_desired_replicas: 0,
                });
                continue;
            };

            let replicas = cluster_workloads.iter().fold(0_u64, |total, workload| {
                total.saturating_add(u64::from(workload.desired_replicas))
            });
            cluster_summaries.push(ClusterWorkloadSummary {
                cluster_id: cluster.id.clone(),
                project_id: cluster.project_id.clone(),
                node_pool_id: placement.node_pool_id,
                node_pool_name: placement.node_pool_name,
                region: placement.region,
                scheduler_pool: placement.scheduler_pool,
                min_nodes: placement.min_nodes,
                desired_nodes: placement.desired_nodes,
                max_nodes: placement.max_nodes,
                workload_count: cluster_workloads.len(),
                total_desired_replicas: replicas,
            });
        }

        Ok(ContainerSummary {
            node_pool_count: node_pools.len(),
            cluster_count: clusters.len(),
            workload_count: workloads.len(),
            total_min_nodes,
            total_desired_nodes,
            total_max_nodes,
            total_desired_replicas,
            active_project_count: projects.len(),
            execution_class_totals: map_to_totals(execution_class_totals),
            region_totals: map_to_totals(region_totals),
            node_pool_summaries,
            cluster_summaries,
        })
    }

    async fn reconcile_all(
        &self,
        context: Option<&RequestContext>,
    ) -> Result<ContainerReconcileSummary> {
        let active_workloads = self
            .workloads
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let active_ids = active_workloads
            .iter()
            .map(|workload| workload.id.clone())
            .collect::<BTreeSet<_>>();

        let mut summary = ContainerReconcileSummary::default();
        for workload in &active_workloads {
            let outcome = self.reconcile_workload(workload, context).await?;
            summary.reconciled_workloads = summary.reconciled_workloads.saturating_add(1);
            match outcome.change {
                ReconcileRecordChange::Created => {
                    summary.created_records = summary.created_records.saturating_add(1);
                }
                ReconcileRecordChange::Updated => {
                    summary.updated_records = summary.updated_records.saturating_add(1);
                }
                ReconcileRecordChange::Replayed => {
                    summary.replayed_records = summary.replayed_records.saturating_add(1);
                }
            }
            if outcome.record.state == WorkloadReconciliationState::Blocked {
                summary.blocked_records = summary.blocked_records.saturating_add(1);
            }
        }

        for (_, stored) in self.reconciliations.list().await? {
            if active_ids.contains(&stored.value.workload_id) && !stored.deleted {
                continue;
            }
            if self.ensure_retired_reconciliation(stored, context).await? {
                summary.retired_records = summary.retired_records.saturating_add(1);
            }
        }

        Ok(summary)
    }

    async fn reconcile_workload(
        &self,
        workload: &ContainerWorkloadRecord,
        context: Option<&RequestContext>,
    ) -> Result<ReconcileWorkloadOutcome> {
        let cluster = self
            .clusters
            .get(workload.cluster_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value);
        let node_pool = match cluster
            .as_ref()
            .and_then(|cluster| cluster.node_pool_id.as_ref())
        {
            Some(node_pool_id) => self
                .node_pools
                .get(node_pool_id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .map(|stored| stored.value),
            None => None,
        };
        let scheduler_pool_availability = match node_pool.as_ref() {
            Some(node_pool) => Some(self.scheduler_pool_availability(node_pool).await?),
            None => None,
        };
        let desired = DesiredWorkloadReconciliation::from_records(
            workload,
            cluster.as_ref(),
            node_pool.as_ref(),
            scheduler_pool_availability,
        );
        let existing = self.reconciliations.get(workload.id.as_str()).await?;
        let (change, record) = match existing.as_ref() {
            Some(stored)
                if workload_reconciliation_matches(&stored.value, &desired) && !stored.deleted =>
            {
                (ReconcileRecordChange::Replayed, stored.value.clone())
            }
            Some(stored) => {
                let record = desired.clone().into_record(Some(&stored.value));
                let _updated = self
                    .reconciliations
                    .upsert(workload.id.as_str(), record.clone(), Some(stored.version))
                    .await?;
                (ReconcileRecordChange::Updated, record)
            }
            None => {
                let record = desired.clone().into_record(None);
                let _created = self
                    .reconciliations
                    .create(workload.id.as_str(), record.clone())
                    .await?;
                (ReconcileRecordChange::Created, record)
            }
        };

        self.emit_reconciliation_event(&record, context).await?;
        Ok(ReconcileWorkloadOutcome { change, record })
    }

    async fn emit_reconciliation_event(
        &self,
        record: &WorkloadReconciliationRecord,
        context: Option<&RequestContext>,
    ) -> Result<()> {
        self.ensure_reconciliation_side_effects(
            record,
            ReconciliationEventKind::Reconciled,
            context,
        )
        .await
    }

    async fn retire_reconciliation_for_workload(
        &self,
        workload_id: &str,
        context: Option<&RequestContext>,
    ) -> Result<bool> {
        let Some(stored) = self.reconciliations.get(workload_id).await? else {
            return Ok(false);
        };
        self.ensure_retired_reconciliation(stored, context).await
    }

    async fn ensure_retired_reconciliation(
        &self,
        stored: StoredDocument<WorkloadReconciliationRecord>,
        context: Option<&RequestContext>,
    ) -> Result<bool> {
        self.ensure_reconciliation_side_effects(
            &stored.value,
            ReconciliationEventKind::Retired,
            context,
        )
        .await?;
        if stored.deleted {
            return Ok(false);
        }

        let key = stored.value.workload_id.to_string();
        let updated = mark_deleted_reconciliation(stored.value, key.as_str());
        let updated = self
            .reconciliations
            .upsert(key.as_str(), updated, Some(stored.version))
            .await?;
        self.reconciliations
            .soft_delete(key.as_str(), Some(updated.version))
            .await?;
        Ok(true)
    }

    async fn ensure_reconciliation_side_effects(
        &self,
        record: &WorkloadReconciliationRecord,
        event_kind: ReconciliationEventKind,
        context: Option<&RequestContext>,
    ) -> Result<()> {
        let idempotency_key = event_kind.idempotency_key(record);
        let existing_outbox = self
            .find_reconciliation_outbox_event(idempotency_key.as_str())
            .await?;
        let existing_audit = self
            .find_reconciliation_audit_event(record, event_kind)
            .await?;
        let event = match (existing_audit.clone(), existing_outbox.clone()) {
            (Some(event), _) | (None, Some(event)) => event,
            (None, None) => build_container_reconciliation_event(record, event_kind, context)?,
        };

        if existing_audit.is_none() {
            self.audit_log.append(&event).await?;
        }
        if existing_outbox.is_none() {
            let _message = self
                .outbox
                .enqueue(
                    CONTAINER_EVENTS_TOPIC,
                    event,
                    Some(idempotency_key.as_str()),
                )
                .await?;
        }
        Ok(())
    }

    async fn find_reconciliation_outbox_event(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        Ok(self
            .outbox
            .list_all()
            .await?
            .into_iter()
            .find_map(|message| {
                (message.topic == CONTAINER_EVENTS_TOPIC
                    && message.idempotency_key.as_deref() == Some(idempotency_key))
                .then_some(message.payload)
            }))
    }

    async fn find_reconciliation_audit_event(
        &self,
        record: &WorkloadReconciliationRecord,
        event_kind: ReconciliationEventKind,
    ) -> Result<Option<PlatformEvent>> {
        let mut selected = None;
        for event in self.read_audit_events().await? {
            if reconciliation_event_matches_replay_candidate(&event, record, event_kind) {
                selected = Some(event);
            }
        }
        Ok(selected)
    }
}

impl HttpService for ContainerService {
    fn name(&self) -> &'static str {
        "container"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/container")];
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
            let headers = request.headers().clone();
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["container"]) => json_response(
                    StatusCode::OK,
                    &json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["container", "node-pools"]) => {
                    json_response(StatusCode::OK, &self.list_active_node_pools().await?).map(Some)
                }
                (Method::POST, ["container", "node-pools"]) => {
                    let body: CreateNodePoolRequest = parse_json(request).await?;
                    self.create_node_pool(body).await.map(Some)
                }
                (Method::GET, ["container", "node-pools", node_pool_id]) => {
                    self.get_node_pool(node_pool_id).await.map(Some)
                }
                (Method::DELETE, ["container", "node-pools", node_pool_id]) => self
                    .delete_node_pool(node_pool_id, &headers)
                    .await
                    .map(Some),
                (Method::GET, ["container", "clusters"]) => {
                    json_response(StatusCode::OK, &self.list_active_clusters().await?).map(Some)
                }
                (Method::POST, ["container", "clusters"]) => {
                    let body: CreateClusterRequest = parse_json(request).await?;
                    self.create_cluster(body).await.map(Some)
                }
                (Method::GET, ["container", "clusters", cluster_id]) => {
                    self.get_cluster(cluster_id).await.map(Some)
                }
                (Method::DELETE, ["container", "clusters", cluster_id]) => {
                    self.delete_cluster(cluster_id, &headers).await.map(Some)
                }
                (Method::GET, ["container", "workloads"]) => {
                    json_response(StatusCode::OK, &self.list_active_workloads().await?).map(Some)
                }
                (Method::POST, ["container", "workloads"]) => {
                    let body: CreateWorkloadRequest = parse_json(request).await?;
                    self.create_workload(body, &context).await.map(Some)
                }
                (Method::GET, ["container", "workloads", workload_id]) => {
                    self.get_workload(workload_id).await.map(Some)
                }
                (Method::DELETE, ["container", "workloads", workload_id]) => self
                    .delete_workload(workload_id, &headers, &context)
                    .await
                    .map(Some),
                (Method::GET, ["container", "reconciliations"]) => {
                    json_response(StatusCode::OK, &self.list_active_reconciliations().await?)
                        .map(Some)
                }
                (Method::POST, ["container", "reconcile"]) => {
                    let summary = self.reconcile_all(Some(&context)).await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["container", "outbox"]) => {
                    json_response(StatusCode::OK, &self.list_outbox_messages().await?).map(Some)
                }
                (Method::GET, ["container", "summary"]) => {
                    json_response(StatusCode::OK, &self.summary().await?).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut buffer = 0_u16;
    let mut bits = 0_u8;

    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;

        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
            bits -= 5;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }

    output
}

fn parse_project_id(value: String, field: &str) -> Result<ProjectId> {
    ProjectId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn parse_cluster_id(value: String, field: &str) -> Result<ContainerClusterId> {
    ContainerClusterId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn parse_node_pool_id(value: String, field: &str) -> Result<ContainerNodePoolId> {
    ContainerNodePoolId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn default_scheduler_pool() -> String {
    String::from(DEFAULT_SCHEDULER_POOL)
}

fn normalize_slug_field(value: &str, field: &str) -> Result<String> {
    validate_slug(&value.trim().to_ascii_lowercase()).map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn normalize_name(value: &str, field: &str) -> Result<String> {
    let trimmed = normalize_nonempty_trimmed(value, field)?;
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds maximum length of 128 bytes"
        )));
    }
    Ok(trimmed)
}

fn normalize_nonempty_trimmed(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    Ok(trimmed.to_owned())
}

fn normalize_command(command: Vec<String>) -> Result<Vec<String>> {
    command
        .into_iter()
        .map(|argument| normalize_nonempty_trimmed(&argument, "command"))
        .collect()
}

fn validate_node_pool_capacity(min_nodes: u16, desired_nodes: u16, max_nodes: u16) -> Result<()> {
    if min_nodes == 0 {
        return Err(PlatformError::invalid(
            "min_nodes must be greater than zero",
        ));
    }
    if desired_nodes == 0 {
        return Err(PlatformError::invalid(
            "desired_nodes must be greater than zero",
        ));
    }
    if max_nodes == 0 {
        return Err(PlatformError::invalid(
            "max_nodes must be greater than zero",
        ));
    }
    if min_nodes > desired_nodes {
        return Err(PlatformError::invalid(
            "min_nodes may not exceed desired_nodes",
        ));
    }
    if desired_nodes > max_nodes {
        return Err(PlatformError::invalid(
            "desired_nodes may not exceed max_nodes",
        ));
    }
    Ok(())
}

fn derived_legacy_node_pool_name(cluster: &ClusterRecord) -> String {
    let suffix = cluster
        .id
        .as_str()
        .split_once('_')
        .map_or(cluster.id.as_str(), |(_, body)| body);
    let suffix = &suffix[..suffix.len().min(8)];
    let reserved = "-pool-".len() + suffix.len();
    let max_cluster_name = 128_usize.saturating_sub(reserved);
    let mut base = cluster.name.clone();
    if base.len() > max_cluster_name {
        base.truncate(max_cluster_name);
    }
    format!("{base}-pool-{suffix}")
}

fn cluster_binding_etag(cluster: &ClusterRecord) -> String {
    sha256_hex(
        format!(
            "container.cluster.binding.v1|{}|{}|{}|{}|{}",
            cluster.id,
            cluster
                .node_pool_id
                .as_ref()
                .map(ContainerNodePoolId::as_str)
                .unwrap_or("-"),
            cluster.region,
            cluster.scheduler_pool,
            cluster.desired_nodes,
        )
        .as_bytes(),
    )
}

fn map_to_totals(input: BTreeMap<String, usize>) -> Vec<TotalByValue> {
    input
        .into_iter()
        .map(|(value, count)| TotalByValue { value, count })
        .collect()
}

fn workload_reconciliation_matches(
    existing: &WorkloadReconciliationRecord,
    desired: &DesiredWorkloadReconciliation,
) -> bool {
    existing.workload_id == desired.workload_id
        && existing.cluster_id == desired.cluster_id
        && existing.project_id == desired.project_id
        && existing.node_pool_id == desired.node_pool_id
        && existing.node_pool_name == desired.node_pool_name
        && existing.workload_name == desired.workload_name
        && existing.image == desired.image
        && existing.desired_replicas == desired.desired_replicas
        && existing.execution_class == desired.execution_class
        && existing.command == desired.command
        && existing.region == desired.region
        && existing.scheduler_pool == desired.scheduler_pool
        && existing.state == desired.state
        && existing.detail == desired.detail
        && existing.reconcile_digest == desired.reconcile_digest
        && existing.event_idempotency_key == desired.event_idempotency_key
}

fn reconcile_event_idempotency_key(workload_id: &str, reconcile_digest: &str) -> String {
    sha256_hex(format!("container.reconcile.event.v1|{workload_id}|{reconcile_digest}").as_bytes())
}

fn retired_reconciliation_idempotency_key(record: &WorkloadReconciliationRecord) -> String {
    sha256_hex(
        format!(
            "container.reconcile.retired.v1|{}|{}",
            record.workload_id, record.reconcile_digest
        )
        .as_bytes(),
    )
}

fn build_container_reconciliation_event(
    record: &WorkloadReconciliationRecord,
    event_kind: ReconciliationEventKind,
    context: Option<&RequestContext>,
) -> Result<PlatformEvent> {
    match event_kind {
        ReconciliationEventKind::Reconciled => build_reconciliation_event(record, context),
        ReconciliationEventKind::Retired => build_retired_reconciliation_event(record, context),
    }
}

fn reconciliation_event_matches_replay_candidate(
    event: &PlatformEvent,
    record: &WorkloadReconciliationRecord,
    event_kind: ReconciliationEventKind,
) -> bool {
    if event.header.event_type != event_kind.event_type() {
        return false;
    }
    let EventPayload::Service(service) = &event.payload else {
        return false;
    };
    if service.resource_kind != "container_workload_reconciliation"
        || service.resource_id != record.workload_id.as_str()
        || service.action != event_kind.action()
    {
        return false;
    }

    let idempotency_key = event_kind.idempotency_key(record);
    if service
        .details
        .get(event_kind.detail_key())
        .and_then(serde_json::Value::as_str)
        == Some(idempotency_key.as_str())
    {
        return true;
    }

    service
        .details
        .get("reconcile_digest")
        .and_then(serde_json::Value::as_str)
        == Some(record.reconcile_digest.as_str())
}

fn build_reconciliation_event(
    record: &WorkloadReconciliationRecord,
    context: Option<&RequestContext>,
) -> Result<PlatformEvent> {
    let event = PlatformEvent {
        header: EventHeader {
            event_id: AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate audit id")
                    .with_detail(error.to_string())
            })?,
            event_type: String::from(CONTAINER_RECONCILED_EVENT_TYPE),
            schema_version: 1,
            source_service: String::from("container"),
            emitted_at: OffsetDateTime::now_utc(),
            actor: reconcile_actor(context),
        },
        payload: EventPayload::Service(ServiceEvent {
            resource_kind: String::from("container_workload_reconciliation"),
            resource_id: record.workload_id.to_string(),
            action: String::from("reconciled"),
            details: json!({
                "workload_id": record.workload_id,
                "cluster_id": record.cluster_id,
                "project_id": record.project_id,
                "node_pool_id": record.node_pool_id,
                "node_pool_name": record.node_pool_name,
                "workload_name": record.workload_name,
                "image": record.image,
                "desired_replicas": record.desired_replicas,
                "execution_class": record.execution_class,
                "command": record.command,
                "region": record.region,
                "scheduler_pool": record.scheduler_pool,
                "state": record.state,
                "detail": record.detail,
                "reconcile_digest": record.reconcile_digest,
                "event_idempotency_key": record.event_idempotency_key,
                "reconciled_at": record.reconciled_at,
            }),
        }),
    };
    event.validate().map_err(|error| {
        PlatformError::invalid("invalid container reconciliation event")
            .with_detail(format!("{error:?}"))
    })?;
    Ok(event)
}

fn build_retired_reconciliation_event(
    record: &WorkloadReconciliationRecord,
    context: Option<&RequestContext>,
) -> Result<PlatformEvent> {
    let event = PlatformEvent {
        header: EventHeader {
            event_id: AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate audit id")
                    .with_detail(error.to_string())
            })?,
            event_type: String::from(CONTAINER_RETIRED_EVENT_TYPE),
            schema_version: 1,
            source_service: String::from("container"),
            emitted_at: OffsetDateTime::now_utc(),
            actor: reconcile_actor(context),
        },
        payload: EventPayload::Service(ServiceEvent {
            resource_kind: String::from("container_workload_reconciliation"),
            resource_id: record.workload_id.to_string(),
            action: String::from("retired"),
            details: json!({
                "workload_id": record.workload_id,
                "cluster_id": record.cluster_id,
                "project_id": record.project_id,
                "node_pool_id": record.node_pool_id,
                "node_pool_name": record.node_pool_name,
                "final_state": record.state,
                "detail": record.detail,
                "reconcile_digest": record.reconcile_digest,
                "last_reconciled_at": record.reconciled_at,
                "retired_idempotency_key": retired_reconciliation_idempotency_key(record),
            }),
        }),
    };
    event.validate().map_err(|error| {
        PlatformError::invalid("invalid retired container reconciliation event")
            .with_detail(format!("{error:?}"))
    })?;
    Ok(event)
}

fn reconcile_actor(context: Option<&RequestContext>) -> AuditActor {
    let actor = context.and_then(|request| request.actor.clone());
    AuditActor {
        subject: actor.unwrap_or_else(|| String::from("system:container-reconciler")),
        actor_type: if context.and_then(|request| request.actor.as_ref()).is_some() {
            String::from("principal")
        } else {
            String::from("system")
        },
        source_ip: None,
        correlation_id: context.map_or_else(
            || String::from(RECONCILE_SYSTEM_CORRELATION_ID),
            |request| request.correlation_id.clone(),
        ),
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
            PlatformError::invalid("invalid record version header").with_detail(error.to_string())
        })?,
    );
    Ok(response)
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
        && expected_etag != stored.value.metadata().etag.as_str()
    {
        return Err(PlatformError::conflict("etag does not match"));
    }

    Ok(())
}

trait HasMetadata {
    fn metadata(&self) -> &ResourceMetadata;
}

impl HasMetadata for NodePoolRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for ClusterRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for ContainerWorkloadRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
}

impl HasMetadata for WorkloadReconciliationRecord {
    fn metadata(&self) -> &ResourceMetadata {
        &self.metadata
    }
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

fn expected_if_match(headers: &HeaderMap) -> Result<Option<String>> {
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
    Ok(Some(trimmed.trim_matches('"').to_owned()))
}

fn mark_deleted_cluster(mut cluster: ClusterRecord, key: &str) -> ClusterRecord {
    mark_deleted_metadata(&mut cluster.metadata, key);
    cluster
}

fn mark_deleted_node_pool(mut node_pool: NodePoolRecord, key: &str) -> NodePoolRecord {
    mark_deleted_metadata(&mut node_pool.metadata, key);
    node_pool
}

fn mark_deleted_workload(
    mut workload: ContainerWorkloadRecord,
    key: &str,
) -> ContainerWorkloadRecord {
    mark_deleted_metadata(&mut workload.metadata, key);
    workload
}

fn mark_deleted_reconciliation(
    mut reconciliation: WorkloadReconciliationRecord,
    key: &str,
) -> WorkloadReconciliationRecord {
    mark_deleted_metadata(&mut reconciliation.metadata, key);
    reconciliation
}

fn mark_deleted_metadata(metadata: &mut ResourceMetadata, key: &str) {
    metadata.lifecycle = ResourceLifecycleState::Deleted;
    metadata.deleted_at = Some(OffsetDateTime::now_utc());
    metadata.touch(sha256_hex(
        format!(
            "{key}:deleted:{}",
            metadata.updated_at.unix_timestamp_nanos()
        )
        .as_bytes(),
    ));
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use http::StatusCode;
    use http::header::{ETAG, HeaderMap, HeaderValue, IF_MATCH};
    use tempfile::tempdir;
    use uhost_core::{RequestContext, sha256_hex};
    use uhost_runtime::{HttpService, RouteClaim};
    use uhost_types::{
        EventPayload, NodeId, OwnershipScope, PlatformEvent, ResourceMetadata, ServiceEvent,
    };

    use super::{
        CONTAINER_EVENTS_TOPIC, CONTAINER_RECONCILED_EVENT_TYPE, CONTAINER_RETIRED_EVENT_TYPE,
        ClusterRecord, ContainerExecutionClass, ContainerService, CreateClusterRequest,
        CreateNodePoolRequest, CreateWorkloadRequest, LEGACY_CLUSTER_NODE_POOL_ANNOTATION,
        NodePoolRecord, RECORD_VERSION_HEADER, SchedulerNodeInventorySnapshot,
        WorkloadReconciliationState,
    };

    #[tokio::test]
    async fn cluster_and_workload_persist_across_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "edge-west-pool",
            "us-west-1",
            "general",
            2,
            3,
            4,
        )
        .await;
        let cluster_response = service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("edge-west"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(cluster_response.status(), StatusCode::CREATED);
        assert!(cluster_response.headers().contains_key(ETAG));
        assert!(
            cluster_response
                .headers()
                .contains_key(RECORD_VERSION_HEADER)
        );

        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));

        let workload_response = service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("api"),
                    image: String::from("registry.local/app/api:2026.04.08"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/api"), String::from("--serve")],
                },
                &request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workload_response.status(), StatusCode::CREATED);
        assert!(workload_response.headers().contains_key(ETAG));
        assert!(
            workload_response
                .headers()
                .contains_key(RECORD_VERSION_HEADER)
        );

        let reopened = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node_pools = reopened
            .list_active_node_pools()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let clusters = reopened
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workloads = reopened
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reconciliations = reopened
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = reopened
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(node_pools.len(), 1);
        assert_eq!(clusters.len(), 1);
        assert_eq!(workloads.len(), 1);
        assert_eq!(reconciliations.len(), 1);
        assert_eq!(outbox.len(), 1);
        assert_eq!(clusters[0].node_pool_id.as_ref(), Some(&node_pools[0].id));
        assert_eq!(workloads[0].cluster_id, clusters[0].id);
        assert_eq!(workloads[0].desired_replicas, 2);
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RECONCILED_EVENT_TYPE,
                workloads[0].id.as_str(),
                "reconciled",
            ),
            1
        );
    }

    #[tokio::test]
    async fn summary_rolls_up_clusters_regions_and_execution_classes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_a = project_id_string();
        let project_b = project_id_string();
        let pool_a = create_node_pool_record(
            &service,
            &project_a,
            "alpha-general",
            "us-east-1",
            "general",
            1,
            2,
            3,
        )
        .await;
        let pool_b = create_node_pool_record(
            &service,
            &project_b,
            "beta-gpu",
            "us-west-2",
            "gpu",
            1,
            1,
            2,
        )
        .await;

        service
            .create_cluster(CreateClusterRequest {
                project_id: project_a.clone(),
                name: String::from("alpha"),
                node_pool_id: pool_a.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .create_cluster(CreateClusterRequest {
                project_id: project_b.clone(),
                name: String::from("beta"),
                node_pool_id: pool_b.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let clusters = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let alpha = clusters
            .iter()
            .find(|cluster| cluster.name == "alpha")
            .unwrap_or_else(|| panic!("missing alpha"))
            .clone();
        let beta = clusters
            .iter()
            .find(|cluster| cluster.name == "beta")
            .unwrap_or_else(|| panic!("missing beta"))
            .clone();

        for (cluster_id, project_id, name, replicas, class) in [
            (
                alpha.id.to_string(),
                alpha.project_id.to_string(),
                "api",
                3,
                ContainerExecutionClass::Service,
            ),
            (
                alpha.id.to_string(),
                alpha.project_id.to_string(),
                "worker",
                2,
                ContainerExecutionClass::Job,
            ),
            (
                beta.id.to_string(),
                beta.project_id.to_string(),
                "frontend",
                1,
                ContainerExecutionClass::Service,
            ),
        ] {
            service
                .create_workload(
                    CreateWorkloadRequest {
                        cluster_id,
                        project_id,
                        name: String::from(name),
                        image: format!("registry.local/{name}:stable"),
                        desired_replicas: replicas,
                        execution_class: Some(class),
                        command: Vec::new(),
                    },
                    &request_context(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let summary = service
            .summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.node_pool_count, 2);
        assert_eq!(summary.cluster_count, 2);
        assert_eq!(summary.workload_count, 3);
        assert_eq!(summary.total_min_nodes, 2);
        assert_eq!(summary.total_desired_nodes, 3);
        assert_eq!(summary.total_max_nodes, 5);
        assert_eq!(summary.total_desired_replicas, 6);
        assert_eq!(summary.active_project_count, 2);
        assert_eq!(summary.execution_class_totals.len(), 2);
        assert_eq!(summary.region_totals.len(), 2);
        assert_eq!(summary.node_pool_summaries.len(), 2);

        let alpha_summary = summary
            .cluster_summaries
            .iter()
            .find(|entry| entry.cluster_id == alpha.id)
            .unwrap_or_else(|| panic!("missing alpha summary"));
        assert_eq!(alpha_summary.node_pool_id.as_ref(), Some(&pool_a.id));
        assert_eq!(alpha_summary.desired_nodes, 2);
        assert_eq!(alpha_summary.workload_count, 2);
        assert_eq!(alpha_summary.total_desired_replicas, 5);
    }

    #[tokio::test]
    async fn delete_requires_matching_version_and_cluster_detaches_last() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "ops-general",
            "us-central-1",
            "general",
            1,
            1,
            2,
        )
        .await;
        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("ops"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));

        let workload_response = service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("janitor"),
                    image: String::from("registry.local/janitor:1"),
                    desired_replicas: 1,
                    execution_class: Some(ContainerExecutionClass::Job),
                    command: vec![String::from("/job/run")],
                },
                &request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workload = service
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("workload should exist"));

        let conflict = match service
            .delete_cluster(cluster.id.as_str(), &HeaderMap::new())
            .await
        {
            Ok(response) => panic!("expected error, got {}", response.status()),
            Err(error) => error,
        };
        assert_eq!(conflict.code, uhost_core::ErrorCode::Conflict);

        let node_pool_conflict = match service
            .delete_node_pool(node_pool.id.as_str(), &HeaderMap::new())
            .await
        {
            Ok(response) => panic!("expected error, got {}", response.status()),
            Err(error) => error,
        };
        assert_eq!(node_pool_conflict.code, uhost_core::ErrorCode::Conflict);

        let mut stale_headers = HeaderMap::new();
        stale_headers.insert(RECORD_VERSION_HEADER, HeaderValue::from_static("999"));
        let stale_delete = service
            .delete_workload(workload.id.as_str(), &stale_headers, &request_context())
            .await;
        assert!(stale_delete.is_err());

        let mut delete_headers = HeaderMap::new();
        delete_headers.insert(
            RECORD_VERSION_HEADER,
            workload_response
                .headers()
                .get(RECORD_VERSION_HEADER)
                .unwrap_or_else(|| panic!("missing x-record-version"))
                .clone(),
        );
        let workload_etag = workload_response
            .headers()
            .get(ETAG)
            .unwrap_or_else(|| panic!("missing etag"))
            .clone();
        delete_headers.insert(IF_MATCH, workload_etag);

        let deleted = service
            .delete_workload(workload.id.as_str(), &delete_headers, &request_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert!(
            service
                .list_active_reconciliations()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let cluster_version = service
            .clusters
            .get(cluster.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("cluster should exist"))
            .version;
        let mut cluster_headers = HeaderMap::new();
        cluster_headers.insert(
            RECORD_VERSION_HEADER,
            HeaderValue::from_str(&cluster_version.to_string())
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let cluster_response = service
            .get_cluster(cluster.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        cluster_headers.insert(
            IF_MATCH,
            cluster_response
                .headers()
                .get(ETAG)
                .unwrap_or_else(|| panic!("missing cluster etag"))
                .clone(),
        );

        let deleted_cluster = service
            .delete_cluster(cluster.id.as_str(), &cluster_headers)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(deleted_cluster.status(), StatusCode::NO_CONTENT);
        assert!(
            service
                .list_active_clusters()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let node_pool_version = service
            .node_pools
            .get(node_pool.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("node pool should exist"))
            .version;
        let mut node_pool_headers = HeaderMap::new();
        node_pool_headers.insert(
            RECORD_VERSION_HEADER,
            HeaderValue::from_str(&node_pool_version.to_string())
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let node_pool_response = service
            .get_node_pool(node_pool.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        node_pool_headers.insert(
            IF_MATCH,
            node_pool_response
                .headers()
                .get(ETAG)
                .unwrap_or_else(|| panic!("missing node pool etag"))
                .clone(),
        );
        let deleted_node_pool = service
            .delete_node_pool(node_pool.id.as_str(), &node_pool_headers)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(deleted_node_pool.status(), StatusCode::NO_CONTENT);
        assert!(
            service
                .list_active_node_pools()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let outbox = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outbox.len(), 2);
        assert!(
            outbox
                .iter()
                .any(|message| message.topic == CONTAINER_EVENTS_TOPIC)
        );
        assert!(outbox.iter().any(|message| {
            matches!(
                &message.payload.payload,
                EventPayload::Service(ServiceEvent { action, .. }) if action == "retired"
            )
        }));
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RECONCILED_EVENT_TYPE,
                workload.id.as_str(),
                "reconciled",
            ),
            1
        );
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RETIRED_EVENT_TYPE,
                workload.id.as_str(),
                "retired",
            ),
            1
        );
    }

    #[tokio::test]
    async fn reconciler_replays_without_duplicate_audit_or_outbox_messages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "reconcile-general",
            "us-west-1",
            "general",
            1,
            2,
            3,
        )
        .await;
        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("reconcile-west"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));
        let context = request_context();

        service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("reconcile-api"),
                    image: String::from("registry.local/reconcile-api:latest"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/reconcile-api")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliations = service
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reconciliations.len(), 1);
        assert_eq!(
            reconciliations[0].state,
            WorkloadReconciliationState::Planned
        );

        let initial_outbox = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(initial_outbox.len(), 1);
        assert_eq!(initial_outbox[0].topic, CONTAINER_EVENTS_TOPIC);
        assert_eq!(
            initial_outbox[0].idempotency_key.as_deref(),
            Some(reconciliations[0].event_idempotency_key.as_str())
        );
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RECONCILED_EVENT_TYPE,
                reconciliations[0].workload_id.as_str(),
                "reconciled",
            ),
            1
        );

        let replay = service
            .reconcile_all(Some(&context))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay.reconciled_workloads, 1);
        assert_eq!(replay.created_records, 0);
        assert_eq!(replay.updated_records, 0);
        assert_eq!(replay.replayed_records, 1);
        assert_eq!(
            service
                .list_outbox_messages()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RECONCILED_EVENT_TYPE,
                reconciliations[0].workload_id.as_str(),
                "reconciled",
            ),
            1
        );

        let reopened = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            reopened
                .list_active_reconciliations()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            reopened
                .list_outbox_messages()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            count_service_events(
                &temp.path().join("container/audit.log"),
                CONTAINER_RECONCILED_EVENT_TYPE,
                reconciliations[0].workload_id.as_str(),
                "reconciled",
            ),
            1
        );
    }

    #[tokio::test]
    async fn reconciler_replays_missing_side_records_without_duplication() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "repair-general",
            "us-west-2",
            "general",
            2,
            3,
            4,
        )
        .await;
        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("repair-west"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));
        let context = request_context();

        service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("repair-api"),
                    image: String::from("registry.local/repair-api:stable"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/repair-api")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliation = service
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("reconciliation should exist"));
        let outbox_path = temp.path().join("container/outbox.json");
        let audit_path = temp.path().join("container/audit.log");

        rewrite_outbox_without_idempotency_key(
            &service,
            &outbox_path,
            reconciliation.event_idempotency_key.as_str(),
        )
        .await;
        let replay_outbox = service
            .reconcile_all(Some(&context))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay_outbox.replayed_records, 1);
        let repaired_outbox = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(repaired_outbox.len(), 1);
        assert_eq!(
            repaired_outbox[0].idempotency_key.as_deref(),
            Some(reconciliation.event_idempotency_key.as_str())
        );
        assert_eq!(
            count_service_events(
                &audit_path,
                CONTAINER_RECONCILED_EVENT_TYPE,
                reconciliation.workload_id.as_str(),
                "reconciled",
            ),
            1
        );

        std::fs::write(&audit_path, b"").unwrap_or_else(|error| panic!("{error}"));
        let replay_audit = service
            .reconcile_all(Some(&context))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay_audit.replayed_records, 1);
        assert_eq!(
            service
                .list_outbox_messages()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            count_service_events(
                &audit_path,
                CONTAINER_RECONCILED_EVENT_TYPE,
                reconciliation.workload_id.as_str(),
                "reconciled",
            ),
            1
        );
    }

    #[tokio::test]
    async fn reconciliation_blocks_when_node_pool_resource_is_missing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "broken-general",
            "us-east-2",
            "general",
            1,
            2,
            3,
        )
        .await;
        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("broken"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));
        let context = request_context();

        service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("broken-api"),
                    image: String::from("registry.local/broken-api:stable"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/broken-api")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_node_pool = service
            .node_pools
            .get(node_pool.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing node pool"));
        let updated = super::mark_deleted_node_pool(stored_node_pool.value, node_pool.id.as_str());
        let updated = service
            .node_pools
            .upsert(
                node_pool.id.as_str(),
                updated,
                Some(stored_node_pool.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .node_pools
            .soft_delete(node_pool.id.as_str(), Some(updated.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay = service
            .reconcile_all(Some(&context))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay.reconciled_workloads, 1);
        assert_eq!(replay.blocked_records, 1);

        let reconciliation = service
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("reconciliation should exist"));
        assert_eq!(reconciliation.state, WorkloadReconciliationState::Blocked);
        assert_eq!(reconciliation.node_pool_id.as_ref(), Some(&node_pool.id));
        assert!(
            reconciliation
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("missing or deleted node pool"))
        );
    }

    #[tokio::test]
    async fn reconciliation_stays_planned_when_scheduler_inventory_backs_bound_node_pool() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "backed-general",
            "us-east-2",
            "general",
            1,
            2,
            3,
        )
        .await;
        seed_scheduler_node(&service, "us-east-2", "general", 4_000, 8_192).await;
        seed_scheduler_node(&service, "us-east-2", "general", 4_000, 8_192).await;
        seed_scheduler_node(&service, "us-east-2", "gpu", 4_000, 8_192).await;

        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("backed"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));

        service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("backed-api"),
                    image: String::from("registry.local/backed-api:stable"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/backed-api")],
                },
                &request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliation = service
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("reconciliation should exist"));
        assert_eq!(reconciliation.state, WorkloadReconciliationState::Planned);
        assert_eq!(reconciliation.node_pool_id.as_ref(), Some(&node_pool.id));
        assert!(
            reconciliation
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains(node_pool.id.as_str()))
        );
        assert!(
            reconciliation
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("via scheduler pool general"))
        );
    }

    #[tokio::test]
    async fn reconciliation_blocks_when_scheduler_inventory_cannot_back_bound_node_pool() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = project_id_string();
        let node_pool = create_node_pool_record(
            &service,
            &project_id,
            "scarce-gpu",
            "us-west-2",
            "gpu",
            1,
            2,
            3,
        )
        .await;
        seed_scheduler_node(&service, "us-west-2", "gpu", 4_000, 8_192).await;
        seed_scheduler_node(&service, "us-west-2", "general", 4_000, 8_192).await;

        service
            .create_cluster(CreateClusterRequest {
                project_id: project_id.clone(),
                name: String::from("scarce"),
                node_pool_id: node_pool.id.to_string(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));

        service
            .create_workload(
                CreateWorkloadRequest {
                    cluster_id: cluster.id.to_string(),
                    project_id: cluster.project_id.to_string(),
                    name: String::from("scarce-api"),
                    image: String::from("registry.local/scarce-api:stable"),
                    desired_replicas: 2,
                    execution_class: Some(ContainerExecutionClass::Service),
                    command: vec![String::from("/bin/scarce-api")],
                },
                &request_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliation = service
            .list_active_reconciliations()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("reconciliation should exist"));
        assert_eq!(reconciliation.state, WorkloadReconciliationState::Blocked);
        assert_eq!(reconciliation.node_pool_id.as_ref(), Some(&node_pool.id));
        assert!(reconciliation.detail.as_deref().is_some_and(|detail| {
            detail.contains("requires 2 active scheduler node(s)")
                && detail.contains("only 1 matching node(s) are registered")
        }));
    }

    #[tokio::test]
    async fn open_migrates_legacy_cluster_placeholders_into_node_pool_resources() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let project_id =
            uhost_types::ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let cluster_id =
            super::ContainerClusterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let legacy_cluster = ClusterRecord {
            id: cluster_id.clone(),
            project_id: project_id.clone(),
            name: String::from("legacy"),
            node_pool_id: None,
            region: String::from("us-east-1"),
            scheduler_pool: String::from("general"),
            desired_nodes: 2,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(cluster_id.to_string()),
                sha256_hex(cluster_id.as_str().as_bytes()),
            ),
        };
        let cluster_store = uhost_store::DocumentStore::<ClusterRecord>::open(
            temp.path().join("container/clusters.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let _created = cluster_store
            .create(cluster_id.as_str(), legacy_cluster)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = ContainerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cluster = service
            .list_active_clusters()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("cluster should exist"));
        let node_pool = service
            .list_active_node_pools()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .pop()
            .unwrap_or_else(|| panic!("node pool should exist"));

        assert_eq!(cluster.node_pool_id.as_ref(), Some(&node_pool.id));
        assert_eq!(
            node_pool
                .metadata
                .annotations
                .get(LEGACY_CLUSTER_NODE_POOL_ANNOTATION)
                .map(String::as_str),
            Some(cluster.id.as_str())
        );
        assert_eq!(node_pool.region, "us-east-1");
        assert_eq!(node_pool.scheduler_pool, "general");
        assert_eq!(node_pool.desired_nodes, 2);
        assert_eq!(node_pool.min_nodes, 2);
        assert_eq!(node_pool.max_nodes, 2);
    }

    #[test]
    fn route_claims_own_container_prefix() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|error| panic!("{error}"));
        let service = runtime
            .block_on(ContainerService::open(temp.path()))
            .unwrap_or_else(|error| panic!("{error}"));
        let claims = service.route_claims();
        assert_eq!(claims, &[RouteClaim::prefix("/container")]);
    }

    async fn create_node_pool_record(
        service: &ContainerService,
        project_id: &str,
        name: &str,
        region: &str,
        scheduler_pool: &str,
        min_nodes: u16,
        desired_nodes: u16,
        max_nodes: u16,
    ) -> NodePoolRecord {
        let response = service
            .create_node_pool(CreateNodePoolRequest {
                project_id: String::from(project_id),
                name: String::from(name),
                region: String::from(region),
                scheduler_pool: String::from(scheduler_pool),
                min_nodes,
                desired_nodes,
                max_nodes,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);
        service
            .list_active_node_pools()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|node_pool| node_pool.name == name)
            .unwrap_or_else(|| panic!("node pool should exist"))
    }

    async fn seed_scheduler_node(
        service: &ContainerService,
        region: &str,
        scheduler_pool: &str,
        cpu_millis: u32,
        memory_mb: u64,
    ) -> SchedulerNodeInventorySnapshot {
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node = SchedulerNodeInventorySnapshot {
            id: node_id.clone(),
            region: String::from(region),
            scheduler_pool: String::from(scheduler_pool),
            cpu_millis,
            memory_mb,
            free_cpu_millis: cpu_millis,
            free_memory_mb: memory_mb,
            drained: false,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(node_id.to_string()),
                sha256_hex(node_id.as_str().as_bytes()),
            ),
        };
        service
            .scheduler_nodes
            .create(node_id.as_str(), node.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        node
    }

    fn project_id_string() -> String {
        uhost_types::ProjectId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string()
    }

    fn request_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("container.test-operator")
    }

    fn read_audit_events(path: &Path) -> Vec<PlatformEvent> {
        let payload = match std::fs::read(path) {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("{error}"),
        };
        payload
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice::<PlatformEvent>(line)
                    .unwrap_or_else(|error| panic!("{error}"))
            })
            .collect()
    }

    fn count_service_events(
        path: &Path,
        event_type: &str,
        resource_id: &str,
        action: &str,
    ) -> usize {
        read_audit_events(path)
            .into_iter()
            .filter(|event| {
                if event.header.event_type != event_type {
                    return false;
                }
                matches!(
                    &event.payload,
                    EventPayload::Service(ServiceEvent {
                        resource_kind,
                        resource_id: event_resource_id,
                        action: event_action,
                        ..
                    }) if resource_kind == "container_workload_reconciliation"
                        && event_resource_id == resource_id
                        && event_action == action
                )
            })
            .count()
    }

    async fn rewrite_outbox_without_idempotency_key(
        service: &ContainerService,
        path: &Path,
        idempotency_key: &str,
    ) {
        let mut collection =
            uhost_store::DocumentCollection::<uhost_store::OutboxMessage<PlatformEvent>>::default();
        for message in service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            if message.idempotency_key.as_deref() == Some(idempotency_key) {
                continue;
            }
            collection.records.insert(
                message.id.clone(),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: message.updated_at,
                    deleted: false,
                    value: message,
                },
            );
        }
        std::fs::write(
            path,
            serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }
}
