//! High-availability and disaster recovery orchestration service.
//!
//! This service manages active/passive role declarations, leader leases with
//! fencing tokens, replication health snapshots, failover and drill workflows,
//! and dependency failure matrix checks used to trigger degraded mode.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::fs;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{ErrorCode, PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::workflow::WorkflowStepEffectExecution;
use uhost_store::{
    AuditLog, CellDirectoryCollection, CellParticipantRecord, CellParticipantState, DocumentStore,
    DurableOutbox, LeaseDrainIntent, LeaseFreshness, LeaseReadiness, OutboxMessage, StoredDocument,
    WorkflowCollection, WorkflowEffectLedgerRecord, WorkflowInstance, WorkflowPhase, WorkflowStep,
    WorkflowStepState,
};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, FailoverOperationId, LeaderLeaseId, NodeId,
    OwnershipScope, PlatformEvent, RepairJobId, ReplicationStreamId, ResourceMetadata,
    ServiceEvent,
};

/// Per-role readiness counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleReadinessSummary {
    pub role: String,
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: usize,
}

/// Lightweight replication readiness totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationReadinessSummary {
    pub total_streams: usize,
    pub healthy_streams: usize,
    pub unhealthy_streams: usize,
    pub max_lag_seconds: Option<u64>,
}

/// Computed failover readiness totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverReadinessSummary {
    pub total_failovers: usize,
    pub in_progress: usize,
    pub failed: usize,
    pub last_completed_at: Option<OffsetDateTime>,
}

/// Readiness summary surface for HA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessSummary {
    pub state_root: String,
    pub roles: Vec<RoleReadinessSummary>,
    pub replication: ReplicationReadinessSummary,
    pub failovers: FailoverReadinessSummary,
    pub reconciliations: Vec<ReconciliationRecord>,
    pub dependencies: Vec<DependencyStatusRecord>,
}

/// Node role declaration for active/passive topologies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRoleRecord {
    /// Node identifier.
    pub node_id: NodeId,
    /// `active` or `passive`.
    pub role: String,
    /// Whether health checks currently pass.
    pub healthy: bool,
    /// Last role heartbeat time.
    pub last_heartbeat_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Leader lease record with fencing token and expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderLeaseRecord {
    /// Lease identifier.
    pub id: LeaderLeaseId,
    /// Lease holder node.
    pub holder_node_id: NodeId,
    /// Monotonic term.
    pub term: u64,
    /// Lease expiration time.
    pub lease_until: OffsetDateTime,
    /// Fencing token updated on each successful lease operation.
    pub fencing_token: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Replication health status between source and target nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationStatusRecord {
    /// Replication stream identifier.
    pub id: ReplicationStreamId,
    /// Source node.
    pub source_node_id: NodeId,
    /// Target node.
    pub target_node_id: NodeId,
    /// Lag in whole seconds.
    pub lag_seconds: u64,
    /// Whether replication is healthy.
    pub healthy: bool,
    /// Last update time.
    pub checked_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Failover operation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverState {
    /// Created and waiting for checks.
    Requested,
    /// Running orchestration actions.
    InProgress,
    /// Completed successfully.
    Completed,
    /// Failed due to failed checks or runtime error.
    Failed,
}

/// Durable evacuation-preparation artifact describing source-route withdrawal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEvacuationRouteWithdrawalArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Node being withdrawn from serving the selected routing scopes.
    pub source_node_id: NodeId,
    /// Routing scopes that should stop resolving to the source node.
    #[serde(default)]
    pub routing_scope_ids: Vec<String>,
    /// Timestamp when the artifact was prepared.
    pub prepared_at: OffsetDateTime,
}

impl HaEvacuationRouteWithdrawalArtifact {
    fn new(
        operation_id: &FailoverOperationId,
        source_node_id: &NodeId,
        routing_scope_ids: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: format!(
                "route-withdrawal:{}:{}",
                operation_id.as_str(),
                source_node_id.as_str()
            ),
            source_node_id: source_node_id.clone(),
            routing_scope_ids: normalize_routing_scope_ids(routing_scope_ids),
            prepared_at,
        }
    }
}

/// Durable evacuation-preparation artifact describing target readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEvacuationTargetReadinessArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Node being evacuated away from.
    pub source_node_id: NodeId,
    /// Node prepared to receive the evacuated routing scopes.
    pub target_node_id: NodeId,
    /// Routing scopes that the target node must be ready to serve.
    #[serde(default)]
    pub routing_scope_ids: Vec<String>,
    /// Timestamp when the artifact was prepared.
    pub prepared_at: OffsetDateTime,
}

impl HaEvacuationTargetReadinessArtifact {
    fn new(
        operation_id: &FailoverOperationId,
        source_node_id: &NodeId,
        target_node_id: &NodeId,
        routing_scope_ids: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: format!(
                "target-readiness:{}:{}:{}",
                operation_id.as_str(),
                source_node_id.as_str(),
                target_node_id.as_str()
            ),
            source_node_id: source_node_id.clone(),
            target_node_id: target_node_id.clone(),
            routing_scope_ids: normalize_routing_scope_ids(routing_scope_ids),
            prepared_at,
        }
    }
}

/// Durable evacuation-preparation artifact describing rollback restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEvacuationRollbackArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Node being evacuated away from.
    pub source_node_id: NodeId,
    /// Node temporarily prepared to serve the evacuated routing scopes.
    pub target_node_id: NodeId,
    /// Routing scopes that should be restored to the source node if the evacuation rolls back.
    #[serde(default)]
    pub routing_scope_ids: Vec<String>,
    /// Timestamp when the artifact was prepared.
    pub prepared_at: OffsetDateTime,
}

impl HaEvacuationRollbackArtifact {
    fn new(
        operation_id: &FailoverOperationId,
        source_node_id: &NodeId,
        target_node_id: &NodeId,
        routing_scope_ids: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: format!(
                "rollback:{}:{}:{}",
                operation_id.as_str(),
                source_node_id.as_str(),
                target_node_id.as_str()
            ),
            source_node_id: source_node_id.clone(),
            target_node_id: target_node_id.clone(),
            routing_scope_ids: normalize_routing_scope_ids(routing_scope_ids),
            prepared_at,
        }
    }
}

/// All durable artifacts created during evacuation preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaEvacuationPreparationArtifacts {
    /// Route-withdrawal artifact prepared before the source is demoted.
    pub route_withdrawal: HaEvacuationRouteWithdrawalArtifact,
    /// Target-readiness artifact prepared before the target is promoted.
    pub target_readiness: HaEvacuationTargetReadinessArtifact,
    /// Rollback artifact prepared before the cutover becomes operator-visible.
    pub rollback: HaEvacuationRollbackArtifact,
}

impl HaEvacuationPreparationArtifacts {
    fn new(
        operation_id: &FailoverOperationId,
        source_node_id: &NodeId,
        target_node_id: &NodeId,
        routing_scope_ids: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        let routing_scope_ids = normalize_routing_scope_ids(routing_scope_ids);
        Self {
            route_withdrawal: HaEvacuationRouteWithdrawalArtifact::new(
                operation_id,
                source_node_id,
                routing_scope_ids.clone(),
                prepared_at,
            ),
            target_readiness: HaEvacuationTargetReadinessArtifact::new(
                operation_id,
                source_node_id,
                target_node_id,
                routing_scope_ids.clone(),
                prepared_at,
            ),
            rollback: HaEvacuationRollbackArtifact::new(
                operation_id,
                source_node_id,
                target_node_id,
                routing_scope_ids,
                prepared_at,
            ),
        }
    }
}

/// Recorded failover or drill operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverRecord {
    /// Operation identifier.
    pub id: FailoverOperationId,
    /// Previous active node.
    pub from_node_id: NodeId,
    /// Target node that should become active.
    pub to_node_id: NodeId,
    /// Whether this operation is a drill.
    pub drill: bool,
    /// Operation mode (`failover`, `drill`, `evacuation`).
    #[serde(default = "default_failover_operation_kind")]
    pub operation_kind: String,
    /// Operator-provided reason.
    pub reason: String,
    /// Current state.
    pub state: FailoverState,
    /// Whether service entered degraded mode.
    pub degraded_mode: bool,
    /// Stable workflow identifier that owns the explicit checkpoints for this operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    /// Durable workflow checkpoints projected into the public failover record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<WorkflowStep>,
    /// Durable evacuation-preparation artifacts when this operation is an evacuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evacuation_artifacts: Option<HaEvacuationPreparationArtifacts>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Completion timestamp when known.
    pub completed_at: Option<OffsetDateTime>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// HA topology drift classes that require repair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaTopologyDriftKind {
    /// No node is currently declared active.
    ZeroActive,
    /// More than one node is currently declared active.
    DualActive,
}

/// Durable workflow state for one anti-entropy repair action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaRepairWorkflowState {
    /// Stable repair workflow identifier.
    pub repair_id: RepairJobId,
    /// Drift class observed by the reconciler.
    pub drift_kind: HaTopologyDriftKind,
    /// Deterministic drift signature used for dedupe.
    pub drift_signature: String,
    /// Nodes currently declared active.
    pub active_node_ids: Vec<NodeId>,
    /// Nodes currently declared passive.
    pub passive_node_ids: Vec<NodeId>,
    /// Preferred node to keep or promote as the single active target.
    pub target_active_node_id: Option<NodeId>,
    /// Nodes that should be demoted during dual-active repair.
    pub demoted_node_ids: Vec<NodeId>,
    /// Drift observation timestamp.
    pub observed_at: OffsetDateTime,
    /// Optional resolution detail once the workflow is no longer actionable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_reason: Option<String>,
}

/// Regional quorum membership and replication progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionalQuorumRecord {
    /// Region key (`us-east-1`, `eu-central-1`, etc.).
    pub region: String,
    /// Node identifier participating in quorum.
    pub node_id: NodeId,
    /// Role (`leader`, `follower`, `candidate`).
    pub role: String,
    /// Raft-like term used for monotonic leadership evolution.
    pub term: u64,
    /// Relative vote weight; defaults to `1`.
    pub vote_weight: u16,
    /// Whether member health checks currently pass.
    pub healthy: bool,
    /// Highest replicated log index observed by this member.
    pub replicated_log_index: u64,
    /// Highest applied log index observed by this member.
    pub applied_log_index: u64,
    /// Lease expiry time for this quorum heartbeat.
    pub lease_until: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Versioned consensus log entry tracked by HA control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusLogEntryRecord {
    /// Region where entry is authored.
    pub region: String,
    /// Monotonic consensus term.
    pub term: u64,
    /// Monotonic log index.
    pub log_index: u64,
    /// High-level operation kind (`failover_plan`, `policy_change`, etc.).
    pub operation_kind: String,
    /// Deterministic payload digest.
    pub payload_hash: String,
    /// Leader node that authored the entry.
    pub leader_node_id: NodeId,
    /// Entry creation timestamp.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Replication shipment progress for one consensus entry to one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationShipmentRecord {
    /// Region where entry belongs.
    pub region: String,
    /// Replicated log index.
    pub log_index: u64,
    /// Replicated term.
    pub term: u64,
    /// Source node performing replication.
    pub source_node_id: NodeId,
    /// Target node applying replication.
    pub target_node_id: NodeId,
    /// Shipment status (`in_flight`, `applied`, `failed`).
    pub status: String,
    /// Optional human-readable status detail.
    pub message: Option<String>,
    /// Last status update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Deterministic reconciliation snapshot for one region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationRecord {
    /// Region key.
    pub region: String,
    /// Latest log index observed in consensus log.
    pub latest_log_index: u64,
    /// Highest contiguous log index considered committed.
    pub committed_log_index: u64,
    /// Quorum majority threshold used for this evaluation.
    pub majority_threshold: u64,
    /// Healthy vote units observed.
    pub healthy_votes: u64,
    /// Number of entries still uncommitted.
    pub uncommitted_entries: u64,
    /// Nodes missing committed entries.
    pub lagging_nodes: Vec<String>,
    /// Whether reconciliation indicates safe failover posture.
    pub fully_reconciled: bool,
    /// Evaluation timestamp.
    pub evaluated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Computed quorum health summary used by failover admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumSummary {
    /// Number of configured vote units.
    pub configured_votes: u64,
    /// Number of currently healthy and non-expired vote units.
    pub healthy_votes: u64,
    /// Threshold required to satisfy quorum.
    pub majority_threshold: u64,
    /// Whether current healthy votes satisfy majority.
    pub quorum_satisfied: bool,
    /// Number of quorum members.
    pub member_count: usize,
    /// Count of unhealthy or lease-expired members.
    pub stale_member_count: usize,
    /// Evaluation timestamp.
    pub evaluated_at: OffsetDateTime,
}

/// Preflight verdict for failover-style operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverPreflightResult {
    /// Source node identifier.
    pub from_node_id: NodeId,
    /// Target node identifier.
    pub to_node_id: NodeId,
    /// Requested lag ceiling.
    pub max_replication_lag_seconds: u64,
    /// Observed replication lag when present.
    pub observed_replication_lag_seconds: Option<u64>,
    /// Whether the source node currently has `active` role.
    pub from_node_active: bool,
    /// Whether the target node currently has `passive` role.
    pub to_node_passive: bool,
    /// Whether the target node is healthy.
    pub to_node_healthy: bool,
    /// Whether a replication edge exists for the pair.
    pub replication_present: bool,
    /// Whether replication is reported healthy.
    pub replication_healthy: bool,
    /// Whether lag is inside the requested ceiling.
    pub replication_within_ceiling: bool,
    /// Whether critical dependency checks currently force degraded mode.
    pub degraded_mode: bool,
    /// Whether regional quorum currently satisfies majority.
    pub quorum_satisfied: bool,
    /// Whether consensus reconciliation indicates no uncommitted entries.
    pub consensus_fully_reconciled: bool,
    /// Highest consensus log index observed.
    pub consensus_latest_log_index: u64,
    /// Highest committed index observed by reconciliation.
    pub consensus_committed_log_index: u64,
    /// Number of uncommitted consensus entries.
    pub consensus_uncommitted_entries: u64,
    /// Human-readable blockers when admission is denied.
    pub blockers: Vec<String>,
    /// Final admission verdict.
    pub allowed: bool,
    /// Evaluation timestamp.
    pub evaluated_at: OffsetDateTime,
}

/// Dependency failure matrix entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyStatusRecord {
    /// Dependency key such as `dns`, `storage`, `database`.
    pub dependency: String,
    /// `up`, `degraded`, or `down`.
    pub status: String,
    /// Whether this dependency is critical for serving traffic.
    pub critical: bool,
    /// Last check time.
    pub checked_at: OffsetDateTime,
    /// Optional message.
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchedulerNodeInventorySnapshot {
    id: NodeId,
    free_cpu_millis: u32,
    free_memory_mb: u64,
    drained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchedulerPlacementDecisionSnapshot {
    workload_id: String,
    node_id: Option<NodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControlWorkloadSnapshot {
    id: String,
    replicas: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControlDeploymentSnapshot {
    workload_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeHeartbeatSnapshot {
    hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeCellOwnershipResolution {
    Unavailable,
    Unhealthy,
    Ambiguous { cell_ids: Vec<String> },
    Owned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SetRoleRequest {
    node_id: String,
    role: String,
    healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseRequest {
    node_id: String,
    lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplicationRequest {
    source_node_id: String,
    target_node_id: String,
    lag_seconds: u64,
    healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailoverRequest {
    from_node_id: String,
    to_node_id: String,
    reason: String,
    max_replication_lag_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailoverPreflightRequest {
    from_node_id: String,
    to_node_id: String,
    max_replication_lag_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegionalQuorumRequest {
    region: String,
    node_id: String,
    role: String,
    term: u64,
    vote_weight: Option<u16>,
    healthy: bool,
    replicated_log_index: u64,
    applied_log_index: u64,
    lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DependencyRequest {
    dependency: String,
    status: String,
    critical: bool,
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConsensusEntryRequest {
    region: String,
    term: u64,
    log_index: u64,
    operation_kind: String,
    payload_hash: String,
    leader_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplicationShipmentRequest {
    region: String,
    log_index: u64,
    term: u64,
    source_node_id: String,
    target_node_id: String,
    status: String,
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReconcileRequest {
    region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedHaDrift {
    drift_kind: HaTopologyDriftKind,
    drift_signature: String,
    active_node_ids: Vec<NodeId>,
    passive_node_ids: Vec<NodeId>,
    target_active_node_id: Option<NodeId>,
    demoted_node_ids: Vec<NodeId>,
}

/// HA service implementation.
#[derive(Debug, Clone)]
pub struct HaService {
    roles: DocumentStore<NodeRoleRecord>,
    leader_lease: DocumentStore<LeaderLeaseRecord>,
    replication: DocumentStore<ReplicationStatusRecord>,
    failovers: DocumentStore<FailoverRecord>,
    failover_workflows: WorkflowCollection<FailoverRecord>,
    failover_effect_ledgers: DocumentStore<WorkflowEffectLedgerRecord>,
    repair_workflows: WorkflowCollection<HaRepairWorkflowState>,
    regional_quorum: DocumentStore<RegionalQuorumRecord>,
    consensus_log: DocumentStore<ConsensusLogEntryRecord>,
    replication_shipments: DocumentStore<ReplicationShipmentRecord>,
    reconciliations: DocumentStore<ReconciliationRecord>,
    dependencies: DocumentStore<DependencyStatusRecord>,
    cell_directory: CellDirectoryCollection,
    scheduler_nodes: DocumentStore<SchedulerNodeInventorySnapshot>,
    scheduler_placements: DocumentStore<SchedulerPlacementDecisionSnapshot>,
    control_workloads: DocumentStore<ControlWorkloadSnapshot>,
    control_deployments: DocumentStore<ControlDeploymentSnapshot>,
    node_heartbeats: DocumentStore<NodeHeartbeatSnapshot>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailoverMode {
    Failover,
    Drill,
    Evacuation,
}

const HA_FAILOVER_WORKFLOW_SUBJECT_KIND: &str = "failover_operation";
const FAILOVER_PRECHECK_STEP_INDEX: usize = 0;
const FAILOVER_INTENT_STEP_INDEX: usize = 1;
const FAILOVER_ARTIFACT_STEP_INDEX: usize = 2;
const FAILOVER_EVACUATION_ARTIFACT_STEP_NAME: &str = "prepare_evacuation_artifacts";
const HA_FAILOVER_WORKFLOW_RUNNER_ID: &str = "ha_failover_controller";
const HA_EVENTS_OUTBOX_TOPIC: &str = "ha.events.v1";
const FAILOVER_STARTED_EVENT_EFFECT_KIND: &str = "emit_started_event";
const FAILOVER_ROLE_TRANSITION_EFFECT_KIND: &str = "apply_role_transition";
const FAILOVER_DRILL_OUTCOME_EFFECT_KIND: &str = "record_drill_outcome";
const FAILOVER_COMPLETED_EVENT_EFFECT_KIND: &str = "emit_completed_event";
const HA_REPAIR_WORKFLOW_KIND: &str = "ha.repair";
const HA_REPAIR_SUBJECT_KIND: &str = "ha_topology_drift";
const HA_REPAIR_WORKFLOW_RUNNER_ID: &str = "ha_anti_entropy_controller";
const HA_REPAIR_CAPTURE_STEP_INDEX: usize = 0;
const HA_REPAIR_PLAN_STEP_INDEX: usize = 1;
const HA_REPAIR_APPLY_STEP_INDEX: usize = 2;
const HA_REPAIR_VERIFY_STEP_INDEX: usize = 3;

type HaFailoverWorkflow = WorkflowInstance<FailoverRecord>;
type HaRepairWorkflow = WorkflowInstance<HaRepairWorkflowState>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HaFailoverWorkflowFence {
    fencing_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HaRepairWorkflowFence {
    fencing_token: String,
}

impl FailoverMode {
    fn is_drill(self) -> bool {
        matches!(self, Self::Drill)
    }

    fn operation_kind(self) -> &'static str {
        match self {
            Self::Failover => "failover",
            Self::Drill => "drill",
            Self::Evacuation => "evacuation",
        }
    }

    fn started_event(self) -> &'static str {
        match self {
            Self::Failover => "ha.failover.started.v1",
            Self::Drill => "ha.failover.drill.started.v1",
            Self::Evacuation => "ha.failover.evacuation.started.v1",
        }
    }

    fn completed_event(self) -> &'static str {
        match self {
            Self::Failover => "ha.failover.completed.v1",
            Self::Drill => "ha.failover.drill.completed.v1",
            Self::Evacuation => "ha.failover.evacuation.completed.v1",
        }
    }

    fn blocked_event(self) -> &'static str {
        match self {
            Self::Failover => "ha.failover.blocked.v1",
            Self::Drill => "ha.failover.drill.blocked.v1",
            Self::Evacuation => "ha.failover.evacuation.blocked.v1",
        }
    }

    fn workflow_kind(self) -> &'static str {
        match self {
            Self::Failover => "ha.failover.workflow.v1",
            Self::Drill => "ha.failover.drill.workflow.v1",
            Self::Evacuation => "ha.evacuation.workflow.v1",
        }
    }

    fn execution_step_name(self) -> &'static str {
        match self {
            Self::Failover => "apply_failover_cutover",
            Self::Drill => "record_drill_outcome",
            Self::Evacuation => "apply_evacuation_cutover",
        }
    }
}

impl HaService {
    /// Open HA state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let base = state_root.as_ref();
        let root = base.join("ha");
        let service = Self {
            roles: DocumentStore::open(root.join("roles.json")).await?,
            leader_lease: DocumentStore::open(root.join("leader_lease.json")).await?,
            replication: DocumentStore::open(root.join("replication_status.json")).await?,
            failovers: DocumentStore::open(root.join("failovers.json")).await?,
            failover_workflows: WorkflowCollection::open_local(
                root.join("failover_workflows.json"),
            )
            .await?,
            failover_effect_ledgers: DocumentStore::open(root.join("failover_effect_ledgers.json"))
                .await?,
            repair_workflows: WorkflowCollection::open_local(root.join("repair_workflows.json"))
                .await?,
            regional_quorum: DocumentStore::open(root.join("regional_quorum.json")).await?,
            consensus_log: DocumentStore::open(root.join("consensus_log.json")).await?,
            replication_shipments: DocumentStore::open(root.join("replication_shipments.json"))
                .await?,
            reconciliations: DocumentStore::open(root.join("reconciliations.json")).await?,
            dependencies: DocumentStore::open(root.join("dependencies.json")).await?,
            cell_directory: CellDirectoryCollection::open_local(
                base.join("runtime").join("cell-directory.json"),
            )
            .await?,
            scheduler_nodes: DocumentStore::open(base.join("scheduler").join("nodes.json")).await?,
            scheduler_placements: DocumentStore::open(
                base.join("scheduler").join("placements.json"),
            )
            .await?,
            control_workloads: DocumentStore::open(base.join("control").join("workloads.json"))
                .await?,
            control_deployments: DocumentStore::open(base.join("control").join("deployments.json"))
                .await?,
            node_heartbeats: DocumentStore::open(base.join("node").join("heartbeats.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.reconcile_failover_workflows().await?;
        let context = RequestContext {
            correlation_id: String::from("ctx_system"),
            request_id: String::from("ctx_system"),
            started_at: OffsetDateTime::now_utc(),
            actor: Some(String::from("system")),
            principal: None,
            tenant_id: None,
            feature_flags: std::collections::BTreeSet::new(),
        };
        service
            .reconcile_anti_entropy(&context, "service_open")
            .await?;
        Ok(service)
    }

    async fn reconcile_failover_workflows(&self) -> Result<()> {
        let legacy_failovers = self.failovers.list().await?;
        for (key, stored) in legacy_failovers {
            if stored.deleted || self.failover_workflows.get(&key).await?.is_some() {
                continue;
            }

            let workflow = build_failover_workflow(stored.value);
            if let Err(error) = self.failover_workflows.create(&key, workflow).await
                && error.code != ErrorCode::Conflict
            {
                return Err(error);
            }
        }

        let workflows = self.failover_workflows.list().await?;
        for (_, stored) in workflows.into_iter().filter(|(_, stored)| !stored.deleted) {
            let workflow = if failover_workflow_needs_shape_normalization(&stored.value) {
                self.normalize_failover_workflow(stored.value.id.as_str())
                    .await?
                    .value
            } else {
                stored.value
            };
            if failover_workflow_requires_execution(&workflow) {
                let _ = self
                    .adopt_failover_workflow_execution_primitives(workflow.id.as_str())
                    .await?;
            } else {
                self.sync_failover_projection(&workflow).await?;
            }
        }
        Ok(())
    }

    async fn create_failover_workflow(
        &self,
        record: FailoverRecord,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        let workflow = build_pending_failover_workflow(record);
        let key = workflow.id.clone();
        let stored = self.failover_workflows.create(&key, workflow).await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn load_failover_workflow(
        &self,
        operation_id: &FailoverOperationId,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.failover_workflows
            .get(operation_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("failover workflow does not exist"))
    }

    async fn begin_failover_step_effect(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        step_index: usize,
        effect_kind: &str,
        detail: String,
    ) -> Result<(
        StoredDocument<HaFailoverWorkflow>,
        WorkflowStepEffectExecution,
    )> {
        let observed_at = self
            .heartbeat_failover_workflow_runner(operation_id, fence)
            .await?;
        let idempotency_key = failover_step_effect_idempotency_key(operation_id, effect_kind);
        let (stored, effect_execution) = self
            .failover_workflows
            .begin_step_effect_at(
                operation_id.as_str(),
                step_index,
                effect_kind,
                idempotency_key.as_str(),
                Some(detail),
                observed_at,
            )
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok((stored, effect_execution))
    }

    async fn complete_failover_step_effect(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        step_index: usize,
        effect_kind: &str,
        result_digest: &str,
        detail: String,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        let observed_at = self
            .heartbeat_failover_workflow_runner(operation_id, fence)
            .await?;
        let (stored, _effect) = self
            .failover_workflows
            .complete_step_effect_at(
                operation_id.as_str(),
                step_index,
                effect_kind,
                Some(result_digest),
                Some(detail),
                observed_at,
            )
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn heartbeat_failover_workflow_runner(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
    ) -> Result<OffsetDateTime> {
        let mut observed_at = None;
        let _stored = self
            .mutate_failover_workflow_fenced(operation_id, fence, |_workflow, heartbeat_at| {
                observed_at = Some(heartbeat_at);
                Ok(())
            })
            .await?;
        observed_at.ok_or_else(|| {
            PlatformError::unavailable("failed to observe failover workflow runner heartbeat time")
        })
    }

    async fn persist_failover_effect_ledger(
        &self,
        workflow: &HaFailoverWorkflow,
        step_index: usize,
        effect_kind: &str,
        result_digest: &str,
        observed_at: OffsetDateTime,
    ) -> Result<StoredDocument<WorkflowEffectLedgerRecord>> {
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
                .failover_effect_ledgers
                .get(ledger_key.as_str())
                .await?
            {
                Some(existing) if !existing.deleted => {
                    existing.value.validate_for_workflow(workflow)?;
                    if existing.value.result_digest != result_digest {
                        return Err(PlatformError::conflict(format!(
                            "failover effect ledger for `{effect_kind}` already records a different result digest"
                        )));
                    }
                    return Ok(existing);
                }
                Some(existing) => {
                    match self
                        .failover_effect_ledgers
                        .upsert(ledger_key.as_str(), ledger.clone(), Some(existing.version))
                        .await
                    {
                        Ok(updated) => return Ok(updated),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self
                    .failover_effect_ledgers
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

    async fn replay_failover_effect_result_from_ledger(
        &self,
        workflow: &HaFailoverWorkflow,
        step_index: usize,
        effect_kind: &str,
    ) -> Result<Option<String>> {
        if !failover_effect_requires_dedicated_ledger(effect_kind) {
            return Ok(None);
        }

        let effect = match workflow
            .step(step_index)
            .and_then(|step| step.effect(effect_kind))
        {
            Some(effect) => effect,
            None => return Ok(None),
        };
        let stored = match self
            .failover_effect_ledgers
            .get(effect.idempotency_key.as_str())
            .await?
        {
            Some(stored) if !stored.deleted => stored,
            _ => return Ok(None),
        };
        stored.value.validate_for_workflow(workflow)?;
        if self
            .failover_effect_result_matches_current_state(
                workflow,
                effect_kind,
                stored.value.result_digest.as_str(),
            )
            .await?
        {
            return Ok(Some(stored.value.result_digest));
        }
        Ok(None)
    }

    async fn failover_effect_result_matches_current_state(
        &self,
        workflow: &HaFailoverWorkflow,
        effect_kind: &str,
        result_digest: &str,
    ) -> Result<bool> {
        match effect_kind {
            FAILOVER_ROLE_TRANSITION_EFFECT_KIND => {
                let from_role = match self.roles.get(workflow.state.from_node_id.as_str()).await? {
                    Some(stored) if !stored.deleted => stored.value,
                    _ => return Ok(false),
                };
                let to_role = match self.roles.get(workflow.state.to_node_id.as_str()).await? {
                    Some(stored) if !stored.deleted => stored.value,
                    _ => return Ok(false),
                };
                Ok(failover_role_transition_result_digest(&from_role, &to_role) == result_digest)
            }
            FAILOVER_DRILL_OUTCOME_EFFECT_KIND => {
                Ok(failover_drill_effect_result_digest(&workflow.state) == result_digest)
            }
            _ => Ok(false),
        }
    }

    async fn emit_failover_started_effect(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        context: &RequestContext,
    ) -> Result<String> {
        let workflow = self.load_failover_workflow(operation_id).await?;
        let mode = failover_mode_from_record(&workflow.value.state);
        let step_index = failover_execute_step_index(mode);
        let detail = failover_started_event_effect_detail(mode);
        let (journaled, effect_execution) = self
            .begin_failover_step_effect(
                operation_id,
                fence,
                step_index,
                FAILOVER_STARTED_EVENT_EFFECT_KIND,
                detail.clone(),
            )
            .await?;
        match effect_execution {
            WorkflowStepEffectExecution::Replay(effect) => failover_effect_replay_result_digest(
                FAILOVER_STARTED_EVENT_EFFECT_KIND,
                effect.result_digest.as_ref(),
            ),
            WorkflowStepEffectExecution::Execute(effect) => {
                let result_digest = self
                    .append_event_with_idempotency(
                        mode.started_event(),
                        "failover",
                        operation_id.as_str(),
                        "started",
                        failover_started_event_details(&journaled.value),
                        context,
                        Some(effect.idempotency_key.as_str()),
                    )
                    .await?;
                let _stored = self
                    .complete_failover_step_effect(
                        operation_id,
                        fence,
                        step_index,
                        FAILOVER_STARTED_EVENT_EFFECT_KIND,
                        result_digest.as_str(),
                        detail,
                    )
                    .await?;
                Ok(result_digest)
            }
        }
    }

    async fn execute_failover_execution_effect(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        context: &RequestContext,
        from_healthy: bool,
        to_healthy: bool,
    ) -> Result<String> {
        let workflow = self.load_failover_workflow(operation_id).await?;
        let mode = failover_mode_from_record(&workflow.value.state);
        let step_index = failover_execute_step_index(mode);
        let effect_kind = failover_execution_effect_kind(mode);
        let detail = failover_execution_effect_detail(
            mode,
            &workflow.value.state.from_node_id,
            &workflow.value.state.to_node_id,
        );
        let (journaled, effect_execution) = self
            .begin_failover_step_effect(
                operation_id,
                fence,
                step_index,
                effect_kind,
                detail.clone(),
            )
            .await?;
        match effect_execution {
            WorkflowStepEffectExecution::Replay(effect) => {
                failover_effect_replay_result_digest(effect_kind, effect.result_digest.as_ref())
            }
            WorkflowStepEffectExecution::Execute(_) => {
                if let Some(result_digest) = self
                    .replay_failover_effect_result_from_ledger(
                        &journaled.value,
                        step_index,
                        effect_kind,
                    )
                    .await?
                {
                    let _stored = self
                        .complete_failover_step_effect(
                            operation_id,
                            fence,
                            step_index,
                            effect_kind,
                            result_digest.as_str(),
                            detail,
                        )
                        .await?;
                    return Ok(result_digest);
                }
                let result_digest = match mode {
                    FailoverMode::Drill => {
                        failover_drill_effect_result_digest(&workflow.value.state)
                    }
                    FailoverMode::Failover | FailoverMode::Evacuation => {
                        self.ensure_failover_role_transition(
                            &workflow.value.state.from_node_id,
                            &workflow.value.state.to_node_id,
                            from_healthy,
                            to_healthy,
                            context,
                        )
                        .await?
                    }
                };
                let _ledger = self
                    .persist_failover_effect_ledger(
                        &journaled.value,
                        step_index,
                        effect_kind,
                        result_digest.as_str(),
                        OffsetDateTime::now_utc(),
                    )
                    .await?;
                let _stored = self
                    .complete_failover_step_effect(
                        operation_id,
                        fence,
                        step_index,
                        effect_kind,
                        result_digest.as_str(),
                        detail,
                    )
                    .await?;
                Ok(result_digest)
            }
        }
    }

    async fn emit_failover_completion_effect(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        context: &RequestContext,
    ) -> Result<String> {
        let workflow = self.load_failover_workflow(operation_id).await?;
        let mode = failover_mode_from_record(&workflow.value.state);
        let step_index = failover_finalize_step_index(mode);
        let detail = failover_completion_event_effect_detail(mode);
        let (journaled, effect_execution) = self
            .begin_failover_step_effect(
                operation_id,
                fence,
                step_index,
                FAILOVER_COMPLETED_EVENT_EFFECT_KIND,
                detail.clone(),
            )
            .await?;
        match effect_execution {
            WorkflowStepEffectExecution::Replay(effect) => failover_effect_replay_result_digest(
                FAILOVER_COMPLETED_EVENT_EFFECT_KIND,
                effect.result_digest.as_ref(),
            ),
            WorkflowStepEffectExecution::Execute(effect) => {
                let result_digest = self
                    .append_event_with_idempotency(
                        mode.completed_event(),
                        "failover",
                        operation_id.as_str(),
                        "completed",
                        failover_completed_event_details(&journaled.value),
                        context,
                        Some(effect.idempotency_key.as_str()),
                    )
                    .await?;
                let _stored = self
                    .complete_failover_step_effect(
                        operation_id,
                        fence,
                        step_index,
                        FAILOVER_COMPLETED_EVENT_EFFECT_KIND,
                        result_digest.as_str(),
                        detail,
                    )
                    .await?;
                Ok(result_digest)
            }
        }
    }

    async fn checkpoint_failover_preflight(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        preflight: &FailoverPreflightResult,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        let detail = failover_precheck_detail(preflight);
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            workflow.current_step_index = Some(FAILOVER_INTENT_STEP_INDEX);
            if let Some(step) = workflow.step_mut(FAILOVER_PRECHECK_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(detail.clone()),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(FAILOVER_INTENT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(failover_intent_active_detail(mode)),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_failover_intent(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            let next_step_index = failover_artifact_step_index(mode)
                .unwrap_or_else(|| failover_execute_step_index(mode));
            let from_node_id = workflow.state.from_node_id.clone();
            let to_node_id = workflow.state.to_node_id.clone();
            let intent_detail =
                failover_intent_detail(mode, workflow.state.evacuation_artifacts.as_ref());
            let next_detail = if next_step_index == failover_execute_step_index(mode) {
                failover_execution_active_detail(mode, &from_node_id, &to_node_id)
            } else {
                failover_artifact_active_detail(&from_node_id, &to_node_id)
            };
            workflow.current_step_index = Some(next_step_index);
            if let Some(step) = workflow.step_mut(FAILOVER_INTENT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(intent_detail),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(next_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(next_detail),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_failover_artifacts(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        artifacts: HaEvacuationPreparationArtifacts,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            if mode != FailoverMode::Evacuation {
                return Err(PlatformError::conflict(
                    "only evacuation workflows may checkpoint evacuation artifacts",
                ));
            }
            let from_node_id = workflow.state.from_node_id.clone();
            let to_node_id = workflow.state.to_node_id.clone();
            workflow.state.evacuation_artifacts = Some(artifacts.clone());
            workflow.current_step_index = Some(failover_execute_step_index(mode));
            if let Some(step) = workflow.step_mut(FAILOVER_ARTIFACT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_artifact_detail(Some(&artifacts))),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(failover_execute_step_index(mode)) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(failover_execution_active_detail(
                        mode,
                        &from_node_id,
                        &to_node_id,
                    )),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_failover_execution(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            let execute_step_index = failover_execute_step_index(mode);
            let finalize_step_index = failover_finalize_step_index(mode);
            let from_node_id = workflow.state.from_node_id.clone();
            let to_node_id = workflow.state.to_node_id.clone();
            workflow.current_step_index = Some(finalize_step_index);
            if let Some(step) = workflow.step_mut(execute_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_execution_completed_detail(
                        mode,
                        &from_node_id,
                        &to_node_id,
                    )),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(finalize_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(failover_completion_active_detail(mode)),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_failover_completion(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            let finalize_step_index = failover_finalize_step_index(mode);
            workflow.current_step_index = Some(finalize_step_index);
            if let Some(step) = workflow.step_mut(finalize_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_completion_detail(mode)),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Completed, observed_at);
            Ok(())
        })
        .await
    }

    async fn adopt_failover_workflow_execution_primitives(
        &self,
        workflow_key: &str,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        let observed_at = OffsetDateTime::now_utc();
        let stored = self
            .failover_workflows
            .mutate(workflow_key, |workflow| {
                ensure_failover_workflow_shape(
                    workflow,
                    failover_mode_from_record(&workflow.state),
                );
                let _changed = apply_failover_workflow_execution_primitives(workflow, observed_at)?;
                Ok(())
            })
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn claim_failover_workflow_runner(
        &self,
        operation_id: &FailoverOperationId,
    ) -> Result<HaFailoverWorkflowFence> {
        let stored = self
            .adopt_failover_workflow_execution_primitives(operation_id.as_str())
            .await?;
        let claim = stored.value.runner_claim.as_ref().ok_or_else(|| {
            PlatformError::conflict("failover workflow does not have an active runner claim")
        })?;
        if claim.runner_id != HA_FAILOVER_WORKFLOW_RUNNER_ID {
            return Err(PlatformError::conflict(format!(
                "failover workflow claim held by {}",
                claim.runner_id
            )));
        }
        Ok(HaFailoverWorkflowFence {
            fencing_token: claim.fencing_token.clone(),
        })
    }

    async fn mutate_failover_workflow_fenced<F>(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        mut mutate: F,
    ) -> Result<StoredDocument<HaFailoverWorkflow>>
    where
        F: FnMut(&mut HaFailoverWorkflow, OffsetDateTime) -> Result<()>,
    {
        let observed_at = OffsetDateTime::now_utc();
        let stored = self
            .failover_workflows
            .mutate(operation_id.as_str(), |workflow| {
                ensure_failover_workflow_shape(
                    workflow,
                    failover_mode_from_record(&workflow.state),
                );
                workflow.assert_runner_fence_at(
                    HA_FAILOVER_WORKFLOW_RUNNER_ID,
                    fence.fencing_token.as_str(),
                    observed_at,
                )?;
                workflow.heartbeat_runner_at(
                    HA_FAILOVER_WORKFLOW_RUNNER_ID,
                    fence.fencing_token.as_str(),
                    ha_failover_workflow_lease_duration(),
                    observed_at,
                )?;
                mutate(workflow, observed_at)?;
                let _changed = sync_failover_workflow_next_attempt(workflow, observed_at);
                Ok(())
            })
            .await?;
        self.sync_failover_projection(&stored.value).await?;
        Ok(stored)
    }

    async fn normalize_failover_workflow(
        &self,
        operation_id: &str,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        self.failover_workflows
            .mutate(operation_id, |workflow| {
                ensure_failover_workflow_shape(
                    workflow,
                    failover_mode_from_record(&workflow.state),
                );
                Ok(())
            })
            .await
    }

    async fn mark_failover_workflow_failed(
        &self,
        operation_id: &FailoverOperationId,
        fence: &HaFailoverWorkflowFence,
        detail: impl Into<String>,
    ) -> Result<StoredDocument<HaFailoverWorkflow>> {
        let detail = detail.into();
        self.mutate_failover_workflow_fenced(operation_id, fence, |workflow, observed_at| {
            let mode = failover_mode_from_record(&workflow.state);
            let failed_step_index = workflow.current_step_index.unwrap_or_else(|| {
                failover_execute_step_index(mode).min(workflow.steps.len().saturating_sub(1))
            });
            workflow.current_step_index = Some(failed_step_index);
            if let Some(step) = workflow.step_mut(failed_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Failed,
                    Some(detail.clone()),
                    observed_at,
                );
            }
            set_failover_workflow_phase_at(workflow, WorkflowPhase::Failed, observed_at);
            Ok(())
        })
        .await
    }

    async fn sync_failover_projection(&self, workflow: &HaFailoverWorkflow) -> Result<()> {
        let projection = project_failover_record(workflow);
        let key = projection.id.to_string();
        loop {
            match self.failovers.get(&key).await? {
                Some(existing) if !existing.deleted && existing.value == projection => {
                    return Ok(());
                }
                Some(existing) => {
                    match self
                        .failovers
                        .upsert(&key, projection.clone(), Some(existing.version))
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.code == ErrorCode::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => match self.failovers.create(&key, projection.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                },
            }
        }
    }

    async fn set_role(
        &self,
        request: SetRoleRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.set_role_internal(request, context, true).await
    }

    async fn set_role_internal(
        &self,
        request: SetRoleRequest,
        context: &RequestContext,
        run_anti_entropy: bool,
    ) -> Result<Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let role = normalize_role(&request.role)?;
        let key = node_id.to_string();
        let existing = self.roles.get(&key).await?;
        let metadata = existing
            .as_ref()
            .map(|record| {
                let mut metadata = record.value.metadata.clone();
                metadata.touch(sha256_hex(key.as_bytes()));
                metadata
            })
            .unwrap_or_else(|| {
                ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(key.clone()),
                    sha256_hex(key.as_bytes()),
                )
            });
        let record = NodeRoleRecord {
            node_id: node_id.clone(),
            role,
            healthy: request.healthy,
            last_heartbeat_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.roles
            .upsert(&key, record.clone(), existing.map(|value| value.version))
            .await?;
        self.append_event(
            "ha.role.updated.v1",
            "ha_role",
            &key,
            "updated",
            serde_json::json!({
                "role": record.role,
                "healthy": record.healthy,
            }),
            context,
        )
        .await?;
        if run_anti_entropy {
            let _ = self.reconcile_anti_entropy(context, "role_update").await?;
        }
        json_response(StatusCode::OK, &record)
    }

    async fn ensure_role_state(
        &self,
        node_id: &NodeId,
        role: &str,
        healthy: bool,
        context: &RequestContext,
    ) -> Result<NodeRoleRecord> {
        let key = node_id.to_string();
        let existing = self.roles.get(node_id.as_str()).await?;
        if let Some(stored) = existing.as_ref()
            && !stored.deleted
            && stored.value.role == role
            && stored.value.healthy == healthy
        {
            return Ok(stored.value.clone());
        }

        let metadata = existing
            .as_ref()
            .map(|record| {
                let mut metadata = record.value.metadata.clone();
                metadata.touch(sha256_hex(key.as_bytes()));
                metadata
            })
            .unwrap_or_else(|| {
                ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(key.clone()),
                    sha256_hex(key.as_bytes()),
                )
            });
        let record = NodeRoleRecord {
            node_id: node_id.clone(),
            role: String::from(role),
            healthy,
            last_heartbeat_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.roles
            .upsert(&key, record.clone(), existing.map(|value| value.version))
            .await?;
        self.append_event(
            "ha.role.updated.v1",
            "ha_role",
            &key,
            "updated",
            serde_json::json!({
                "role": record.role,
                "healthy": record.healthy,
            }),
            context,
        )
        .await?;
        let stored = self
            .roles
            .get(node_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node role does not exist after update"))?;
        if stored.deleted {
            return Err(PlatformError::conflict(
                "node role was deleted during failover execution",
            ));
        }
        if stored.value.role != role || stored.value.healthy != healthy {
            return Err(PlatformError::conflict(format!(
                "node role did not converge to `{role}` during failover execution"
            )));
        }
        Ok(stored.value)
    }

    async fn ensure_failover_role_transition(
        &self,
        from: &NodeId,
        to: &NodeId,
        from_healthy: bool,
        to_healthy: bool,
        context: &RequestContext,
    ) -> Result<String> {
        let from_role = self
            .ensure_role_state(from, "passive", from_healthy, context)
            .await?;
        let to_role = self
            .ensure_role_state(to, "active", to_healthy, context)
            .await?;
        let _repair = self
            .reconcile_anti_entropy(context, "failover_role_transition")
            .await?;
        Ok(failover_role_transition_result_digest(&from_role, &to_role))
    }

    async fn reconcile_anti_entropy(
        &self,
        context: &RequestContext,
        trigger: &str,
    ) -> Result<Option<HaRepairWorkflow>> {
        // Anti-entropy reconciliation deduplicates workflows by drift
        // signature, supersedes stale competing repairs, closes resolved drift,
        // and immediately executes the surviving or newly-created workflow when
        // repair is still required.
        let detected_drift = self.detect_anti_entropy_drift().await?;
        let workflows = self.repair_workflows.list().await?;
        let mut matched = None;

        for (key, stored) in workflows.into_iter().filter(|(_, stored)| !stored.deleted) {
            if is_terminal_workflow_phase(&stored.value.phase) {
                continue;
            }

            match &detected_drift {
                Some(drift) if stored.value.state.drift_signature == drift.drift_signature => {
                    let refreshed = self.refresh_repair_workflow(&key, drift).await?;
                    if matched.is_none() {
                        matched = Some(refreshed);
                    } else {
                        self.finish_repair_workflow(
                            &key,
                            WorkflowPhase::Failed,
                            String::from(
                                "duplicate open anti-entropy repair workflow for same drift",
                            ),
                            context,
                            "ha.anti_entropy.repair.superseded.v1",
                            trigger,
                        )
                        .await?;
                    }
                }
                Some(drift) => {
                    self.finish_repair_workflow(
                        &key,
                        WorkflowPhase::Failed,
                        format!(
                            "superseded by current drift signature {}",
                            drift.drift_signature
                        ),
                        context,
                        "ha.anti_entropy.repair.superseded.v1",
                        trigger,
                    )
                    .await?;
                }
                None => {
                    self.finish_repair_workflow(
                        &key,
                        WorkflowPhase::Completed,
                        String::from("topology drift cleared before repair execution"),
                        context,
                        "ha.anti_entropy.repair.resolved.v1",
                        trigger,
                    )
                    .await?;
                }
            }
        }

        if let Some(workflow) = matched {
            if repair_workflow_requires_execution(&workflow) {
                return Ok(Some(
                    self.execute_repair_workflow(workflow.id.as_str(), context, trigger)
                        .await?,
                ));
            }
            return Ok(Some(workflow));
        }

        let Some(drift) = detected_drift else {
            return Ok(None);
        };
        let workflow = build_repair_workflow(drift)?;
        self.repair_workflows
            .create(workflow.id.as_str(), workflow.clone())
            .await?;
        self.append_event(
            "ha.anti_entropy.repair.enqueued.v1",
            "ha_repair_workflow",
            workflow.id.as_str(),
            "enqueued",
            serde_json::json!({
                "drift_kind": &workflow.state.drift_kind,
                "drift_signature": &workflow.state.drift_signature,
                "active_node_ids": &workflow.state.active_node_ids,
                "passive_node_ids": &workflow.state.passive_node_ids,
                "target_active_node_id": &workflow.state.target_active_node_id,
                "demoted_node_ids": &workflow.state.demoted_node_ids,
                "trigger": trigger,
            }),
            context,
        )
        .await?;
        if repair_workflow_requires_execution(&workflow) {
            return Ok(Some(
                self.execute_repair_workflow(workflow.id.as_str(), context, trigger)
                    .await?,
            ));
        }
        Ok(Some(workflow))
    }

    async fn detect_anti_entropy_drift(&self) -> Result<Option<DetectedHaDrift>> {
        let roles = self
            .roles
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let active_records = roles
            .iter()
            .filter(|record| record.role == "active")
            .cloned()
            .collect::<Vec<_>>();
        let passive_records = roles
            .iter()
            .filter(|record| record.role == "passive")
            .cloned()
            .collect::<Vec<_>>();
        let active_node_ids = sorted_node_ids(active_records.iter().map(|record| &record.node_id));
        let passive_node_ids =
            sorted_node_ids(passive_records.iter().map(|record| &record.node_id));

        if active_records.is_empty() {
            if passive_records.is_empty() {
                return Ok(None);
            }
            let target_active_node_id = preferred_repair_target(&passive_records, true);
            return Ok(Some(DetectedHaDrift {
                drift_kind: HaTopologyDriftKind::ZeroActive,
                drift_signature: zero_active_drift_signature(&passive_node_ids),
                active_node_ids,
                passive_node_ids,
                target_active_node_id,
                demoted_node_ids: Vec::new(),
            }));
        }

        if active_records.len() == 1 {
            return Ok(None);
        }

        let target_active_node_id = preferred_repair_target(&active_records, false);
        let demoted_node_ids = active_node_ids
            .iter()
            .filter(|node_id| target_active_node_id.as_ref() != Some(node_id))
            .cloned()
            .collect::<Vec<_>>();
        Ok(Some(DetectedHaDrift {
            drift_kind: HaTopologyDriftKind::DualActive,
            drift_signature: dual_active_drift_signature(&active_node_ids),
            active_node_ids,
            passive_node_ids,
            target_active_node_id,
            demoted_node_ids,
        }))
    }

    async fn refresh_repair_workflow(
        &self,
        key: &str,
        drift: &DetectedHaDrift,
    ) -> Result<HaRepairWorkflow> {
        let observed_at = OffsetDateTime::now_utc();
        Ok(self
            .repair_workflows
            .mutate(key, |workflow| {
                apply_detected_drift(workflow, drift, observed_at);
                Ok(())
            })
            .await?
            .value)
    }

    async fn finish_repair_workflow(
        &self,
        key: &str,
        phase: WorkflowPhase,
        reason: String,
        context: &RequestContext,
        event_type: &str,
        trigger: &str,
    ) -> Result<HaRepairWorkflow> {
        let observed_at = OffsetDateTime::now_utc();
        let phase_value = phase.clone();
        let reason_value = reason.clone();
        let workflow = self
            .repair_workflows
            .mutate(key, |workflow| {
                workflow.state.resolution_reason = Some(reason_value.clone());
                workflow.set_phase_at(phase_value.clone(), observed_at);
                Ok(())
            })
            .await?
            .value;
        self.append_event(
            event_type,
            "ha_repair_workflow",
            workflow.id.as_str(),
            "updated",
            serde_json::json!({
                "drift_kind": &workflow.state.drift_kind,
                "drift_signature": &workflow.state.drift_signature,
                "phase": &workflow.phase,
                "reason": reason,
                "trigger": trigger,
            }),
            context,
        )
        .await?;
        Ok(workflow)
    }

    async fn load_repair_workflow(
        &self,
        repair_workflow_id: &str,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        self.repair_workflows
            .get(repair_workflow_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("HA repair workflow does not exist"))
    }

    async fn adopt_repair_workflow_execution_primitives(
        &self,
        workflow_key: &str,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        let observed_at = OffsetDateTime::now_utc();
        self.repair_workflows
            .mutate(workflow_key, |workflow| {
                ensure_repair_workflow_shape(workflow);
                let _changed = apply_repair_workflow_execution_primitives(workflow, observed_at)?;
                Ok(())
            })
            .await
    }

    async fn claim_repair_workflow_runner(
        &self,
        repair_workflow_id: &str,
    ) -> Result<HaRepairWorkflowFence> {
        let stored = self
            .adopt_repair_workflow_execution_primitives(repair_workflow_id)
            .await?;
        let claim = stored.value.runner_claim.as_ref().ok_or_else(|| {
            PlatformError::conflict("HA repair workflow does not have an active runner claim")
        })?;
        if claim.runner_id != HA_REPAIR_WORKFLOW_RUNNER_ID {
            return Err(PlatformError::conflict(format!(
                "HA repair workflow claim held by {}",
                claim.runner_id
            )));
        }
        Ok(HaRepairWorkflowFence {
            fencing_token: claim.fencing_token.clone(),
        })
    }

    async fn mutate_repair_workflow_fenced<F>(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
        mut mutate: F,
    ) -> Result<StoredDocument<HaRepairWorkflow>>
    where
        F: FnMut(&mut HaRepairWorkflow, OffsetDateTime) -> Result<()>,
    {
        let observed_at = OffsetDateTime::now_utc();
        self.repair_workflows
            .mutate(repair_workflow_id, |workflow| {
                ensure_repair_workflow_shape(workflow);
                workflow.assert_runner_fence_at(
                    HA_REPAIR_WORKFLOW_RUNNER_ID,
                    fence.fencing_token.as_str(),
                    observed_at,
                )?;
                workflow.heartbeat_runner_at(
                    HA_REPAIR_WORKFLOW_RUNNER_ID,
                    fence.fencing_token.as_str(),
                    ha_repair_workflow_lease_duration(),
                    observed_at,
                )?;
                mutate(workflow, observed_at)?;
                let _changed = sync_repair_workflow_next_attempt(workflow, observed_at);
                Ok(())
            })
            .await
    }

    async fn heartbeat_repair_workflow_runner(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
    ) -> Result<OffsetDateTime> {
        let mut observed_at = None;
        let _stored = self
            .mutate_repair_workflow_fenced(repair_workflow_id, fence, |_workflow, heartbeat_at| {
                observed_at = Some(heartbeat_at);
                Ok(())
            })
            .await?;
        observed_at.ok_or_else(|| {
            PlatformError::unavailable("failed to observe HA repair workflow runner heartbeat time")
        })
    }

    async fn checkpoint_repair_capture(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        self.mutate_repair_workflow_fenced(repair_workflow_id, fence, |workflow, observed_at| {
            let capture_detail = repair_capture_detail(&workflow.state);
            let plan_detail = repair_plan_active_detail(&workflow.state);
            workflow.current_step_index = Some(HA_REPAIR_PLAN_STEP_INDEX);
            if let Some(step) = workflow.step_mut(HA_REPAIR_CAPTURE_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(capture_detail),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(HA_REPAIR_PLAN_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(plan_detail),
                    observed_at,
                );
            }
            workflow.set_phase_at(WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_repair_plan(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        self.mutate_repair_workflow_fenced(repair_workflow_id, fence, |workflow, observed_at| {
            let plan_detail = repair_plan_completed_detail(&workflow.state);
            let apply_detail = repair_apply_active_detail(&workflow.state);
            workflow.current_step_index = Some(HA_REPAIR_APPLY_STEP_INDEX);
            if let Some(step) = workflow.step_mut(HA_REPAIR_PLAN_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(plan_detail),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(HA_REPAIR_APPLY_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(apply_detail),
                    observed_at,
                );
            }
            workflow.set_phase_at(WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn checkpoint_repair_apply(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        self.mutate_repair_workflow_fenced(repair_workflow_id, fence, |workflow, observed_at| {
            let apply_detail = repair_apply_completed_detail(&workflow.state);
            let verify_detail = repair_verify_active_detail();
            workflow.current_step_index = Some(HA_REPAIR_VERIFY_STEP_INDEX);
            if let Some(step) = workflow.step_mut(HA_REPAIR_APPLY_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(apply_detail),
                    observed_at,
                );
            }
            if let Some(step) = workflow.step_mut(HA_REPAIR_VERIFY_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(verify_detail),
                    observed_at,
                );
            }
            workflow.set_phase_at(WorkflowPhase::Running, observed_at);
            Ok(())
        })
        .await
    }

    async fn complete_repair_workflow(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
        detail: impl Into<String>,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        let detail = detail.into();
        self.mutate_repair_workflow_fenced(repair_workflow_id, fence, |workflow, observed_at| {
            workflow.current_step_index = Some(HA_REPAIR_VERIFY_STEP_INDEX);
            workflow.state.resolution_reason = Some(detail.clone());
            if let Some(step) = workflow.step_mut(HA_REPAIR_VERIFY_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(detail.clone()),
                    observed_at,
                );
            }
            workflow.set_phase_at(WorkflowPhase::Completed, observed_at);
            Ok(())
        })
        .await
    }

    async fn mark_repair_workflow_failed(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
        detail: impl Into<String>,
    ) -> Result<StoredDocument<HaRepairWorkflow>> {
        let detail = detail.into();
        self.mutate_repair_workflow_fenced(repair_workflow_id, fence, |workflow, observed_at| {
            let failed_step_index = workflow
                .current_step_index
                .unwrap_or(HA_REPAIR_CAPTURE_STEP_INDEX)
                .min(workflow.steps.len().saturating_sub(1));
            workflow.current_step_index = Some(failed_step_index);
            workflow.state.resolution_reason = Some(detail.clone());
            if let Some(step) = workflow.step_mut(failed_step_index) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Failed,
                    Some(detail.clone()),
                    observed_at,
                );
            }
            workflow.set_phase_at(WorkflowPhase::Failed, observed_at);
            Ok(())
        })
        .await
    }

    async fn apply_repair_role_plan(
        &self,
        repair_workflow_id: &str,
        fence: &HaRepairWorkflowFence,
        context: &RequestContext,
    ) -> Result<()> {
        let _observed_at = self
            .heartbeat_repair_workflow_runner(repair_workflow_id, fence)
            .await?;
        let workflow = self.load_repair_workflow(repair_workflow_id).await?;
        let target_active_node_id = workflow
            .value
            .state
            .target_active_node_id
            .clone()
            .ok_or_else(|| {
                PlatformError::conflict(
                    "HA repair workflow has no target active node for role repair execution",
                )
            })?;
        let target_record = self
            .roles
            .get(target_active_node_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| {
                PlatformError::conflict(
                    "HA repair workflow target active node no longer exists during execution",
                )
            })?;
        let _target = self
            .ensure_role_state(
                &target_active_node_id,
                "active",
                target_record.value.healthy,
                context,
            )
            .await?;

        for node_id in workflow
            .value
            .state
            .demoted_node_ids
            .iter()
            .filter(|node_id| **node_id != target_active_node_id)
        {
            let record = self
                .roles
                .get(node_id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .ok_or_else(|| {
                    PlatformError::conflict(format!(
                        "HA repair workflow demotion target {} no longer exists during execution",
                        node_id.as_str()
                    ))
                })?;
            let _updated = self
                .ensure_role_state(node_id, "passive", record.value.healthy, context)
                .await?;
        }
        Ok(())
    }

    async fn execute_repair_workflow(
        &self,
        repair_workflow_id: &str,
        context: &RequestContext,
        trigger: &str,
    ) -> Result<HaRepairWorkflow> {
        let fence = self
            .claim_repair_workflow_runner(repair_workflow_id)
            .await?;
        let workflow = self.load_repair_workflow(repair_workflow_id).await?;
        if is_terminal_workflow_phase(&workflow.value.phase) {
            return Ok(workflow.value);
        }

        let mut current = workflow.value;
        if !current
            .step(HA_REPAIR_CAPTURE_STEP_INDEX)
            .is_some_and(|step| matches!(step.state, WorkflowStepState::Completed))
        {
            current = self
                .checkpoint_repair_capture(repair_workflow_id, &fence)
                .await?
                .value;
        }
        if !current
            .step(HA_REPAIR_PLAN_STEP_INDEX)
            .is_some_and(|step| matches!(step.state, WorkflowStepState::Completed))
        {
            current = self
                .checkpoint_repair_plan(repair_workflow_id, &fence)
                .await?
                .value;
        }
        if !current
            .step(HA_REPAIR_APPLY_STEP_INDEX)
            .is_some_and(|step| matches!(step.state, WorkflowStepState::Completed))
        {
            if let Err(error) = self
                .apply_repair_role_plan(repair_workflow_id, &fence, context)
                .await
            {
                let detail = format!("failed to apply HA role repair: {error}");
                let failed = self
                    .mark_repair_workflow_failed(repair_workflow_id, &fence, detail.clone())
                    .await?;
                self.append_event(
                    "ha.anti_entropy.repair.failed.v1",
                    "ha_repair_workflow",
                    failed.value.id.as_str(),
                    "failed",
                    serde_json::json!({
                        "drift_kind": &failed.value.state.drift_kind,
                        "drift_signature": &failed.value.state.drift_signature,
                        "phase": &failed.value.phase,
                        "reason": detail,
                        "trigger": trigger,
                    }),
                    context,
                )
                .await?;
                return Ok(failed.value);
            }
            current = self
                .checkpoint_repair_apply(repair_workflow_id, &fence)
                .await?
                .value;
        }
        if !current
            .step(HA_REPAIR_VERIFY_STEP_INDEX)
            .is_some_and(|step| matches!(step.state, WorkflowStepState::Completed))
        {
            if let Some(drift) = self.detect_anti_entropy_drift().await? {
                let detail = format!(
                    "HA role repair did not converge; current drift signature {}",
                    drift.drift_signature
                );
                let failed = self
                    .mark_repair_workflow_failed(repair_workflow_id, &fence, detail.clone())
                    .await?;
                self.append_event(
                    "ha.anti_entropy.repair.failed.v1",
                    "ha_repair_workflow",
                    failed.value.id.as_str(),
                    "failed",
                    serde_json::json!({
                        "drift_kind": &failed.value.state.drift_kind,
                        "drift_signature": &failed.value.state.drift_signature,
                        "phase": &failed.value.phase,
                        "reason": detail,
                        "trigger": trigger,
                    }),
                    context,
                )
                .await?;
                return Ok(failed.value);
            }
            let detail = String::from("single active topology verified after HA repair execution");
            let completed = self
                .complete_repair_workflow(repair_workflow_id, &fence, detail.clone())
                .await?;
            self.append_event(
                "ha.anti_entropy.repair.completed.v1",
                "ha_repair_workflow",
                completed.value.id.as_str(),
                "completed",
                serde_json::json!({
                    "drift_kind": &completed.value.state.drift_kind,
                    "drift_signature": &completed.value.state.drift_signature,
                    "phase": &completed.value.phase,
                    "reason": detail,
                    "trigger": trigger,
                }),
                context,
            )
            .await?;
            return Ok(completed.value);
        }
        Ok(current)
    }

    async fn acquire_lease(
        &self,
        request: LeaseRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let ttl_seconds = request.lease_seconds.clamp(5, 300);
        let now = OffsetDateTime::now_utc();

        let existing = self.leader_lease.get("leader").await?;
        if let Some(stored) = &existing
            && stored.value.holder_node_id != node_id
            && stored.value.lease_until > now
        {
            return Err(PlatformError::conflict(format!(
                "leader lease currently held by {} until {}",
                stored.value.holder_node_id, stored.value.lease_until
            )));
        }

        let term = existing.as_ref().map_or(1, |stored| stored.value.term + 1);
        let id = if let Some(stored) = &existing {
            stored.value.id.clone()
        } else {
            LeaderLeaseId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate leader lease id")
                    .with_detail(error.to_string())
            })?
        };
        let metadata = existing
            .as_ref()
            .map(|stored| {
                let mut metadata = stored.value.metadata.clone();
                metadata.touch(sha256_hex(node_id.as_str().as_bytes()));
                metadata
            })
            .unwrap_or_else(|| {
                ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(node_id.to_string()),
                    sha256_hex(node_id.as_str().as_bytes()),
                )
            });
        let lease = LeaderLeaseRecord {
            id,
            holder_node_id: node_id.clone(),
            term,
            lease_until: now + Duration::seconds(i64::from(ttl_seconds)),
            fencing_token: sha256_hex(format!("{node_id}:{term}:{now}").as_bytes()),
            metadata,
        };
        self.leader_lease
            .upsert(
                "leader",
                lease.clone(),
                existing.map(|stored| stored.version),
            )
            .await?;
        self.append_event(
            "ha.leader_lease.renewed.v1",
            "leader_lease",
            "leader",
            "renewed",
            serde_json::json!({
                "holder": lease.holder_node_id,
                "term": lease.term,
                "lease_until": lease.lease_until,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &lease)
    }

    async fn update_replication_status(
        &self,
        request: ReplicationRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let source = NodeId::parse(request.source_node_id).map_err(|error| {
            PlatformError::invalid("invalid source_node_id").with_detail(error.to_string())
        })?;
        let target = NodeId::parse(request.target_node_id).map_err(|error| {
            PlatformError::invalid("invalid target_node_id").with_detail(error.to_string())
        })?;
        let key = format!("{}:{}", source.as_str(), target.as_str());
        let existing = self.replication.get(&key).await?;
        let id = if let Some(stored) = &existing {
            stored.value.id.clone()
        } else {
            ReplicationStreamId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate replication stream id")
                    .with_detail(error.to_string())
            })?
        };
        let metadata = existing
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
            });
        let record = ReplicationStatusRecord {
            id,
            source_node_id: source,
            target_node_id: target,
            lag_seconds: request.lag_seconds,
            healthy: request.healthy,
            checked_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.replication
            .upsert(&key, record.clone(), existing.map(|stored| stored.version))
            .await?;
        self.append_event(
            "ha.replication.updated.v1",
            "replication_stream",
            &key,
            "updated",
            serde_json::json!({
                "lag_seconds": record.lag_seconds,
                "healthy": record.healthy,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn upsert_regional_quorum(
        &self,
        request: RegionalQuorumRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.applied_log_index > request.replicated_log_index {
            return Err(PlatformError::invalid(
                "applied_log_index may not exceed replicated_log_index",
            ));
        }
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let region = normalize_region_key(&request.region)?;
        let role = normalize_quorum_role(&request.role)?;
        let key = format!("{region}:{}", node_id.as_str());
        let existing = self.regional_quorum.get(&key).await?;
        let metadata = existing
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
            });
        let now = OffsetDateTime::now_utc();
        let lease_seconds = request.lease_seconds.unwrap_or(30).clamp(5, 600);
        let record = RegionalQuorumRecord {
            region,
            node_id,
            role,
            term: request.term.max(1),
            vote_weight: request.vote_weight.unwrap_or(1).max(1),
            healthy: request.healthy,
            replicated_log_index: request.replicated_log_index,
            applied_log_index: request.applied_log_index,
            lease_until: now + Duration::seconds(i64::from(lease_seconds)),
            updated_at: now,
            metadata,
        };
        self.regional_quorum
            .upsert(&key, record.clone(), existing.map(|stored| stored.version))
            .await?;
        self.append_event(
            "ha.quorum.updated.v1",
            "regional_quorum",
            &key,
            "updated",
            serde_json::json!({
                "term": record.term,
                "vote_weight": record.vote_weight,
                "healthy": record.healthy,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn append_consensus_entry(
        &self,
        request: ConsensusEntryRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let region = normalize_region_key(&request.region)?;
        if request.term == 0 {
            return Err(PlatformError::invalid("term must be at least 1"));
        }
        if request.log_index == 0 {
            return Err(PlatformError::invalid("log_index must be at least 1"));
        }
        let operation_kind = normalize_operation_kind(&request.operation_kind)?;
        let payload_hash = normalize_payload_hash(&request.payload_hash)?;
        let leader_node_id = NodeId::parse(request.leader_node_id).map_err(|error| {
            PlatformError::invalid("invalid leader_node_id").with_detail(error.to_string())
        })?;

        let key = consensus_entry_key(&region, request.log_index);
        if let Some(stored) = self.consensus_log.get(&key).await? {
            if stored.value.term == request.term
                && stored.value.payload_hash == payload_hash
                && stored.value.operation_kind == operation_kind
                && stored.value.leader_node_id == leader_node_id
            {
                return json_response(StatusCode::OK, &stored.value);
            }
            return Err(PlatformError::conflict(
                "consensus entry already exists with different content",
            ));
        }

        let mut region_entries = self
            .consensus_log
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.region == region)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        region_entries.sort_by_key(|entry| entry.log_index);
        if let Some(previous) = region_entries.last() {
            if request.term < previous.term {
                return Err(PlatformError::conflict(
                    "consensus term may not regress for a region",
                ));
            }
            let expected = previous.log_index.saturating_add(1);
            if request.log_index != expected {
                return Err(PlatformError::conflict(format!(
                    "consensus log_index must be contiguous; expected {}",
                    expected
                )));
            }
        } else if request.log_index != 1 {
            return Err(PlatformError::conflict(
                "first consensus entry in region must use log_index=1",
            ));
        }

        let record = ConsensusLogEntryRecord {
            region: region.clone(),
            term: request.term,
            log_index: request.log_index,
            operation_kind,
            payload_hash,
            leader_node_id,
            created_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(key.clone()),
                sha256_hex(key.as_bytes()),
            ),
        };
        self.consensus_log.create(&key, record.clone()).await?;
        self.append_event(
            "ha.consensus.entry.appended.v1",
            "consensus_log_entry",
            &key,
            "appended",
            serde_json::json!({
                "region": record.region,
                "term": record.term,
                "log_index": record.log_index,
                "operation_kind": record.operation_kind,
            }),
            context,
        )
        .await?;
        let _ = self
            .reconcile_region_now(&region, context, "consensus_append")
            .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn update_replication_shipment(
        &self,
        request: ReplicationShipmentRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let region = normalize_region_key(&request.region)?;
        if request.log_index == 0 {
            return Err(PlatformError::invalid("log_index must be at least 1"));
        }
        if request.term == 0 {
            return Err(PlatformError::invalid("term must be at least 1"));
        }
        let source_node_id = NodeId::parse(request.source_node_id).map_err(|error| {
            PlatformError::invalid("invalid source_node_id").with_detail(error.to_string())
        })?;
        let target_node_id = NodeId::parse(request.target_node_id).map_err(|error| {
            PlatformError::invalid("invalid target_node_id").with_detail(error.to_string())
        })?;
        let status = normalize_shipment_status(&request.status)?;
        let entry_key = consensus_entry_key(&region, request.log_index);
        let entry = self
            .consensus_log
            .get(&entry_key)
            .await?
            .ok_or_else(|| PlatformError::not_found("consensus entry does not exist"))?
            .value;
        if entry.term != request.term {
            return Err(PlatformError::conflict(
                "replication shipment term does not match consensus entry term",
            ));
        }
        let key = shipment_key(&region, request.log_index, &source_node_id, &target_node_id);
        let existing = self.replication_shipments.get(&key).await?;
        let metadata = existing
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
            });
        let record = ReplicationShipmentRecord {
            region: region.clone(),
            log_index: request.log_index,
            term: request.term,
            source_node_id,
            target_node_id,
            status,
            message: request
                .message
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            updated_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.replication_shipments
            .upsert(&key, record.clone(), existing.map(|stored| stored.version))
            .await?;
        self.append_event(
            "ha.replication.shipment.updated.v1",
            "replication_shipment",
            &key,
            "updated",
            serde_json::json!({
                "region": record.region,
                "term": record.term,
                "log_index": record.log_index,
                "status": record.status,
            }),
            context,
        )
        .await?;
        let _ = self
            .reconcile_region_now(&region, context, "shipment_update")
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn compute_reconciliation(&self, region: &str) -> Result<ReconciliationRecord> {
        let now = OffsetDateTime::now_utc();
        let mut entries = self
            .consensus_log
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.region == region)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.log_index);

        let quorum_members = self
            .regional_quorum
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.region == region)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let configured_votes = quorum_members
            .iter()
            .map(|member| u64::from(member.vote_weight))
            .sum::<u64>();
        let healthy_members = quorum_members
            .iter()
            .filter(|member| member.healthy && member.lease_until > now)
            .collect::<Vec<_>>();
        let healthy_votes = healthy_members
            .iter()
            .map(|member| u64::from(member.vote_weight))
            .sum::<u64>();
        let majority_threshold = if configured_votes == 0 {
            0
        } else {
            (configured_votes / 2) + 1
        };

        let shipments = self
            .replication_shipments
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.region == region)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();

        let mut node_applied_index = std::collections::BTreeMap::<String, u64>::new();
        for entry in &entries {
            let key = entry.leader_node_id.to_string();
            let slot = node_applied_index.entry(key).or_insert(0);
            if entry.log_index > *slot {
                *slot = entry.log_index;
            }
        }
        for shipment in shipments
            .iter()
            .filter(|shipment| shipment.status == "applied")
        {
            for node in [&shipment.source_node_id, &shipment.target_node_id] {
                let key = node.to_string();
                let slot = node_applied_index.entry(key).or_insert(0);
                if shipment.log_index > *slot {
                    *slot = shipment.log_index;
                }
            }
        }

        let mut committed_log_index = 0_u64;
        for entry in &entries {
            let votes = healthy_members
                .iter()
                .filter_map(|member| {
                    let applied = node_applied_index
                        .get(member.node_id.as_str())
                        .copied()
                        .unwrap_or(0);
                    if applied >= entry.log_index {
                        Some(u64::from(member.vote_weight))
                    } else {
                        None
                    }
                })
                .sum::<u64>();
            if configured_votes == 0 || votes >= majority_threshold {
                committed_log_index = entry.log_index;
            } else {
                break;
            }
        }

        let latest_log_index = entries.last().map(|entry| entry.log_index).unwrap_or(0);
        let uncommitted_entries = latest_log_index.saturating_sub(committed_log_index);
        let lagging_nodes = healthy_members
            .iter()
            .filter_map(|member| {
                let applied = node_applied_index
                    .get(member.node_id.as_str())
                    .copied()
                    .unwrap_or(0);
                if applied < committed_log_index {
                    Some(member.node_id.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let fully_reconciled =
            configured_votes > 0 && uncommitted_entries == 0 && healthy_votes >= majority_threshold;
        let key = region.to_owned();
        let existing = self.reconciliations.get(&key).await?;
        let metadata = existing
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
            });

        Ok(ReconciliationRecord {
            region: region.to_owned(),
            latest_log_index,
            committed_log_index,
            majority_threshold,
            healthy_votes,
            uncommitted_entries,
            lagging_nodes,
            fully_reconciled,
            evaluated_at: now,
            metadata,
        })
    }

    async fn reconcile_region_now(
        &self,
        region: &str,
        context: &RequestContext,
        trigger: &str,
    ) -> Result<ReconciliationRecord> {
        let record = self.compute_reconciliation(region).await?;
        let existing = self.reconciliations.get(region).await?;
        self.reconciliations
            .upsert(
                region,
                record.clone(),
                existing.map(|stored| stored.version),
            )
            .await?;
        self.append_event(
            "ha.reconciliation.updated.v1",
            "ha_reconciliation",
            region,
            "updated",
            serde_json::json!({
                "region": record.region,
                "latest_log_index": record.latest_log_index,
                "committed_log_index": record.committed_log_index,
                "fully_reconciled": record.fully_reconciled,
                "trigger": trigger,
            }),
            context,
        )
        .await?;
        Ok(record)
    }

    async fn reconcile_region(
        &self,
        request: ReconcileRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let region = normalize_region_key(&request.region)?;
        let record = self
            .reconcile_region_now(&region, context, "manual_reconcile")
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn consensus_reconciliation_status(&self) -> Result<(bool, u64, u64, u64)> {
        let entries = self
            .consensus_log
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Ok((true, 0, 0, 0));
        }

        let mut latest_by_region = std::collections::BTreeMap::<String, u64>::new();
        for entry in entries {
            let slot = latest_by_region.entry(entry.region).or_insert(0);
            if entry.log_index > *slot {
                *slot = entry.log_index;
            }
        }

        let reconciliations = self
            .reconciliations
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut committed_by_region = std::collections::BTreeMap::<String, u64>::new();
        for reconciliation in reconciliations {
            let slot = committed_by_region
                .entry(reconciliation.region)
                .or_insert(0);
            if reconciliation.committed_log_index > *slot {
                *slot = reconciliation.committed_log_index;
            }
        }

        let mut latest_log_index = 0_u64;
        let mut committed_log_index = 0_u64;
        let mut uncommitted_entries = 0_u64;
        for (region, latest) in latest_by_region {
            let committed = committed_by_region.get(&region).copied().unwrap_or(0);
            latest_log_index = latest_log_index.max(latest);
            committed_log_index = committed_log_index.max(committed);
            uncommitted_entries =
                uncommitted_entries.saturating_add(latest.saturating_sub(committed));
        }
        Ok((
            uncommitted_entries == 0,
            latest_log_index,
            committed_log_index,
            uncommitted_entries,
        ))
    }

    async fn quorum_summary(&self) -> Result<QuorumSummary> {
        let now = OffsetDateTime::now_utc();
        let members = self
            .regional_quorum
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();

        let configured_votes = members
            .iter()
            .map(|member| u64::from(member.vote_weight))
            .sum::<u64>();
        let healthy_votes = members
            .iter()
            .filter(|member| member.healthy && member.lease_until > now)
            .map(|member| u64::from(member.vote_weight))
            .sum::<u64>();
        let stale_member_count = members
            .iter()
            .filter(|member| !member.healthy || member.lease_until <= now)
            .count();
        let majority_threshold = if configured_votes == 0 {
            0
        } else {
            (configured_votes / 2) + 1
        };
        let quorum_satisfied = configured_votes > 0 && healthy_votes >= majority_threshold;

        Ok(QuorumSummary {
            configured_votes,
            healthy_votes,
            majority_threshold,
            quorum_satisfied,
            member_count: members.len(),
            stale_member_count,
            evaluated_at: now,
        })
    }

    async fn resolve_node_cell_ownership(
        &self,
        node_id: &NodeId,
    ) -> Result<NodeCellOwnershipResolution> {
        let mut aliases = BTreeSet::from([node_id.to_string()]);
        if let Some(heartbeat) = self
            .node_heartbeats
            .get(node_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
        {
            aliases.insert(heartbeat.hostname);
        }

        let mut matched_any = false;
        let mut healthy_cells = BTreeSet::new();
        for (_, stored) in self
            .cell_directory
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
        {
            for participant in &stored.value.participants {
                if participant_matches_node(participant, node_id, &aliases) {
                    matched_any = true;
                    if participant
                        .state
                        .as_ref()
                        .is_some_and(healthy_cell_participant_state)
                    {
                        healthy_cells.insert(stored.value.cell_id.clone());
                    }
                }
            }
        }

        if !matched_any {
            return Ok(NodeCellOwnershipResolution::Unavailable);
        }

        match healthy_cells.len() {
            0 => Ok(NodeCellOwnershipResolution::Unhealthy),
            1 => Ok(NodeCellOwnershipResolution::Owned),
            _ => Ok(NodeCellOwnershipResolution::Ambiguous {
                cell_ids: healthy_cells.into_iter().collect(),
            }),
        }
    }

    async fn scheduler_capacity_blockers(&self, to: &NodeId) -> Result<Vec<String>> {
        let nodes = self
            .scheduler_nodes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        if nodes.is_empty() {
            return Ok(Vec::new());
        }

        let Some(target) = nodes.into_iter().find(|node| node.id == *to) else {
            return Ok(vec![String::from(
                "target node is missing from scheduler inventory",
            )]);
        };

        let mut blockers = Vec::new();
        if target.drained {
            blockers.push(String::from(
                "target node is drained in scheduler inventory",
            ));
        }
        if target.free_cpu_millis == 0 {
            blockers.push(String::from(
                "target node has no free cpu in scheduler inventory",
            ));
        }
        if target.free_memory_mb == 0 {
            blockers.push(String::from(
                "target node has no free memory in scheduler inventory",
            ));
        }
        Ok(blockers)
    }

    async fn placement_safety_blockers(&self, from: &NodeId, to: &NodeId) -> Result<Vec<String>> {
        let workloads = self
            .control_workloads
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .map(|workload| (workload.id.clone(), workload))
            .collect::<BTreeMap<_, _>>();
        let deployments = self
            .control_deployments
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let placements = self
            .scheduler_placements
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();

        if workloads.is_empty() && deployments.is_empty() && placements.is_empty() {
            return Ok(Vec::new());
        }

        let mut deployment_counts = BTreeMap::<String, usize>::new();
        for deployment in &deployments {
            *deployment_counts
                .entry(deployment.workload_id.clone())
                .or_default() += 1;
        }

        let unanchored_deployments = deployments
            .iter()
            .filter(|deployment| !workloads.contains_key(&deployment.workload_id))
            .count();
        let mut missing_workload_anchors = Vec::new();
        let mut missing_deployment_anchors = Vec::new();
        let mut unsupported_spread = Vec::new();

        for placement in placements.iter().filter(|placement| {
            placement
                .node_id
                .as_ref()
                .is_some_and(|node_id| node_id == from || node_id == to)
        }) {
            let Some(workload) = workloads.get(&placement.workload_id) else {
                missing_workload_anchors.push(placement.workload_id.clone());
                continue;
            };
            if deployment_counts
                .get(&placement.workload_id)
                .copied()
                .unwrap_or(0)
                == 0
            {
                missing_deployment_anchors.push(placement.workload_id.clone());
                continue;
            }
            if placement.node_id.as_ref() == Some(from) && workload.replicas > 1 {
                unsupported_spread.push(format!(
                    "{} (desired replicas: {})",
                    workload.id, workload.replicas
                ));
            }
        }

        sort_and_dedup(&mut missing_workload_anchors);
        sort_and_dedup(&mut missing_deployment_anchors);
        sort_and_dedup(&mut unsupported_spread);

        let mut blockers = Vec::new();
        if unanchored_deployments > 0 {
            blockers.push(format!(
                "control service has {unanchored_deployments} deployment(s) without active workload anchors"
            ));
        }
        if !missing_workload_anchors.is_empty() {
            blockers.push(format!(
                "scheduler placements on failover nodes reference workload(s) with no active control workload anchor: {}",
                missing_workload_anchors.join(", ")
            ));
        }
        if !missing_deployment_anchors.is_empty() {
            blockers.push(format!(
                "scheduler placements on failover nodes reference workload(s) with no active deployment anchor: {}",
                missing_deployment_anchors.join(", ")
            ));
        }
        if !unsupported_spread.is_empty() {
            blockers.push(format!(
                "shard placement safety cannot be proven for source-node workload(s) in the current single-placement scheduler: {}",
                unsupported_spread.join(", ")
            ));
        }
        Ok(blockers)
    }

    async fn evacuation_routing_scope_ids(&self, from: &NodeId) -> Result<Vec<String>> {
        let workload_ids = self
            .control_workloads
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.id)
            .collect::<BTreeSet<_>>();
        let deployment_workload_ids = self
            .control_deployments
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.workload_id)
            .collect::<BTreeSet<_>>();
        let mut routing_scope_ids = self
            .scheduler_placements
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|placement| placement.node_id.as_ref() == Some(from))
            .filter(|placement| workload_ids.contains(&placement.workload_id))
            .filter(|placement| deployment_workload_ids.contains(&placement.workload_id))
            .map(|placement| format!("workload:{}", placement.workload_id))
            .collect::<BTreeSet<_>>();

        if routing_scope_ids.is_empty() {
            routing_scope_ids.insert(format!("node:{}", from.as_str()));
        }

        Ok(routing_scope_ids.into_iter().collect())
    }

    async fn prepare_evacuation_artifacts(
        &self,
        operation_id: &FailoverOperationId,
        from: &NodeId,
        to: &NodeId,
        prepared_at: OffsetDateTime,
    ) -> Result<HaEvacuationPreparationArtifacts> {
        let routing_scope_ids = self.evacuation_routing_scope_ids(from).await?;
        Ok(HaEvacuationPreparationArtifacts::new(
            operation_id,
            from,
            to,
            routing_scope_ids,
            prepared_at,
        ))
    }

    async fn build_failover_preflight(
        &self,
        from: NodeId,
        to: NodeId,
        lag_ceiling: u64,
    ) -> Result<FailoverPreflightResult> {
        let from_role = self
            .roles
            .get(from.as_str())
            .await?
            .map(|stored| stored.value);
        let to_role = self
            .roles
            .get(to.as_str())
            .await?
            .map(|stored| stored.value);
        let from_node_active = from_role
            .as_ref()
            .map(|record| record.role == "active")
            .unwrap_or(false);
        let to_node_passive = to_role
            .as_ref()
            .map(|record| record.role == "passive")
            .unwrap_or(false);
        let to_node_healthy = to_role
            .as_ref()
            .map(|record| record.healthy)
            .unwrap_or(false);

        let replication_key = format!("{}:{}", from.as_str(), to.as_str());
        let replication = self
            .replication
            .get(&replication_key)
            .await?
            .map(|stored| stored.value);
        let observed_replication_lag_seconds =
            replication.as_ref().map(|record| record.lag_seconds);
        let replication_present = replication.is_some();
        let replication_healthy = replication
            .as_ref()
            .map(|record| record.healthy)
            .unwrap_or(false);
        let replication_within_ceiling = replication
            .as_ref()
            .map(|record| record.lag_seconds <= lag_ceiling)
            .unwrap_or(false);
        let degraded_mode = self.degraded_mode().await?;
        let quorum = self.quorum_summary().await?;
        let quorum_satisfied = quorum.quorum_satisfied;
        let (
            consensus_fully_reconciled,
            consensus_latest_log_index,
            consensus_committed_log_index,
            consensus_uncommitted_entries,
        ) = self.consensus_reconciliation_status().await?;

        let mut blockers = Vec::new();
        if from_role.is_none() {
            blockers.push(String::from("from_node role does not exist"));
        }
        if to_role.is_none() {
            blockers.push(String::from("to_node role does not exist"));
        }
        if !from_node_active {
            blockers.push(String::from("from_node is not active"));
        }
        if !to_node_passive {
            blockers.push(String::from("to_node is not passive"));
        }
        if !to_node_healthy {
            blockers.push(String::from("to_node is not healthy"));
        }
        if !replication_present {
            blockers.push(String::from("replication status missing for failover path"));
        } else {
            if !replication_healthy {
                blockers.push(String::from("replication status is unhealthy"));
            }
            if !replication_within_ceiling {
                blockers.push(format!("replication lag exceeds ceiling of {lag_ceiling}s"));
            }
        }
        if degraded_mode {
            blockers.push(String::from(
                "critical dependency matrix indicates degraded mode",
            ));
        }
        if quorum.member_count == 0 {
            blockers.push(String::from("regional quorum has no configured members"));
        }
        if !quorum_satisfied {
            blockers.push(String::from(
                "regional quorum does not currently satisfy majority",
            ));
        }
        if !consensus_fully_reconciled {
            blockers.push(format!(
                "consensus reconciliation has {} uncommitted entries",
                consensus_uncommitted_entries
            ));
        }
        match self.resolve_node_cell_ownership(&from).await? {
            NodeCellOwnershipResolution::Unavailable | NodeCellOwnershipResolution::Owned => {}
            NodeCellOwnershipResolution::Unhealthy => blockers.push(String::from(
                "from_node has runtime cell ownership evidence but no healthy cell owner",
            )),
            NodeCellOwnershipResolution::Ambiguous { cell_ids } => blockers.push(format!(
                "from_node cell ownership is ambiguous across cells: {}",
                cell_ids.join(", ")
            )),
        }
        match self.resolve_node_cell_ownership(&to).await? {
            NodeCellOwnershipResolution::Unavailable | NodeCellOwnershipResolution::Owned => {}
            NodeCellOwnershipResolution::Unhealthy => blockers.push(String::from(
                "to_node has runtime cell ownership evidence but no healthy cell owner",
            )),
            NodeCellOwnershipResolution::Ambiguous { cell_ids } => blockers.push(format!(
                "to_node cell ownership is ambiguous across cells: {}",
                cell_ids.join(", ")
            )),
        }
        blockers.extend(self.scheduler_capacity_blockers(&to).await?);
        blockers.extend(self.placement_safety_blockers(&from, &to).await?);

        Ok(FailoverPreflightResult {
            from_node_id: from,
            to_node_id: to,
            max_replication_lag_seconds: lag_ceiling,
            observed_replication_lag_seconds,
            from_node_active,
            to_node_passive,
            to_node_healthy,
            replication_present,
            replication_healthy,
            replication_within_ceiling,
            degraded_mode,
            quorum_satisfied,
            consensus_fully_reconciled,
            consensus_latest_log_index,
            consensus_committed_log_index,
            consensus_uncommitted_entries,
            allowed: blockers.is_empty(),
            blockers,
            evaluated_at: OffsetDateTime::now_utc(),
        })
    }

    async fn preflight_failover(
        &self,
        request: FailoverPreflightRequest,
    ) -> Result<Response<ApiBody>> {
        let from = NodeId::parse(request.from_node_id).map_err(|error| {
            PlatformError::invalid("invalid from_node_id").with_detail(error.to_string())
        })?;
        let to = NodeId::parse(request.to_node_id).map_err(|error| {
            PlatformError::invalid("invalid to_node_id").with_detail(error.to_string())
        })?;
        let lag_ceiling = request.max_replication_lag_seconds.unwrap_or(30);
        let result = self.build_failover_preflight(from, to, lag_ceiling).await?;
        json_response(StatusCode::OK, &result)
    }

    async fn failover(
        &self,
        request: FailoverRequest,
        context: &RequestContext,
        mode: FailoverMode,
    ) -> Result<Response<ApiBody>> {
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let from = NodeId::parse(request.from_node_id.clone()).map_err(|error| {
            PlatformError::invalid("invalid from_node_id").with_detail(error.to_string())
        })?;
        let to = NodeId::parse(request.to_node_id.clone()).map_err(|error| {
            PlatformError::invalid("invalid to_node_id").with_detail(error.to_string())
        })?;
        let lag_ceiling = request.max_replication_lag_seconds.unwrap_or(30);

        let preflight = self
            .build_failover_preflight(from.clone(), to.clone(), lag_ceiling)
            .await?;
        if !preflight.allowed {
            let blocker_message = preflight.blockers.join("; ");
            self.append_event(
                mode.blocked_event(),
                "failover",
                "preflight",
                "blocked",
                serde_json::json!({
                    "operation_kind": mode.operation_kind(),
                    "from_node_id": from,
                    "to_node_id": to,
                    "blockers": preflight.blockers,
                }),
                context,
            )
            .await?;
            return Err(PlatformError::conflict(format!(
                "failover preflight denied: {blocker_message}"
            )));
        }

        let from_role = self
            .roles
            .get(from.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("from_node role does not exist"))?;
        let to_role = self
            .roles
            .get(to.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("to_node role does not exist"))?;

        let id = FailoverOperationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate failover operation id")
                .with_detail(error.to_string())
        })?;
        let created_at = OffsetDateTime::now_utc();
        let evacuation_artifacts = if mode == FailoverMode::Evacuation {
            Some(
                self.prepare_evacuation_artifacts(&id, &from, &to, created_at)
                    .await?,
            )
        } else {
            None
        };
        self.create_failover_workflow(FailoverRecord {
            id: id.clone(),
            from_node_id: from.clone(),
            to_node_id: to.clone(),
            drill: mode.is_drill(),
            operation_kind: String::from(mode.operation_kind()),
            reason: request.reason,
            state: FailoverState::Requested,
            degraded_mode: preflight.degraded_mode,
            workflow_id: None,
            checkpoints: Vec::new(),
            evacuation_artifacts: None,
            created_at,
            completed_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        })
        .await?;
        let fence = self.claim_failover_workflow_runner(&id).await?;
        self.checkpoint_failover_preflight(&id, &fence, &preflight)
            .await?;
        self.checkpoint_failover_intent(&id, &fence).await?;
        if let Some(artifacts) = evacuation_artifacts {
            self.checkpoint_failover_artifacts(&id, &fence, artifacts)
                .await?;
        }
        if let Err(error) = self
            .emit_failover_started_effect(&id, &fence, context)
            .await
        {
            let _ = self
                .mark_failover_workflow_failed(
                    &id,
                    &fence,
                    format!("failed to emit started event: {error}"),
                )
                .await;
            return Err(error);
        }

        if let Err(error) = self
            .execute_failover_execution_effect(
                &id,
                &fence,
                context,
                from_role.value.healthy,
                to_role.value.healthy,
            )
            .await
        {
            let failure_detail = if mode.is_drill() {
                format!("drill execution failed: {error}")
            } else {
                format!("role transition failed: {error}")
            };
            let _ = self
                .mark_failover_workflow_failed(&id, &fence, failure_detail)
                .await;
            if !mode.is_drill() {
                let _ = self
                    .reconcile_anti_entropy(context, "failover_role_transition_failed")
                    .await;
            }
            return Err(error);
        }

        self.checkpoint_failover_execution(&id, &fence).await?;
        if let Err(error) = self
            .emit_failover_completion_effect(&id, &fence, context)
            .await
        {
            let _ = self
                .mark_failover_workflow_failed(
                    &id,
                    &fence,
                    format!("failed to emit completion event: {error}"),
                )
                .await;
            return Err(error);
        }
        let stored = self.checkpoint_failover_completion(&id, &fence).await?;
        let record = project_failover_record(&stored.value);

        json_response(StatusCode::OK, &record)
    }

    async fn set_dependency_status(
        &self,
        request: DependencyRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let dependency = request.dependency.trim().to_ascii_lowercase();
        if dependency.is_empty() {
            return Err(PlatformError::invalid("dependency may not be empty"));
        }
        let status = normalize_dependency_status(&request.status)?;
        let existing = self.dependencies.get(&dependency).await?;
        let record = DependencyStatusRecord {
            dependency: dependency.clone(),
            status: status.clone(),
            critical: request.critical,
            checked_at: OffsetDateTime::now_utc(),
            message: request.message,
        };
        self.dependencies
            .upsert(
                &dependency,
                record.clone(),
                existing.map(|stored| stored.version),
            )
            .await?;
        self.append_event(
            "ha.dependency.updated.v1",
            "dependency_status",
            &dependency,
            "updated",
            serde_json::json!({
                "status": status,
                "critical": record.critical,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn degraded_mode(&self) -> Result<bool> {
        let values = self
            .dependencies
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        Ok(values.into_iter().any(|record| {
            record.critical && (record.status == "down" || record.status == "degraded")
        }))
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
        let _result_digest = self
            .append_event_with_idempotency(
                event_type,
                resource_kind,
                resource_id,
                action,
                details,
                context,
                None,
            )
            .await?;
        Ok(())
    }

    async fn append_event_with_idempotency(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
        context: &RequestContext,
        idempotency_key: Option<&str>,
    ) -> Result<String> {
        let expected_details = details.clone();
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("ha"),
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
        let generated_idempotency_key = event.header.event_id.to_string();
        let outbox_idempotency_key = idempotency_key.unwrap_or(generated_idempotency_key.as_str());
        let message = self
            .outbox
            .enqueue(HA_EVENTS_OUTBOX_TOPIC, event, Some(outbox_idempotency_key))
            .await?;
        validate_failover_event_outbox_message(
            &message,
            event_type,
            resource_kind,
            resource_id,
            action,
            &expected_details,
        )?;
        self.ensure_event_in_audit_log(&message.payload).await?;
        Ok(failover_event_result_digest(
            &message.payload,
            message.id.as_str(),
        ))
    }

    async fn ensure_event_in_audit_log(&self, event: &PlatformEvent) -> Result<()> {
        if self
            .audit_log_contains_event_id(event.header.event_id.as_str())
            .await?
        {
            return Ok(());
        }
        self.audit_log.append(event).await
    }

    async fn audit_log_contains_event_id(&self, event_id: &str) -> Result<bool> {
        let audit_path = self.state_root.join("audit.log");
        let contents = match fs::read_to_string(&audit_path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(PlatformError::unavailable("failed to read HA audit log")
                    .with_detail(error.to_string()));
            }
        };

        for line in contents.lines().filter(|line| !line.trim().is_empty()) {
            let event: PlatformEvent = serde_json::from_str(line).map_err(|error| {
                PlatformError::unavailable("failed to parse HA audit log event")
                    .with_detail(error.to_string())
            })?;
            if event.header.event_id.as_str() == event_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn readiness_summary(&self) -> Result<ReadinessSummary> {
        let roles = self
            .roles
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let mut role_map = std::collections::BTreeMap::new();
        for role in roles {
            let entry = role_map
                .entry(role.role.clone())
                .or_insert_with(|| RoleReadinessSummary {
                    role: role.role.clone(),
                    total: 0,
                    healthy: 0,
                    unhealthy: 0,
                });
            entry.total += 1;
            if role.healthy {
                entry.healthy += 1;
            } else {
                entry.unhealthy += 1;
            }
        }

        let replication_records = self
            .replication
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let healthy_streams = replication_records
            .iter()
            .filter(|record| record.healthy)
            .count();
        let unhealthy_streams = replication_records.len().saturating_sub(healthy_streams);
        let max_lag_seconds = replication_records
            .iter()
            .map(|record| record.lag_seconds)
            .max();

        let failover_records = self
            .failovers
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let last_completed_at = failover_records
            .iter()
            .filter_map(|record| record.completed_at)
            .max();
        let in_progress = failover_records
            .iter()
            .filter(|record| matches!(record.state, FailoverState::InProgress))
            .count();
        let failed = failover_records
            .iter()
            .filter(|record| matches!(record.state, FailoverState::Failed))
            .count();

        let reconciliations = self
            .reconciliations
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();

        let dependencies = self
            .dependencies
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();

        Ok(ReadinessSummary {
            state_root: self.state_root.display().to_string(),
            roles: role_map.into_values().collect(),
            replication: ReplicationReadinessSummary {
                total_streams: replication_records.len(),
                healthy_streams,
                unhealthy_streams,
                max_lag_seconds,
            },
            failovers: FailoverReadinessSummary {
                total_failovers: failover_records.len(),
                in_progress,
                failed,
                last_completed_at,
            },
            reconciliations,
            dependencies,
        })
    }
}

impl HttpService for HaService {
    fn name(&self) -> &'static str {
        "ha"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/ha")];
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
                (Method::GET, ["ha"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "topology": "active_passive_with_regional_quorum",
                    }),
                )
                .map(Some),
                (Method::GET, ["ha", "readiness-summary"]) => {
                    let summary = self.readiness_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["ha", "roles"]) => {
                    let values = self
                        .roles
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "roles"]) => {
                    let body: SetRoleRequest = parse_json(request).await?;
                    self.set_role(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "leader-lease"]) => {
                    let value = self
                        .leader_lease
                        .get("leader")
                        .await?
                        .map(|record| record.value);
                    json_response(StatusCode::OK, &value).map(Some)
                }
                (Method::POST, ["ha", "leader-lease"]) => {
                    let body: LeaseRequest = parse_json(request).await?;
                    self.acquire_lease(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "replication-status"]) => {
                    let values = self
                        .replication
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "replication-status"]) => {
                    let body: ReplicationRequest = parse_json(request).await?;
                    self.update_replication_status(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["ha", "regional-quorum"]) => {
                    let values = self
                        .regional_quorum
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "regional-quorum"]) => {
                    let body: RegionalQuorumRequest = parse_json(request).await?;
                    self.upsert_regional_quorum(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "consensus-log"]) => {
                    let values = self
                        .consensus_log
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "consensus-log"]) => {
                    let body: ConsensusEntryRequest = parse_json(request).await?;
                    self.append_consensus_entry(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "replication-shipping"]) => {
                    let values = self
                        .replication_shipments
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "replication-shipping"]) => {
                    let body: ReplicationShipmentRequest = parse_json(request).await?;
                    self.update_replication_shipment(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["ha", "reconciliations"]) => {
                    let values = self
                        .reconciliations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "reconcile"]) => {
                    let body: ReconcileRequest = parse_json(request).await?;
                    self.reconcile_region(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "repair-workflows"]) => {
                    let values = self
                        .repair_workflows
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "anti-entropy", "reconcile"]) => {
                    let workflow = self
                        .reconcile_anti_entropy(&context, "manual_reconcile")
                        .await?;
                    json_response(StatusCode::OK, &workflow).map(Some)
                }
                (Method::GET, ["ha", "quorum-summary"]) => {
                    let summary = self.quorum_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["ha", "failovers"]) => {
                    let values = self
                        .failovers
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "failover"]) => {
                    let body: FailoverRequest = parse_json(request).await?;
                    self.failover(body, &context, FailoverMode::Failover)
                        .await
                        .map(Some)
                }
                (Method::POST, ["ha", "failover-preflight"]) => {
                    let body: FailoverPreflightRequest = parse_json(request).await?;
                    self.preflight_failover(body).await.map(Some)
                }
                (Method::POST, ["ha", "evacuation"]) => {
                    let body: FailoverRequest = parse_json(request).await?;
                    self.failover(body, &context, FailoverMode::Evacuation)
                        .await
                        .map(Some)
                }
                (Method::POST, ["ha", "drills"]) => {
                    let body: FailoverRequest = parse_json(request).await?;
                    self.failover(body, &context, FailoverMode::Drill)
                        .await
                        .map(Some)
                }
                (Method::GET, ["ha", "dependency-matrix"]) => {
                    let values = self
                        .dependencies
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["ha", "dependency-matrix"]) => {
                    let body: DependencyRequest = parse_json(request).await?;
                    self.set_dependency_status(body, &context).await.map(Some)
                }
                (Method::GET, ["ha", "degraded-mode"]) => {
                    let degraded = self.degraded_mode().await?;
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "degraded_mode": degraded,
                        }),
                    )
                    .map(Some)
                }
                (Method::GET, ["ha", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn healthy_cell_participant_state(state: &CellParticipantState) -> bool {
    state.readiness == LeaseReadiness::Ready
        && state.drain_intent == LeaseDrainIntent::Serving
        && state.lease.freshness == LeaseFreshness::Fresh
}

fn participant_matches_node(
    participant: &CellParticipantRecord,
    node_id: &NodeId,
    aliases: &BTreeSet<String>,
) -> bool {
    participant.subject_id == node_id.as_str()
        || participant.registration_id == node_id.as_str()
        || participant
            .lease_registration_id
            .as_deref()
            .is_some_and(|value| value == node_id.as_str())
        || participant
            .node_name
            .as_deref()
            .is_some_and(|value| aliases.contains(value))
}

fn sort_and_dedup(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

fn normalize_role(value: &str) -> Result<String> {
    let role = value.trim().to_ascii_lowercase();
    match role.as_str() {
        "active" | "passive" => Ok(role),
        _ => Err(PlatformError::invalid("role must be `active` or `passive`")),
    }
}

fn normalize_quorum_role(value: &str) -> Result<String> {
    let role = value.trim().to_ascii_lowercase();
    match role.as_str() {
        "leader" | "follower" | "candidate" => Ok(role),
        _ => Err(PlatformError::invalid(
            "quorum role must be one of leader/follower/candidate",
        )),
    }
}

fn normalize_region_key(value: &str) -> Result<String> {
    let key = value.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(PlatformError::invalid("region may not be empty"));
    }
    if key
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    {
        Ok(key)
    } else {
        Err(PlatformError::invalid(
            "region must contain only [a-z0-9_-] characters",
        ))
    }
}

fn normalize_operation_kind(value: &str) -> Result<String> {
    let kind = value.trim().to_ascii_lowercase();
    if kind.is_empty() {
        return Err(PlatformError::invalid("operation_kind may not be empty"));
    }
    if !kind
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(PlatformError::invalid(
            "operation_kind must contain only [a-z0-9_-] characters",
        ));
    }
    Ok(kind)
}

fn normalize_payload_hash(value: &str) -> Result<String> {
    let hash = value.trim().to_ascii_lowercase();
    if hash.is_empty() {
        return Err(PlatformError::invalid("payload_hash may not be empty"));
    }
    if !hash
        .chars()
        .all(|character| character.is_ascii_hexdigit() || character == '-')
    {
        return Err(PlatformError::invalid(
            "payload_hash must contain hex characters",
        ));
    }
    Ok(hash)
}

fn normalize_shipment_status(value: &str) -> Result<String> {
    let status = value.trim().to_ascii_lowercase();
    match status.as_str() {
        "in_flight" | "applied" | "failed" => Ok(status),
        _ => Err(PlatformError::invalid(
            "shipment status must be one of in_flight/applied/failed",
        )),
    }
}

fn consensus_entry_key(region: &str, log_index: u64) -> String {
    format!("{region}:{log_index:020}")
}

fn shipment_key(region: &str, log_index: u64, source: &NodeId, target: &NodeId) -> String {
    format!(
        "{region}:{log_index:020}:{}:{}",
        source.as_str(),
        target.as_str()
    )
}

fn default_failover_operation_kind() -> String {
    String::from("failover")
}

fn normalize_dependency_status(value: &str) -> Result<String> {
    let status = value.trim().to_ascii_lowercase();
    match status.as_str() {
        "up" | "degraded" | "down" => Ok(status),
        _ => Err(PlatformError::invalid(
            "status must be one of up/degraded/down",
        )),
    }
}

fn build_pending_failover_workflow(record: FailoverRecord) -> HaFailoverWorkflow {
    let mode = failover_mode_from_record(&record);
    let created_at = record.created_at;
    let mut workflow_state = record.clone();
    workflow_state.workflow_id = None;
    workflow_state.checkpoints.clear();
    let mut workflow = HaFailoverWorkflow::new(
        record.id.to_string(),
        mode.workflow_kind(),
        HA_FAILOVER_WORKFLOW_SUBJECT_KIND,
        record.id.to_string(),
        workflow_state,
        failover_workflow_steps(mode),
    );
    workflow.created_at = created_at;
    workflow.updated_at = created_at;
    workflow.completed_at = None;
    workflow.current_step_index = None;
    set_failover_workflow_phase_at(&mut workflow, WorkflowPhase::Pending, created_at);
    workflow
}

fn build_failover_workflow(record: FailoverRecord) -> HaFailoverWorkflow {
    let mode = failover_mode_from_record(&record);
    let created_at = record.created_at;
    let updated_at = if let Some(completed_at) = record.completed_at {
        completed_at
    } else {
        record.metadata.updated_at
    };
    let mut workflow_state = record.clone();
    let checkpoints = workflow_state.checkpoints.clone();
    workflow_state.workflow_id = None;
    workflow_state.checkpoints.clear();
    let mut workflow = HaFailoverWorkflow::new(
        record.id.to_string(),
        mode.workflow_kind(),
        HA_FAILOVER_WORKFLOW_SUBJECT_KIND,
        record.id.to_string(),
        workflow_state,
        failover_workflow_steps(mode),
    );
    workflow.created_at = created_at;
    workflow.updated_at = updated_at;
    ensure_failover_workflow_shape(&mut workflow, mode);

    if !checkpoints.is_empty() {
        workflow.phase = workflow_phase_from_failover_state(&record.state);
        workflow.steps = normalize_failover_workflow_steps(
            &checkpoints,
            mode,
            &workflow.phase,
            record.evacuation_artifacts.as_ref(),
            updated_at,
        );
        workflow.current_step_index = failover_current_step_index(&workflow.steps, &workflow.phase);
        workflow.completed_at = if is_terminal_workflow_phase(&workflow.phase) {
            record.completed_at.or(Some(updated_at))
        } else {
            None
        };
        return workflow;
    }

    match &record.state {
        FailoverState::Requested => {
            workflow.phase = WorkflowPhase::Pending;
            workflow.current_step_index = None;
            workflow.completed_at = None;
        }
        FailoverState::InProgress => {
            workflow.phase = WorkflowPhase::Running;
            workflow.current_step_index = Some(failover_execute_step_index(mode));
            if let Some(step) = workflow.step_mut(FAILOVER_PRECHECK_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(String::from(
                        "preflight accepted (reconstructed legacy workflow)",
                    )),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(FAILOVER_INTENT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_intent_detail(
                        mode,
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(artifact_step_index) = failover_artifact_step_index(mode)
                && let Some(step) = workflow.step_mut(artifact_step_index)
            {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_artifact_detail(
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(failover_execute_step_index(mode)) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Active,
                    Some(failover_execution_active_detail(
                        mode,
                        &record.from_node_id,
                        &record.to_node_id,
                    )),
                    updated_at,
                );
            }
            workflow.completed_at = None;
        }
        FailoverState::Completed => {
            workflow.phase = WorkflowPhase::Completed;
            workflow.current_step_index = Some(failover_finalize_step_index(mode));
            if let Some(step) = workflow.step_mut(FAILOVER_PRECHECK_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(String::from("preflight accepted")),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(FAILOVER_INTENT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_intent_detail(
                        mode,
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(artifact_step_index) = failover_artifact_step_index(mode)
                && let Some(step) = workflow.step_mut(artifact_step_index)
            {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_artifact_detail(
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(failover_execute_step_index(mode)) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_execution_completed_detail(
                        mode,
                        &record.from_node_id,
                        &record.to_node_id,
                    )),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(failover_finalize_step_index(mode)) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_completion_detail(mode)),
                    updated_at,
                );
            }
            workflow.completed_at = record.completed_at.or(Some(updated_at));
        }
        FailoverState::Failed => {
            workflow.phase = WorkflowPhase::Failed;
            workflow.current_step_index = Some(failover_execute_step_index(mode));
            if let Some(step) = workflow.step_mut(FAILOVER_PRECHECK_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(String::from("preflight accepted")),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(FAILOVER_INTENT_STEP_INDEX) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_intent_detail(
                        mode,
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(artifact_step_index) = failover_artifact_step_index(mode)
                && let Some(step) = workflow.step_mut(artifact_step_index)
            {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Completed,
                    Some(failover_artifact_detail(
                        record.evacuation_artifacts.as_ref(),
                    )),
                    updated_at,
                );
            }
            if let Some(step) = workflow.step_mut(failover_execute_step_index(mode)) {
                set_failover_step_state_at(
                    step,
                    WorkflowStepState::Failed,
                    Some(String::from("legacy failover record marked failed")),
                    updated_at,
                );
            }
            workflow.completed_at = record.completed_at.or(Some(updated_at));
        }
    }

    workflow
}

fn ensure_failover_workflow_shape(workflow: &mut HaFailoverWorkflow, mode: FailoverMode) {
    workflow.workflow_kind = String::from(mode.workflow_kind());
    workflow.subject_kind = String::from(HA_FAILOVER_WORKFLOW_SUBJECT_KIND);
    workflow.subject_id = workflow.state.id.to_string();
    workflow.steps = normalize_failover_workflow_steps(
        &workflow.steps,
        mode,
        &workflow.phase,
        workflow.state.evacuation_artifacts.as_ref(),
        workflow.updated_at,
    );
    workflow.current_step_index = failover_current_step_index(&workflow.steps, &workflow.phase);
}

fn failover_workflow_steps(mode: FailoverMode) -> Vec<WorkflowStep> {
    failover_workflow_step_names(mode)
        .into_iter()
        .enumerate()
        .map(|(index, name)| WorkflowStep::new(name, index))
        .collect::<Vec<_>>()
}

fn failover_workflow_step_names(mode: FailoverMode) -> Vec<&'static str> {
    let mut steps = vec!["validate_preflight", "persist_intent_checkpoint"];
    if mode == FailoverMode::Evacuation {
        steps.push(FAILOVER_EVACUATION_ARTIFACT_STEP_NAME);
    }
    steps.push(mode.execution_step_name());
    steps.push("persist_completion_checkpoint");
    steps
}

fn failover_artifact_step_index(mode: FailoverMode) -> Option<usize> {
    (mode == FailoverMode::Evacuation).then_some(FAILOVER_ARTIFACT_STEP_INDEX)
}

fn failover_execute_step_index(mode: FailoverMode) -> usize {
    match mode {
        FailoverMode::Evacuation => FAILOVER_ARTIFACT_STEP_INDEX + 1,
        FailoverMode::Failover | FailoverMode::Drill => FAILOVER_ARTIFACT_STEP_INDEX,
    }
}

fn failover_finalize_step_index(mode: FailoverMode) -> usize {
    failover_execute_step_index(mode) + 1
}

fn ha_failover_workflow_lease_duration() -> Duration {
    Duration::minutes(5)
}

fn ha_repair_workflow_lease_duration() -> Duration {
    Duration::minutes(5)
}

fn failover_workflow_requires_execution(workflow: &HaFailoverWorkflow) -> bool {
    matches!(
        workflow.phase,
        WorkflowPhase::Pending | WorkflowPhase::Running
    )
}

fn repair_workflow_requires_execution(workflow: &HaRepairWorkflow) -> bool {
    matches!(
        workflow.phase,
        WorkflowPhase::Pending | WorkflowPhase::Running
    )
}

fn sync_failover_workflow_next_attempt(
    workflow: &mut HaFailoverWorkflow,
    observed_at: OffsetDateTime,
) -> bool {
    let desired_next_attempt_at =
        failover_workflow_requires_execution(workflow).then_some(observed_at);
    if workflow.next_attempt_at == desired_next_attempt_at {
        return false;
    }
    workflow.set_next_attempt_at(desired_next_attempt_at, observed_at);
    true
}

fn sync_repair_workflow_next_attempt(
    workflow: &mut HaRepairWorkflow,
    observed_at: OffsetDateTime,
) -> bool {
    let desired_next_attempt_at =
        repair_workflow_requires_execution(workflow).then_some(observed_at);
    if workflow.next_attempt_at == desired_next_attempt_at {
        return false;
    }
    workflow.set_next_attempt_at(desired_next_attempt_at, observed_at);
    true
}

fn apply_failover_workflow_execution_primitives(
    workflow: &mut HaFailoverWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    // Failover execution is lease/fencing guarded: adopt the runner claim only
    // if it is absent or already ours, heartbeat the claim while runnable work
    // remains, and keep `next_attempt_at` aligned with whether the workflow can
    // still make forward progress.
    let desired_next_attempt_at =
        failover_workflow_requires_execution(workflow).then_some(observed_at);
    let active_claim = workflow
        .runner_claim
        .clone()
        .filter(|claim| claim.is_active_at(observed_at));

    if active_claim
        .as_ref()
        .is_some_and(|claim| claim.runner_id != HA_FAILOVER_WORKFLOW_RUNNER_ID)
    {
        return Ok(false);
    }

    let mut changed = false;
    if desired_next_attempt_at.is_some() {
        if let Some(active_claim) = active_claim.as_ref() {
            let fencing_token = active_claim.fencing_token.clone();
            workflow.heartbeat_runner_at(
                HA_FAILOVER_WORKFLOW_RUNNER_ID,
                fencing_token.as_str(),
                ha_failover_workflow_lease_duration(),
                observed_at,
            )?;
        } else {
            workflow.claim_runner_at(
                HA_FAILOVER_WORKFLOW_RUNNER_ID,
                ha_failover_workflow_lease_duration(),
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

fn apply_repair_workflow_execution_primitives(
    workflow: &mut HaRepairWorkflow,
    observed_at: OffsetDateTime,
) -> Result<bool> {
    let desired_next_attempt_at =
        repair_workflow_requires_execution(workflow).then_some(observed_at);
    let active_claim = workflow
        .runner_claim
        .clone()
        .filter(|claim| claim.is_active_at(observed_at));

    if active_claim
        .as_ref()
        .is_some_and(|claim| claim.runner_id != HA_REPAIR_WORKFLOW_RUNNER_ID)
    {
        return Ok(false);
    }

    let mut changed = false;
    if desired_next_attempt_at.is_some() {
        if let Some(active_claim) = active_claim.as_ref() {
            let fencing_token = active_claim.fencing_token.clone();
            workflow.heartbeat_runner_at(
                HA_REPAIR_WORKFLOW_RUNNER_ID,
                fencing_token.as_str(),
                ha_repair_workflow_lease_duration(),
                observed_at,
            )?;
        } else {
            workflow.claim_runner_at(
                HA_REPAIR_WORKFLOW_RUNNER_ID,
                ha_repair_workflow_lease_duration(),
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

fn failover_workflow_needs_shape_normalization(workflow: &HaFailoverWorkflow) -> bool {
    let mode = failover_mode_from_record(&workflow.state);
    let step_names = failover_workflow_step_names(mode);
    workflow.workflow_kind != mode.workflow_kind()
        || workflow.subject_kind != HA_FAILOVER_WORKFLOW_SUBJECT_KIND
        || workflow.subject_id != workflow.state.id.to_string()
        || workflow.steps.len() != step_names.len()
        || workflow
            .steps
            .iter()
            .zip(step_names.iter())
            .enumerate()
            .any(|(index, (step, expected_name))| {
                step.index != index || step.name != *expected_name
            })
}

fn normalize_failover_workflow_steps(
    existing_steps: &[WorkflowStep],
    mode: FailoverMode,
    phase: &WorkflowPhase,
    evacuation_artifacts: Option<&HaEvacuationPreparationArtifacts>,
    observed_at: OffsetDateTime,
) -> Vec<WorkflowStep> {
    let mut normalized = failover_workflow_steps(mode);
    let step_names = failover_workflow_step_names(mode);
    for (index, name) in step_names.iter().enumerate() {
        if let Some(existing) = existing_steps.iter().find(|step| step.name == *name) {
            let mut step = existing.clone();
            step.name = String::from(*name);
            step.index = index;
            normalized[index] = step;
        }
    }

    if let Some(artifact_step_index) = failover_artifact_step_index(mode)
        && let Some(step) = normalized.get_mut(artifact_step_index)
        && step.state == WorkflowStepState::Pending
        && should_backfill_evacuation_artifact_step(phase, evacuation_artifacts)
    {
        set_failover_step_state_at(
            step,
            WorkflowStepState::Completed,
            Some(failover_artifact_detail(evacuation_artifacts)),
            observed_at,
        );
    }

    normalized
}

fn should_backfill_evacuation_artifact_step(
    phase: &WorkflowPhase,
    evacuation_artifacts: Option<&HaEvacuationPreparationArtifacts>,
) -> bool {
    evacuation_artifacts.is_some()
        || matches!(
            phase,
            WorkflowPhase::Completed | WorkflowPhase::Failed | WorkflowPhase::RolledBack
        )
}

fn failover_mode_from_record(record: &FailoverRecord) -> FailoverMode {
    match record.operation_kind.as_str() {
        "drill" => FailoverMode::Drill,
        "evacuation" => FailoverMode::Evacuation,
        _ if record.drill => FailoverMode::Drill,
        _ => FailoverMode::Failover,
    }
}

fn failover_precheck_detail(preflight: &FailoverPreflightResult) -> String {
    let observed_lag = preflight
        .observed_replication_lag_seconds
        .map(|value| format!("{value}s"))
        .unwrap_or_else(|| String::from("missing"));
    format!(
        "preflight allowed; lag_ceiling={}s; observed_lag={observed_lag}; quorum_satisfied={}; consensus_committed={}/{}; degraded_mode={}",
        preflight.max_replication_lag_seconds,
        preflight.quorum_satisfied,
        preflight.consensus_committed_log_index,
        preflight.consensus_latest_log_index,
        preflight.degraded_mode,
    )
}

fn failover_intent_detail(
    mode: FailoverMode,
    evacuation_artifacts: Option<&HaEvacuationPreparationArtifacts>,
) -> String {
    if mode == FailoverMode::Evacuation
        && let Some(artifacts) = evacuation_artifacts
    {
        return format!(
            "evacuation preparation persisted route-withdrawal={}, target-readiness={}, rollback={}; routing_scopes={}",
            artifacts.route_withdrawal.artifact_id,
            artifacts.target_readiness.artifact_id,
            artifacts.rollback.artifact_id,
            artifacts.route_withdrawal.routing_scope_ids.join(", ")
        );
    }
    if mode == FailoverMode::Evacuation {
        return String::from("evacuation intent persisted before evacuation artifact preparation");
    }
    format!(
        "{} intent persisted before side-effect execution",
        mode.operation_kind()
    )
}

fn failover_intent_active_detail(mode: FailoverMode) -> String {
    if mode == FailoverMode::Evacuation {
        return String::from(
            "persisting evacuation intent checkpoint before evacuation artifact preparation",
        );
    }
    format!(
        "persisting {} intent checkpoint before side-effect execution",
        mode.operation_kind()
    )
}

fn failover_artifact_detail(
    evacuation_artifacts: Option<&HaEvacuationPreparationArtifacts>,
) -> String {
    match evacuation_artifacts {
        Some(artifacts) => format!(
            "evacuation artifacts prepared route-withdrawal={}, target-readiness={}, rollback={}; routing_scopes={}",
            artifacts.route_withdrawal.artifact_id,
            artifacts.target_readiness.artifact_id,
            artifacts.rollback.artifact_id,
            artifacts.route_withdrawal.routing_scope_ids.join(", ")
        ),
        None => {
            String::from("evacuation artifact checkpoint reconstructed without durable artifacts")
        }
    }
}

fn failover_artifact_active_detail(from: &NodeId, to: &NodeId) -> String {
    format!(
        "preparing evacuation artifacts for {} to {} cutover",
        from.as_str(),
        to.as_str()
    )
}

fn failover_execution_active_detail(mode: FailoverMode, from: &NodeId, to: &NodeId) -> String {
    match mode {
        FailoverMode::Failover => {
            format!("promoting {} while demoting {}", to.as_str(), from.as_str())
        }
        FailoverMode::Drill => format!(
            "recording drill from {} to {} without role mutation",
            from.as_str(),
            to.as_str()
        ),
        FailoverMode::Evacuation => format!("evacuating {} onto {}", from.as_str(), to.as_str()),
    }
}

fn failover_execution_completed_detail(mode: FailoverMode, from: &NodeId, to: &NodeId) -> String {
    match mode {
        FailoverMode::Failover => format!(
            "failover applied; {} is passive and {} is active",
            from.as_str(),
            to.as_str()
        ),
        FailoverMode::Drill => format!(
            "drill recorded for {} to {} without mutating roles",
            from.as_str(),
            to.as_str()
        ),
        FailoverMode::Evacuation => format!(
            "evacuation applied; {} is passive and {} is active",
            from.as_str(),
            to.as_str()
        ),
    }
}

fn failover_completion_detail(mode: FailoverMode) -> String {
    format!("{} completion checkpoint persisted", mode.operation_kind())
}

fn failover_completion_active_detail(mode: FailoverMode) -> String {
    format!(
        "persisting {} completion checkpoint after execution",
        mode.operation_kind()
    )
}

fn failover_step_effect_idempotency_key(
    operation_id: &FailoverOperationId,
    effect_kind: &str,
) -> String {
    format!("ha.failover:{}:{effect_kind}", operation_id.as_str())
}

fn failover_started_event_effect_detail(mode: FailoverMode) -> String {
    format!("{} started event emitted", mode.operation_kind())
}

fn failover_execution_effect_kind(mode: FailoverMode) -> &'static str {
    match mode {
        FailoverMode::Drill => FAILOVER_DRILL_OUTCOME_EFFECT_KIND,
        FailoverMode::Failover | FailoverMode::Evacuation => FAILOVER_ROLE_TRANSITION_EFFECT_KIND,
    }
}

fn failover_execution_effect_detail(mode: FailoverMode, from: &NodeId, to: &NodeId) -> String {
    failover_execution_completed_detail(mode, from, to)
}

fn failover_completion_event_effect_detail(mode: FailoverMode) -> String {
    format!("{} completion event emitted", mode.operation_kind())
}

fn failover_effect_replay_result_digest(
    effect_kind: &str,
    result_digest: Option<&String>,
) -> Result<String> {
    result_digest.cloned().ok_or_else(|| {
        PlatformError::conflict(format!(
            "failover effect `{effect_kind}` is replayable but missing a result digest"
        ))
    })
}

fn failover_effect_requires_dedicated_ledger(effect_kind: &str) -> bool {
    matches!(
        effect_kind,
        FAILOVER_ROLE_TRANSITION_EFFECT_KIND | FAILOVER_DRILL_OUTCOME_EFFECT_KIND
    )
}

fn failover_event_result_digest(event: &PlatformEvent, outbox_message_id: &str) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}",
            event.header.event_id.as_str(),
            outbox_message_id,
            event.header.event_type
        )
        .as_bytes(),
    )
}

fn failover_role_transition_result_digest(
    from_role: &NodeRoleRecord,
    to_role: &NodeRoleRecord,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            from_role.node_id.as_str(),
            from_role.role,
            from_role.healthy,
            from_role.last_heartbeat_at.unix_timestamp_nanos(),
            to_role.node_id.as_str(),
            to_role.role,
            to_role.healthy,
            to_role.last_heartbeat_at.unix_timestamp_nanos(),
        )
        .as_bytes(),
    )
}

fn failover_drill_effect_result_digest(record: &FailoverRecord) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{}",
            record.id.as_str(),
            record.operation_kind.as_str(),
            record.from_node_id.as_str(),
            record.to_node_id.as_str(),
            record.reason.as_str(),
        )
        .as_bytes(),
    )
}

fn failover_started_event_details(workflow: &HaFailoverWorkflow) -> serde_json::Value {
    serde_json::json!({
        "operation_kind": workflow.state.operation_kind.clone(),
        "from": workflow.state.from_node_id.clone(),
        "to": workflow.state.to_node_id.clone(),
        "degraded_mode": workflow.state.degraded_mode,
        "workflow_id": workflow.id.clone(),
        "evacuation_artifacts": &workflow.state.evacuation_artifacts,
    })
}

fn failover_completed_event_details(workflow: &HaFailoverWorkflow) -> serde_json::Value {
    serde_json::json!({
        "operation_kind": workflow.state.operation_kind.clone(),
        "workflow_id": workflow.id.clone(),
        "checkpoint_count": workflow.steps.len(),
        "evacuation_artifacts": &workflow.state.evacuation_artifacts,
    })
}

fn validate_failover_event_outbox_message(
    message: &OutboxMessage<PlatformEvent>,
    event_type: &str,
    resource_kind: &str,
    resource_id: &str,
    action: &str,
    details: &serde_json::Value,
) -> Result<()> {
    if message.payload.header.event_type != event_type {
        return Err(PlatformError::conflict(format!(
            "outbox idempotency key is already bound to event type `{}`",
            message.payload.header.event_type
        )));
    }
    let EventPayload::Service(service) = &message.payload.payload else {
        return Err(PlatformError::conflict(
            "outbox idempotency key is already bound to a non-service event payload",
        ));
    };
    if service.resource_kind != resource_kind
        || service.resource_id != resource_id
        || service.action != action
        || service.details != *details
    {
        return Err(PlatformError::conflict(
            "outbox idempotency key is already bound to a different HA event payload",
        ));
    }
    Ok(())
}

fn normalize_routing_scope_ids(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn workflow_phase_from_failover_state(state: &FailoverState) -> WorkflowPhase {
    match state {
        FailoverState::Requested => WorkflowPhase::Pending,
        FailoverState::InProgress => WorkflowPhase::Running,
        FailoverState::Completed => WorkflowPhase::Completed,
        FailoverState::Failed => WorkflowPhase::Failed,
    }
}

fn failover_state_from_workflow_phase(phase: &WorkflowPhase) -> FailoverState {
    match phase {
        WorkflowPhase::Pending => FailoverState::Requested,
        WorkflowPhase::Running | WorkflowPhase::Paused => FailoverState::InProgress,
        WorkflowPhase::Completed => FailoverState::Completed,
        WorkflowPhase::Failed | WorkflowPhase::RolledBack => FailoverState::Failed,
    }
}

fn failover_current_step_index(steps: &[WorkflowStep], phase: &WorkflowPhase) -> Option<usize> {
    steps
        .iter()
        .find(|step| {
            matches!(
                step.state,
                WorkflowStepState::Active
                    | WorkflowStepState::Failed
                    | WorkflowStepState::RolledBack
            )
        })
        .map(|step| step.index)
        .or_else(|| {
            steps
                .iter()
                .filter(|step| matches!(step.state, WorkflowStepState::Completed))
                .map(|step| step.index)
                .max()
        })
        .or_else(|| (!steps.is_empty() && !matches!(phase, WorkflowPhase::Pending)).then_some(0))
}

fn project_failover_record(workflow: &HaFailoverWorkflow) -> FailoverRecord {
    let mut record = workflow.state.clone();
    record.state = failover_state_from_workflow_phase(&workflow.phase);
    record.workflow_id = Some(workflow.id.clone());
    record.checkpoints = workflow.steps.clone();
    record.created_at = workflow.created_at;
    record.completed_at = if is_terminal_workflow_phase(&workflow.phase) {
        workflow
            .completed_at
            .or(record.completed_at)
            .or(Some(workflow.updated_at))
    } else {
        None
    };
    record.metadata.created_at = workflow.created_at;
    record.metadata.updated_at = workflow.updated_at;
    record.metadata.etag = sha256_hex(
        format!(
            "{}:{}:{}",
            workflow.id,
            workflow_phase_label(&workflow.phase),
            workflow.updated_at.unix_timestamp_nanos(),
        )
        .as_bytes(),
    );
    record
        .metadata
        .annotations
        .insert(String::from("ha.workflow_id"), workflow.id.clone());
    record.metadata.annotations.insert(
        String::from("ha.workflow_kind"),
        workflow.workflow_kind.clone(),
    );
    record.metadata.annotations.insert(
        String::from("ha.workflow_phase"),
        String::from(workflow_phase_label(&workflow.phase)),
    );
    record
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

fn set_failover_step_state_at(
    step: &mut WorkflowStep,
    state: WorkflowStepState,
    detail: Option<String>,
    observed_at: OffsetDateTime,
) {
    step.state = state;
    step.detail = detail;
    step.updated_at = observed_at;
}

fn set_failover_workflow_phase_at(
    workflow: &mut HaFailoverWorkflow,
    phase: WorkflowPhase,
    observed_at: OffsetDateTime,
) {
    workflow.set_phase_at(phase.clone(), observed_at);
    workflow.state.state = failover_state_from_workflow_phase(&phase);
}

fn build_repair_workflow(drift: DetectedHaDrift) -> Result<HaRepairWorkflow> {
    let repair_id = RepairJobId::generate().map_err(|error| {
        PlatformError::unavailable("failed to allocate HA repair workflow id")
            .with_detail(error.to_string())
    })?;
    Ok(HaRepairWorkflow::new(
        repair_id.to_string(),
        HA_REPAIR_WORKFLOW_KIND,
        HA_REPAIR_SUBJECT_KIND,
        drift.drift_signature.clone(),
        HaRepairWorkflowState {
            repair_id,
            drift_kind: drift.drift_kind,
            drift_signature: drift.drift_signature,
            active_node_ids: drift.active_node_ids,
            passive_node_ids: drift.passive_node_ids,
            target_active_node_id: drift.target_active_node_id,
            demoted_node_ids: drift.demoted_node_ids,
            observed_at: OffsetDateTime::now_utc(),
            resolution_reason: None,
        },
        repair_workflow_steps(),
    ))
}

fn repair_workflow_steps() -> Vec<WorkflowStep> {
    repair_workflow_step_names()
        .into_iter()
        .enumerate()
        .map(|(index, name)| WorkflowStep::new(name, index))
        .collect::<Vec<_>>()
}

fn repair_workflow_step_names() -> Vec<&'static str> {
    vec![
        "capture_drift",
        "plan_role_repair",
        "apply_role_repair",
        "verify_single_active",
    ]
}

fn normalize_repair_workflow_steps(steps: &[WorkflowStep]) -> Vec<WorkflowStep> {
    repair_workflow_step_names()
        .into_iter()
        .enumerate()
        .map(|(index, expected_name)| {
            let mut step = steps
                .iter()
                .find(|step| step.index == index)
                .cloned()
                .unwrap_or_else(|| WorkflowStep::new(expected_name, index));
            step.name = String::from(expected_name);
            step.index = index;
            step
        })
        .collect::<Vec<_>>()
}

fn repair_current_step_index(steps: &[WorkflowStep], phase: &WorkflowPhase) -> Option<usize> {
    steps
        .iter()
        .find(|step| {
            matches!(
                step.state,
                WorkflowStepState::Active
                    | WorkflowStepState::Failed
                    | WorkflowStepState::RolledBack
            )
        })
        .map(|step| step.index)
        .or_else(|| {
            steps
                .iter()
                .filter(|step| matches!(step.state, WorkflowStepState::Completed))
                .map(|step| step.index)
                .max()
        })
        .or_else(|| (!steps.is_empty() && !matches!(phase, WorkflowPhase::Pending)).then_some(0))
}

fn ensure_repair_workflow_shape(workflow: &mut HaRepairWorkflow) {
    workflow.workflow_kind = String::from(HA_REPAIR_WORKFLOW_KIND);
    workflow.subject_kind = String::from(HA_REPAIR_SUBJECT_KIND);
    workflow.subject_id = workflow.state.drift_signature.clone();
    workflow.steps = normalize_repair_workflow_steps(&workflow.steps);
    workflow.current_step_index = repair_current_step_index(&workflow.steps, &workflow.phase);
}

fn repair_capture_detail(state: &HaRepairWorkflowState) -> String {
    format!(
        "captured {:?} drift; active_nodes={}; passive_nodes={}",
        state.drift_kind,
        join_node_ids(&state.active_node_ids),
        join_node_ids(&state.passive_node_ids),
    )
}

fn repair_plan_active_detail(state: &HaRepairWorkflowState) -> String {
    let target_active_node = state
        .target_active_node_id
        .as_ref()
        .map(NodeId::as_str)
        .unwrap_or("missing");
    let demoted_node_ids = if state.demoted_node_ids.is_empty() {
        String::from("none")
    } else {
        join_node_ids(&state.demoted_node_ids)
    };
    format!(
        "planning HA role repair target_active={target_active_node}; demotions={demoted_node_ids}"
    )
}

fn repair_plan_completed_detail(state: &HaRepairWorkflowState) -> String {
    repair_plan_active_detail(state)
}

fn repair_apply_active_detail(state: &HaRepairWorkflowState) -> String {
    let target_active_node = state
        .target_active_node_id
        .as_ref()
        .map(NodeId::as_str)
        .unwrap_or("missing");
    let demoted_node_ids = if state.demoted_node_ids.is_empty() {
        String::from("none")
    } else {
        join_node_ids(&state.demoted_node_ids)
    };
    format!(
        "applying HA role repair target_active={target_active_node}; demotions={demoted_node_ids}"
    )
}

fn repair_apply_completed_detail(state: &HaRepairWorkflowState) -> String {
    let target_active_node = state
        .target_active_node_id
        .as_ref()
        .map(NodeId::as_str)
        .unwrap_or("missing");
    format!("applied HA role repair target_active={target_active_node}")
}

fn repair_verify_active_detail() -> String {
    String::from("verifying that HA topology converged back to a single active node")
}

fn apply_detected_drift(
    workflow: &mut HaRepairWorkflow,
    drift: &DetectedHaDrift,
    observed_at: OffsetDateTime,
) {
    ensure_repair_workflow_shape(workflow);
    workflow.subject_id = drift.drift_signature.clone();
    workflow.state.drift_kind = drift.drift_kind.clone();
    workflow.state.drift_signature = drift.drift_signature.clone();
    workflow.state.active_node_ids = drift.active_node_ids.clone();
    workflow.state.passive_node_ids = drift.passive_node_ids.clone();
    workflow.state.target_active_node_id = drift.target_active_node_id.clone();
    workflow.state.demoted_node_ids = drift.demoted_node_ids.clone();
    workflow.state.observed_at = observed_at;
    workflow.state.resolution_reason = None;
    if !is_terminal_workflow_phase(&workflow.phase) {
        workflow.completed_at = None;
    }
    workflow.current_step_index = repair_current_step_index(&workflow.steps, &workflow.phase);
    workflow.set_next_attempt_at(None, observed_at);
}

fn zero_active_drift_signature(passive_node_ids: &[NodeId]) -> String {
    if passive_node_ids.is_empty() {
        String::from("zero_active")
    } else {
        format!("zero_active:{}", join_node_ids(passive_node_ids))
    }
}

fn dual_active_drift_signature(active_node_ids: &[NodeId]) -> String {
    format!("dual_active:{}", join_node_ids(active_node_ids))
}

fn join_node_ids(node_ids: &[NodeId]) -> String {
    node_ids
        .iter()
        .map(NodeId::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn sorted_node_ids<'a>(node_ids: impl Iterator<Item = &'a NodeId>) -> Vec<NodeId> {
    let mut values = node_ids.cloned().collect::<Vec<_>>();
    values.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    values
}

fn preferred_repair_target(records: &[NodeRoleRecord], require_healthy: bool) -> Option<NodeId> {
    let mut candidates = records
        .iter()
        .filter(|record| !require_healthy || record.healthy)
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() && !require_healthy {
        candidates = records.to_vec();
    }
    candidates.sort_by(|left, right| {
        right
            .healthy
            .cmp(&left.healthy)
            .then_with(|| right.last_heartbeat_at.cmp(&left.last_heartbeat_at))
            .then_with(|| left.node_id.as_str().cmp(right.node_id.as_str()))
    });
    candidates.first().map(|record| record.node_id.clone())
}

fn is_terminal_workflow_phase(phase: &WorkflowPhase) -> bool {
    matches!(
        phase,
        WorkflowPhase::Completed | WorkflowPhase::Failed | WorkflowPhase::RolledBack
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{Method, Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use tempfile::tempdir;

    use super::{
        ConsensusEntryRequest, ControlDeploymentSnapshot, ControlWorkloadSnapshot,
        DependencyStatusRecord, FAILOVER_ARTIFACT_STEP_INDEX, FAILOVER_COMPLETED_EVENT_EFFECT_KIND,
        FAILOVER_DRILL_OUTCOME_EFFECT_KIND, FAILOVER_EVACUATION_ARTIFACT_STEP_NAME,
        FAILOVER_INTENT_STEP_INDEX, FAILOVER_PRECHECK_STEP_INDEX,
        FAILOVER_ROLE_TRANSITION_EFFECT_KIND, FAILOVER_STARTED_EVENT_EFFECT_KIND, FailoverMode,
        FailoverRecord, FailoverRequest, FailoverState, HA_FAILOVER_WORKFLOW_RUNNER_ID,
        HA_FAILOVER_WORKFLOW_SUBJECT_KIND, HA_REPAIR_PLAN_STEP_INDEX, HA_REPAIR_SUBJECT_KIND,
        HA_REPAIR_VERIFY_STEP_INDEX, HA_REPAIR_WORKFLOW_KIND, HA_REPAIR_WORKFLOW_RUNNER_ID,
        HaEvacuationPreparationArtifacts, HaFailoverWorkflow, HaFailoverWorkflowFence,
        HaRepairWorkflow, HaRepairWorkflowFence, HaRepairWorkflowState, HaService,
        HaTopologyDriftKind, LeaseRequest, NodeHeartbeatSnapshot, NodeRoleRecord, ReconcileRequest,
        ReconciliationRecord, RegionalQuorumRequest, ReplicationRequest,
        ReplicationShipmentRequest, SchedulerNodeInventorySnapshot,
        SchedulerPlacementDecisionSnapshot, SetRoleRequest, dual_active_drift_signature,
        failover_completed_event_details, failover_completion_event_effect_detail,
        failover_drill_effect_result_digest, failover_execute_step_index,
        failover_execution_effect_detail, failover_execution_effect_kind,
        failover_finalize_step_index, failover_intent_detail, failover_started_event_details,
        failover_started_event_effect_detail, is_terminal_workflow_phase,
        set_failover_step_state_at, zero_active_drift_signature,
    };
    use time::{Duration, OffsetDateTime};
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_core::sha256_hex;
    use uhost_runtime::HttpService;
    use uhost_store::workflow::{WorkflowStepEffectExecution, WorkflowStepEffectState};
    use uhost_store::{
        CellDirectoryRecord, CellParticipantLeaseState, CellParticipantRecord,
        CellParticipantState, DocumentStore, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
        RegionDirectoryRecord, WorkflowCollection, WorkflowEffectLedgerRecord, WorkflowPhase,
        WorkflowStep, WorkflowStepState,
    };
    use uhost_types::{
        FailoverOperationId, NodeId, OwnershipScope, RepairJobId, ResourceMetadata, WorkloadId,
    };

    async fn all_repair_workflows(service: &HaService) -> Vec<HaRepairWorkflow> {
        service
            .repair_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>()
    }

    async fn seed_failover_preconditions(
        service: &HaService,
        context: &RequestContext,
        active: &NodeId,
        passive: &NodeId,
    ) {
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 1,
                    healthy: true,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: active.to_string(),
                    role: String::from("leader"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: passive.to_string(),
                    role: String::from("follower"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_scheduler_node(
        service: &HaService,
        node_id: &NodeId,
        free_cpu_millis: u32,
        free_memory_mb: u64,
        drained: bool,
    ) {
        service
            .scheduler_nodes
            .create(
                node_id.as_str(),
                SchedulerNodeInventorySnapshot {
                    id: node_id.clone(),
                    free_cpu_millis,
                    free_memory_mb,
                    drained,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_failover_workload_anchor(
        service: &HaService,
        workload_id: &WorkloadId,
        node_id: &NodeId,
    ) {
        service
            .control_workloads
            .create(
                workload_id.as_str(),
                ControlWorkloadSnapshot {
                    id: workload_id.to_string(),
                    replicas: 1,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .control_deployments
            .create(
                &format!("deployment:{}", workload_id.as_str()),
                ControlDeploymentSnapshot {
                    workload_id: workload_id.to_string(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .scheduler_placements
            .create(
                workload_id.as_str(),
                SchedulerPlacementDecisionSnapshot {
                    workload_id: workload_id.to_string(),
                    node_id: Some(node_id.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    fn workflow_checkpoint(
        name: &str,
        index: usize,
        state: WorkflowStepState,
        detail: &str,
        observed_at: OffsetDateTime,
    ) -> WorkflowStep {
        let mut step = WorkflowStep::new(name, index);
        set_failover_step_state_at(&mut step, state, Some(String::from(detail)), observed_at);
        step
    }

    async fn count_event_messages(service: &HaService, event_type: &str) -> usize {
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| message.payload.header.event_type == event_type)
            .count()
    }

    async fn failover_effect_ledgers(service: &HaService) -> Vec<WorkflowEffectLedgerRecord> {
        service
            .failover_effect_ledgers
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>()
    }

    async fn seed_node_heartbeat(service: &HaService, node_id: &NodeId, hostname: &str) {
        service
            .node_heartbeats
            .create(
                node_id.as_str(),
                NodeHeartbeatSnapshot {
                    hostname: hostname.to_owned(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    fn healthy_cell_participant(subject_id: &str, node_name: &str) -> CellParticipantRecord {
        CellParticipantRecord::new(
            format!("runtime:{subject_id}"),
            "runtime_process",
            subject_id,
            "control",
        )
        .with_node_name(node_name.to_owned())
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                OffsetDateTime::now_utc(),
                OffsetDateTime::now_utc() + Duration::seconds(60),
                60,
                LeaseFreshness::Fresh,
            ),
        ))
    }

    async fn open_repair_workflows(service: &HaService) -> Vec<HaRepairWorkflow> {
        all_repair_workflows(service)
            .await
            .into_iter()
            .filter(|workflow| !is_terminal_workflow_phase(&workflow.phase))
            .collect::<Vec<_>>()
    }

    async fn parse_api_body<T: serde::de::DeserializeOwned>(
        response: http::Response<ApiBody>,
    ) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn dispatch_anti_entropy_reconcile(
        service: &HaService,
        context: RequestContext,
    ) -> http::Response<ApiBody> {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/ha/anti-entropy/reconcile")
            .body(uhost_runtime::RequestBody::Right(Full::new(Bytes::new())))
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .handle(request, context)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing anti-entropy reconcile route response"))
    }

    async fn seed_role_record(service: &HaService, node_id: &NodeId, role: &str, healthy: bool) {
        service
            .roles
            .create(
                node_id.as_str(),
                NodeRoleRecord {
                    node_id: node_id.clone(),
                    role: String::from(role),
                    healthy,
                    last_heartbeat_at: OffsetDateTime::now_utc(),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(node_id.to_string()),
                        sha256_hex(node_id.to_string().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn lease_conflicts_for_different_holder_before_expiry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_a = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node_b = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .acquire_lease(
                LeaseRequest {
                    node_id: node_a.to_string(),
                    lease_seconds: 60,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let conflict = service
            .acquire_lease(
                LeaseRequest {
                    node_id: node_b.to_string(),
                    lease_seconds: 60,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected lease conflict"));
        assert_eq!(conflict.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn failover_requires_healthy_replication() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 120,
                    healthy: false,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let conflict = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("planned"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Failover,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected replication conflict"));
        assert_eq!(conflict.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn quorum_summary_requires_configured_members() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .quorum_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.configured_votes, 0);
        assert_eq!(summary.member_count, 0);
        assert!(!summary.quorum_satisfied);
    }

    #[tokio::test]
    async fn preflight_denies_when_regional_quorum_is_missing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 2,
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!preflight.allowed);
        assert!(!preflight.quorum_satisfied);
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("no configured members"))
        );
    }

    #[tokio::test]
    async fn preflight_denies_when_target_scheduler_inventory_is_drained() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        seed_scheduler_node(&service, &active, 2_000, 4_096, false).await;
        seed_scheduler_node(&service, &passive, 2_000, 4_096, true).await;

        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!preflight.allowed);
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("drained in scheduler inventory"))
        );
    }

    #[tokio::test]
    async fn preflight_denies_when_source_cell_ownership_is_ambiguous() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let hostname = String::from("ha-active.internal");

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        seed_scheduler_node(&service, &active, 2_000, 4_096, false).await;
        seed_scheduler_node(&service, &passive, 2_000, 4_096, false).await;
        seed_node_heartbeat(&service, &active, &hostname).await;
        service
            .cell_directory
            .create(
                "us-east-1:cell-a",
                CellDirectoryRecord::new(
                    "us-east-1:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("us-east-1", "US East 1"),
                )
                .with_participant(healthy_cell_participant(active.as_str(), &hostname)),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .cell_directory
            .create(
                "us-east-1:cell-b",
                CellDirectoryRecord::new(
                    "us-east-1:cell-b",
                    "cell-b",
                    RegionDirectoryRecord::new("us-east-1", "US East 1"),
                )
                .with_participant(healthy_cell_participant(active.as_str(), &hostname)),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!preflight.allowed);
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("from_node cell ownership is ambiguous"))
        );
    }

    #[tokio::test]
    async fn preflight_denies_when_failover_node_placements_are_unanchored_or_unspread() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let missing_workload_anchor =
            WorkloadId::generate().unwrap_or_else(|error| panic!("{error}"));
        let missing_deployment_anchor =
            WorkloadId::generate().unwrap_or_else(|error| panic!("{error}"));
        let spread_workload = WorkloadId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        seed_scheduler_node(&service, &active, 2_000, 4_096, false).await;
        seed_scheduler_node(&service, &passive, 2_000, 4_096, false).await;
        service
            .control_workloads
            .create(
                missing_deployment_anchor.as_str(),
                ControlWorkloadSnapshot {
                    id: missing_deployment_anchor.to_string(),
                    replicas: 1,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .control_workloads
            .create(
                spread_workload.as_str(),
                ControlWorkloadSnapshot {
                    id: spread_workload.to_string(),
                    replicas: 3,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .control_deployments
            .create(
                &format!("deployment:{}", spread_workload.as_str()),
                ControlDeploymentSnapshot {
                    workload_id: spread_workload.to_string(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .scheduler_placements
            .create(
                missing_workload_anchor.as_str(),
                SchedulerPlacementDecisionSnapshot {
                    workload_id: missing_workload_anchor.to_string(),
                    node_id: Some(active.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .scheduler_placements
            .create(
                missing_deployment_anchor.as_str(),
                SchedulerPlacementDecisionSnapshot {
                    workload_id: missing_deployment_anchor.to_string(),
                    node_id: Some(active.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .scheduler_placements
            .create(
                spread_workload.as_str(),
                SchedulerPlacementDecisionSnapshot {
                    workload_id: spread_workload.to_string(),
                    node_id: Some(active.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!preflight.allowed);
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("no active control workload anchor"))
        );
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("no active deployment anchor"))
        );
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("shard placement safety cannot be proven"))
        );
    }

    #[tokio::test]
    async fn service_open_claims_pending_failover_workflow_runner() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active,
                to_node_id: passive,
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("startup adoption"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = reopened
            .failover_workflows
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reopened failover workflow"));
        let claim = workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing runner claim on pending workflow"));
        assert_eq!(claim.runner_id, HA_FAILOVER_WORKFLOW_RUNNER_ID);
        assert_eq!(workflow.value.phase, WorkflowPhase::Pending);
        assert!(workflow.value.next_attempt_at.is_some());
    }

    #[tokio::test]
    async fn failover_workflow_advances_checkpoint_by_checkpoint() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("checkpoint progression"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.value.phase, WorkflowPhase::Pending);
        assert!(
            created
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Pending)
        );
        let created_projection = service
            .failovers
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing created failover projection"));
        assert_eq!(created_projection.value.state, FailoverState::Requested);
        assert!(
            created_projection
                .value
                .checkpoints
                .iter()
                .all(|step| step.state == WorkflowStepState::Pending)
        );
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claimed_workflow = service
            .failover_workflows
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing claimed failover workflow"));
        let claim = claimed_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing failover workflow claim"));
        assert_eq!(claim.runner_id, HA_FAILOVER_WORKFLOW_RUNNER_ID);
        assert!(claimed_workflow.value.next_attempt_at.is_some());

        let after_preflight = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(after_preflight.value.phase, WorkflowPhase::Running);
        assert_eq!(
            after_preflight.value.current_step_index,
            Some(FAILOVER_INTENT_STEP_INDEX)
        );
        assert_eq!(
            after_preflight.value.steps[FAILOVER_PRECHECK_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            after_preflight.value.steps[FAILOVER_INTENT_STEP_INDEX].state,
            WorkflowStepState::Active
        );
        assert!(
            after_preflight.value.steps[FAILOVER_INTENT_STEP_INDEX]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("persisting failover intent checkpoint"))
        );
        assert!(after_preflight.value.next_attempt_at.is_some());

        let after_intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let execute_step_index = failover_execute_step_index(FailoverMode::Failover);
        assert_eq!(
            after_intent.value.steps[FAILOVER_INTENT_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            after_intent.value.steps[execute_step_index].state,
            WorkflowStepState::Active
        );
        assert_eq!(
            after_intent.value.current_step_index,
            Some(execute_step_index)
        );
        assert!(after_intent.value.next_attempt_at.is_some());

        let after_execution = service
            .checkpoint_failover_execution(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let finalize_step_index = failover_finalize_step_index(FailoverMode::Failover);
        assert_eq!(
            after_execution.value.steps[execute_step_index].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            after_execution.value.steps[finalize_step_index].state,
            WorkflowStepState::Active
        );
        assert_eq!(
            after_execution.value.current_step_index,
            Some(finalize_step_index)
        );
        assert!(after_execution.value.next_attempt_at.is_some());

        let completed = service
            .checkpoint_failover_completion(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            completed.value.steps[finalize_step_index].state,
            WorkflowStepState::Completed
        );
        assert_eq!(completed.value.next_attempt_at, None);
        let completed_claim = completed
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing completed workflow claim"));
        assert_eq!(completed_claim.runner_id, HA_FAILOVER_WORKFLOW_RUNNER_ID);
        assert_eq!(
            completed_claim.lease_expires_at,
            completed
                .value
                .completed_at
                .unwrap_or_else(|| panic!("missing completion time"))
        );
        let completed_projection = service
            .failovers
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing completed failover projection"));
        assert_eq!(completed_projection.value.state, FailoverState::Completed);
        assert!(
            completed_projection
                .value
                .checkpoints
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );
    }

    #[tokio::test]
    async fn failover_checkpoint_requires_current_fencing_token() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active,
                to_node_id: passive,
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("stale fencing"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _claimed = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_fence = HaFailoverWorkflowFence {
            fencing_token: String::from("stale-token"),
        };
        let error = service
            .checkpoint_failover_preflight(&operation_id, &stale_fence, &preflight)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected stale fencing conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn evacuation_artifacts_appear_only_after_artifact_checkpoint() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("evacuation"),
                reason: String::from("evacuation checkpoint"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let after_intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(after_intent.value.state.evacuation_artifacts.is_none());
        assert_eq!(
            after_intent.value.steps[FAILOVER_ARTIFACT_STEP_INDEX].state,
            WorkflowStepState::Active
        );
        let before_projection = service
            .failovers
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing pre-artifact evacuation projection"));
        assert!(before_projection.value.evacuation_artifacts.is_none());

        let artifacts = service
            .prepare_evacuation_artifacts(&operation_id, &active, &passive, created_at)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let after_artifacts = service
            .checkpoint_failover_artifacts(&operation_id, &fence, artifacts.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            after_artifacts.value.state.evacuation_artifacts.as_ref(),
            Some(&artifacts)
        );
        assert_eq!(
            after_artifacts.value.steps[FAILOVER_ARTIFACT_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            after_artifacts.value.steps[failover_execute_step_index(FailoverMode::Evacuation)]
                .state,
            WorkflowStepState::Active
        );
        let after_projection = service
            .failovers
            .get(operation_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing post-artifact evacuation projection"));
        assert_eq!(
            after_projection.value.evacuation_artifacts.as_ref(),
            Some(&artifacts)
        );
    }

    #[tokio::test]
    async fn evacuation_operation_is_recorded_with_distinct_kind() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let workload_id = WorkloadId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        seed_failover_workload_anchor(&service, &workload_id, &active).await;

        let _ = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("regional evacuation"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Evacuation,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let operations = service
            .failovers
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].operation_kind, "evacuation");
        assert!(!operations[0].drill);
        assert_eq!(
            operations[0].workflow_id.as_deref(),
            Some(operations[0].id.as_str())
        );
        assert_eq!(operations[0].checkpoints.len(), 5);
        assert_eq!(
            operations[0].checkpoints[FAILOVER_ARTIFACT_STEP_INDEX].name,
            FAILOVER_EVACUATION_ARTIFACT_STEP_NAME
        );
        assert_eq!(
            operations[0].checkpoints[failover_execute_step_index(FailoverMode::Evacuation)].name,
            "apply_evacuation_cutover"
        );
        let artifact_detail = operations[0].checkpoints[FAILOVER_ARTIFACT_STEP_INDEX]
            .detail
            .clone()
            .unwrap_or_else(|| panic!("missing evacuation artifact detail"));
        assert!(artifact_detail.contains("route-withdrawal"));
        assert!(artifact_detail.contains("target-readiness"));
        assert!(artifact_detail.contains("rollback"));
        let intent_detail = operations[0].checkpoints[FAILOVER_INTENT_STEP_INDEX]
            .detail
            .clone()
            .unwrap_or_else(|| panic!("missing evacuation intent detail"));
        assert!(intent_detail.contains("evacuation intent persisted"));
        assert!(
            operations[0]
                .checkpoints
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );
        let artifacts = operations[0]
            .evacuation_artifacts
            .as_ref()
            .unwrap_or_else(|| panic!("missing evacuation artifacts"));
        assert_eq!(artifacts.route_withdrawal.source_node_id, active);
        assert_eq!(artifacts.target_readiness.source_node_id, active);
        assert_eq!(artifacts.target_readiness.target_node_id, passive);
        assert_eq!(artifacts.rollback.source_node_id, active);
        assert_eq!(artifacts.rollback.target_node_id, passive);
        assert_eq!(
            artifacts.route_withdrawal.routing_scope_ids,
            vec![format!("workload:{}", workload_id.as_str())]
        );
        assert_eq!(
            artifacts.target_readiness.routing_scope_ids,
            vec![format!("workload:{}", workload_id.as_str())]
        );
        assert_eq!(
            artifacts.rollback.routing_scope_ids,
            vec![format!("workload:{}", workload_id.as_str())]
        );
        assert_eq!(
            artifacts.route_withdrawal.prepared_at,
            operations[0].created_at
        );
        assert_eq!(
            artifacts.target_readiness.prepared_at,
            operations[0].created_at
        );
        assert_eq!(artifacts.rollback.prepared_at, operations[0].created_at);

        let workflow = service
            .failover_workflows
            .get(operations[0].id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing evacuation workflow"));
        assert_eq!(
            workflow.value.state.evacuation_artifacts.as_ref(),
            Some(artifacts)
        );
    }

    #[tokio::test]
    async fn drill_operation_uses_distinct_workflow_and_preserves_roles() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;

        let _ = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("drill rehearsal"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Drill,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let drill = service
            .failovers
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .next()
            .unwrap_or_else(|| panic!("missing drill projection"));
        assert_eq!(drill.operation_kind, "drill");
        assert!(drill.drill);
        assert_eq!(drill.checkpoints.len(), 4);
        assert_eq!(
            drill.checkpoints[failover_execute_step_index(FailoverMode::Drill)].name,
            "record_drill_outcome"
        );
        let workflow = service
            .failover_workflows
            .get(drill.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing drill workflow"));
        assert_eq!(
            workflow.value.workflow_kind,
            "ha.failover.drill.workflow.v1"
        );
        assert_eq!(
            workflow.value.current_step_index,
            Some(failover_finalize_step_index(FailoverMode::Drill))
        );
        let from_role = service
            .roles
            .get(active.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing source role after drill"));
        let to_role = service
            .roles
            .get(passive.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target role after drill"));
        assert_eq!(from_role.value.role, "active");
        assert_eq!(to_role.value.role, "passive");
    }

    #[tokio::test]
    async fn failover_persists_checkpointed_workflow_projection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;

        let _ = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("planned cutover"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Failover,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failover = service
            .failovers
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .next()
            .unwrap_or_else(|| panic!("missing failover projection"));
        assert_eq!(failover.workflow_id.as_deref(), Some(failover.id.as_str()));
        assert_eq!(failover.checkpoints.len(), 4);
        assert_eq!(
            failover.checkpoints[FAILOVER_PRECHECK_STEP_INDEX].name,
            "validate_preflight"
        );
        assert_eq!(
            failover.checkpoints[failover_execute_step_index(FailoverMode::Failover)].name,
            "apply_failover_cutover"
        );
        assert!(
            failover
                .checkpoints
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );
        assert!(failover.evacuation_artifacts.is_none());

        let workflow = service
            .failover_workflows
            .get(failover.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing failover workflow"));
        assert_eq!(workflow.value.workflow_kind, "ha.failover.workflow.v1");
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(
            workflow.value.current_step_index,
            Some(failover_finalize_step_index(FailoverMode::Failover))
        );
        assert_eq!(workflow.value.next_attempt_at, None);
        let claim = workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing failover workflow runner claim"));
        assert_eq!(claim.runner_id, HA_FAILOVER_WORKFLOW_RUNNER_ID);
        assert_eq!(
            claim.lease_expires_at,
            workflow
                .value
                .completed_at
                .unwrap_or_else(|| panic!("missing failover workflow completion time"))
        );
    }

    #[tokio::test]
    async fn failover_persists_effect_journals_for_started_execution_and_completion() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_failover_preconditions(&service, &context, &active, &passive).await;

        let _response = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("effect journal coverage"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Failover,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflow = service
            .failover_workflows
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .next()
            .unwrap_or_else(|| panic!("missing failover workflow"));
        let execute_step_index = failover_execute_step_index(FailoverMode::Failover);
        let finalize_step_index = failover_finalize_step_index(FailoverMode::Failover);

        let started_effect = workflow.steps[execute_step_index]
            .effect(FAILOVER_STARTED_EVENT_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing started-event effect journal"));
        assert_eq!(started_effect.state, WorkflowStepEffectState::Completed);
        assert!(started_effect.result_digest.is_some());

        let role_transition_effect = workflow.steps[execute_step_index]
            .effect(FAILOVER_ROLE_TRANSITION_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing role-transition effect journal"));
        assert_eq!(
            role_transition_effect.state,
            WorkflowStepEffectState::Completed
        );
        assert!(role_transition_effect.result_digest.is_some());

        let completion_effect = workflow.steps[finalize_step_index]
            .effect(FAILOVER_COMPLETED_EVENT_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing completion-event effect journal"));
        assert_eq!(completion_effect.state, WorkflowStepEffectState::Completed);
        assert!(completion_effect.result_digest.is_some());

        assert_eq!(workflow.steps[execute_step_index].effect_journal.len(), 2);
        assert_eq!(workflow.steps[finalize_step_index].effect_journal.len(), 1);
        assert_eq!(
            count_event_messages(&service, FailoverMode::Failover.started_event()).await,
            1
        );
        assert_eq!(
            count_event_messages(&service, FailoverMode::Failover.completed_event()).await,
            1
        );
        let ledgers = failover_effect_ledgers(&service).await;
        assert_eq!(ledgers.len(), 1);
        assert_eq!(ledgers[0].effect_kind, FAILOVER_ROLE_TRANSITION_EFFECT_KIND);
        assert_eq!(
            ledgers[0].result_digest,
            role_transition_effect
                .result_digest
                .clone()
                .unwrap_or_else(|| panic!("missing role-transition digest"))
        );
    }

    #[tokio::test]
    async fn started_event_effect_reuses_existing_outbox_message_when_pending() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("pending started-event replay"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _preflight = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflow = service
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (_journaled, effect_execution) = service
            .begin_failover_step_effect(
                &operation_id,
                &fence,
                failover_execute_step_index(FailoverMode::Failover),
                FAILOVER_STARTED_EVENT_EFFECT_KIND,
                failover_started_event_effect_detail(FailoverMode::Failover),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first started-event effect should execute")
            }
        };
        let first_digest = service
            .append_event_with_idempotency(
                FailoverMode::Failover.started_event(),
                "failover",
                operation_id.as_str(),
                "started",
                failover_started_event_details(&workflow.value),
                &context,
                Some(effect.idempotency_key.as_str()),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            count_event_messages(&service, FailoverMode::Failover.started_event()).await,
            1
        );

        let reopened = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_fence = reopened
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_digest = reopened
            .emit_failover_started_effect(&operation_id, &replay_fence, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay_digest, first_digest);
        assert_eq!(
            count_event_messages(&reopened, FailoverMode::Failover.started_event()).await,
            1
        );
        let replayed_workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_effect = replayed_workflow.value.steps
            [failover_execute_step_index(FailoverMode::Failover)]
        .effect(FAILOVER_STARTED_EVENT_EFFECT_KIND)
        .unwrap_or_else(|| panic!("missing replayed started-event effect"));
        assert_eq!(replayed_effect.state, WorkflowStepEffectState::Completed);
        assert_eq!(
            replayed_effect.result_digest.as_deref(),
            Some(first_digest.as_str())
        );
    }

    #[tokio::test]
    async fn completion_event_effect_reuses_existing_outbox_message_when_pending() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("pending completion-event replay"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _preflight = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _execution = service
            .checkpoint_failover_execution(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let (journaled, effect_execution) = service
            .begin_failover_step_effect(
                &operation_id,
                &fence,
                failover_finalize_step_index(FailoverMode::Failover),
                FAILOVER_COMPLETED_EVENT_EFFECT_KIND,
                failover_completion_event_effect_detail(FailoverMode::Failover),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first completion-event effect should execute")
            }
        };
        let first_digest = service
            .append_event_with_idempotency(
                FailoverMode::Failover.completed_event(),
                "failover",
                operation_id.as_str(),
                "completed",
                failover_completed_event_details(&journaled.value),
                &context,
                Some(effect.idempotency_key.as_str()),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            count_event_messages(&service, FailoverMode::Failover.completed_event()).await,
            1
        );

        let reopened = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_fence = reopened
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_digest = reopened
            .emit_failover_completion_effect(&operation_id, &replay_fence, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay_digest, first_digest);
        assert_eq!(
            count_event_messages(&reopened, FailoverMode::Failover.completed_event()).await,
            1
        );
        assert!(failover_effect_ledgers(&reopened).await.is_empty());

        let replayed_workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replayed_effect = replayed_workflow.value.steps
            [failover_finalize_step_index(FailoverMode::Failover)]
        .effect(FAILOVER_COMPLETED_EVENT_EFFECT_KIND)
        .unwrap_or_else(|| panic!("missing replayed completion-event effect"));
        assert_eq!(replayed_effect.state, WorkflowStepEffectState::Completed);
        assert_eq!(
            replayed_effect.result_digest.as_deref(),
            Some(first_digest.as_str())
        );
    }

    #[tokio::test]
    async fn execution_effect_reuses_already_converged_roles_when_pending() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("failover"),
                reason: String::from("pending execution replay"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _preflight = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let (journaled, effect_execution) = service
            .begin_failover_step_effect(
                &operation_id,
                &fence,
                failover_execute_step_index(FailoverMode::Failover),
                failover_execution_effect_kind(FailoverMode::Failover),
                failover_execution_effect_detail(FailoverMode::Failover, &active, &passive),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first execution effect should execute")
            }
        };

        let digest = service
            .ensure_failover_role_transition(&active, &passive, true, true, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ledger = service
            .persist_failover_effect_ledger(
                &journaled.value,
                failover_execute_step_index(FailoverMode::Failover),
                FAILOVER_ROLE_TRANSITION_EFFECT_KIND,
                digest.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_before = service
            .roles
            .get(active.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing source role"));
        let target_before = service
            .roles
            .get(passive.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target role"));

        let reopened = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_fence = reopened
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_digest = reopened
            .replay_failover_effect_result_from_ledger(
                &replay_workflow.value,
                failover_execute_step_index(FailoverMode::Failover),
                FAILOVER_ROLE_TRANSITION_EFFECT_KIND,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replay digest from dedicated ledger"));
        assert_eq!(replay_digest, digest);

        let digest = reopened
            .execute_failover_execution_effect(&operation_id, &replay_fence, &context, true, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_after = reopened
            .roles
            .get(active.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing source role after replay"));
        let target_after = reopened
            .roles
            .get(passive.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target role after replay"));
        assert_eq!(source_after.version, source_before.version);
        assert_eq!(target_after.version, target_before.version);

        let workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = workflow.value.steps[failover_execute_step_index(FailoverMode::Failover)]
            .effect(FAILOVER_ROLE_TRANSITION_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing completed execution effect"));
        assert_eq!(effect.state, WorkflowStepEffectState::Completed);
        assert_eq!(effect.result_digest.as_deref(), Some(digest.as_str()));
    }

    #[tokio::test]
    async fn drill_execution_effect_reuses_persisted_ledger_when_pending() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let operation_id =
            FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        seed_failover_preconditions(&service, &context, &active, &passive).await;
        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _created = service
            .create_failover_workflow(FailoverRecord {
                id: operation_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: true,
                operation_kind: String::from("drill"),
                reason: String::from("pending drill execution replay"),
                state: FailoverState::Requested,
                degraded_mode: false,
                workflow_id: None,
                checkpoints: Vec::new(),
                evacuation_artifacts: None,
                created_at,
                completed_at: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(operation_id.to_string()),
                    sha256_hex(operation_id.as_str().as_bytes()),
                ),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let fence = service
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _preflight = service
            .checkpoint_failover_preflight(&operation_id, &fence, &preflight)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _intent = service
            .checkpoint_failover_intent(&operation_id, &fence)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let (journaled, effect_execution) = service
            .begin_failover_step_effect(
                &operation_id,
                &fence,
                failover_execute_step_index(FailoverMode::Drill),
                failover_execution_effect_kind(FailoverMode::Drill),
                failover_execution_effect_detail(FailoverMode::Drill, &active, &passive),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _effect = match effect_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first drill execution effect should execute")
            }
        };

        let digest = failover_drill_effect_result_digest(&journaled.value.state);
        let _ledger = service
            .persist_failover_effect_ledger(
                &journaled.value,
                failover_execute_step_index(FailoverMode::Drill),
                FAILOVER_DRILL_OUTCOME_EFFECT_KIND,
                digest.as_str(),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_before = service
            .roles
            .get(active.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing source role"));
        let target_before = service
            .roles
            .get(passive.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target role"));

        let reopened = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_fence = reopened
            .claim_failover_workflow_runner(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_digest = reopened
            .replay_failover_effect_result_from_ledger(
                &replay_workflow.value,
                failover_execute_step_index(FailoverMode::Drill),
                FAILOVER_DRILL_OUTCOME_EFFECT_KIND,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replay digest from drill ledger"));
        assert_eq!(replay_digest, digest);

        let digest = reopened
            .execute_failover_execution_effect(&operation_id, &replay_fence, &context, true, true)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_after = reopened
            .roles
            .get(active.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing source role after drill replay"));
        let target_after = reopened
            .roles
            .get(passive.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target role after drill replay"));
        assert_eq!(source_after.version, source_before.version);
        assert_eq!(target_after.version, target_before.version);
        assert_eq!(source_after.value.role, "active");
        assert_eq!(target_after.value.role, "passive");

        let ledgers = failover_effect_ledgers(&reopened).await;
        assert_eq!(ledgers.len(), 1);
        assert_eq!(ledgers[0].effect_kind, FAILOVER_DRILL_OUTCOME_EFFECT_KIND);

        let workflow = reopened
            .load_failover_workflow(&operation_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effect = workflow.value.steps[failover_execute_step_index(FailoverMode::Drill)]
            .effect(FAILOVER_DRILL_OUTCOME_EFFECT_KIND)
            .unwrap_or_else(|| panic!("missing completed drill execution effect"));
        assert_eq!(effect.state, WorkflowStepEffectState::Completed);
        assert_eq!(effect.result_digest.as_deref(), Some(digest.as_str()));
    }

    #[tokio::test]
    async fn open_reconciles_legacy_failover_records_into_workflows() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let failover_id = FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();

        DocumentStore::<FailoverRecord>::open(temp.path().join("ha/failovers.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .create(
                failover_id.as_str(),
                FailoverRecord {
                    id: failover_id.clone(),
                    from_node_id: active.clone(),
                    to_node_id: passive.clone(),
                    drill: false,
                    operation_kind: String::from("failover"),
                    reason: String::from("legacy projection"),
                    state: FailoverState::Completed,
                    degraded_mode: false,
                    workflow_id: None,
                    checkpoints: Vec::new(),
                    evacuation_artifacts: None,
                    created_at,
                    completed_at: Some(created_at),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(failover_id.to_string()),
                        sha256_hex(failover_id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflow = service
            .failover_workflows
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled workflow"));
        assert_eq!(workflow.value.workflow_kind, "ha.failover.workflow.v1");
        assert_eq!(workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.value.steps.len(), 4);
        assert!(
            workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Completed)
        );

        let projection = service
            .failovers
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciled projection"));
        assert_eq!(
            projection.value.workflow_id.as_deref(),
            Some(failover_id.as_str())
        );
        assert_eq!(projection.value.checkpoints.len(), 4);
    }

    #[tokio::test]
    async fn open_normalizes_legacy_evacuation_workflow_to_artifact_checkpoint_shape() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let failover_id = FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created_at = OffsetDateTime::now_utc();
        let artifacts = HaEvacuationPreparationArtifacts::new(
            &failover_id,
            &active,
            &passive,
            vec![String::from("workload:legacy-ha")],
            created_at,
        );
        let mut legacy_workflow = HaFailoverWorkflow::new(
            failover_id.to_string(),
            "ha.evacuation.workflow.v1",
            HA_FAILOVER_WORKFLOW_SUBJECT_KIND,
            failover_id.to_string(),
            FailoverRecord {
                id: failover_id.clone(),
                from_node_id: active.clone(),
                to_node_id: passive.clone(),
                drill: false,
                operation_kind: String::from("evacuation"),
                reason: String::from("legacy workflow"),
                state: FailoverState::Completed,
                degraded_mode: false,
                workflow_id: Some(failover_id.to_string()),
                checkpoints: Vec::new(),
                evacuation_artifacts: Some(artifacts.clone()),
                created_at,
                completed_at: Some(created_at),
                metadata: ResourceMetadata::new(
                    OwnershipScope::Platform,
                    Some(failover_id.to_string()),
                    sha256_hex(failover_id.as_str().as_bytes()),
                ),
            },
            vec![
                workflow_checkpoint(
                    "validate_preflight",
                    0,
                    WorkflowStepState::Completed,
                    "preflight accepted",
                    created_at,
                ),
                workflow_checkpoint(
                    "persist_intent_checkpoint",
                    1,
                    WorkflowStepState::Completed,
                    &failover_intent_detail(FailoverMode::Evacuation, Some(&artifacts)),
                    created_at,
                ),
                workflow_checkpoint(
                    "apply_evacuation_cutover",
                    2,
                    WorkflowStepState::Completed,
                    "evacuation applied; legacy source is passive and legacy target is active",
                    created_at,
                ),
                workflow_checkpoint(
                    "persist_completion_checkpoint",
                    3,
                    WorkflowStepState::Completed,
                    "evacuation completion checkpoint persisted",
                    created_at,
                ),
            ],
        );
        legacy_workflow.phase = WorkflowPhase::Completed;
        legacy_workflow.current_step_index = Some(3);
        legacy_workflow.created_at = created_at;
        legacy_workflow.updated_at = created_at;
        legacy_workflow.completed_at = Some(created_at);

        WorkflowCollection::<FailoverRecord>::open_local(
            temp.path().join("ha/failover_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .create(failover_id.as_str(), legacy_workflow)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflow = service
            .failover_workflows
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing normalized evacuation workflow"));
        assert_eq!(workflow.value.steps.len(), 5);
        assert_eq!(
            workflow.value.steps[FAILOVER_ARTIFACT_STEP_INDEX].name,
            FAILOVER_EVACUATION_ARTIFACT_STEP_NAME
        );
        assert_eq!(
            workflow.value.steps[FAILOVER_ARTIFACT_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            workflow.value.steps[failover_execute_step_index(FailoverMode::Evacuation)].name,
            "apply_evacuation_cutover"
        );
        assert_eq!(
            workflow.value.current_step_index,
            Some(failover_finalize_step_index(FailoverMode::Evacuation))
        );
        assert!(
            workflow.value.steps[FAILOVER_ARTIFACT_STEP_INDEX]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("route-withdrawal"))
        );

        let projection = service
            .failovers
            .get(failover_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing normalized evacuation projection"));
        assert_eq!(projection.value.checkpoints.len(), 5);
        assert_eq!(
            projection.value.checkpoints[FAILOVER_ARTIFACT_STEP_INDEX].name,
            FAILOVER_EVACUATION_ARTIFACT_STEP_NAME
        );
        assert_eq!(
            projection.value.evacuation_artifacts.as_ref(),
            Some(&artifacts)
        );
    }

    #[tokio::test]
    async fn reconciliation_marks_entries_committed_after_majority_apply() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let leader = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let follower_a = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let follower_b = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        for node in [&leader, &follower_a, &follower_b] {
            let role = if node == &leader {
                "leader"
            } else {
                "follower"
            };
            let _ = service
                .upsert_regional_quorum(
                    RegionalQuorumRequest {
                        region: String::from("us-east-1"),
                        node_id: node.to_string(),
                        role: String::from(role),
                        term: 1,
                        vote_weight: Some(1),
                        healthy: true,
                        replicated_log_index: 10,
                        applied_log_index: 10,
                        lease_seconds: Some(60),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let _ = service
            .append_consensus_entry(
                ConsensusEntryRequest {
                    region: String::from("us-east-1"),
                    term: 1,
                    log_index: 1,
                    operation_kind: String::from("failover_plan"),
                    payload_hash: String::from("feedface"),
                    leader_node_id: leader.to_string(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_shipment(
                ReplicationShipmentRequest {
                    region: String::from("us-east-1"),
                    log_index: 1,
                    term: 1,
                    source_node_id: leader.to_string(),
                    target_node_id: follower_a.to_string(),
                    status: String::from("applied"),
                    message: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .reconcile_region(
                ReconcileRequest {
                    region: String::from("us-east-1"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliation = service
            .reconciliations
            .get("us-east-1")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reconciliation"));
        assert_eq!(reconciliation.value.committed_log_index, 1);
        assert!(reconciliation.value.fully_reconciled);
    }

    #[tokio::test]
    async fn reconciliation_without_quorum_members_is_not_fully_reconciled() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliation = service
            .compute_reconciliation("us-east-1")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(reconciliation.latest_log_index, 0);
        assert_eq!(reconciliation.committed_log_index, 0);
        assert!(!reconciliation.fully_reconciled);
    }

    #[tokio::test]
    async fn failover_preflight_blocks_when_consensus_has_uncommitted_entries() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 1,
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: active.to_string(),
                    role: String::from("leader"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: passive.to_string(),
                    role: String::from("follower"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .append_consensus_entry(
                ConsensusEntryRequest {
                    region: String::from("us-east-1"),
                    term: 1,
                    log_index: 1,
                    operation_kind: String::from("policy_change"),
                    payload_hash: String::from("deadcafe"),
                    leader_node_id: active.to_string(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_shipment(
                ReplicationShipmentRequest {
                    region: String::from("us-east-1"),
                    log_index: 1,
                    term: 1,
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    status: String::from("failed"),
                    message: Some(String::from("simulated transport failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight = service
            .build_failover_preflight(active.clone(), passive.clone(), 30)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!preflight.allowed);
        assert!(!preflight.consensus_fully_reconciled);
        assert!(preflight.consensus_uncommitted_entries > 0);
        assert!(
            preflight
                .blockers
                .iter()
                .any(|entry| entry.contains("consensus"))
        );
    }

    #[tokio::test]
    async fn readiness_summary_aggregates_role_replication_and_failover_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: false,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 5,
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failovers =
            DocumentStore::<FailoverRecord>::open(temp.path().join("ha/failovers.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        failovers
            .create(
                "failover-1",
                FailoverRecord {
                    id: FailoverOperationId::generate().unwrap_or_else(|error| panic!("{error}")),
                    from_node_id: active.clone(),
                    to_node_id: passive.clone(),
                    drill: false,
                    operation_kind: String::from("failover"),
                    reason: String::from("test"),
                    state: FailoverState::Completed,
                    degraded_mode: false,
                    workflow_id: None,
                    checkpoints: Vec::new(),
                    evacuation_artifacts: None,
                    created_at: OffsetDateTime::now_utc(),
                    completed_at: Some(OffsetDateTime::now_utc()),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(active.to_string()),
                        sha256_hex(active.to_string().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        DocumentStore::<ReconciliationRecord>::open(temp.path().join("ha/reconciliations.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .create(
                "recon-1",
                ReconciliationRecord {
                    region: String::from("us-east-1"),
                    latest_log_index: 10,
                    committed_log_index: 10,
                    majority_threshold: 2,
                    healthy_votes: 2,
                    uncommitted_entries: 0,
                    lagging_nodes: Vec::new(),
                    fully_reconciled: true,
                    evaluated_at: OffsetDateTime::now_utc(),
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(active.to_string()),
                        sha256_hex(active.to_string().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        DocumentStore::<DependencyStatusRecord>::open(temp.path().join("ha/dependencies.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .create(
                "storage",
                DependencyStatusRecord {
                    dependency: String::from("storage"),
                    status: String::from("up"),
                    critical: true,
                    checked_at: OffsetDateTime::now_utc(),
                    message: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .readiness_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            summary.roles.iter().map(|role| role.total).sum::<usize>(),
            2
        );
        assert_eq!(summary.replication.total_streams, 1);
        assert_eq!(summary.replication.healthy_streams, 1);
        assert_eq!(summary.failovers.total_failovers, 1);
        assert_eq!(summary.failovers.in_progress, 0);
        assert!(
            summary
                .reconciliations
                .iter()
                .any(|record| record.fully_reconciled)
        );
        assert_eq!(summary.dependencies.len(), 1);
    }

    #[tokio::test]
    async fn zero_active_drift_executes_repair_workflow_under_runner_claim() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: first.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: second.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: first.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 1);
        let workflow = &workflows[0];
        assert_eq!(workflow.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.state.drift_kind, HaTopologyDriftKind::ZeroActive);
        assert!(workflow.state.active_node_ids.is_empty());
        assert_eq!(workflow.state.passive_node_ids.len(), 2);
        assert!(workflow.state.passive_node_ids.contains(&first));
        assert!(workflow.state.passive_node_ids.contains(&second));
        assert_eq!(
            workflow.current_step_index,
            Some(HA_REPAIR_VERIFY_STEP_INDEX)
        );
        assert_eq!(
            workflow.steps[HA_REPAIR_VERIFY_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        assert_eq!(workflow.next_attempt_at, None);
        let claim = workflow
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing repair workflow runner claim"));
        assert_eq!(claim.runner_id, HA_REPAIR_WORKFLOW_RUNNER_ID);
        assert_eq!(
            claim.lease_expires_at,
            workflow
                .completed_at
                .unwrap_or_else(|| panic!("missing repair workflow completion time"))
        );
        assert!(open_repair_workflows(&service).await.is_empty());
        assert!(
            workflow
                .state
                .target_active_node_id
                .as_ref()
                .is_some_and(|node_id| workflow.state.passive_node_ids.contains(node_id))
        );
        assert!(workflow.state.demoted_node_ids.is_empty());
        let first_role = service
            .roles
            .get(first.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first repaired role"));
        let second_role = service
            .roles
            .get(second.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second repaired role"));
        let active_node_ids = [first_role.value, second_role.value]
            .into_iter()
            .filter(|record| record.role == "active")
            .map(|record| record.node_id)
            .collect::<Vec<_>>();
        assert_eq!(active_node_ids.len(), 1);
        assert_eq!(
            active_node_ids.first(),
            workflow.state.target_active_node_id.as_ref()
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.enqueued.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.completed.v1").await,
            1
        );
    }

    #[tokio::test]
    async fn repair_checkpoint_requires_current_fencing_token() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let repair_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let drift_signature = dual_active_drift_signature(&[first.clone(), second.clone()]);
        let workflow = HaRepairWorkflow::new(
            repair_id.to_string(),
            HA_REPAIR_WORKFLOW_KIND,
            HA_REPAIR_SUBJECT_KIND,
            drift_signature.clone(),
            HaRepairWorkflowState {
                repair_id,
                drift_kind: HaTopologyDriftKind::DualActive,
                drift_signature,
                active_node_ids: vec![first.clone(), second.clone()],
                passive_node_ids: Vec::new(),
                target_active_node_id: Some(first.clone()),
                demoted_node_ids: vec![second.clone()],
                observed_at: OffsetDateTime::now_utc(),
                resolution_reason: None,
            },
            vec![
                WorkflowStep::new("capture_drift", 0),
                WorkflowStep::new("plan_role_repair", 1),
                WorkflowStep::new("apply_role_repair", 2),
                WorkflowStep::new("verify_single_active", 3),
            ],
        );
        service
            .repair_workflows
            .create(workflow.id.as_str(), workflow.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _claimed = service
            .claim_repair_workflow_runner(workflow.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claimed = service
            .repair_workflows
            .get(workflow.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing claimed repair workflow"));
        let claim = claimed
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing repair workflow claim"));
        assert_eq!(claim.runner_id, HA_REPAIR_WORKFLOW_RUNNER_ID);
        assert!(claimed.value.next_attempt_at.is_some());

        let stale_fence = HaRepairWorkflowFence {
            fencing_token: String::from("stale-token"),
        };
        let error = service
            .checkpoint_repair_capture(workflow.id.as_str(), &stale_fence)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected stale repair fencing conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn service_open_backfills_and_executes_dual_active_repair_workflow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let roles = DocumentStore::<NodeRoleRecord>::open(temp.path().join("ha/roles.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for node_id in [&first, &second] {
            roles
                .create(
                    node_id.as_str(),
                    NodeRoleRecord {
                        node_id: node_id.clone(),
                        role: String::from("active"),
                        healthy: true,
                        last_heartbeat_at: OffsetDateTime::now_utc(),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Platform,
                            Some(node_id.to_string()),
                            sha256_hex(node_id.to_string().as_bytes()),
                        ),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 1);
        let workflow = &workflows[0];
        assert_eq!(workflow.phase, WorkflowPhase::Completed);
        assert_eq!(workflow.state.drift_kind, HaTopologyDriftKind::DualActive);
        assert_eq!(workflow.state.active_node_ids.len(), 2);
        assert!(workflow.state.active_node_ids.contains(&first));
        assert!(workflow.state.active_node_ids.contains(&second));
        assert!(open_repair_workflows(&service).await.is_empty());
        let claim = workflow
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing completed repair workflow claim"));
        assert_eq!(claim.runner_id, HA_REPAIR_WORKFLOW_RUNNER_ID);
        assert_eq!(
            claim.lease_expires_at,
            workflow
                .completed_at
                .unwrap_or_else(|| panic!("missing completed repair time"))
        );
        let first_role = service
            .roles
            .get(first.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first repaired role"));
        let second_role = service
            .roles
            .get(second.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second repaired role"));
        let active_node_ids = [first_role.value, second_role.value]
            .into_iter()
            .filter(|record| record.role == "active")
            .map(|record| record.node_id)
            .collect::<Vec<_>>();
        assert_eq!(active_node_ids.len(), 1);
        assert_eq!(
            active_node_ids.first(),
            workflow.state.target_active_node_id.as_ref()
        );
    }

    #[tokio::test]
    async fn service_open_normalizes_and_executes_open_repair_workflow_for_current_drift() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let roles = DocumentStore::<NodeRoleRecord>::open(temp.path().join("ha/roles.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for node_id in [&first, &second] {
            roles
                .create(
                    node_id.as_str(),
                    NodeRoleRecord {
                        node_id: node_id.clone(),
                        role: String::from("active"),
                        healthy: true,
                        last_heartbeat_at: OffsetDateTime::now_utc(),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Platform,
                            Some(node_id.to_string()),
                            sha256_hex(node_id.to_string().as_bytes()),
                        ),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let mut active_node_ids = vec![first.clone(), second.clone()];
        active_node_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let drift_signature = dual_active_drift_signature(&active_node_ids);
        let repair_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let repair_workflows = WorkflowCollection::<HaRepairWorkflowState>::open_local(
            temp.path().join("ha/repair_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let mut stale_workflow = HaRepairWorkflow::new(
            repair_id.to_string(),
            "ha.repair.legacy",
            "legacy_repair_subject",
            "legacy_subject_id",
            HaRepairWorkflowState {
                repair_id,
                drift_kind: HaTopologyDriftKind::DualActive,
                drift_signature: drift_signature.clone(),
                active_node_ids,
                passive_node_ids: Vec::new(),
                target_active_node_id: Some(second.clone()),
                demoted_node_ids: vec![first.clone()],
                observed_at: OffsetDateTime::now_utc() - Duration::seconds(60),
                resolution_reason: Some(String::from("stale resolution")),
            },
            vec![
                WorkflowStep::new("capture_old_drift", 0),
                WorkflowStep::new("plan_old_repair", 1),
                WorkflowStep::new("apply_old_repair", 2),
                WorkflowStep::new("verify_old_repair", 3),
            ],
        );
        stale_workflow.phase = WorkflowPhase::Running;
        stale_workflow.current_step_index = Some(1);
        stale_workflow.completed_at = Some(OffsetDateTime::now_utc() - Duration::seconds(30));
        stale_workflow.steps[1].state = WorkflowStepState::Active;
        stale_workflow.steps[1].detail = Some(String::from("legacy active step"));
        repair_workflows
            .create(stale_workflow.id.as_str(), stale_workflow.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 1);
        let workflow = &workflows[0];
        assert_eq!(workflow.id, stale_workflow.id);
        assert_eq!(workflow.workflow_kind, HA_REPAIR_WORKFLOW_KIND);
        assert_eq!(workflow.subject_kind, HA_REPAIR_SUBJECT_KIND);
        assert_eq!(workflow.subject_id, drift_signature);
        assert_eq!(workflow.phase, WorkflowPhase::Completed);
        assert_eq!(
            workflow.current_step_index,
            Some(HA_REPAIR_VERIFY_STEP_INDEX)
        );
        assert!(workflow.completed_at.is_some());
        assert_eq!(
            workflow.state.resolution_reason.as_deref(),
            Some("single active topology verified after HA repair execution")
        );
        assert_eq!(
            workflow
                .steps
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "capture_drift",
                "plan_role_repair",
                "apply_role_repair",
                "verify_single_active"
            ]
        );
        assert_eq!(
            workflow.steps[HA_REPAIR_VERIFY_STEP_INDEX].state,
            WorkflowStepState::Completed
        );
        let claim = workflow
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing normalized repair workflow claim"));
        assert_eq!(claim.runner_id, HA_REPAIR_WORKFLOW_RUNNER_ID);
        assert!(open_repair_workflows(&service).await.is_empty());
    }

    #[tokio::test]
    async fn service_open_supersedes_stale_open_repair_workflow_and_executes_current_drift() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let roles = DocumentStore::<NodeRoleRecord>::open(temp.path().join("ha/roles.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for node_id in [&first, &second] {
            roles
                .create(
                    node_id.as_str(),
                    NodeRoleRecord {
                        node_id: node_id.clone(),
                        role: String::from("active"),
                        healthy: true,
                        last_heartbeat_at: OffsetDateTime::now_utc(),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Platform,
                            Some(node_id.to_string()),
                            sha256_hex(node_id.to_string().as_bytes()),
                        ),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let repair_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let repair_workflows = WorkflowCollection::<HaRepairWorkflowState>::open_local(
            temp.path().join("ha/repair_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let stale_drift_signature = zero_active_drift_signature(&[first.clone(), second.clone()]);
        let stale_workflow = HaRepairWorkflow::new(
            repair_id.to_string(),
            HA_REPAIR_WORKFLOW_KIND,
            HA_REPAIR_SUBJECT_KIND,
            stale_drift_signature.clone(),
            HaRepairWorkflowState {
                repair_id,
                drift_kind: HaTopologyDriftKind::ZeroActive,
                drift_signature: stale_drift_signature,
                active_node_ids: Vec::new(),
                passive_node_ids: vec![first.clone(), second.clone()],
                target_active_node_id: Some(first.clone()),
                demoted_node_ids: Vec::new(),
                observed_at: OffsetDateTime::now_utc() - Duration::seconds(60),
                resolution_reason: None,
            },
            vec![
                WorkflowStep::new("capture_drift", 0),
                WorkflowStep::new("plan_role_repair", 1),
                WorkflowStep::new("apply_role_repair", 2),
                WorkflowStep::new("verify_single_active", 3),
            ],
        );
        repair_workflows
            .create(stale_workflow.id.as_str(), stale_workflow.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let open_workflows = open_repair_workflows(&service).await;
        assert!(open_workflows.is_empty());

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 2);
        let stale = workflows
            .iter()
            .find(|workflow| workflow.id == stale_workflow.id)
            .unwrap_or_else(|| panic!("missing stale superseded workflow"));
        let current = workflows
            .iter()
            .find(|workflow| workflow.id != stale_workflow.id)
            .unwrap_or_else(|| panic!("missing executed current repair workflow"));
        assert_eq!(current.phase, WorkflowPhase::Completed);
        assert_eq!(current.state.drift_kind, HaTopologyDriftKind::DualActive);
        assert_eq!(stale.phase, WorkflowPhase::Failed);
        let expected_reason = format!(
            "superseded by current drift signature {}",
            current.state.drift_signature
        );
        assert_eq!(
            stale.state.resolution_reason.as_deref(),
            Some(expected_reason.as_str())
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.superseded.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.enqueued.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.completed.v1").await,
            1
        );
    }

    #[tokio::test]
    async fn manual_reconcile_route_resolves_open_repair_workflow_when_topology_is_healthy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_role_record(&service, &first, "active", true).await;
        seed_role_record(&service, &second, "passive", true).await;

        let mut stale_active_node_ids = vec![first.clone(), second.clone()];
        stale_active_node_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let drift_signature = dual_active_drift_signature(&stale_active_node_ids);
        let repair_id = RepairJobId::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut stale_workflow = HaRepairWorkflow::new(
            repair_id.to_string(),
            HA_REPAIR_WORKFLOW_KIND,
            HA_REPAIR_SUBJECT_KIND,
            drift_signature,
            HaRepairWorkflowState {
                repair_id,
                drift_kind: HaTopologyDriftKind::DualActive,
                drift_signature: dual_active_drift_signature(&stale_active_node_ids),
                active_node_ids: stale_active_node_ids,
                passive_node_ids: Vec::new(),
                target_active_node_id: Some(first.clone()),
                demoted_node_ids: vec![second.clone()],
                observed_at: OffsetDateTime::now_utc() - Duration::seconds(60),
                resolution_reason: None,
            },
            vec![
                WorkflowStep::new("capture_drift", 0),
                WorkflowStep::new("plan_role_repair", 1),
                WorkflowStep::new("apply_role_repair", 2),
                WorkflowStep::new("verify_single_active", 3),
            ],
        );
        stale_workflow.phase = WorkflowPhase::Running;
        stale_workflow.current_step_index = Some(HA_REPAIR_PLAN_STEP_INDEX);
        stale_workflow.steps[HA_REPAIR_PLAN_STEP_INDEX].state = WorkflowStepState::Active;
        service
            .repair_workflows
            .create(stale_workflow.id.as_str(), stale_workflow.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = dispatch_anti_entropy_reconcile(
            &service,
            RequestContext::new().unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let workflow: Option<HaRepairWorkflow> = parse_api_body(response).await;
        assert!(workflow.is_none());

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 1);
        let resolved = workflows
            .iter()
            .find(|workflow| workflow.id == stale_workflow.id)
            .unwrap_or_else(|| panic!("missing resolved repair workflow"));
        assert_eq!(resolved.phase, WorkflowPhase::Completed);
        assert!(resolved.completed_at.is_some());
        assert_eq!(
            resolved.state.resolution_reason.as_deref(),
            Some("topology drift cleared before repair execution")
        );
        assert!(open_repair_workflows(&service).await.is_empty());
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.resolved.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.enqueued.v1").await,
            0
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.completed.v1").await,
            0
        );
    }

    #[tokio::test]
    async fn anti_entropy_reconcile_route_is_idempotent_after_repair_execution() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let second = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        seed_role_record(&service, &first, "active", true).await;
        seed_role_record(&service, &second, "active", true).await;

        let first_response = dispatch_anti_entropy_reconcile(
            &service,
            RequestContext::new().unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_workflow: Option<HaRepairWorkflow> = parse_api_body(first_response).await;
        let first_workflow = first_workflow
            .unwrap_or_else(|| panic!("expected first reconcile to return a workflow"));
        assert_eq!(first_workflow.phase, WorkflowPhase::Completed);
        assert_eq!(
            first_workflow.state.drift_kind,
            HaTopologyDriftKind::DualActive
        );
        assert_eq!(
            first_workflow.current_step_index,
            Some(HA_REPAIR_VERIFY_STEP_INDEX)
        );

        let second_response = dispatch_anti_entropy_reconcile(
            &service,
            RequestContext::new().unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(second_response.status(), StatusCode::OK);
        let second_workflow: Option<HaRepairWorkflow> = parse_api_body(second_response).await;
        assert!(second_workflow.is_none());

        let workflows = all_repair_workflows(&service).await;
        assert_eq!(workflows.len(), 1);
        let stored = workflows
            .iter()
            .find(|workflow| workflow.id == first_workflow.id)
            .unwrap_or_else(|| panic!("missing stored repair workflow after repeated reconcile"));
        assert_eq!(stored.phase, WorkflowPhase::Completed);
        assert!(open_repair_workflows(&service).await.is_empty());
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.enqueued.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.completed.v1").await,
            1
        );
        assert_eq!(
            count_event_messages(&service, "ha.anti_entropy.repair.resolved.v1").await,
            0
        );

        let first_role = service
            .roles
            .get(first.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first repaired role"));
        let second_role = service
            .roles
            .get(second.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second repaired role"));
        let active_node_ids = [first_role.value, second_role.value]
            .into_iter()
            .filter(|record| record.role == "active")
            .map(|record| record.node_id)
            .collect::<Vec<_>>();
        assert_eq!(active_node_ids.len(), 1);
        assert_eq!(
            active_node_ids.first(),
            stored.state.target_active_node_id.as_ref()
        );
    }

    #[tokio::test]
    async fn failover_does_not_enqueue_transient_zero_active_repair_workflow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = HaService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let active = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let passive = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: active.to_string(),
                    role: String::from("active"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .set_role(
                SetRoleRequest {
                    node_id: passive.to_string(),
                    role: String::from("passive"),
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .update_replication_status(
                ReplicationRequest {
                    source_node_id: active.to_string(),
                    target_node_id: passive.to_string(),
                    lag_seconds: 1,
                    healthy: true,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: active.to_string(),
                    role: String::from("leader"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_regional_quorum(
                RegionalQuorumRequest {
                    region: String::from("us-east-1"),
                    node_id: passive.to_string(),
                    role: String::from("follower"),
                    term: 1,
                    vote_weight: Some(1),
                    healthy: true,
                    replicated_log_index: 10,
                    applied_log_index: 10,
                    lease_seconds: Some(60),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .failover(
                FailoverRequest {
                    from_node_id: active.to_string(),
                    to_node_id: passive.to_string(),
                    reason: String::from("planned maintenance"),
                    max_replication_lag_seconds: Some(30),
                },
                &context,
                FailoverMode::Failover,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(all_repair_workflows(&service).await.is_empty());
    }
}
