//! UVM node capability, runtime orchestration, and checkpoint service.
//!
//! This bounded context owns host-side UVM execution concerns:
//! - node accelerator capability declarations
//! - device profile catalog
//! - backend selection and admission preflight reports
//! - runtime session lifecycle transitions on nodes
//! - checkpoint envelope generation for migration/restore workflows
//!
//! The service persists every control decision and emits audit/outbox events so
//! operators can replay and diagnose node-plane behavior.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentCollection, DocumentStore, DurableOutbox, StoredDocument};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, NodeId, OwnershipScope, PlatformEvent,
    ResourceMetadata, ServiceEvent, UvmCheckpointId, UvmDeviceProfileId, UvmInstanceId,
    UvmMigrationId, UvmNodeCapabilityId, UvmNodeDrainId, UvmRuntimeSessionId, WorkloadId,
};
use uhost_uvm::{
    BackendSelectionRequest, BootDevice, ClaimTier, CpuTopologySpec, ExecutionPlanRequest,
    GuestArchitecture, GuestProfile, HostClass, HostClassEnvironment, HostPlatform,
    HypervisorBackend, HypervisorHealth, LaunchSpec, MachineFamily, MigrationBudget,
    MigrationEnvelope, MigrationStrategy, NumaPolicySpec, PlacementRequest,
    UvmCompatibilityAssessment, UvmCompatibilityEvidence, UvmCompatibilityEvidenceSource,
    UvmCompatibilityRequirement, UvmExecutionIntent, UvmNodeCompatibilitySummary,
    UvmPortabilityAssessment, VmRuntimeAction, VmRuntimeState, assess_execution_intent,
    build_launch_command, evaluate_migration_budget, normalize_path_or_uri_reference,
    plan_placement, select_backend, synthesize_execution_plan, transition_state,
};

/// Host node capability declaration for UVM acceleration and migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmNodeCapabilityRecord {
    /// Capability identifier.
    pub id: UvmNodeCapabilityId,
    /// Host node identifier.
    pub node_id: NodeId,
    /// Host platform family used for backend selection.
    #[serde(default = "default_host_platform_key")]
    pub host_platform: String,
    /// Shared host-class key for this node posture.
    #[serde(default)]
    pub host_class: String,
    /// Host architecture.
    pub architecture: String,
    /// Supported accelerator backends in preference order.
    pub accelerator_backends: Vec<String>,
    /// Supported machine families in preference order.
    #[serde(default)]
    pub supported_machine_families: Vec<String>,
    /// Supported guest profiles for this capability.
    #[serde(default)]
    pub supported_guest_profiles: Vec<String>,
    /// Default claim tier allowed for this capability.
    #[serde(default = "default_claim_tier_key")]
    pub default_claim_tier: String,
    /// Whether the software runner is explicitly allowed on this node.
    #[serde(default = "default_software_runner_supported")]
    pub software_runner_supported: bool,
    /// Whether the node is in a container-restricted posture.
    #[serde(default)]
    pub container_restricted: bool,
    /// Evidence mode used to justify the capability posture.
    #[serde(default = "default_host_evidence_mode_key")]
    pub host_evidence_mode: String,
    /// Maximum vCPU supported for one instance.
    pub max_vcpu: u16,
    /// Maximum memory supported for one instance (MiB).
    pub max_memory_mb: u64,
    /// Number of NUMA nodes exposed.
    pub numa_nodes: u8,
    /// Whether secure boot is supported.
    pub supports_secure_boot: bool,
    /// Whether live migration is supported.
    pub supports_live_migration: bool,
    /// Whether PCI passthrough is supported.
    pub supports_pci_passthrough: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Device profile contract used by control-plane VM declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmDeviceProfileRecord {
    /// Device profile identifier.
    pub id: UvmDeviceProfileId,
    /// Profile name.
    pub name: String,
    /// Legacy emulated devices.
    pub legacy_devices: Vec<String>,
    /// Modern virtio/paravirtual devices.
    pub modern_devices: Vec<String>,
    /// Whether profile allows passthrough.
    pub passthrough_enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Adapter selection response used by schedulers and admission checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmAdapterSelection {
    /// Selected capability identifier.
    pub capability_id: UvmNodeCapabilityId,
    /// Selected backend.
    pub accelerator_backend: String,
    /// Machine family that should be used with the selected backend.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile assumed by the selection result.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Claim tier attached to the selection result.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Runtime incarnation kind tracked within one durable runtime session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmRuntimeIncarnationKind {
    /// First successful boot for the runtime session.
    OriginalBoot,
    /// Restart after an explicit stop.
    Restart,
    /// Restore from a persisted checkpoint.
    Restore,
    /// Activation after a migration checkpoint cutover.
    PostMigrationCutover,
}

/// Durable lineage entry for one runtime incarnation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeIncarnationRecord {
    /// Monotonic incarnation sequence scoped to one runtime session.
    pub sequence: u32,
    /// Incarnation trigger class.
    pub kind: UvmRuntimeIncarnationKind,
    /// Previous incarnation sequence when this was not the first activation.
    #[serde(default)]
    pub previous_sequence: Option<u32>,
    /// Runtime state immediately before this incarnation activated.
    #[serde(default)]
    pub previous_state: Option<VmRuntimeState>,
    /// Source node when a checkpoint restore or migration cutover had a distinct origin.
    #[serde(default)]
    pub source_node_id: Option<NodeId>,
    /// Node hosting this incarnation after activation.
    pub target_node_id: NodeId,
    /// Checkpoint that created this incarnation when applicable.
    #[serde(default)]
    pub checkpoint_id: Option<UvmCheckpointId>,
    /// Migration operation that created this incarnation when applicable.
    #[serde(default)]
    pub migration_id: Option<UvmMigrationId>,
    /// Operator or workflow reason linked to this activation when one existed.
    #[serde(default)]
    pub reason: Option<String>,
    /// Activation timestamp.
    pub activated_at: OffsetDateTime,
}

/// Runtime execution session record for one UVM instance on one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeSessionRecord {
    /// Runtime session identifier.
    pub id: UvmRuntimeSessionId,
    /// Owning UVM instance.
    pub instance_id: UvmInstanceId,
    /// Bound node.
    pub node_id: NodeId,
    /// Capability used for admission.
    pub capability_id: UvmNodeCapabilityId,
    /// Guest architecture.
    pub guest_architecture: String,
    /// Effective vCPU count used at registration time.
    pub vcpu: u16,
    /// Effective memory in MiB used at registration time.
    pub memory_mb: u64,
    /// Guest OS hint.
    pub guest_os: String,
    /// CPU topology profile used for admission.
    pub cpu_topology_profile: String,
    /// NUMA policy profile used for admission.
    pub numa_policy_profile: String,
    /// NUMA nodes selected by placement planner.
    pub planned_pinned_numa_nodes: Vec<u8>,
    /// Memory distribution across `planned_pinned_numa_nodes`.
    pub planned_memory_per_numa_mb: Vec<u64>,
    /// Migration policy profile (`cold_only`, `best_effort_live`, `strict_live`, `live_postcopy`).
    pub migration_policy: String,
    /// Machine family selected for execution planning.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile selected for execution planning.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Claim tier attached to the runtime contract.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Runner lifecycle phase when using the software backend.
    #[serde(default = "default_runner_phase_key")]
    pub runner_phase: String,
    /// Worker lifecycle markers emitted by the software backend.
    #[serde(default)]
    pub worker_states: Vec<String>,
    /// Runtime evidence mode carried from the node capability posture.
    #[serde(default = "default_runtime_evidence_mode_key")]
    pub runtime_evidence_mode: String,
    /// Recommended checkpoint kind computed from migration budget.
    pub planned_migration_checkpoint_kind: String,
    /// Expected downtime budget (ms) from migration planner.
    pub planned_migration_downtime_ms: u32,
    /// Selected backend key.
    pub accelerator_backend: String,
    /// Program used for launch.
    pub launch_program: String,
    /// Program arguments used for launch.
    pub launch_args: Vec<String>,
    /// Environment entries used for launch in `KEY=VALUE` format.
    pub launch_env: Vec<String>,
    /// Node isolation profile.
    pub isolation_profile: String,
    /// Boot-path profile synthesized by UVM execution planning.
    #[serde(default)]
    pub boot_path: String,
    /// Execution-class profile synthesized by UVM execution planning.
    #[serde(default)]
    pub execution_class: String,
    /// Memory-backing mode synthesized by UVM execution planning.
    #[serde(default)]
    pub memory_backing: String,
    /// Device-model profile synthesized by UVM execution planning.
    #[serde(default)]
    pub device_model: String,
    /// Sandbox layers requested for hardening.
    #[serde(default)]
    pub sandbox_layers: Vec<String>,
    /// Telemetry streams requested for runtime observability.
    #[serde(default)]
    pub telemetry_streams: Vec<String>,
    /// Restart policy (`never`, `on-failure`, `always`).
    pub restart_policy: String,
    /// Max restart attempts before hard-fail.
    pub max_restarts: u16,
    /// Start attempts performed so far.
    pub start_attempts: u16,
    /// Runtime state.
    pub state: VmRuntimeState,
    /// Last reported runtime heartbeat timestamp.
    #[serde(default)]
    pub last_heartbeat_at: Option<OffsetDateTime>,
    /// Monotonic heartbeat observation sequence accepted by the node plane.
    #[serde(default)]
    pub heartbeat_sequence: u64,
    /// Latest authoritative runner heartbeat sequence accepted for this runtime session.
    #[serde(default)]
    pub last_runner_sequence_id: Option<u64>,
    /// Latest authoritative runner lifecycle event referenced by a heartbeat.
    #[serde(default)]
    pub last_lifecycle_event_id: Option<AuditId>,
    /// Observed PID or platform-equivalent runtime identifier.
    #[serde(default)]
    pub observed_pid: Option<u32>,
    /// Observed resident memory assigned by the adapter in MiB.
    #[serde(default)]
    pub observed_assigned_memory_mb: Option<u64>,
    /// Last hypervisor health report.
    #[serde(default = "default_hypervisor_health_key")]
    pub hypervisor_health: String,
    /// Last observed exit or stall reason reported by the node plane.
    #[serde(default)]
    pub last_exit_reason: Option<String>,
    /// Whether a migration operation currently owns this runtime session.
    #[serde(default)]
    pub migration_in_progress: bool,
    /// Most recent checkpoint captured for this runtime session.
    #[serde(default)]
    pub last_checkpoint_id: Option<UvmCheckpointId>,
    /// Most recent checkpoint restored into this runtime session.
    #[serde(default)]
    pub restored_from_checkpoint_id: Option<UvmCheckpointId>,
    /// Number of restore operations recorded for this runtime session.
    #[serde(default)]
    pub restore_count: u32,
    /// Timestamp of the last restore operation.
    #[serde(default)]
    pub last_restore_at: Option<OffsetDateTime>,
    /// Current runtime incarnation when the session has activated at least once.
    #[serde(default)]
    pub current_incarnation: Option<UvmRuntimeIncarnationRecord>,
    /// Durable incarnation lineage for original boot, restarts, restores, and cutovers.
    #[serde(default)]
    pub incarnation_lineage: Vec<UvmRuntimeIncarnationRecord>,
    /// Optional last error.
    pub last_error: Option<String>,
    /// Record creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last transition timestamp.
    pub last_transition_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Persisted execution-intent lineage for one runtime session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeSessionIntentRecord {
    /// Stable lineage identifier for this runtime session execution intent record.
    #[serde(default)]
    pub lineage_id: Option<AuditId>,
    /// Runtime session identifier.
    pub runtime_session_id: UvmRuntimeSessionId,
    /// Owning UVM instance.
    pub instance_id: UvmInstanceId,
    /// Typed execution intent resolved at registration time.
    pub execution_intent: UvmExecutionIntent,
    /// First-placement portability assessment captured during initial runtime admission.
    #[serde(default)]
    pub first_placement_portability_assessment: Option<UvmPortabilityAssessment>,
    /// Latest session-scoped portability preflight linked to this runtime lineage.
    #[serde(default)]
    pub last_portability_preflight_id: Option<AuditId>,
    /// Record creation timestamp.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Runtime preflight report persisted for admission diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimePreflightRecord {
    /// Report identifier.
    pub id: AuditId,
    /// Target capability.
    pub capability_id: UvmNodeCapabilityId,
    /// Target node.
    pub node_id: NodeId,
    /// Guest architecture.
    pub guest_architecture: String,
    /// Guest OS hint.
    pub guest_os: String,
    /// Machine family derived for the requested guest shape.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile derived for the requested guest shape.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Claim tier allowed by this preflight report.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Whether request is Apple guest workload.
    pub apple_guest: bool,
    /// Whether legal guardrails allowed the request.
    pub legal_allowed: bool,
    /// Whether placement admission checks passed.
    pub placement_admitted: bool,
    /// NUMA nodes selected by placement planner.
    pub placement_pinned_numa_nodes: Vec<u8>,
    /// Whether secure boot was required.
    pub require_secure_boot: bool,
    /// Whether live migration was required.
    pub requires_live_migration: bool,
    /// Selected backend if available.
    pub selected_backend: Option<String>,
    /// Launch program if available.
    pub launch_program: Option<String>,
    /// Recommended checkpoint kind from migration planner.
    pub migration_recommended_checkpoint_kind: Option<String>,
    /// Expected migration downtime from migration planner.
    pub migration_expected_downtime_ms: Option<u32>,
    /// Admission blockers.
    pub blockers: Vec<String>,
    /// Shared compatibility assessment produced for this preflight.
    #[serde(default)]
    pub compatibility_assessment: Option<UvmCompatibilityAssessment>,
    /// Structured execution-intent portability assessment for backend selection.
    #[serde(default)]
    pub portability_assessment: Option<UvmPortabilityAssessment>,
    /// Report timestamp.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Heartbeat window captured when a runtime checkpoint is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UvmRuntimeCheckpointHeartbeatWindow {
    /// First heartbeat observed in the checkpoint provenance window.
    #[serde(default)]
    pub first_heartbeat_id: Option<AuditId>,
    /// First heartbeat sequence observed in the checkpoint provenance window.
    #[serde(default)]
    pub first_sequence: Option<u64>,
    /// Timestamp of the first heartbeat observed in the provenance window.
    #[serde(default)]
    pub first_observed_at: Option<OffsetDateTime>,
    /// Last heartbeat observed in the checkpoint provenance window.
    #[serde(default)]
    pub last_heartbeat_id: Option<AuditId>,
    /// Last heartbeat sequence observed in the checkpoint provenance window.
    #[serde(default)]
    pub last_sequence: Option<u64>,
    /// Timestamp of the last heartbeat observed in the provenance window.
    #[serde(default)]
    pub last_observed_at: Option<OffsetDateTime>,
}

/// Witness digests carried alongside checkpoint provenance for operator replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UvmRuntimeCheckpointWitnessDigests {
    /// Digest of the runtime session record used as the source witness.
    #[serde(default)]
    pub runtime_session: Option<String>,
    /// Digest of the execution-intent lineage witness when available.
    #[serde(default)]
    pub execution_intent: Option<String>,
    /// Digest of the linked portability preflight witness when available.
    #[serde(default)]
    pub portability_preflight: Option<String>,
    /// Digest of the first heartbeat witness in the checkpoint heartbeat window.
    #[serde(default)]
    pub heartbeat_window_start: Option<String>,
    /// Digest of the last heartbeat witness in the checkpoint heartbeat window.
    #[serde(default)]
    pub heartbeat_window_end: Option<String>,
}

/// Operator-readable source provenance captured for one runtime checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UvmRuntimeCheckpointProvenance {
    /// Source PID observed for the runtime when the checkpoint was created.
    #[serde(default)]
    pub source_pid: Option<u32>,
    /// Heartbeat window that bounded the checkpoint source runtime.
    #[serde(default)]
    pub heartbeat_window: UvmRuntimeCheckpointHeartbeatWindow,
    /// Stable execution-intent lineage identifier when one exists.
    #[serde(default)]
    pub execution_intent_lineage_id: Option<AuditId>,
    /// Latest linked portability preflight identifier when one exists.
    #[serde(default)]
    pub portability_preflight_id: Option<AuditId>,
    /// Digests of the persisted witnesses that justified the checkpoint provenance.
    #[serde(default)]
    pub witness_digests: UvmRuntimeCheckpointWitnessDigests,
}

/// Runtime checkpoint envelope persisted for migration coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeCheckpointRecord {
    /// Checkpoint identifier.
    pub id: UvmCheckpointId,
    /// Runtime session identifier.
    pub runtime_session_id: UvmRuntimeSessionId,
    /// UVM instance identifier.
    pub instance_id: UvmInstanceId,
    /// Source node.
    pub source_node_id: NodeId,
    /// Target node.
    pub target_node_id: NodeId,
    /// Checkpoint kind (`crash_consistent`, `live_precopy`, `live_postcopy`).
    pub kind: String,
    /// Checkpoint URI.
    pub checkpoint_uri: String,
    /// Memory bitmap hash.
    pub memory_bitmap_hash: String,
    /// Disk generation for idempotency.
    pub disk_generation: u64,
    /// Deterministic migration envelope digest.
    pub envelope_digest: String,
    /// Source lineage captured when the checkpoint was created.
    #[serde(default)]
    pub provenance: UvmRuntimeCheckpointProvenance,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Runtime migration operation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeMigrationRecord {
    /// Migration operation identifier.
    pub id: UvmMigrationId,
    /// Runtime session identifier.
    pub runtime_session_id: UvmRuntimeSessionId,
    /// UVM instance identifier.
    pub instance_id: UvmInstanceId,
    /// Source node.
    pub source_node_id: NodeId,
    /// Target node.
    pub target_node_id: NodeId,
    /// Target capability used after cutover.
    pub target_capability_id: UvmNodeCapabilityId,
    /// Checkpoint identifier backing the migration operation.
    pub checkpoint_id: UvmCheckpointId,
    /// Migration state (`requested`, `in_progress`, `committed`, `rolled_back`, `failed`).
    pub state: String,
    /// Operator reason.
    pub reason: String,
    /// Optional failure detail.
    pub failure_detail: Option<String>,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UvmNodeOperationKind {
    Start,
    Stop,
    Restore,
    Recover,
    Migrate,
    Drain,
    Repair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UvmNodeOperationState {
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmNodeOperationRecord {
    id: AuditId,
    kind: UvmNodeOperationKind,
    state: UvmNodeOperationState,
    node_id: NodeId,
    #[serde(default)]
    target_node_id: Option<NodeId>,
    #[serde(default)]
    runtime_session_id: Option<UvmRuntimeSessionId>,
    #[serde(default)]
    instance_id: Option<UvmInstanceId>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    from_state: Option<String>,
    #[serde(default)]
    to_state: Option<String>,
    #[serde(default)]
    checkpoint_id: Option<UvmCheckpointId>,
    #[serde(default)]
    linked_resource_kind: Option<String>,
    #[serde(default)]
    linked_resource_id: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    #[serde(default)]
    completed_at: Option<OffsetDateTime>,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmNodeDrainOperationRecord {
    id: UvmNodeDrainId,
    node_id: NodeId,
    state: String,
    reason: String,
    failure_detail: Option<String>,
    tracked_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    active_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    inactive_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    migrating_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    snapshot_at: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct UvmRunnerSupervisionRecord {
    runtime_session_id: UvmRuntimeSessionId,
    runtime_incarnation: u32,
    instance_id: UvmInstanceId,
    node_id: NodeId,
    launch_program: String,
    launch_args: Vec<String>,
    launch_env: Vec<String>,
    stop_sentinel_path: String,
    state: String,
    observed_pid: Option<u32>,
    last_event_kind: Option<String>,
    last_lifecycle_state: Option<String>,
    last_runner_phase: Option<String>,
    #[serde(default)]
    workers: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_access: Option<UvmRuntimeNetworkAccessRecord>,
    boot_stages: Vec<String>,
    console_trace: Vec<String>,
    guest_control_ready: bool,
    last_heartbeat_sequence: Option<u64>,
    stop_reason: Option<String>,
    exit_status: Option<i32>,
    failure_detail: Option<String>,
    requested_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    last_event_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmRuntimeNetworkAccessRecord {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    egress_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_http_bind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_http_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_tcp_bind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_tcp_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_udp_bind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_udp_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_web_root: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    supported_guest_commands: Vec<String>,
}

/// Persisted runtime heartbeat record for forensic replay and health summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeHeartbeatRecord {
    /// Heartbeat identifier.
    pub id: AuditId,
    /// Target runtime session identifier.
    pub runtime_session_id: UvmRuntimeSessionId,
    /// Runtime incarnation sequence active when the heartbeat was accepted.
    #[serde(default)]
    pub runtime_incarnation_sequence: Option<u32>,
    /// Monotonic node-plane observation sequence for this heartbeat.
    pub sequence: u64,
    /// Authoritative runner heartbeat sequence carried by this observation.
    #[serde(default)]
    pub runner_sequence_id: Option<u64>,
    /// Adapter health state.
    pub hypervisor_health: String,
    /// Observed PID or platform-equivalent runtime identifier.
    pub observed_pid: Option<u32>,
    /// Observed resident memory assigned by the adapter in MiB.
    pub observed_assigned_memory_mb: Option<u64>,
    /// Optional exit or stall reason.
    pub exit_reason: Option<String>,
    /// Runner lifecycle phase emitted by the software backend.
    #[serde(default = "default_runner_phase_key")]
    pub runner_phase: String,
    /// Worker lifecycle markers emitted by the software backend.
    #[serde(default)]
    pub worker_states: Vec<String>,
    /// Authoritative runner lifecycle event linked to this heartbeat.
    #[serde(default)]
    pub lifecycle_event_id: Option<AuditId>,
    /// Observation timestamp.
    pub observed_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Computed runtime health summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRuntimeHealthSummary {
    /// Total runtime sessions in the node-plane view.
    pub total_sessions: usize,
    /// Sessions currently in running state.
    pub running_sessions: usize,
    /// Sessions considered stale because their heartbeat exceeded the threshold.
    pub stale_sessions: usize,
    /// Sessions reporting degraded adapter health.
    pub degraded_sessions: usize,
    /// Sessions reporting failed adapter health or failed runtime state.
    pub failed_sessions: usize,
    /// Sessions currently using the software backend.
    pub software_backend_sessions: usize,
    /// Sessions that have recorded at least one restore operation.
    pub restored_sessions: usize,
    /// Threshold used for stale evaluation.
    pub stale_after_seconds: i64,
    /// Session identifiers currently considered stale.
    pub stale_runtime_session_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNodeCapabilityRequest {
    node_id: String,
    host_platform: Option<String>,
    architecture: String,
    accelerator_backends: Vec<String>,
    max_vcpu: u16,
    max_memory_mb: u64,
    numa_nodes: u8,
    supports_secure_boot: bool,
    supports_live_migration: bool,
    supports_pci_passthrough: bool,
    software_runner_supported: Option<bool>,
    container_restricted: Option<bool>,
    host_evidence_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDeviceProfileRequest {
    name: String,
    legacy_devices: Vec<String>,
    modern_devices: Vec<String>,
    passthrough_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SelectAdapterRequest {
    capability_id: String,
    guest_architecture: String,
    apple_guest: bool,
    requires_live_migration: bool,
    require_secure_boot: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisterRuntimeSessionRequest {
    instance_id: String,
    node_id: String,
    capability_id: String,
    guest_architecture: String,
    guest_os: String,
    disk_image: String,
    cdrom_image: Option<String>,
    boot_device: Option<String>,
    vcpu: Option<u16>,
    memory_mb: Option<u64>,
    firmware_profile: Option<String>,
    cpu_topology: Option<String>,
    numa_policy: Option<String>,
    migration_policy: Option<String>,
    require_secure_boot: Option<bool>,
    requires_live_migration: Option<bool>,
    migration_max_downtime_ms: Option<u32>,
    migration_max_iterations: Option<u16>,
    migration_bandwidth_mbps: Option<u64>,
    migration_dirty_page_rate_mbps: Option<u64>,
    isolation_profile: Option<String>,
    restart_policy: Option<String>,
    max_restarts: Option<u16>,
    apple_guest_approved: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeFailureRequest {
    error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeRecoverRequest {
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreRuntimeRequest {
    checkpoint_id: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RepairRuntimeRequest {
    reason: Option<String>,
    stale_after_seconds: Option<i64>,
    target_node_id: Option<String>,
    target_capability_id: Option<String>,
    #[serde(default)]
    execution_intent: Option<UvmExecutionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeHeartbeatRequest {
    observed_pid: Option<u32>,
    observed_assigned_memory_mb: Option<u64>,
    hypervisor_health: String,
    exit_reason: Option<String>,
    runner_phase: Option<String>,
    worker_states: Option<Vec<String>>,
    runner_sequence_id: Option<u64>,
    lifecycle_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateCheckpointRequest {
    runtime_session_id: String,
    kind: String,
    checkpoint_uri: String,
    memory_bitmap_hash: String,
    disk_generation: u64,
    target_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimePreflightRequest {
    capability_id: String,
    guest_architecture: String,
    guest_os: String,
    cdrom_image: Option<String>,
    boot_device: Option<String>,
    vcpu: Option<u16>,
    memory_mb: Option<u64>,
    cpu_topology: Option<String>,
    numa_policy: Option<String>,
    migration_policy: Option<String>,
    require_secure_boot: Option<bool>,
    requires_live_migration: Option<bool>,
    migration_max_downtime_ms: Option<u32>,
    migration_max_iterations: Option<u16>,
    migration_bandwidth_mbps: Option<u64>,
    migration_dirty_page_rate_mbps: Option<u64>,
    apple_guest_approved: Option<bool>,
    #[serde(default)]
    compatibility_requirement: Option<UvmCompatibilityRequirement>,
    #[serde(default)]
    execution_intent: Option<UvmExecutionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeMigrationPreflightRequest {
    runtime_session_id: String,
    to_node_id: String,
    target_capability_id: String,
    require_secure_boot: Option<bool>,
    migration_max_downtime_ms: Option<u32>,
    migration_max_iterations: Option<u16>,
    migration_bandwidth_mbps: Option<u64>,
    migration_dirty_page_rate_mbps: Option<u64>,
    #[serde(default)]
    execution_intent: Option<UvmExecutionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct UvmImageArtifactRecord {
    source_uri: String,
    verified: bool,
    #[serde(default)]
    architecture: String,
    #[serde(default = "default_machine_family_key")]
    machine_family: String,
    #[serde(default = "default_guest_profile_key")]
    guest_profile: String,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    #[serde(default)]
    compatibility_evidence: Vec<UvmCompatibilityEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmFirmwareBundleArtifactRecord {
    firmware_profile: String,
    artifact_uri: String,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedImageCompatibilityArtifact {
    row_id: String,
    host_class: String,
    region: String,
    cell: String,
    accelerator_backend: String,
    machine_family: String,
    guest_profile: String,
    claim_tier: String,
    secure_boot_supported: bool,
    live_migration_supported: bool,
    policy_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StartRuntimeMigrationRequest {
    runtime_session_id: String,
    to_node_id: String,
    target_capability_id: String,
    kind: String,
    checkpoint_uri: String,
    memory_bitmap_hash: String,
    disk_generation: u64,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResolveRuntimeMigrationRequest {
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodePlaneProcessReportRecord {
    node_id: NodeId,
    workload_id: WorkloadId,
    state: String,
    exit_code: Option<i32>,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNodeDrainRequest {
    node_id: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResolveNodeDrainRequest {
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeRepairSelection {
    selected_action: &'static str,
    checkpoint_id: Option<UvmCheckpointId>,
    target_node_id: Option<NodeId>,
    target_capability_id: Option<UvmNodeCapabilityId>,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct UvmControlInstanceIntentSnapshot {
    id: UvmInstanceId,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_control_execution_intent"
    )]
    execution_intent: Option<UvmExecutionIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum StoredControlExecutionIntent {
    Contract(UvmExecutionIntent),
    LegacyKey(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeDrainRuntimeSnapshot {
    runtime_session_ids: Vec<UvmRuntimeSessionId>,
    active_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    inactive_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    migrating_runtime_session_ids: Vec<UvmRuntimeSessionId>,
    snapshot_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeOperationCreateRequest {
    kind: UvmNodeOperationKind,
    state: UvmNodeOperationState,
    node_id: NodeId,
    target_node_id: Option<NodeId>,
    runtime_session_id: Option<UvmRuntimeSessionId>,
    instance_id: Option<UvmInstanceId>,
    reason: Option<String>,
    detail: Option<String>,
    phase: Option<String>,
    from_state: Option<VmRuntimeState>,
    to_state: Option<VmRuntimeState>,
    checkpoint_id: Option<UvmCheckpointId>,
    linked_resource_kind: Option<String>,
    linked_resource_id: Option<String>,
}

impl NodeOperationCreateRequest {
    fn new(kind: UvmNodeOperationKind, state: UvmNodeOperationState, node_id: NodeId) -> Self {
        Self {
            kind,
            state,
            node_id,
            target_node_id: None,
            runtime_session_id: None,
            instance_id: None,
            reason: None,
            detail: None,
            phase: None,
            from_state: None,
            to_state: None,
            checkpoint_id: None,
            linked_resource_kind: None,
            linked_resource_id: None,
        }
    }
}

/// UVM node service.
#[derive(Debug, Clone)]
pub struct UvmNodeService {
    capabilities: DocumentStore<UvmNodeCapabilityRecord>,
    device_profiles: DocumentStore<UvmDeviceProfileRecord>,
    runtime_sessions: DocumentStore<UvmRuntimeSessionRecord>,
    node_process_reports: DocumentStore<NodePlaneProcessReportRecord>,
    runtime_session_intents: DocumentStore<UvmRuntimeSessionIntentRecord>,
    runner_supervision: DocumentStore<UvmRunnerSupervisionRecord>,
    runtime_preflights: DocumentStore<UvmRuntimePreflightRecord>,
    runtime_checkpoints: DocumentStore<UvmRuntimeCheckpointRecord>,
    runtime_migrations: DocumentStore<UvmRuntimeMigrationRecord>,
    node_operations: DocumentStore<UvmNodeOperationRecord>,
    node_drains: DocumentStore<UvmNodeDrainOperationRecord>,
    runtime_heartbeats: DocumentStore<UvmRuntimeHeartbeatRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl UvmNodeService {
    /// Open UVM node service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let platform_root = state_root.as_ref();
        let root = platform_root.join("uvm-node");
        let service = Self {
            capabilities: DocumentStore::open(root.join("node_capabilities.json")).await?,
            device_profiles: DocumentStore::open(root.join("device_profiles.json")).await?,
            runtime_sessions: DocumentStore::open(root.join("runtime_sessions.json")).await?,
            node_process_reports: DocumentStore::open(
                platform_root.join("node/process_reports.json"),
            )
            .await?,
            runtime_session_intents: DocumentStore::open(root.join("runtime_session_intents.json"))
                .await?,
            runner_supervision: DocumentStore::open(root.join("runner_supervision.json")).await?,
            runtime_preflights: DocumentStore::open(root.join("runtime_preflights.json")).await?,
            runtime_checkpoints: DocumentStore::open(root.join("runtime_checkpoints.json")).await?,
            runtime_migrations: DocumentStore::open(root.join("runtime_migrations.json")).await?,
            node_operations: DocumentStore::open(root.join("node_operations.json")).await?,
            node_drains: DocumentStore::open(root.join("node_drains.json")).await?,
            runtime_heartbeats: DocumentStore::open(root.join("runtime_heartbeats.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.normalize_capability_host_classes().await?;
        service
            .reconcile_runtime_migration_node_operation_links()
            .await?;
        service.reconcile_node_process_reports().await?;
        Ok(service)
    }

    fn platform_state_root(&self) -> &Path {
        self.state_root
            .parent()
            .unwrap_or(self.state_root.as_path())
    }

    async fn reconcile_node_process_reports(&self) -> Result<()> {
        for (_, stored) in self.runtime_sessions.list().await? {
            if stored.deleted {
                continue;
            }
            self.project_runtime_session_into_node_plane(&stored.value)
                .await?;
        }
        Ok(())
    }

    async fn reconcile_runtime_migration_node_operation_links(&self) -> Result<()> {
        let migrations = self.runtime_migrations.list().await?;
        if migrations.is_empty() {
            return Ok(());
        }
        let operations = self.node_operations.list().await?;
        for (_, migration_stored) in migrations {
            if migration_stored.deleted
                || self
                    .find_node_operation_for_linked_resource(
                        UvmNodeOperationKind::Migrate,
                        "runtime_migration",
                        migration_stored.value.id.as_str(),
                    )
                    .await?
                    .is_some()
            {
                continue;
            }

            let mut selected: Option<(String, StoredDocument<UvmNodeOperationRecord>)> = None;
            for (operation_id, operation_stored) in &operations {
                if operation_stored.deleted
                    || !runtime_migration_node_operation_needs_link_backfill(
                        &operation_stored.value,
                    )
                    || !runtime_migration_matches_legacy_node_operation(
                        &operation_stored.value,
                        &migration_stored.value,
                    )
                {
                    continue;
                }
                if selected
                    .as_ref()
                    .map(|(_, current)| {
                        current.value.created_at > operation_stored.value.created_at
                            || (current.value.created_at == operation_stored.value.created_at
                                && current.value.updated_at >= operation_stored.value.updated_at)
                    })
                    .unwrap_or(false)
                {
                    continue;
                }
                selected = Some((operation_id.clone(), operation_stored.clone()));
            }

            let Some((operation_id, operation_stored)) = selected else {
                continue;
            };
            let mut operation = operation_stored.value;
            operation.linked_resource_kind = Some(String::from("runtime_migration"));
            operation.linked_resource_id = Some(migration_stored.value.id.to_string());
            operation.updated_at = OffsetDateTime::now_utc();
            operation
                .metadata
                .touch(sha256_hex(operation.id.as_str().as_bytes()));
            self.node_operations
                .upsert(
                    operation_id.as_str(),
                    operation,
                    Some(operation_stored.version),
                )
                .await?;
        }
        Ok(())
    }

    async fn project_runtime_session_into_node_plane(
        &self,
        runtime: &UvmRuntimeSessionRecord,
    ) -> Result<()> {
        let workload_id = node_plane_workload_id(&runtime.id)?;
        let report = NodePlaneProcessReportRecord {
            node_id: runtime.node_id.clone(),
            workload_id: workload_id.clone(),
            state: String::from(runtime.state.as_str()),
            exit_code: node_plane_process_exit_code(runtime),
            updated_at: node_plane_process_updated_at(runtime),
        };
        let _ = self
            .node_process_reports
            .upsert(workload_id.as_str(), report, None)
            .await?;
        Ok(())
    }

    async fn read_optional_collection<T>(
        &self,
        path: &Path,
    ) -> Result<Option<DocumentCollection<T>>>
    where
        T: Clone + for<'de> Deserialize<'de>,
    {
        let raw = match fs::read(path).await {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to read collection from disk")
                        .with_detail(error.to_string()),
                );
            }
        };
        let collection =
            serde_json::from_slice::<DocumentCollection<T>>(&raw).map_err(|error| {
                PlatformError::unavailable("failed to decode collection payload")
                    .with_detail(error.to_string())
            })?;
        Ok(Some(collection))
    }

    async fn resolve_verified_local_disk_artifact_uri(
        &self,
        requested_disk_image: &str,
    ) -> Result<Option<String>> {
        let mut matches = self
            .list_verified_image_artifact_records(requested_disk_image)
            .await?
            .into_iter()
            .map(|record| record.source_uri)
            .map(|value| normalize_local_file_artifact_uri(&value, "disk_image"))
            .collect::<Result<Vec<_>>>()?;
        matches.sort_unstable();
        matches.dedup();
        Ok(matches.into_iter().next())
    }

    async fn list_verified_image_artifact_records(
        &self,
        requested_disk_image: &str,
    ) -> Result<Vec<UvmImageArtifactRecord>> {
        let images_path = self.platform_state_root().join("uvm-image/images.json");
        let Some(collection) = self
            .read_optional_collection::<UvmImageArtifactRecord>(&images_path)
            .await?
        else {
            return Ok(Vec::new());
        };

        let mut matches = collection
            .records
            .into_values()
            .filter_map(|stored| {
                if stored.deleted
                    || !stored.value.verified
                    || stored.value.source_uri != requested_disk_image
                {
                    return None;
                }
                Some(stored.value)
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.source_uri
                .cmp(&right.source_uri)
                .then(left.architecture.cmp(&right.architecture))
                .then(left.machine_family.cmp(&right.machine_family))
                .then(left.guest_profile.cmp(&right.guest_profile))
                .then(left.claim_tier.cmp(&right.claim_tier))
        });
        Ok(matches)
    }

    async fn resolve_scoped_image_compatibility_artifact(
        &self,
        requested_disk_image: &str,
        capability: &UvmNodeCapabilityRecord,
        guest_architecture: GuestArchitecture,
        machine_family: &str,
        guest_profile: &str,
        require_secure_boot: bool,
        requires_live_migration: bool,
        selected_backend: HypervisorBackend,
    ) -> Result<Option<ScopedImageCompatibilityArtifact>> {
        // Image admission is intentionally strict: start from verified image
        // records, apply the optional architecture filter, parse compatibility
        // rows, require an exact `global/global` scope match for this
        // publication path, and only then enforce backend/security/migration
        // policy gates.
        let records = self
            .list_verified_image_artifact_records(requested_disk_image)
            .await?;
        if records.is_empty() {
            return Ok(None);
        }

        let mut parsed_artifacts = Vec::new();
        for record in &records {
            if !record.architecture.is_empty() && record.architecture != guest_architecture.as_str()
            {
                continue;
            }
            for row in &record.compatibility_evidence {
                if let Some(artifact) = Self::parse_scoped_image_compatibility_artifact(row)? {
                    parsed_artifacts.push(artifact);
                }
            }
        }
        if parsed_artifacts.is_empty() {
            return Ok(None);
        }

        let mut exact_matches = parsed_artifacts
            .into_iter()
            .filter(|artifact| {
                artifact.host_class == capability.host_class
                    && artifact.region == "global"
                    && artifact.cell == "global"
                    && artifact.accelerator_backend == selected_backend.as_str()
                    && artifact.machine_family == machine_family
                    && artifact.guest_profile == guest_profile
                    && artifact.claim_tier == capability.default_claim_tier
            })
            .collect::<Vec<_>>();
        exact_matches.sort_by(|left, right| {
            left.row_id
                .cmp(&right.row_id)
                .then(left.host_class.cmp(&right.host_class))
                .then(left.region.cmp(&right.region))
                .then(left.cell.cmp(&right.cell))
                .then(left.accelerator_backend.cmp(&right.accelerator_backend))
        });

        if exact_matches.is_empty() {
            return Err(PlatformError::conflict(format!(
                "image compatibility artifacts do not publish backend `{}` for host_class `{}` in scope `global/global` with machine_family `{}` guest_profile `{}` and claim_tier `{}`",
                selected_backend.as_str(),
                capability.host_class,
                machine_family,
                guest_profile,
                capability.default_claim_tier,
            )));
        }
        if exact_matches.len() > 1 {
            let row_ids = exact_matches
                .iter()
                .map(|artifact| artifact.row_id.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(PlatformError::conflict(format!(
                "multiple scoped image compatibility artifacts matched runtime registration: {row_ids}"
            )));
        }

        let artifact = exact_matches.pop().ok_or_else(|| {
            PlatformError::conflict("failed to select scoped image compatibility artifact")
        })?;
        if !artifact.policy_approved {
            return Err(PlatformError::conflict(format!(
                "image compatibility artifact `{}` is not policy-approved for host_class `{}`",
                artifact.row_id, artifact.host_class,
            )));
        }
        if require_secure_boot && !artifact.secure_boot_supported {
            return Err(PlatformError::conflict(format!(
                "image compatibility artifact `{}` does not allow secure boot on host_class `{}`",
                artifact.row_id, artifact.host_class,
            )));
        }
        if requires_live_migration && !artifact.live_migration_supported {
            return Err(PlatformError::conflict(format!(
                "image compatibility artifact `{}` does not allow live migration on host_class `{}`",
                artifact.row_id, artifact.host_class,
            )));
        }
        Ok(Some(artifact))
    }

    async fn resolve_verified_local_firmware_artifact_uri(
        &self,
        firmware_profile: &str,
    ) -> Result<Option<String>> {
        let bundles_path = self
            .platform_state_root()
            .join("uvm-image/firmware_bundles.json");
        let Some(collection) = self
            .read_optional_collection::<UvmFirmwareBundleArtifactRecord>(&bundles_path)
            .await?
        else {
            return Ok(None);
        };

        let mut matches = collection
            .records
            .into_values()
            .filter_map(|stored| {
                if stored.deleted
                    || !stored.value.verified
                    || stored.value.firmware_profile != firmware_profile
                {
                    return None;
                }
                Some(stored.value.artifact_uri)
            })
            .map(|value| normalize_local_file_artifact_uri(&value, "firmware_artifact"))
            .collect::<Result<Vec<_>>>()?;
        matches.sort_unstable();
        matches.dedup();
        Ok(matches.into_iter().next())
    }

    async fn resolve_preserved_local_firmware_artifact_uri(
        &self,
        launch_spec: &LaunchSpec,
    ) -> Result<Option<String>> {
        if let Some(firmware_artifact) = launch_spec.firmware_artifact.as_deref() {
            return Ok(Some(normalize_local_file_artifact_uri(
                firmware_artifact,
                "firmware_artifact",
            )?));
        }
        self.resolve_verified_local_firmware_artifact_uri(&launch_spec.firmware_profile)
            .await
    }

    fn parse_scoped_image_compatibility_artifact(
        row: &UvmCompatibilityEvidence,
    ) -> Result<Option<ScopedImageCompatibilityArtifact>> {
        if row.source != UvmCompatibilityEvidenceSource::ImageContract
            || !row.summary.starts_with("compatibility_artifact ")
        {
            return Ok(None);
        }
        let parse_bool = |field: &str| -> Result<bool> {
            image_compatibility_artifact_value(&row.summary, field)
                .ok_or_else(|| {
                    PlatformError::invalid(format!(
                        "scoped image compatibility artifact is missing `{field}`"
                    ))
                })?
                .parse::<bool>()
                .map_err(|error| {
                    PlatformError::invalid(format!(
                        "scoped image compatibility artifact `{field}` is invalid"
                    ))
                    .with_detail(error.to_string())
                })
        };
        Ok(Some(ScopedImageCompatibilityArtifact {
            row_id: image_compatibility_artifact_value(&row.summary, "row_id")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `row_id`",
                    )
                })?
                .to_owned(),
            host_class: image_compatibility_artifact_value(&row.summary, "host_class")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `host_class`",
                    )
                })?
                .to_owned(),
            region: image_compatibility_artifact_value(&row.summary, "region")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `region`",
                    )
                })?
                .to_owned(),
            cell: image_compatibility_artifact_value(&row.summary, "cell")
                .ok_or_else(|| {
                    PlatformError::invalid("scoped image compatibility artifact is missing `cell`")
                })?
                .to_owned(),
            accelerator_backend: image_compatibility_artifact_value(
                &row.summary,
                "accelerator_backend",
            )
            .ok_or_else(|| {
                PlatformError::invalid(
                    "scoped image compatibility artifact is missing `accelerator_backend`",
                )
            })?
            .to_owned(),
            machine_family: image_compatibility_artifact_value(&row.summary, "machine_family")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `machine_family`",
                    )
                })?
                .to_owned(),
            guest_profile: image_compatibility_artifact_value(&row.summary, "guest_profile")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `guest_profile`",
                    )
                })?
                .to_owned(),
            claim_tier: image_compatibility_artifact_value(&row.summary, "claim_tier")
                .ok_or_else(|| {
                    PlatformError::invalid(
                        "scoped image compatibility artifact is missing `claim_tier`",
                    )
                })?
                .to_owned(),
            secure_boot_supported: parse_bool("secure_boot_supported")?,
            live_migration_supported: parse_bool("live_migration_supported")?,
            policy_approved: parse_bool("policy_approved")?,
        }))
    }

    async fn create_node_operation_record(
        &self,
        request: NodeOperationCreateRequest,
    ) -> Result<UvmNodeOperationRecord> {
        let operation_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate node operation id")
                .with_detail(error.to_string())
        })?;
        let created_at = OffsetDateTime::now_utc();
        let NodeOperationCreateRequest {
            kind,
            state,
            node_id,
            target_node_id,
            runtime_session_id,
            instance_id,
            reason,
            detail,
            phase,
            from_state,
            to_state,
            checkpoint_id,
            linked_resource_kind,
            linked_resource_id,
        } = request;
        let record = UvmNodeOperationRecord {
            id: operation_id.clone(),
            kind,
            state,
            node_id,
            target_node_id,
            runtime_session_id,
            instance_id,
            reason,
            detail,
            phase,
            from_state: from_state.map(|value| String::from(value.as_str())),
            to_state: to_state.map(|value| String::from(value.as_str())),
            checkpoint_id,
            linked_resource_kind,
            linked_resource_id,
            created_at,
            updated_at: created_at,
            completed_at: (state != UvmNodeOperationState::InProgress).then_some(created_at),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(operation_id.to_string()),
                sha256_hex(operation_id.as_str().as_bytes()),
            ),
        };
        self.node_operations
            .create(record.id.as_str(), record.clone())
            .await?;
        Ok(record)
    }

    async fn find_in_progress_node_operation_for_runtime(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
        kind: UvmNodeOperationKind,
    ) -> Result<Option<StoredDocument<UvmNodeOperationRecord>>> {
        let mut selected: Option<StoredDocument<UvmNodeOperationRecord>> = None;
        for (_, stored) in self.node_operations.list().await? {
            if stored.deleted
                || stored.value.kind != kind
                || stored.value.runtime_session_id.as_ref() != Some(runtime_session_id)
                || stored.value.state != UvmNodeOperationState::InProgress
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| current.value.updated_at >= stored.value.updated_at)
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn find_node_operation_for_linked_resource(
        &self,
        kind: UvmNodeOperationKind,
        linked_resource_kind: &str,
        linked_resource_id: &str,
    ) -> Result<Option<StoredDocument<UvmNodeOperationRecord>>> {
        let mut selected: Option<StoredDocument<UvmNodeOperationRecord>> = None;
        for (_, stored) in self.node_operations.list().await? {
            if stored.deleted
                || stored.value.kind != kind
                || stored.value.linked_resource_kind.as_deref() != Some(linked_resource_kind)
                || stored.value.linked_resource_id.as_deref() != Some(linked_resource_id)
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| current.value.updated_at >= stored.value.updated_at)
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn update_node_operation_record(
        &self,
        stored: StoredDocument<UvmNodeOperationRecord>,
        state: Option<UvmNodeOperationState>,
        detail: Option<String>,
        phase: Option<String>,
        to_state: Option<VmRuntimeState>,
        target_node_id: Option<NodeId>,
    ) -> Result<UvmNodeOperationRecord> {
        let mut record = stored.value;
        let now = time::OffsetDateTime::now_utc();
        if let Some(state) = state {
            record.state = state;
            record.completed_at = if state == UvmNodeOperationState::InProgress {
                None
            } else {
                Some(now)
            };
        }
        if detail.is_some() {
            record.detail = detail;
        }
        if phase.is_some() {
            record.phase = phase;
        }
        if let Some(to_state) = to_state {
            record.to_state = Some(String::from(to_state.as_str()));
        }
        if let Some(target_node_id) = target_node_id {
            record.target_node_id = Some(target_node_id);
        }
        record.updated_at = now;
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.node_operations
            .upsert(record.id.as_str(), record.clone(), Some(stored.version))
            .await?;
        Ok(record)
    }

    async fn relink_runtime_migration_node_operation_if_needed(
        &self,
        stored: StoredDocument<UvmNodeOperationRecord>,
        migration: &UvmRuntimeMigrationRecord,
    ) -> Result<StoredDocument<UvmNodeOperationRecord>> {
        if stored.value.linked_resource_kind.as_deref() == Some("runtime_migration")
            && stored.value.linked_resource_id.as_deref() == Some(migration.id.as_str())
        {
            return Ok(stored);
        }
        if !runtime_migration_node_operation_needs_link_backfill(&stored.value) {
            return Ok(stored);
        }

        let mut record = stored.value;
        record.linked_resource_kind = Some(String::from("runtime_migration"));
        record.linked_resource_id = Some(migration.id.to_string());
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        let record_id = record.id.to_string();
        let stored = self
            .node_operations
            .upsert(record_id.as_str(), record, Some(stored.version))
            .await?;
        Ok(stored)
    }

    async fn find_restore_node_operation_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint_id: &UvmCheckpointId,
        replay_key: &str,
    ) -> Result<Option<StoredDocument<UvmNodeOperationRecord>>> {
        if let Some(stored) = self
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Restore,
                "runtime_restore",
                replay_key,
            )
            .await?
        {
            return Ok(Some(stored));
        }

        let mut selected: Option<StoredDocument<UvmNodeOperationRecord>> = None;
        for (_, stored) in self.node_operations.list().await? {
            if stored.deleted
                || !restore_node_operation_matches_replay_candidate(
                    &stored.value,
                    runtime,
                    checkpoint_id,
                )
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| {
                    current.value.created_at > stored.value.created_at
                        || (current.value.created_at == stored.value.created_at
                            && current.value.updated_at >= stored.value.updated_at)
                })
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn find_restore_outbox_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint_id: &UvmCheckpointId,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let mut selected = None;
        for message in self.outbox.list_all().await? {
            if restore_event_matches_replay_candidate(
                &message.payload,
                runtime,
                checkpoint_id,
                replay_key,
            ) {
                selected = Some(message.payload);
            }
        }
        Ok(selected)
    }

    async fn find_restore_audit_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint_id: &UvmCheckpointId,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let audit_path = self.state_root.join("audit.log");
        let payload = match fs::read(&audit_path).await {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to read uvm-node audit log")
                        .with_detail(error.to_string()),
                );
            }
        };

        let mut selected = None;
        for line in payload.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_slice::<PlatformEvent>(line).map_err(|error| {
                PlatformError::unavailable("failed to decode uvm-node audit log record")
                    .with_detail(error.to_string())
            })?;
            if restore_event_matches_replay_candidate(&event, runtime, checkpoint_id, replay_key) {
                selected = Some(event);
            }
        }
        Ok(selected)
    }

    async fn reconcile_restore_replay_side_effects(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint: &UvmRuntimeCheckpointRecord,
        context: &RequestContext,
    ) -> Result<()> {
        let replay_key = restore_replay_key(runtime, &checkpoint.id)?;
        let incarnation = restore_runtime_incarnation(runtime, &checkpoint.id)?;

        if self
            .find_restore_node_operation_for_replay(runtime, &checkpoint.id, &replay_key)
            .await?
            .is_none()
        {
            let _ = self
                .create_node_operation_record(NodeOperationCreateRequest {
                    runtime_session_id: Some(runtime.id.clone()),
                    instance_id: Some(runtime.instance_id.clone()),
                    reason: incarnation.reason.clone(),
                    from_state: incarnation.previous_state,
                    to_state: Some(runtime.state),
                    checkpoint_id: Some(checkpoint.id.clone()),
                    linked_resource_kind: Some(String::from("runtime_restore")),
                    linked_resource_id: Some(replay_key.clone()),
                    ..NodeOperationCreateRequest::new(
                        UvmNodeOperationKind::Restore,
                        UvmNodeOperationState::Completed,
                        runtime.node_id.clone(),
                    )
                })
                .await?;
        }

        let existing_outbox = self
            .find_restore_outbox_event_for_replay(runtime, &checkpoint.id, &replay_key)
            .await?;
        let existing_audit = self
            .find_restore_audit_event_for_replay(runtime, &checkpoint.id, &replay_key)
            .await?;
        let event = match (existing_audit.clone(), existing_outbox.clone()) {
            (Some(event), _) | (None, Some(event)) => event,
            (None, None) => build_service_platform_event(
                "uvm.node.runtime.restored.v1",
                "uvm_runtime_session",
                runtime.id.as_str(),
                "restore",
                restore_event_details(runtime, &checkpoint.id, &replay_key)?,
                context,
            )?,
        };

        if existing_audit.is_none() {
            self.audit_log.append(&event).await?;
        }
        if existing_outbox.is_none() {
            let _ = self
                .outbox
                .enqueue(
                    "uvm.node.runtime.restored.v1",
                    event,
                    Some(replay_key.as_str()),
                )
                .await?;
        }
        Ok(())
    }

    async fn find_migration_cutover_node_operation_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
    ) -> Result<Option<StoredDocument<UvmNodeOperationRecord>>> {
        if let Some(stored) = self
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration.id.as_str(),
            )
            .await?
        {
            return Ok(Some(stored));
        }

        let mut selected: Option<StoredDocument<UvmNodeOperationRecord>> = None;
        for (_, stored) in self.node_operations.list().await? {
            if stored.deleted
                || !migration_cutover_node_operation_matches_replay_candidate(
                    &stored.value,
                    runtime,
                    migration,
                )
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| {
                    current.value.created_at > stored.value.created_at
                        || (current.value.created_at == stored.value.created_at
                            && current.value.updated_at >= stored.value.updated_at)
                })
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn find_migration_cutover_outbox_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let mut selected = None;
        for message in self.outbox.list_all().await? {
            if migration_cutover_event_matches_replay_candidate(
                &message.payload,
                runtime,
                migration,
                replay_key,
            ) {
                selected = Some(message.payload);
            }
        }
        Ok(selected)
    }

    async fn find_migration_cutover_audit_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let audit_path = self.state_root.join("audit.log");
        let payload = match fs::read(&audit_path).await {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to read uvm-node audit log")
                        .with_detail(error.to_string()),
                );
            }
        };

        let mut selected = None;
        for line in payload.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_slice::<PlatformEvent>(line).map_err(|error| {
                PlatformError::unavailable("failed to decode uvm-node audit log record")
                    .with_detail(error.to_string())
            })?;
            if migration_cutover_event_matches_replay_candidate(
                &event, runtime, migration, replay_key,
            ) {
                selected = Some(event);
            }
        }
        Ok(selected)
    }

    async fn reconcile_migration_cutover_replay_side_effects(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        context: &RequestContext,
    ) -> Result<()> {
        let replay_key = migration_cutover_replay_key(runtime, migration)?;
        let incarnation = migration_cutover_incarnation(runtime, migration)?;

        if let Some(existing) = self
            .find_migration_cutover_node_operation_for_replay(runtime, migration)
            .await?
        {
            if existing.value.state != UvmNodeOperationState::Completed
                || existing.value.phase.as_deref() != Some("committed")
                || existing.value.to_state.as_deref() != Some(runtime.state.as_str())
                || existing.value.target_node_id.as_ref() != Some(&migration.target_node_id)
            {
                let _ = self
                    .update_node_operation_record(
                        existing,
                        Some(UvmNodeOperationState::Completed),
                        None,
                        Some(String::from("committed")),
                        Some(runtime.state),
                        Some(migration.target_node_id.clone()),
                    )
                    .await?;
            }
        } else {
            let _ = self
                .create_node_operation_record(NodeOperationCreateRequest {
                    target_node_id: Some(migration.target_node_id.clone()),
                    runtime_session_id: Some(runtime.id.clone()),
                    instance_id: Some(runtime.instance_id.clone()),
                    reason: incarnation.reason.clone(),
                    phase: Some(String::from("committed")),
                    from_state: incarnation.previous_state,
                    to_state: Some(runtime.state),
                    checkpoint_id: Some(migration.checkpoint_id.clone()),
                    linked_resource_kind: Some(String::from("runtime_migration")),
                    linked_resource_id: Some(migration.id.to_string()),
                    ..NodeOperationCreateRequest::new(
                        UvmNodeOperationKind::Migrate,
                        UvmNodeOperationState::Completed,
                        migration.source_node_id.clone(),
                    )
                })
                .await?;
        }

        let existing_outbox = self
            .find_migration_cutover_outbox_event_for_replay(runtime, migration, &replay_key)
            .await?;
        let existing_audit = self
            .find_migration_cutover_audit_event_for_replay(runtime, migration, &replay_key)
            .await?;
        let event = match (existing_audit.clone(), existing_outbox.clone()) {
            (Some(event), _) | (None, Some(event)) => event,
            (None, None) => build_service_platform_event(
                "uvm.migration.committed.v1",
                "uvm_runtime_migration",
                migration.id.as_str(),
                "commit",
                migration_cutover_event_details(runtime, migration, &replay_key)?,
                context,
            )?,
        };

        if existing_audit.is_none() {
            self.audit_log.append(&event).await?;
        }
        if existing_outbox.is_none() {
            let _ = self
                .outbox
                .enqueue(
                    "uvm.migration.committed.v1",
                    event,
                    Some(replay_key.as_str()),
                )
                .await?;
        }
        Ok(())
    }

    async fn find_migration_terminal_node_operation_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
    ) -> Result<Option<StoredDocument<UvmNodeOperationRecord>>> {
        if let Some(stored) = self
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration.id.as_str(),
            )
            .await?
        {
            return Ok(Some(stored));
        }

        let mut selected: Option<StoredDocument<UvmNodeOperationRecord>> = None;
        for (_, stored) in self.node_operations.list().await? {
            if stored.deleted
                || !migration_terminal_node_operation_matches_replay_candidate(
                    &stored.value,
                    runtime,
                    migration,
                    action,
                )
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| {
                    current.value.created_at > stored.value.created_at
                        || (current.value.created_at == stored.value.created_at
                            && current.value.updated_at >= stored.value.updated_at)
                })
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        let Some(selected) = selected else {
            return Ok(None);
        };
        let selected = self
            .relink_runtime_migration_node_operation_if_needed(selected, migration)
            .await?;
        Ok(Some(selected))
    }

    async fn find_migration_terminal_outbox_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let mut selected = None;
        for message in self.outbox.list_all().await? {
            if migration_terminal_event_matches_replay_candidate(
                &message.payload,
                runtime,
                migration,
                action,
                replay_key,
            ) {
                selected = Some(message.payload);
            }
        }
        Ok(selected)
    }

    async fn find_migration_terminal_audit_event_for_replay(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
        replay_key: &str,
    ) -> Result<Option<PlatformEvent>> {
        let audit_path = self.state_root.join("audit.log");
        let payload = match fs::read(&audit_path).await {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to read uvm-node audit log")
                        .with_detail(error.to_string()),
                );
            }
        };

        let mut selected = None;
        for line in payload.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_slice::<PlatformEvent>(line).map_err(|error| {
                PlatformError::unavailable("failed to decode uvm-node audit log record")
                    .with_detail(error.to_string())
            })?;
            if migration_terminal_event_matches_replay_candidate(
                &event, runtime, migration, action, replay_key,
            ) {
                selected = Some(event);
            }
        }
        Ok(selected)
    }

    async fn reconcile_migration_terminal_replay_side_effects(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
        context: &RequestContext,
    ) -> Result<()> {
        let replay_key = migration_terminal_replay_key(runtime, migration, action)?;
        let event_type = migration_terminal_event_type(action).ok_or_else(|| {
            PlatformError::invalid("unsupported runtime migration terminal replay action")
        })?;
        let operation_state = match action {
            "rollback" => UvmNodeOperationState::RolledBack,
            "fail" => UvmNodeOperationState::Failed,
            _ => {
                return Err(PlatformError::invalid(
                    "unsupported runtime migration terminal replay action",
                ));
            }
        };
        let terminal_state = terminal_migration_state(action);

        if let Some(existing) = self
            .find_migration_terminal_node_operation_for_replay(runtime, migration, action)
            .await?
        {
            if existing.value.state != operation_state
                || existing.value.phase.as_deref() != Some(terminal_state)
                || existing.value.detail != migration.failure_detail
                || existing.value.to_state.as_deref() != Some(runtime.state.as_str())
                || existing.value.target_node_id.as_ref() != Some(&migration.target_node_id)
            {
                let _ = self
                    .update_node_operation_record(
                        existing,
                        Some(operation_state),
                        migration.failure_detail.clone(),
                        Some(String::from(terminal_state)),
                        Some(runtime.state),
                        Some(migration.target_node_id.clone()),
                    )
                    .await?;
            }
        } else {
            let _ = self
                .create_node_operation_record(NodeOperationCreateRequest {
                    target_node_id: Some(migration.target_node_id.clone()),
                    runtime_session_id: Some(runtime.id.clone()),
                    instance_id: Some(runtime.instance_id.clone()),
                    reason: Some(migration.reason.clone()),
                    detail: migration.failure_detail.clone(),
                    phase: Some(String::from(terminal_state)),
                    from_state: Some(runtime.state),
                    to_state: Some(runtime.state),
                    checkpoint_id: Some(migration.checkpoint_id.clone()),
                    linked_resource_kind: Some(String::from("runtime_migration")),
                    linked_resource_id: Some(migration.id.to_string()),
                    ..NodeOperationCreateRequest::new(
                        UvmNodeOperationKind::Migrate,
                        operation_state,
                        migration.source_node_id.clone(),
                    )
                })
                .await?;
        }

        let existing_outbox = self
            .find_migration_terminal_outbox_event_for_replay(
                runtime,
                migration,
                action,
                &replay_key,
            )
            .await?;
        let existing_audit = self
            .find_migration_terminal_audit_event_for_replay(runtime, migration, action, &replay_key)
            .await?;
        let event = match (existing_audit.clone(), existing_outbox.clone()) {
            (Some(event), _) | (None, Some(event)) => event,
            (None, None) => build_service_platform_event(
                event_type,
                "uvm_runtime_migration",
                migration.id.as_str(),
                action,
                migration_terminal_event_details(runtime, migration, action, &replay_key)?,
                context,
            )?,
        };

        if existing_audit.is_none() {
            self.audit_log.append(&event).await?;
        }
        if existing_outbox.is_none() {
            let _ = self
                .outbox
                .enqueue(event_type, event, Some(replay_key.as_str()))
                .await?;
        }
        Ok(())
    }

    async fn record_runtime_transition_operation(
        &self,
        record: &UvmRuntimeSessionRecord,
        previous_state: VmRuntimeState,
        action: VmRuntimeAction,
        operation_detail: Option<&str>,
    ) -> Result<()> {
        match action {
            VmRuntimeAction::Start => {
                let _ = self
                    .create_node_operation_record(NodeOperationCreateRequest {
                        runtime_session_id: Some(record.id.clone()),
                        instance_id: Some(record.instance_id.clone()),
                        from_state: Some(previous_state),
                        to_state: Some(record.state),
                        ..NodeOperationCreateRequest::new(
                            UvmNodeOperationKind::Start,
                            UvmNodeOperationState::Completed,
                            record.node_id.clone(),
                        )
                    })
                    .await?;
            }
            VmRuntimeAction::Stop => {
                let _ = self
                    .create_node_operation_record(NodeOperationCreateRequest {
                        runtime_session_id: Some(record.id.clone()),
                        instance_id: Some(record.instance_id.clone()),
                        from_state: Some(previous_state),
                        to_state: Some(record.state),
                        ..NodeOperationCreateRequest::new(
                            UvmNodeOperationKind::Stop,
                            UvmNodeOperationState::Completed,
                            record.node_id.clone(),
                        )
                    })
                    .await?;
            }
            VmRuntimeAction::BeginRecover => {
                let _ = self
                    .create_node_operation_record(NodeOperationCreateRequest {
                        runtime_session_id: Some(record.id.clone()),
                        instance_id: Some(record.instance_id.clone()),
                        reason: operation_detail.map(str::to_owned),
                        phase: Some(String::from("begin")),
                        from_state: Some(previous_state),
                        to_state: Some(record.state),
                        ..NodeOperationCreateRequest::new(
                            UvmNodeOperationKind::Recover,
                            UvmNodeOperationState::InProgress,
                            record.node_id.clone(),
                        )
                    })
                    .await?;
            }
            VmRuntimeAction::CompleteRecover => {
                if let Some(existing) = self
                    .find_in_progress_node_operation_for_runtime(
                        &record.id,
                        UvmNodeOperationKind::Recover,
                    )
                    .await?
                {
                    let _ = self
                        .update_node_operation_record(
                            existing,
                            Some(UvmNodeOperationState::Completed),
                            None,
                            Some(String::from("completed")),
                            Some(record.state),
                            None,
                        )
                        .await?;
                } else {
                    let _ = self
                        .create_node_operation_record(NodeOperationCreateRequest {
                            runtime_session_id: Some(record.id.clone()),
                            instance_id: Some(record.instance_id.clone()),
                            phase: Some(String::from("completed")),
                            from_state: Some(previous_state),
                            to_state: Some(record.state),
                            ..NodeOperationCreateRequest::new(
                                UvmNodeOperationKind::Recover,
                                UvmNodeOperationState::Completed,
                                record.node_id.clone(),
                            )
                        })
                        .await?;
                }
            }
            VmRuntimeAction::Prepare | VmRuntimeAction::Fail => {}
        }
        Ok(())
    }

    async fn capture_node_drain_runtime_snapshot(
        &self,
        node_id: &NodeId,
    ) -> Result<NodeDrainRuntimeSnapshot> {
        let mut runtime_session_ids = Vec::new();
        let mut active_runtime_session_ids = Vec::new();
        let mut inactive_runtime_session_ids = Vec::new();
        let mut migrating_runtime_session_ids = Vec::new();

        for (_, stored) in self.runtime_sessions.list().await? {
            if stored.deleted || stored.value.node_id != *node_id {
                continue;
            }
            let runtime_session_id = stored.value.id.clone();
            runtime_session_ids.push(runtime_session_id.clone());
            if runtime_state_blocks_drain_completion(stored.value.state) {
                active_runtime_session_ids.push(runtime_session_id.clone());
            } else {
                inactive_runtime_session_ids.push(runtime_session_id.clone());
            }
            if stored.value.migration_in_progress {
                migrating_runtime_session_ids.push(runtime_session_id);
            }
        }

        sort_runtime_session_ids(&mut runtime_session_ids);
        sort_runtime_session_ids(&mut active_runtime_session_ids);
        sort_runtime_session_ids(&mut inactive_runtime_session_ids);
        sort_runtime_session_ids(&mut migrating_runtime_session_ids);

        Ok(NodeDrainRuntimeSnapshot {
            runtime_session_ids,
            active_runtime_session_ids,
            inactive_runtime_session_ids,
            migrating_runtime_session_ids,
            snapshot_at: OffsetDateTime::now_utc(),
        })
    }

    async fn materialize_node_drain_record(
        &self,
        record: &UvmNodeDrainOperationRecord,
    ) -> Result<UvmNodeDrainOperationRecord> {
        if !node_drain_state_requires_live_snapshot(record.state.as_str()) {
            return Ok(record.clone());
        }

        let snapshot = self
            .capture_node_drain_runtime_snapshot(&record.node_id)
            .await?;
        let mut materialized = record.clone();
        materialized.tracked_runtime_session_ids = merge_runtime_session_ids(
            &record.tracked_runtime_session_ids,
            &snapshot.runtime_session_ids,
        );
        materialized.active_runtime_session_ids = snapshot.active_runtime_session_ids;
        materialized.inactive_runtime_session_ids = snapshot.inactive_runtime_session_ids;
        materialized.migrating_runtime_session_ids = snapshot.migrating_runtime_session_ids;
        materialized.snapshot_at = snapshot.snapshot_at;
        Ok(materialized)
    }

    async fn find_active_node_drain(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<StoredDocument<UvmNodeDrainOperationRecord>>> {
        let mut selected: Option<StoredDocument<UvmNodeDrainOperationRecord>> = None;
        for (_, stored) in self.node_drains.list().await? {
            if stored.deleted
                || stored.value.node_id != *node_id
                || !node_drain_state_blocks_new_runtime_work(stored.value.state.as_str())
            {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| current.value.updated_at >= stored.value.updated_at)
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn ensure_node_accepts_new_runtime_work(&self, node_id: &NodeId) -> Result<()> {
        if let Some(active) = self.find_active_node_drain(node_id).await? {
            return Err(PlatformError::conflict(format!(
                "node {} is under drain operation {} in state `{}` and is not accepting new runtime work",
                node_id.as_str(),
                active.value.id.as_str(),
                active.value.state,
            )));
        }
        Ok(())
    }

    async fn create_node_drain(
        &self,
        request: CreateNodeDrainRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let reason = normalize_reason(&request.reason)?;
        if let Some(active) = self.find_active_node_drain(&node_id).await? {
            return Err(PlatformError::conflict(format!(
                "node drain {} is already active for node {} in state `{}`",
                active.value.id.as_str(),
                node_id.as_str(),
                active.value.state,
            )));
        }
        let snapshot = self.capture_node_drain_runtime_snapshot(&node_id).await?;
        let drain_id = UvmNodeDrainId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate node drain id")
                .with_detail(error.to_string())
        })?;
        let now = time::OffsetDateTime::now_utc();
        let record = UvmNodeDrainOperationRecord {
            id: drain_id.clone(),
            node_id: node_id.clone(),
            state: String::from("quiesce"),
            reason,
            failure_detail: None,
            tracked_runtime_session_ids: snapshot.runtime_session_ids.clone(),
            active_runtime_session_ids: snapshot.active_runtime_session_ids,
            inactive_runtime_session_ids: snapshot.inactive_runtime_session_ids,
            migrating_runtime_session_ids: snapshot.migrating_runtime_session_ids,
            snapshot_at: snapshot.snapshot_at,
            created_at: now,
            updated_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(drain_id.to_string()),
                sha256_hex(drain_id.as_str().as_bytes()),
            ),
        };
        self.node_drains
            .create(drain_id.as_str(), record.clone())
            .await?;
        let _ = self
            .create_node_operation_record(NodeOperationCreateRequest {
                reason: Some(record.reason.clone()),
                phase: Some(record.state.clone()),
                linked_resource_kind: Some(String::from("node_drain")),
                linked_resource_id: Some(record.id.to_string()),
                ..NodeOperationCreateRequest::new(
                    UvmNodeOperationKind::Drain,
                    UvmNodeOperationState::InProgress,
                    record.node_id.clone(),
                )
            })
            .await?;
        self.append_event(
            "uvm.node.drain.quiesced.v1",
            "uvm_node_drain",
            drain_id.as_str(),
            "quiesce",
            serde_json::json!({
                "node_id": node_id,
                "tracked_runtime_session_ids": record.tracked_runtime_session_ids,
                "active_runtime_session_ids": record.active_runtime_session_ids,
                "migrating_runtime_session_ids": record.migrating_runtime_session_ids,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn transition_node_drain(
        &self,
        drain_id: &str,
        action: &str,
        failure_detail: Option<String>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let drain_id = UvmNodeDrainId::parse(drain_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid node drain id").with_detail(error.to_string())
        })?;
        let stored = self
            .node_drains
            .get(drain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node drain does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("node drain does not exist"));
        }
        let mut record = stored.value;
        let snapshot = self
            .capture_node_drain_runtime_snapshot(&record.node_id)
            .await?;
        record.tracked_runtime_session_ids = merge_runtime_session_ids(
            &record.tracked_runtime_session_ids,
            &snapshot.runtime_session_ids,
        );
        record.active_runtime_session_ids = snapshot.active_runtime_session_ids;
        record.inactive_runtime_session_ids = snapshot.inactive_runtime_session_ids;
        record.migrating_runtime_session_ids = snapshot.migrating_runtime_session_ids;
        record.snapshot_at = snapshot.snapshot_at;

        match action {
            "evacuate" => {
                if matches!(record.state.as_str(), "completed" | "failed") {
                    return Err(PlatformError::conflict(
                        "node drain cannot evacuate after reaching a terminal state",
                    ));
                }
                record.state = String::from("evacuate");
                record.failure_detail = None;
            }
            "complete" => {
                if record.state == "completed" {
                    let materialized = self.materialize_node_drain_record(&record).await?;
                    return json_response(StatusCode::OK, &materialized);
                }
                if record.state == "failed" {
                    return Err(PlatformError::conflict(
                        "node drain cannot complete after failure",
                    ));
                }
                if !record.active_runtime_session_ids.is_empty() {
                    return Err(PlatformError::conflict(format!(
                        "node drain cannot complete while active runtime sessions remain on node: {}",
                        format_runtime_session_id_list(&record.active_runtime_session_ids)
                    )));
                }
                record.state = String::from("completed");
                record.failure_detail = None;
            }
            "fail" => {
                if record.state == "completed" {
                    return Err(PlatformError::conflict(
                        "node drain cannot fail after completion",
                    ));
                }
                if record.state == "failed" {
                    return json_response(StatusCode::OK, &record);
                }
                record.state = String::from("failed");
                record.failure_detail = normalize_optional_failure_detail(failure_detail)?
                    .or_else(|| Some(String::from("node drain failed without detail")));
            }
            _ => {
                return Err(PlatformError::invalid(
                    "unknown node drain transition action",
                ));
            }
        }

        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        self.node_drains
            .upsert(record.id.as_str(), record.clone(), Some(stored.version))
            .await?;
        let materialized = self.materialize_node_drain_record(&record).await?;
        let operation_state = match action {
            "evacuate" => UvmNodeOperationState::InProgress,
            "complete" => UvmNodeOperationState::Completed,
            "fail" => UvmNodeOperationState::Failed,
            _ => {
                return Err(PlatformError::invalid(
                    "unknown node drain transition action",
                ));
            }
        };
        if let Some(existing) = self
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Drain,
                "node_drain",
                record.id.as_str(),
            )
            .await?
        {
            let _ = self
                .update_node_operation_record(
                    existing,
                    Some(operation_state),
                    materialized.failure_detail.clone(),
                    Some(materialized.state.clone()),
                    None,
                    None,
                )
                .await?;
        } else {
            let _ = self
                .create_node_operation_record(NodeOperationCreateRequest {
                    reason: Some(materialized.reason.clone()),
                    detail: materialized.failure_detail.clone(),
                    phase: Some(materialized.state.clone()),
                    linked_resource_kind: Some(String::from("node_drain")),
                    linked_resource_id: Some(materialized.id.to_string()),
                    ..NodeOperationCreateRequest::new(
                        UvmNodeOperationKind::Drain,
                        operation_state,
                        materialized.node_id.clone(),
                    )
                })
                .await?;
        }
        self.append_event(
            match action {
                "evacuate" => "uvm.node.drain.evacuating.v1",
                "complete" => "uvm.node.drain.completed.v1",
                "fail" => "uvm.node.drain.failed.v1",
                _ => "uvm.node.drain.unknown.v1",
            },
            "uvm_node_drain",
            record.id.as_str(),
            action,
            serde_json::json!({
                "node_id": record.node_id,
                "state": materialized.state,
                "tracked_runtime_session_ids": materialized.tracked_runtime_session_ids,
                "active_runtime_session_ids": materialized.active_runtime_session_ids,
                "inactive_runtime_session_ids": materialized.inactive_runtime_session_ids,
                "migrating_runtime_session_ids": materialized.migrating_runtime_session_ids,
                "failure_detail": materialized.failure_detail,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &materialized)
    }

    async fn create_node_capability(
        &self,
        request: CreateNodeCapabilityRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let host_platform = request
            .host_platform
            .as_deref()
            .map(HostPlatform::parse)
            .transpose()
            .map_err(|error| {
                PlatformError::invalid("invalid host_platform").with_detail(error.to_string())
            })?
            .unwrap_or_else(HostPlatform::current);
        let architecture = normalize_architecture(&request.architecture)?;
        if request.accelerator_backends.is_empty() {
            return Err(PlatformError::invalid(
                "accelerator_backends may not be empty",
            ));
        }
        let mut accelerator_backends = request
            .accelerator_backends
            .into_iter()
            .map(|backend| normalize_backend(&backend))
            .collect::<Result<Vec<_>>>()?;
        accelerator_backends.dedup();
        let guest_architecture = GuestArchitecture::parse(&architecture)?;
        let supported_machine_families =
            supported_machine_families_for_capability(&architecture, &accelerator_backends);
        let supported_guest_profiles = supported_guest_profiles_for_capability(
            host_platform,
            &architecture,
            &accelerator_backends,
        );
        let container_restricted = request.container_restricted.unwrap_or(false);
        let software_runner_supported = request.software_runner_supported.unwrap_or(
            accelerator_backends
                .iter()
                .any(|backend| backend == HypervisorBackend::SoftwareDbt.as_str()),
        );
        let host_evidence_mode =
            normalize_host_evidence_mode(request.host_evidence_mode.as_deref().unwrap_or(
                if container_restricted {
                    "container_restricted"
                } else {
                    "direct_host"
                },
            ))?;
        let host_class =
            derive_node_host_class(host_platform, &host_evidence_mode, container_restricted);
        for backend_key in &accelerator_backends {
            let backend = HypervisorBackend::parse(backend_key)?;
            if !backend.supported_on_host(host_platform) {
                return Err(PlatformError::conflict(format!(
                    "backend {} is not valid on host_platform {}",
                    backend.as_str(),
                    host_platform.as_str()
                )));
            }
            if !backend.supports_guest_architecture(guest_architecture) {
                return Err(PlatformError::conflict(format!(
                    "backend {} does not support guest architecture {}",
                    backend.as_str(),
                    architecture
                )));
            }
        }
        for backend in &accelerator_backends {
            let parsed = HypervisorBackend::parse(backend)?;
            if !parsed.supported_on_host(host_platform) {
                return Err(PlatformError::conflict(format!(
                    "backend {} is not compatible with declared host_platform {}",
                    parsed.as_str(),
                    host_platform.as_str(),
                )));
            }
        }

        let id = UvmNodeCapabilityId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate node capability id")
                .with_detail(error.to_string())
        })?;
        let record = UvmNodeCapabilityRecord {
            id: id.clone(),
            node_id,
            host_platform: String::from(host_platform.as_str()),
            host_class,
            architecture,
            accelerator_backends,
            supported_machine_families,
            supported_guest_profiles,
            default_claim_tier: default_claim_tier_key(),
            software_runner_supported,
            container_restricted,
            host_evidence_mode,
            max_vcpu: request.max_vcpu.max(1),
            max_memory_mb: request.max_memory_mb.max(512),
            numa_nodes: request.numa_nodes.max(1),
            supports_secure_boot: request.supports_secure_boot,
            supports_live_migration: request.supports_live_migration,
            supports_pci_passthrough: request.supports_pci_passthrough,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.capabilities
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.node.capability.created.v1",
            "uvm_node_capability",
            id.as_str(),
            "created",
            serde_json::json!({
                "node_id": record.node_id,
                "host_platform": record.host_platform,
                "host_class": record.host_class,
                "architecture": record.architecture,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_device_profile(
        &self,
        request: CreateDeviceProfileRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let profile_name = request.name.trim();
        if profile_name.is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        if profile_name.len() > 128 {
            return Err(PlatformError::invalid("name exceeds 128 bytes"));
        }

        let mut legacy_devices = request
            .legacy_devices
            .into_iter()
            .map(|value| normalize_profile(&value, "legacy device"))
            .collect::<Result<Vec<_>>>()?;
        let mut modern_devices = request
            .modern_devices
            .into_iter()
            .map(|value| normalize_profile(&value, "modern device"))
            .collect::<Result<Vec<_>>>()?;
        legacy_devices.sort_unstable();
        legacy_devices.dedup();
        modern_devices.sort_unstable();
        modern_devices.dedup();
        if legacy_devices.is_empty() && modern_devices.is_empty() {
            return Err(PlatformError::invalid(
                "device profile must define at least one device",
            ));
        }

        let id = UvmDeviceProfileId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate device profile id")
                .with_detail(error.to_string())
        })?;
        let record = UvmDeviceProfileRecord {
            id: id.clone(),
            name: profile_name.to_owned(),
            legacy_devices,
            modern_devices,
            passthrough_enabled: request.passthrough_enabled,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.device_profiles
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.node.device_profile.created.v1",
            "uvm_device_profile",
            id.as_str(),
            "created",
            serde_json::json!({
                "name": record.name,
                "passthrough_enabled": record.passthrough_enabled,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn select_adapter(
        &self,
        request: SelectAdapterRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let capability_id = UvmNodeCapabilityId::parse(request.capability_id).map_err(|error| {
            PlatformError::invalid("invalid capability_id").with_detail(error.to_string())
        })?;
        let stored = self
            .capabilities
            .get(capability_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node capability does not exist"))?;
        let record = stored.value;

        let guest_architecture = GuestArchitecture::parse(&request.guest_architecture)?;
        let guest_os_hint = if request.apple_guest {
            "macos"
        } else {
            "linux"
        };
        let guest_profile = default_guest_profile_for_guest_os(guest_os_hint);
        let machine_family = default_machine_family_for_guest(guest_architecture, guest_os_hint);
        let selection = self.select_backend_for_capability(
            &record,
            guest_architecture,
            request.apple_guest,
            request.requires_live_migration,
            request.require_secure_boot.unwrap_or(false),
        )?;

        let decision = UvmAdapterSelection {
            capability_id,
            accelerator_backend: String::from(selection.backend.as_str()),
            machine_family,
            guest_profile,
            claim_tier: record.default_claim_tier.clone(),
            reason: selection.reason,
        };
        self.append_event(
            "uvm.node.adapter.selected.v1",
            "uvm_adapter_selection",
            decision.capability_id.as_str(),
            "selected",
            serde_json::json!({
                "accelerator_backend": decision.accelerator_backend,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &decision)
    }

    async fn preflight_runtime(
        &self,
        request: RuntimePreflightRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let capability_id = UvmNodeCapabilityId::parse(request.capability_id).map_err(|error| {
            PlatformError::invalid("invalid capability_id").with_detail(error.to_string())
        })?;
        let stored = self
            .capabilities
            .get(capability_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node capability does not exist"))?;
        let capability = stored.value;

        let guest_architecture = GuestArchitecture::parse(&request.guest_architecture)?;
        let guest_os = normalize_guest_os(&request.guest_os)?;
        let cdrom_image = request
            .cdrom_image
            .as_deref()
            .map(|value| normalize_storage_reference(value, "cdrom_image"))
            .transpose()?;
        let boot_device =
            normalize_boot_device(request.boot_device.as_deref(), cdrom_image.is_some())?;
        let guest_profile = default_guest_profile_for_guest_os(&guest_os);
        let machine_family = default_machine_family_for_guest(guest_architecture, &guest_os);
        let apple_guest = is_apple_guest_os(&guest_os);
        let apple_guest_approved = request.apple_guest_approved.unwrap_or(false);
        let require_secure_boot = request.require_secure_boot.unwrap_or(false);
        let requires_live_migration = request.requires_live_migration.unwrap_or(false);
        let execution_intent = request
            .execution_intent
            .clone()
            .unwrap_or_else(|| default_execution_intent_for_guest_profile(&guest_profile));
        let derived_requirement = UvmCompatibilityRequirement::parse_keys(
            guest_architecture,
            &machine_family,
            &guest_profile,
            &boot_device,
            &capability.default_claim_tier,
        )?;
        let compatibility_requirement = request
            .compatibility_requirement
            .clone()
            .unwrap_or_else(|| derived_requirement.clone());
        let capability_compatibility = compatibility_summary_from_capability(&capability)?;
        let mut blockers = Vec::new();
        if capability.architecture != guest_architecture.as_str() {
            blockers.push(String::from(
                "host capability architecture does not match guest architecture",
            ));
        }
        if boot_device == BootDevice::Cdrom.as_str() && cdrom_image.is_none() {
            blockers.push(String::from("boot_device `cdrom` requires a cdrom_image"));
        }
        let mut compatibility_assessment = capability_compatibility.assess(
            &compatibility_requirement,
            require_secure_boot,
            requires_live_migration,
        );
        if request.compatibility_requirement.is_some() {
            let mismatches = compatibility_requirement.mismatch_blockers(&derived_requirement);
            compatibility_assessment
                .blockers
                .extend(mismatches.iter().cloned());
            compatibility_assessment.evidence.push(UvmCompatibilityEvidence {
                source: UvmCompatibilityEvidenceSource::ImageContract,
                summary: if mismatches.is_empty() {
                    String::from(
                        "provided image compatibility requirement matched the requested runtime shape",
                    )
                } else {
                    format!(
                        "provided image compatibility requirement mismatched the requested runtime shape: {}",
                        mismatches.join("; "),
                    )
                },
                evidence_mode: None,
            });
        }
        compatibility_assessment.supported = compatibility_assessment.blockers.is_empty();
        blockers.extend(compatibility_assessment.blockers.iter().cloned());
        let migration_max_downtime_ms = if request.migration_max_downtime_ms == Some(0) {
            blockers.push(String::from("migration_max_downtime_ms must be at least 1"));
            None
        } else {
            request.migration_max_downtime_ms
        };
        let migration_max_iterations = if request.migration_max_iterations == Some(0) {
            blockers.push(String::from("migration_max_iterations must be at least 1"));
            None
        } else {
            request.migration_max_iterations
        };
        let migration_bandwidth_mbps = if request.migration_bandwidth_mbps == Some(0) {
            blockers.push(String::from("migration_bandwidth_mbps must be at least 1"));
            None
        } else {
            request.migration_bandwidth_mbps
        };
        let migration_dirty_page_rate_mbps = if request.migration_dirty_page_rate_mbps == Some(0) {
            blockers.push(String::from(
                "migration_dirty_page_rate_mbps must be at least 1",
            ));
            None
        } else {
            request.migration_dirty_page_rate_mbps
        };
        let default_vcpu = capability.max_vcpu.clamp(1, 2);
        let requested_vcpu = request.vcpu.unwrap_or(default_vcpu);
        if request.vcpu == Some(0) {
            blockers.push(String::from("vcpu must be at least 1"));
        }
        if requested_vcpu > capability.max_vcpu {
            blockers.push(format!(
                "requested vcpu {} exceeds capability max_vcpu {}",
                requested_vcpu, capability.max_vcpu
            ));
        }
        let vcpu = requested_vcpu.max(1);
        let default_memory_mb = capability.max_memory_mb.clamp(256, 2_048);
        let requested_memory_mb = request.memory_mb.unwrap_or(default_memory_mb);
        if requested_memory_mb < 256 {
            blockers.push(String::from("memory_mb must be at least 256"));
        }
        if requested_memory_mb > capability.max_memory_mb {
            blockers.push(format!(
                "requested memory_mb {} exceeds capability max_memory_mb {}",
                requested_memory_mb, capability.max_memory_mb
            ));
        }
        let memory_mb = requested_memory_mb.max(256);
        let cpu_topology_profile = normalize_profile(
            request.cpu_topology.as_deref().unwrap_or("balanced"),
            "cpu_topology",
        )?;
        let numa_policy_profile = normalize_profile(
            request.numa_policy.as_deref().unwrap_or("preferred_local"),
            "numa_policy",
        )?;
        let migration_policy =
            normalize_migration_policy(request.migration_policy.as_deref().unwrap_or(
                if requires_live_migration {
                    "best_effort_live"
                } else {
                    "cold_only"
                },
            ))?;
        if apple_guest && !apple_guest_approved {
            blockers.push(String::from(
                "apple guest workloads require explicit apple_guest_approved=true",
            ));
        }

        let cpu_topology = CpuTopologySpec::from_profile(&cpu_topology_profile, vcpu)?;
        let numa_policy =
            NumaPolicySpec::from_profile(&numa_policy_profile, capability.numa_nodes)?;
        let placement = plan_placement(&PlacementRequest {
            requested_vcpu: vcpu,
            requested_memory_mb: memory_mb,
            host_max_vcpu: capability.max_vcpu.max(1),
            host_max_memory_mb: capability.max_memory_mb.max(256),
            host_numa_nodes: capability.numa_nodes.max(1),
            cpu_topology: cpu_topology.clone(),
            numa_policy: numa_policy.clone(),
        })?;
        blockers.extend(placement.blockers.clone());

        let strategy = MigrationStrategy::parse(&migration_policy)?;
        if requires_live_migration && strategy == MigrationStrategy::Cold {
            blockers.push(String::from(
                "requires_live_migration=true is incompatible with migration_policy=cold_only",
            ));
        }

        let portability_request = BackendSelectionRequest {
            host: HostPlatform::parse(&capability.host_platform).map_err(|error| {
                PlatformError::invalid("capability host_platform is invalid")
                    .with_detail(error.to_string())
            })?,
            candidates: capability
                .accelerator_backends
                .iter()
                .map(|backend| HypervisorBackend::parse(backend))
                .collect::<Result<Vec<_>>>()?,
            guest_architecture,
            apple_guest,
            requires_live_migration,
            require_secure_boot,
        };
        let mut portability_assessment = assess_execution_intent(
            &portability_request,
            Some(&execution_intent),
            Some(capability.host_evidence_mode.as_str()),
        )?;
        if portability_assessment.selected_backend == Some(HypervisorBackend::SoftwareDbt)
            && !capability.software_runner_supported
        {
            portability_assessment.blockers.push(String::from(
                "software_dbt backend requires software_runner_supported capability posture",
            ));
            portability_assessment.supported = false;
            portability_assessment.selected_backend = None;
            portability_assessment.selected_via_fallback = false;
            portability_assessment.selection_reason = None;
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                    summary: String::from(
                        "software_dbt candidate rejected because software_runner_supported=false",
                    ),
                    evidence_mode: None,
                });
        }
        blockers.extend(portability_assessment.blockers.iter().cloned());

        let selection = if blockers.is_empty() {
            match portability_assessment.selected_backend {
                Some(backend) => Some(uhost_uvm::BackendSelection {
                    backend,
                    reason: portability_assessment
                        .selection_reason
                        .clone()
                        .unwrap_or_else(|| {
                            format!(
                                "selected {} from execution intent portability assessment",
                                backend.as_str()
                            )
                        }),
                }),
                None => {
                    blockers.push(String::from(
                        "no backend selected by execution intent portability assessment",
                    ));
                    None
                }
            }
        } else {
            None
        };

        let migration_budget = MigrationBudget {
            strategy,
            max_downtime_ms: migration_max_downtime_ms.unwrap_or(if requires_live_migration {
                500
            } else {
                5_000
            }),
            max_iterations: migration_max_iterations.unwrap_or(5),
            available_bandwidth_mbps: migration_bandwidth_mbps.unwrap_or(10_000),
            dirty_page_rate_mbps: migration_dirty_page_rate_mbps.unwrap_or((memory_mb / 64).max(1)),
            memory_mb,
        };
        let migration_plan = selection.as_ref().and_then(|selected| {
            evaluate_migration_budget(selected.backend, &migration_budget).ok()
        });
        if let Some(plan) = &migration_plan {
            blockers.extend(plan.blockers.clone());
        }

        let launch_program = selection.as_ref().and_then(|selected| {
            build_launch_command(
                selected.backend,
                &LaunchSpec {
                    runtime_session_id: String::from("preview"),
                    instance_id: String::from("preview"),
                    guest_architecture,
                    vcpu,
                    memory_mb,
                    require_secure_boot,
                    firmware_profile: String::from(if require_secure_boot {
                        "uefi_secure"
                    } else {
                        "uefi_standard"
                    }),
                    firmware_artifact: None,
                    disk_image: String::from("object://uvm-preview/runtime.img"),
                    cdrom_image: cdrom_image.clone(),
                    boot_device: boot_device.clone(),
                },
            )
            .ok()
            .map(|command| command.program)
        });

        let report_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime preflight id")
                .with_detail(error.to_string())
        })?;
        let report = UvmRuntimePreflightRecord {
            id: report_id.clone(),
            capability_id,
            node_id: capability.node_id.clone(),
            guest_architecture: String::from(guest_architecture.as_str()),
            guest_os,
            machine_family,
            guest_profile,
            claim_tier: capability.default_claim_tier.clone(),
            apple_guest,
            legal_allowed: blockers.is_empty(),
            placement_admitted: placement.admitted,
            placement_pinned_numa_nodes: placement.pinned_numa_nodes.clone(),
            require_secure_boot,
            requires_live_migration,
            selected_backend: selection.map(|selected| String::from(selected.backend.as_str())),
            launch_program,
            migration_recommended_checkpoint_kind: migration_plan
                .as_ref()
                .map(|plan| plan.recommended_checkpoint_kind.clone()),
            migration_expected_downtime_ms: migration_plan
                .as_ref()
                .map(|plan| plan.expected_downtime_ms),
            blockers: blockers.clone(),
            compatibility_assessment: Some(compatibility_assessment),
            portability_assessment: Some(portability_assessment),
            created_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(report_id.to_string()),
                sha256_hex(report_id.as_str().as_bytes()),
            ),
        };
        self.runtime_preflights
            .create(report.id.as_str(), report.clone())
            .await?;
        self.append_event(
            "uvm.node.runtime.preflight.v1",
            "uvm_runtime_preflight",
            report.id.as_str(),
            "preflight",
            serde_json::json!({
                "legal_allowed": report.legal_allowed,
                "blockers": blockers,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &report)
    }

    async fn register_runtime_session(
        &self,
        request: RegisterRuntimeSessionRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = UvmInstanceId::parse(request.instance_id).map_err(|error| {
            PlatformError::invalid("invalid instance_id").with_detail(error.to_string())
        })?;
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let capability_id = UvmNodeCapabilityId::parse(request.capability_id).map_err(|error| {
            PlatformError::invalid("invalid capability_id").with_detail(error.to_string())
        })?;
        let stored = self
            .capabilities
            .get(capability_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node capability does not exist"))?;
        let capability = stored.value;
        if capability.node_id != node_id {
            return Err(PlatformError::conflict(
                "capability node_id does not match runtime session node_id",
            ));
        }

        let guest_architecture = GuestArchitecture::parse(&request.guest_architecture)?;
        let guest_os = normalize_guest_os(&request.guest_os)?;
        let cdrom_image = request
            .cdrom_image
            .as_deref()
            .map(|value| normalize_storage_reference(value, "cdrom_image"))
            .transpose()?;
        let boot_device =
            normalize_boot_device(request.boot_device.as_deref(), cdrom_image.is_some())?;
        if boot_device == BootDevice::Cdrom.as_str() && cdrom_image.is_none() {
            return Err(PlatformError::conflict(
                "boot_device `cdrom` requires a cdrom_image",
            ));
        }
        let guest_profile = default_guest_profile_for_guest_os(&guest_os);
        let machine_family = default_machine_family_for_guest(guest_architecture, &guest_os);
        let execution_intent = self
            .resolve_registration_execution_intent(&instance_id, &guest_profile)
            .await?;
        if !capability
            .supported_machine_families
            .iter()
            .any(|value| value == &machine_family)
        {
            return Err(PlatformError::conflict(format!(
                "selected capability does not support machine_family {machine_family}"
            )));
        }
        if !capability
            .supported_guest_profiles
            .iter()
            .any(|value| value == &guest_profile)
        {
            return Err(PlatformError::conflict(format!(
                "selected capability does not support guest_profile {guest_profile}"
            )));
        }
        let apple_guest = is_apple_guest_os(&guest_os);
        let requires_live_migration = request.requires_live_migration.unwrap_or(false);
        let require_secure_boot = request.require_secure_boot.unwrap_or(false);
        let migration_max_downtime_ms = validate_optional_positive_u32(
            request.migration_max_downtime_ms,
            "migration_max_downtime_ms",
        )?;
        let migration_max_iterations = validate_optional_positive_u16(
            request.migration_max_iterations,
            "migration_max_iterations",
        )?;
        let migration_bandwidth_mbps = validate_optional_positive_u64(
            request.migration_bandwidth_mbps,
            "migration_bandwidth_mbps",
        )?;
        let migration_dirty_page_rate_mbps = validate_optional_positive_u64(
            request.migration_dirty_page_rate_mbps,
            "migration_dirty_page_rate_mbps",
        )?;
        if apple_guest && !request.apple_guest_approved.unwrap_or(false) {
            return Err(PlatformError::conflict(
                "apple guest workloads require explicit apple_guest_approved=true",
            ));
        }
        let disk_image = normalize_storage_reference(&request.disk_image, "disk_image")?;
        let vcpu = request.vcpu.unwrap_or(capability.max_vcpu.clamp(1, 2));
        if vcpu == 0 {
            return Err(PlatformError::invalid("vcpu must be at least 1"));
        }
        if vcpu > capability.max_vcpu {
            return Err(PlatformError::conflict(format!(
                "requested vcpu {} exceeds capability max_vcpu {}",
                vcpu, capability.max_vcpu
            )));
        }
        let memory_mb = request
            .memory_mb
            .unwrap_or(capability.max_memory_mb.clamp(256, 2_048));
        if memory_mb < 256 {
            return Err(PlatformError::invalid("memory_mb must be at least 256"));
        }
        if memory_mb > capability.max_memory_mb {
            return Err(PlatformError::conflict(format!(
                "requested memory_mb {} exceeds capability max_memory_mb {}",
                memory_mb, capability.max_memory_mb
            )));
        }
        let cpu_topology_profile = normalize_profile(
            request.cpu_topology.as_deref().unwrap_or("balanced"),
            "cpu_topology",
        )?;
        let numa_policy_profile = normalize_profile(
            request.numa_policy.as_deref().unwrap_or("preferred_local"),
            "numa_policy",
        )?;
        let migration_policy =
            normalize_migration_policy(request.migration_policy.as_deref().unwrap_or(
                if requires_live_migration {
                    "best_effort_live"
                } else {
                    "cold_only"
                },
            ))?;
        let cpu_topology = CpuTopologySpec::from_profile(&cpu_topology_profile, vcpu)?;
        let numa_policy =
            NumaPolicySpec::from_profile(&numa_policy_profile, capability.numa_nodes)?;
        let placement = plan_placement(&PlacementRequest {
            requested_vcpu: vcpu,
            requested_memory_mb: memory_mb,
            host_max_vcpu: capability.max_vcpu.max(1),
            host_max_memory_mb: capability.max_memory_mb.max(256),
            host_numa_nodes: capability.numa_nodes.max(1),
            cpu_topology: cpu_topology.clone(),
            numa_policy: numa_policy.clone(),
        })?;
        if !placement.admitted {
            return Err(PlatformError::conflict(format!(
                "runtime placement denied: {}",
                placement.blockers.join("; ")
            )));
        }
        let strategy = MigrationStrategy::parse(&migration_policy)?;
        if requires_live_migration && strategy == MigrationStrategy::Cold {
            return Err(PlatformError::conflict(
                "requires_live_migration=true is incompatible with migration_policy=cold_only",
            ));
        }
        let selection = self.select_backend_for_capability_with_execution_intent(
            &capability,
            guest_architecture,
            apple_guest,
            requires_live_migration,
            require_secure_boot,
            &execution_intent,
        )?;
        let image_compatibility_artifact = self
            .resolve_scoped_image_compatibility_artifact(
                &disk_image,
                &capability,
                guest_architecture,
                &machine_family,
                &guest_profile,
                require_secure_boot,
                requires_live_migration,
                selection.backend,
            )
            .await?;
        let first_placement_portability_assessment = self
            .assess_registration_portability_for_capability(
                &capability,
                guest_architecture,
                apple_guest,
                requires_live_migration,
                require_secure_boot,
                &execution_intent,
                selection.backend,
                image_compatibility_artifact.as_ref(),
            )?;
        let migration_budget = MigrationBudget {
            strategy,
            max_downtime_ms: migration_max_downtime_ms.unwrap_or(if requires_live_migration {
                500
            } else {
                5_000
            }),
            max_iterations: migration_max_iterations.unwrap_or(5),
            available_bandwidth_mbps: migration_bandwidth_mbps.unwrap_or(10_000),
            dirty_page_rate_mbps: migration_dirty_page_rate_mbps.unwrap_or((memory_mb / 64).max(1)),
            memory_mb,
        };
        let migration_plan = evaluate_migration_budget(selection.backend, &migration_budget)?;
        if !migration_plan.allowed {
            return Err(PlatformError::conflict(format!(
                "runtime migration policy denied: {}",
                migration_plan.blockers.join("; ")
            )));
        }
        let isolation_profile = normalize_isolation_profile(request.isolation_profile.as_deref())?;
        let restart_policy = normalize_restart_policy(request.restart_policy.as_deref())?;
        let max_restarts =
            validate_optional_positive_u16(request.max_restarts, "max_restarts")?.unwrap_or(3);

        let firmware_profile =
            normalize_firmware_profile(request.firmware_profile.as_deref().unwrap_or(
                if require_secure_boot {
                    "uefi_secure"
                } else {
                    "uefi_standard"
                },
            ))?;
        let software_disk_artifact_uri = if selection.backend == HypervisorBackend::SoftwareDbt {
            self.resolve_verified_local_disk_artifact_uri(&disk_image)
                .await?
        } else {
            None
        };
        let software_firmware_artifact_uri = if selection.backend == HypervisorBackend::SoftwareDbt
        {
            self.resolve_verified_local_firmware_artifact_uri(&firmware_profile)
                .await?
        } else {
            None
        };
        let runner_phase = if selection.backend == HypervisorBackend::SoftwareDbt {
            default_runner_phase_key()
        } else {
            String::from("external_adapter")
        };
        let worker_states = if selection.backend == HypervisorBackend::SoftwareDbt {
            software_runner_worker_states_for_phase("registered")
        } else {
            Vec::new()
        };
        let build_registration_plan = |runtime_session_id: &str| -> Result<(
            uhost_uvm::UvmExecutionPlan,
            String,
            Vec<String>,
            Vec<String>,
        )> {
            let launch_spec = LaunchSpec {
                runtime_session_id: runtime_session_id.to_owned(),
                instance_id: instance_id.to_string(),
                guest_architecture,
                vcpu,
                memory_mb,
                require_secure_boot,
                firmware_profile: firmware_profile.clone(),
                firmware_artifact: None,
                disk_image: disk_image.clone(),
                cdrom_image: cdrom_image.clone(),
                boot_device: boot_device.clone(),
            };
            let execution_plan = synthesize_execution_plan(&ExecutionPlanRequest {
                backend: selection.backend,
                launch_spec: &launch_spec,
                placement: &placement,
                migration_plan: &migration_plan,
                cpu_topology: &cpu_topology,
                numa_policy: &numa_policy,
                isolation_profile: &isolation_profile,
                restart_policy: &restart_policy,
            })?;
            let (launch_program, launch_args, launch_env) = build_persisted_launch_contract(
                selection.backend,
                &execution_plan,
                software_disk_artifact_uri.as_deref(),
                software_firmware_artifact_uri.as_deref(),
            )?;
            Ok((execution_plan, launch_program, launch_args, launch_env))
        };
        if let Some(existing) = self.find_runtime_session_for_instance(&instance_id).await? {
            let (execution_plan, launch_program, launch_args, launch_env) =
                build_registration_plan(existing.value.id.as_str())?;
            let expected = RuntimeRegistrationExpectation {
                node_id: &node_id,
                capability_id: &capability_id,
                guest_architecture,
                guest_os: &guest_os,
                vcpu,
                memory_mb,
                cpu_topology_profile: &cpu_topology_profile,
                numa_policy_profile: &numa_policy_profile,
                migration_policy: &migration_policy,
                machine_family: &execution_plan.machine_family,
                guest_profile: &guest_profile,
                claim_tier: &capability.default_claim_tier,
                placement: &placement,
                migration_plan: &migration_plan,
                backend: selection.backend,
                isolation_profile: &isolation_profile,
                restart_policy: &restart_policy,
                max_restarts,
                runtime_evidence_mode: &capability.host_evidence_mode,
                runner_phase: &runner_phase,
                worker_states: &worker_states,
                boot_path: &execution_plan.boot_path,
                execution_class: &execution_plan.execution_class,
                memory_backing: &execution_plan.memory_backing,
                device_model: &execution_plan.device_model,
                sandbox_layers: &execution_plan.sandbox_layers,
                telemetry_streams: &execution_plan.telemetry_streams,
                launch_program: &launch_program,
                launch_args: &launch_args,
                launch_env: &launch_env,
            };
            if runtime_registration_matches(&existing.value, &expected)? {
                match self
                    .load_persisted_runtime_session_execution_intent(&existing.value.id)
                    .await?
                {
                    Some(stored_intent) if stored_intent == execution_intent => {
                        self.persist_runtime_session_execution_intent(
                            &existing.value.id,
                            &instance_id,
                            &execution_intent,
                            Some(&first_placement_portability_assessment),
                        )
                        .await?;
                        self.project_runtime_session_into_node_plane(&existing.value)
                            .await?;
                        return json_response(StatusCode::OK, &existing.value);
                    }
                    None => {
                        self.persist_runtime_session_execution_intent(
                            &existing.value.id,
                            &instance_id,
                            &execution_intent,
                            Some(&first_placement_portability_assessment),
                        )
                        .await?;
                        self.project_runtime_session_into_node_plane(&existing.value)
                            .await?;
                        return json_response(StatusCode::OK, &existing.value);
                    }
                    Some(_) => {
                        return Err(PlatformError::conflict(
                            "runtime session already exists for this instance with different execution_intent",
                        ));
                    }
                }
            }
            return Err(PlatformError::conflict(
                "runtime session already exists for this instance",
            ));
        }

        let runtime_session_id = UvmRuntimeSessionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime session id")
                .with_detail(error.to_string())
        })?;
        let (execution_plan, launch_program, launch_args, launch_env) =
            build_registration_plan(runtime_session_id.as_str())?;
        let now = OffsetDateTime::now_utc();
        let record = UvmRuntimeSessionRecord {
            id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            node_id: node_id.clone(),
            capability_id: capability_id.clone(),
            guest_architecture: String::from(guest_architecture.as_str()),
            vcpu,
            memory_mb,
            guest_os,
            cpu_topology_profile: cpu_topology_profile.clone(),
            numa_policy_profile: numa_policy_profile.clone(),
            planned_pinned_numa_nodes: placement.pinned_numa_nodes.clone(),
            planned_memory_per_numa_mb: placement.per_node_memory_mb.clone(),
            migration_policy: migration_policy.clone(),
            machine_family: execution_plan.machine_family.clone(),
            guest_profile,
            claim_tier: capability.default_claim_tier.clone(),
            runner_phase,
            worker_states,
            runtime_evidence_mode: capability.host_evidence_mode.clone(),
            planned_migration_checkpoint_kind: migration_plan.recommended_checkpoint_kind.clone(),
            planned_migration_downtime_ms: migration_plan.expected_downtime_ms,
            accelerator_backend: String::from(selection.backend.as_str()),
            launch_program,
            launch_args,
            launch_env,
            isolation_profile,
            boot_path: execution_plan.boot_path.clone(),
            execution_class: execution_plan.execution_class.clone(),
            memory_backing: execution_plan.memory_backing.clone(),
            device_model: execution_plan.device_model.clone(),
            sandbox_layers: execution_plan.sandbox_layers.clone(),
            telemetry_streams: execution_plan.telemetry_streams.clone(),
            restart_policy,
            max_restarts,
            start_attempts: 0,
            state: VmRuntimeState::Registered,
            last_heartbeat_at: None,
            heartbeat_sequence: 0,
            last_runner_sequence_id: None,
            last_lifecycle_event_id: None,
            observed_pid: None,
            observed_assigned_memory_mb: None,
            hypervisor_health: String::from(HypervisorHealth::Unknown.as_str()),
            last_exit_reason: None,
            migration_in_progress: false,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            restore_count: 0,
            last_restore_at: None,
            current_incarnation: None,
            incarnation_lineage: Vec::new(),
            last_error: None,
            created_at: now,
            last_transition_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(runtime_session_id.to_string()),
                sha256_hex(runtime_session_id.as_str().as_bytes()),
            ),
        };
        if let Some(existing) = self.find_matching_runtime_session(&record).await? {
            match self
                .load_persisted_runtime_session_execution_intent(&existing.id)
                .await?
            {
                Some(stored_intent) if stored_intent == execution_intent => {
                    self.persist_runtime_session_execution_intent(
                        &existing.id,
                        &instance_id,
                        &execution_intent,
                        Some(&first_placement_portability_assessment),
                    )
                    .await?;
                    self.project_runtime_session_into_node_plane(&existing)
                        .await?;
                    return json_response(StatusCode::OK, &existing);
                }
                None => {
                    self.persist_runtime_session_execution_intent(
                        &existing.id,
                        &instance_id,
                        &execution_intent,
                        Some(&first_placement_portability_assessment),
                    )
                    .await?;
                    self.project_runtime_session_into_node_plane(&existing)
                        .await?;
                    return json_response(StatusCode::OK, &existing);
                }
                Some(_) => {
                    return Err(PlatformError::conflict(
                        "matching runtime session already exists with different execution_intent",
                    ));
                }
            }
        }
        self.ensure_node_accepts_new_runtime_work(&node_id).await?;
        self.runtime_sessions
            .create(runtime_session_id.as_str(), record.clone())
            .await?;
        self.persist_runtime_session_execution_intent(
            &runtime_session_id,
            &instance_id,
            &execution_intent,
            Some(&first_placement_portability_assessment),
        )
        .await?;
        self.project_runtime_session_into_node_plane(&record)
            .await?;
        self.append_event(
            "uvm.node.runtime.registered.v1",
            "uvm_runtime_session",
            runtime_session_id.as_str(),
            "registered",
            serde_json::json!({
                "instance_id": instance_id,
                "node_id": node_id,
                "accelerator_backend": record.accelerator_backend,
                "firmware_profile": firmware_profile,
                "boot_device": boot_device,
                "cdrom_image": cdrom_image,
                "cpu_topology_profile": cpu_topology_profile,
                "numa_policy_profile": numa_policy_profile,
                "migration_policy": migration_policy,
                "planned_pinned_numa_nodes": record.planned_pinned_numa_nodes,
                "planned_migration_checkpoint_kind": record.planned_migration_checkpoint_kind,
                "execution_intent": execution_intent,
                "boot_path": record.boot_path,
                "execution_class": record.execution_class,
                "memory_backing": record.memory_backing,
                "device_model": record.device_model,
                "sandbox_layers": record.sandbox_layers,
                "telemetry_streams": record.telemetry_streams,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn get_runtime_session(&self, session_id: &str) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
            })?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("runtime session does not exist"));
        }
        json_response(StatusCode::OK, &stored.value)
    }

    async fn get_runtime_checkpoint(&self, checkpoint_id: &str) -> Result<http::Response<ApiBody>> {
        let checkpoint_id = UvmCheckpointId::parse(checkpoint_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid runtime checkpoint id").with_detail(error.to_string())
        })?;
        let stored = self
            .runtime_checkpoints
            .get(checkpoint_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime checkpoint does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found(
                "runtime checkpoint does not exist",
            ));
        }
        json_response(StatusCode::OK, &stored.value)
    }

    async fn get_runtime_migration(&self, migration_id: &str) -> Result<http::Response<ApiBody>> {
        let migration_id = UvmMigrationId::parse(migration_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid runtime migration id").with_detail(error.to_string())
        })?;
        let stored = self
            .runtime_migrations
            .get(migration_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime migration does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("runtime migration does not exist"));
        }
        json_response(StatusCode::OK, &stored.value)
    }

    async fn get_outbox_message(&self, message_id: &str) -> Result<http::Response<ApiBody>> {
        let message_id = AuditId::parse(message_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid outbox message id").with_detail(error.to_string())
        })?;
        let message = self
            .outbox
            .list_all()
            .await?
            .into_iter()
            .find(|message| message.id == message_id.as_str())
            .ok_or_else(|| PlatformError::not_found("outbox message does not exist"))?;
        json_response(StatusCode::OK, &message)
    }

    async fn transition_runtime_session(
        &self,
        session_id: &str,
        action: VmRuntimeAction,
        action_name: &str,
        operation_detail: Option<String>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
            })?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        let previous_state = stored.value.state;
        let mut record = stored.value;
        if is_runtime_transition_noop(previous_state, action) {
            return json_response(StatusCode::OK, &record);
        }
        if record.migration_in_progress && action != VmRuntimeAction::Fail {
            return Err(PlatformError::conflict(
                "runtime session is locked by an in-progress migration",
            ));
        }
        if matches!(
            action,
            VmRuntimeAction::Prepare | VmRuntimeAction::Start | VmRuntimeAction::CompleteRecover
        ) {
            self.ensure_node_accepts_new_runtime_work(&record.node_id)
                .await?;
        }
        let operation_detail = match action {
            VmRuntimeAction::Fail => normalize_optional_failure_detail(operation_detail)?,
            VmRuntimeAction::BeginRecover => operation_detail
                .map(|value| normalize_reason(&value))
                .transpose()?,
            _ => operation_detail,
        };
        let now = OffsetDateTime::now_utc();
        record.state = transition_state(record.state, action)?;
        record.last_transition_at = now;
        if action == VmRuntimeAction::Start && previous_state == VmRuntimeState::Stopped {
            record.start_attempts = record.start_attempts.saturating_add(1);
        }
        let target_node_id = record.node_id.clone();
        if let Some(kind) = (action == VmRuntimeAction::Start)
            .then(|| runtime_incarnation_for_start(previous_state))
            .flatten()
        {
            record_runtime_incarnation(
                &mut record,
                kind,
                Some(previous_state),
                None,
                target_node_id,
                None,
                None,
                None,
                now,
            );
        }
        if record.accelerator_backend == HypervisorBackend::SoftwareDbt.as_str() {
            match action {
                VmRuntimeAction::Prepare => {
                    record.runner_phase = String::from("prepared");
                    record.worker_states = software_runner_worker_states_for_phase("prepared");
                }
                VmRuntimeAction::Start => {
                    record.runner_phase = String::from("running");
                    record.worker_states = software_runner_worker_states_for_phase("running");
                }
                VmRuntimeAction::Stop => {
                    record.runner_phase = String::from("stopped");
                    record.worker_states = software_runner_worker_states_for_phase("stopped");
                }
                VmRuntimeAction::Fail => {
                    record.runner_phase = String::from("failed");
                    record.worker_states = software_runner_worker_states_for_phase("failed");
                }
                VmRuntimeAction::BeginRecover => {
                    record.runner_phase = String::from("recovering");
                    record.worker_states = software_runner_worker_states_for_phase("recovering");
                }
                VmRuntimeAction::CompleteRecover => {
                    record.runner_phase = String::from("running");
                    record.worker_states = software_runner_worker_states_for_phase("running");
                }
            }
        }
        if action == VmRuntimeAction::Fail {
            let error = operation_detail
                .as_deref()
                .unwrap_or("runtime failure without detail");
            if error.trim().is_empty() {
                return Err(PlatformError::invalid("failure error may not be empty"));
            }
            record.last_error = Some(error.trim().to_owned());
        } else if action == VmRuntimeAction::CompleteRecover {
            record.last_error = None;
        }
        record
            .metadata
            .touch(sha256_hex(runtime_session_id.as_str().as_bytes()));
        self.runtime_sessions
            .upsert(
                runtime_session_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;
        if action == VmRuntimeAction::Start {
            self.schedule_runner_supervision(&record).await?;
        }
        if matches!(action, VmRuntimeAction::Stop | VmRuntimeAction::Fail) {
            self.request_runner_supervision_stop(&record).await?;
        }
        self.record_runtime_transition_operation(
            &record,
            previous_state,
            action,
            operation_detail.as_deref(),
        )
        .await?;
        self.project_runtime_session_into_node_plane(&record)
            .await?;
        self.append_event(
            match action {
                VmRuntimeAction::Prepare => "uvm.node.runtime.prepared.v1",
                VmRuntimeAction::Start => "uvm.node.runtime.started.v1",
                VmRuntimeAction::Stop => "uvm.node.runtime.stopped.v1",
                VmRuntimeAction::Fail => "uvm.node.runtime.failed.v1",
                VmRuntimeAction::BeginRecover => "uvm.node.runtime.recovering.v1",
                VmRuntimeAction::CompleteRecover => "uvm.node.runtime.recovered.v1",
            },
            "uvm_runtime_session",
            runtime_session_id.as_str(),
            action_name,
            serde_json::json!({
                "from_state": previous_state.as_str(),
                "to_state": record.state.as_str(),
                "last_error": record.last_error,
                "operation_detail": operation_detail,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn heartbeat_runtime_session(
        &self,
        session_id: &str,
        request: RuntimeHeartbeatRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
            })?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("runtime session does not exist"));
        }
        let mut record = stored.value;
        let health = HypervisorHealth::parse(&request.hypervisor_health)?;
        let exit_reason = normalize_optional_failure_detail(request.exit_reason)?;
        let runner_phase = request
            .runner_phase
            .as_deref()
            .map(normalize_runner_phase)
            .transpose()?;
        let worker_states = request
            .worker_states
            .map(normalize_worker_states)
            .transpose()?;
        let runner_sequence_id =
            validate_optional_positive_u64(request.runner_sequence_id, "runner_sequence_id")?;
        let lifecycle_event_id =
            parse_optional_audit_id(request.lifecycle_event_id, "lifecycle_event_id")?;
        let observed_assigned_memory_mb = match request.observed_assigned_memory_mb {
            Some(0) => {
                return Err(PlatformError::invalid(
                    "observed_assigned_memory_mb must be at least 1 when set",
                ));
            }
            value => value,
        };
        if let (Some(previous), Some(next)) = (record.last_runner_sequence_id, runner_sequence_id)
            && next <= previous
        {
            return Err(PlatformError::conflict(
                "runner_sequence_id must advance monotonically",
            ));
        }
        let now = OffsetDateTime::now_utc();
        record.heartbeat_sequence = record.heartbeat_sequence.saturating_add(1);
        record.last_heartbeat_at = Some(now);
        let runtime_incarnation_sequence = record
            .current_incarnation
            .as_ref()
            .map(|incarnation| incarnation.sequence);
        if let Some(runner_sequence_id) = runner_sequence_id {
            record.last_runner_sequence_id = Some(runner_sequence_id);
        }
        if let Some(lifecycle_event_id) = lifecycle_event_id.clone() {
            record.last_lifecycle_event_id = Some(lifecycle_event_id);
        }
        record.observed_pid = request.observed_pid;
        record.observed_assigned_memory_mb = observed_assigned_memory_mb;
        record.hypervisor_health = String::from(health.as_str());
        if let Some(runner_phase) = runner_phase.clone() {
            record.runner_phase = runner_phase;
        }
        if let Some(worker_states) = worker_states.clone() {
            record.worker_states = worker_states;
        }
        if exit_reason.is_some() {
            record.last_exit_reason = exit_reason.clone();
        }
        if health == HypervisorHealth::Failed && record.last_error.is_none() {
            record.last_error = exit_reason.clone().or_else(|| {
                Some(String::from(
                    "runtime heartbeat reported failed health state",
                ))
            });
        }
        record
            .metadata
            .touch(sha256_hex(runtime_session_id.as_str().as_bytes()));
        self.runtime_sessions
            .upsert(
                runtime_session_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;

        let heartbeat_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime heartbeat id")
                .with_detail(error.to_string())
        })?;
        let heartbeat = UvmRuntimeHeartbeatRecord {
            id: heartbeat_id.clone(),
            runtime_session_id: runtime_session_id.clone(),
            runtime_incarnation_sequence,
            sequence: record.heartbeat_sequence,
            runner_sequence_id,
            hypervisor_health: String::from(health.as_str()),
            observed_pid: record.observed_pid,
            observed_assigned_memory_mb,
            exit_reason: exit_reason.clone(),
            runner_phase: record.runner_phase.clone(),
            worker_states: record.worker_states.clone(),
            lifecycle_event_id: lifecycle_event_id.clone(),
            observed_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(heartbeat_id.to_string()),
                sha256_hex(heartbeat_id.as_str().as_bytes()),
            ),
        };
        self.runtime_heartbeats
            .create(heartbeat.id.as_str(), heartbeat.clone())
            .await?;
        self.append_event(
            "uvm.node.runtime.heartbeat.v1",
            "uvm_runtime_heartbeat",
            heartbeat.id.as_str(),
            "heartbeat",
            serde_json::json!({
                "runtime_session_id": runtime_session_id,
                "runtime_incarnation_sequence": heartbeat.runtime_incarnation_sequence,
                "sequence": heartbeat.sequence,
                "runner_sequence_id": heartbeat.runner_sequence_id,
                "hypervisor_health": heartbeat.hypervisor_health,
                "observed_pid": heartbeat.observed_pid,
                "exit_reason": heartbeat.exit_reason,
                "runner_phase": heartbeat.runner_phase,
                "worker_states": heartbeat.worker_states,
                "lifecycle_event_id": heartbeat.lifecycle_event_id,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn runtime_health_summary(
        &self,
        stale_after_seconds: i64,
    ) -> Result<UvmRuntimeHealthSummary> {
        if stale_after_seconds <= 0 {
            return Err(PlatformError::invalid(
                "stale_after_seconds must be greater than zero",
            ));
        }
        let values = self.runtime_sessions.list().await?;
        let now = OffsetDateTime::now_utc();
        let mut summary = UvmRuntimeHealthSummary {
            total_sessions: 0,
            running_sessions: 0,
            stale_sessions: 0,
            degraded_sessions: 0,
            failed_sessions: 0,
            software_backend_sessions: 0,
            restored_sessions: 0,
            stale_after_seconds,
            stale_runtime_session_ids: Vec::new(),
        };
        for (_, stored) in values {
            if stored.deleted {
                continue;
            }
            let value = stored.value;
            summary.total_sessions += 1;
            if value.accelerator_backend == HypervisorBackend::SoftwareDbt.as_str() {
                summary.software_backend_sessions += 1;
            }
            if value.restore_count > 0 {
                summary.restored_sessions += 1;
            }
            if value.state == VmRuntimeState::Running {
                summary.running_sessions += 1;
            }
            let heartbeat_age_seconds = value
                .last_heartbeat_at
                .map(|heartbeat| (now - heartbeat).whole_seconds());
            let stale = matches!(
                value.state,
                VmRuntimeState::Running | VmRuntimeState::Recovering
            ) && heartbeat_age_seconds
                .map(|age| age > stale_after_seconds)
                .unwrap_or(true);
            if stale {
                summary.stale_sessions += 1;
                summary.stale_runtime_session_ids.push(value.id.to_string());
            }
            let hypervisor_failed = match HypervisorHealth::parse(&value.hypervisor_health)
                .unwrap_or(HypervisorHealth::Unknown)
            {
                HypervisorHealth::Degraded => {
                    summary.degraded_sessions += 1;
                    false
                }
                HypervisorHealth::Failed => true,
                HypervisorHealth::Unknown | HypervisorHealth::Healthy => false,
            };
            if hypervisor_failed || value.state == VmRuntimeState::Failed {
                summary.failed_sessions += 1;
            }
        }
        Ok(summary)
    }

    async fn mutate_runner_supervision<F>(&self, key: &str, mutate: F) -> Result<()>
    where
        F: FnOnce(&mut UvmRunnerSupervisionRecord),
    {
        let Some(stored) = self.runner_supervision.get(key).await? else {
            return Err(PlatformError::not_found(
                "runner supervision record does not exist",
            ));
        };
        if stored.deleted {
            return Err(PlatformError::not_found(
                "runner supervision record does not exist",
            ));
        }
        let mut record = stored.value;
        mutate(&mut record);
        record.metadata.touch(sha256_hex(key.as_bytes()));
        self.runner_supervision
            .upsert(key, record, Some(stored.version))
            .await?;
        Ok(())
    }

    async fn schedule_runner_supervision(&self, runtime: &UvmRuntimeSessionRecord) -> Result<()> {
        if runtime.accelerator_backend != HypervisorBackend::SoftwareDbt.as_str() {
            return Ok(());
        }
        let Some(runtime_incarnation) = runtime.current_incarnation.as_ref() else {
            return Ok(());
        };
        let key = runner_supervision_key(&runtime.id, runtime_incarnation.sequence);
        if self.runner_supervision.get(&key).await?.is_some() {
            return Ok(());
        }

        let stop_sentinel_path = self
            .state_root
            .join("runner_supervision")
            .join(runtime.id.as_str())
            .join(format!("incarnation-{}", runtime_incarnation.sequence))
            .join("stop.sentinel");
        if let Some(parent) = stop_sentinel_path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create runner supervision state directory")
                    .with_detail(error.to_string())
            })?;
        }
        match fs::remove_file(&stop_sentinel_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(PlatformError::unavailable(
                    "failed to reset runner supervision stop sentinel",
                )
                .with_detail(error.to_string()));
            }
        }

        let requested_at = OffsetDateTime::now_utc();
        let record = UvmRunnerSupervisionRecord {
            runtime_session_id: runtime.id.clone(),
            runtime_incarnation: runtime_incarnation.sequence,
            instance_id: runtime.instance_id.clone(),
            node_id: runtime.node_id.clone(),
            launch_program: runtime.launch_program.clone(),
            launch_args: launch_args_with_stop_sentinel(
                &runtime.launch_args,
                stop_sentinel_path.to_string_lossy().as_ref(),
            )?,
            launch_env: runtime.launch_env.clone(),
            stop_sentinel_path: stop_sentinel_path.to_string_lossy().into_owned(),
            state: String::from("launch_requested"),
            observed_pid: None,
            last_event_kind: Some(String::from("launch_requested")),
            last_lifecycle_state: None,
            last_runner_phase: None,
            workers: Vec::new(),
            network_access: None,
            boot_stages: Vec::new(),
            console_trace: Vec::new(),
            guest_control_ready: false,
            last_heartbeat_sequence: None,
            stop_reason: None,
            exit_status: None,
            failure_detail: None,
            requested_at,
            started_at: None,
            last_event_at: requested_at,
            finished_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(key.clone()),
                sha256_hex(key.as_bytes()),
            ),
        };
        self.runner_supervision.create(&key, record.clone()).await?;

        let service = self.clone();
        let runtime_handle = tokio::runtime::Handle::current();
        thread::spawn(move || {
            watch_runner_supervision_process(service, runtime_handle, key, record);
        });
        Ok(())
    }

    async fn request_runner_supervision_stop(
        &self,
        runtime: &UvmRuntimeSessionRecord,
    ) -> Result<()> {
        let Some(key) = active_runner_supervision_key(runtime) else {
            return Ok(());
        };
        let Some(stored) = self.runner_supervision.get(&key).await? else {
            return Ok(());
        };
        if stored.deleted || stored.value.finished_at.is_some() {
            return Ok(());
        }
        if let Some(parent) = Path::new(&stored.value.stop_sentinel_path).parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable(
                    "failed to create runner supervision stop-sentinel directory",
                )
                .with_detail(error.to_string())
            })?;
        }
        fs::write(&stored.value.stop_sentinel_path, b"stop\n")
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to write runner supervision stop sentinel")
                    .with_detail(error.to_string())
            })?;
        self.mutate_runner_supervision(&key, |record| {
            record.state = String::from("stop_requested");
            record.last_event_kind = Some(String::from("stop_requested"));
            record.last_event_at = OffsetDateTime::now_utc();
        })
        .await?;
        Ok(())
    }

    async fn note_runner_supervision_spawned(&self, key: &str, pid: u32) -> Result<()> {
        self.mutate_runner_supervision(key, |record| {
            let now = OffsetDateTime::now_utc();
            record.state = String::from("running");
            record.observed_pid = Some(pid);
            record.started_at = Some(now);
            record.last_event_at = now;
            record.last_event_kind = Some(String::from("spawned"));
        })
        .await
    }

    async fn note_runner_supervision_event(
        &self,
        key: &str,
        event: &serde_json::Value,
    ) -> Result<()> {
        let workers = parse_optional_runner_workers(event)?;
        let network_access = parse_optional_runner_network_access(event)?;
        let boot_stages = parse_optional_runner_string_array(event, "boot_stages", 64, 128)?;
        let console_trace = parse_optional_runner_string_array(event, "console_trace", 128, 512)?;
        let guest_control_ready = parse_optional_runner_bool(event, "guest_control_ready")?;
        let carries_lifecycle_witness = boot_stages.is_some() || console_trace.is_some();
        if carries_lifecycle_witness
            && (boot_stages.is_none() || console_trace.is_none() || guest_control_ready.is_none())
        {
            return Err(PlatformError::invalid(
                "runner lifecycle witness requires boot_stages, console_trace, and guest_control_ready",
            ));
        }
        self.mutate_runner_supervision(key, |record| {
            let now = OffsetDateTime::now_utc();
            record.last_event_at = now;
            if let Some(kind) = event.get("event").and_then(serde_json::Value::as_str) {
                record.last_event_kind = Some(kind.to_owned());
            }
            if let Some(phase) = event.get("phase").and_then(serde_json::Value::as_str) {
                record.last_runner_phase = Some(phase.to_owned());
            }
            if let Some(workers) = workers.clone() {
                record.workers = workers;
            }
            if let Some(network_access) = network_access.clone() {
                record.network_access = Some(network_access);
            }
            if let Some(boot_stages) = boot_stages.clone() {
                record.boot_stages = boot_stages;
            }
            if let Some(console_trace) = console_trace.clone() {
                record.console_trace = console_trace;
            }
            if let Some(guest_control_ready) = guest_control_ready {
                record.guest_control_ready = guest_control_ready;
            }
            if let Some(sequence) = event
                .get("heartbeat_sequence")
                .and_then(serde_json::Value::as_u64)
            {
                record.last_heartbeat_sequence = Some(sequence);
            }
            if let Some(sequence) = event
                .get("final_heartbeat_sequence")
                .and_then(serde_json::Value::as_u64)
            {
                record.last_heartbeat_sequence = Some(sequence);
            }
            if event.get("event").and_then(serde_json::Value::as_str) == Some("heartbeat")
                && record.state != "stop_requested"
            {
                record.state = String::from("running");
            }
            if event.get("event").and_then(serde_json::Value::as_str) == Some("lifecycle") {
                if let Some(state) = event.get("state").and_then(serde_json::Value::as_str) {
                    record.last_lifecycle_state = Some(state.to_owned());
                    match state {
                        "started" => {
                            record.state = String::from("running");
                            if record.started_at.is_none() {
                                record.started_at = Some(now);
                            }
                        }
                        "stopping" => {
                            record.state = String::from("stop_requested");
                        }
                        "stopped" => {
                            if record.state != "failed" {
                                record.state = String::from("stop_requested");
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(reason) = event.get("reason").and_then(serde_json::Value::as_str) {
                    record.stop_reason = Some(reason.to_owned());
                }
            }
        })
        .await
    }

    async fn note_runner_supervision_parse_error(&self, key: &str, detail: String) -> Result<()> {
        self.mutate_runner_supervision(key, |record| {
            record.failure_detail = Some(detail);
            record.last_event_kind = Some(String::from("parse_error"));
            record.last_event_at = OffsetDateTime::now_utc();
        })
        .await
    }

    async fn finish_runner_supervision(
        &self,
        key: &str,
        state: &str,
        exit_status: Option<i32>,
        failure_detail: Option<String>,
    ) -> Result<()> {
        let terminal_state = state.to_owned();
        self.mutate_runner_supervision(key, move |record| {
            let now = OffsetDateTime::now_utc();
            record.state = terminal_state;
            record.exit_status = exit_status;
            record.finished_at = Some(now);
            record.last_event_at = now;
            if let Some(detail) = failure_detail {
                record.failure_detail = Some(detail);
            }
        })
        .await
    }

    async fn create_checkpoint(
        &self,
        request: CreateCheckpointRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let checkpoint = self.build_runtime_checkpoint(&request).await?;
        if let Some(existing) = self.find_matching_checkpoint(&checkpoint).await? {
            return json_response(StatusCode::OK, &existing);
        }
        self.store_runtime_checkpoint(checkpoint.clone(), context)
            .await?;
        json_response(StatusCode::CREATED, &checkpoint)
    }

    async fn restore_runtime_session(
        &self,
        session_id: &str,
        request: RestoreRuntimeRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
            })?;
        let checkpoint_id = UvmCheckpointId::parse(request.checkpoint_id).map_err(|error| {
            PlatformError::invalid("invalid checkpoint_id").with_detail(error.to_string())
        })?;
        let reason = request
            .reason
            .as_deref()
            .map(normalize_reason)
            .transpose()?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        let checkpoint = self
            .runtime_checkpoints
            .get(checkpoint_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("checkpoint does not exist"))?;
        if checkpoint.deleted {
            return Err(PlatformError::not_found("checkpoint does not exist"));
        }
        if checkpoint.value.runtime_session_id != runtime_session_id {
            return Err(PlatformError::conflict(
                "checkpoint does not belong to the requested runtime session",
            ));
        }
        let previous_state = stored.value.state;
        let mut record = stored.value;
        if runtime_restore_is_already_applied(&record, &checkpoint.value) {
            self.reconcile_restore_replay_side_effects(&record, &checkpoint.value, context)
                .await?;
            self.project_runtime_session_into_node_plane(&record)
                .await?;
            return json_response(StatusCode::OK, &record);
        }
        if record.migration_in_progress {
            return Err(PlatformError::conflict(
                "runtime session is locked by an in-progress migration",
            ));
        }
        self.ensure_node_accepts_new_runtime_work(&record.node_id)
            .await?;
        let now = OffsetDateTime::now_utc();
        let target_node_id = record.node_id.clone();
        record.state = VmRuntimeState::Running;
        record.restored_from_checkpoint_id = Some(checkpoint_id.clone());
        record.restore_count = record.restore_count.saturating_add(1);
        record.last_restore_at = Some(now);
        record_runtime_incarnation(
            &mut record,
            UvmRuntimeIncarnationKind::Restore,
            Some(previous_state),
            Some(checkpoint.value.source_node_id.clone()),
            target_node_id,
            Some(checkpoint_id.clone()),
            None,
            reason.clone(),
            now,
        );
        if record.accelerator_backend == HypervisorBackend::SoftwareDbt.as_str() {
            record.runner_phase = String::from("restored");
            record.worker_states = software_runner_worker_states_for_phase("restored");
        }
        record
            .metadata
            .touch(sha256_hex(runtime_session_id.as_str().as_bytes()));
        self.runtime_sessions
            .upsert(
                runtime_session_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;
        self.reconcile_restore_replay_side_effects(&record, &checkpoint.value, context)
            .await?;
        self.project_runtime_session_into_node_plane(&record)
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn repair_runtime_session(
        &self,
        session_id: &str,
        request: RepairRuntimeRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(session_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid runtime session id").with_detail(error.to_string())
            })?;
        let stale_after_seconds = request.stale_after_seconds.unwrap_or(120);
        if stale_after_seconds <= 0 {
            return Err(PlatformError::invalid(
                "stale_after_seconds must be greater than zero",
            ));
        }
        if request.target_node_id.is_some() ^ request.target_capability_id.is_some() {
            return Err(PlatformError::invalid(
                "target_node_id and target_capability_id must be supplied together",
            ));
        }
        let hinted_target_node_id = request
            .target_node_id
            .as_deref()
            .map(|value| {
                NodeId::parse(value.to_owned()).map_err(|error| {
                    PlatformError::invalid("invalid target_node_id").with_detail(error.to_string())
                })
            })
            .transpose()?;
        let hinted_target_capability_id = request
            .target_capability_id
            .as_deref()
            .map(|value| {
                UvmNodeCapabilityId::parse(value.to_owned()).map_err(|error| {
                    PlatformError::invalid("invalid target_capability_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        let reason = request
            .reason
            .as_deref()
            .map(normalize_reason)
            .transpose()?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("runtime session does not exist"));
        }
        if stored.value.migration_in_progress
            || self
                .find_in_progress_runtime_migration(&runtime_session_id)
                .await?
                .is_some()
        {
            return Err(PlatformError::conflict(
                "runtime repair cannot run while migration is in progress",
            ));
        }
        let runtime = stored.value;
        let selection = self
            .select_runtime_repair(
                &runtime,
                stale_after_seconds,
                hinted_target_node_id.as_ref(),
                hinted_target_capability_id.as_ref(),
                request.execution_intent.as_ref(),
            )
            .await?;
        let reason = reason.unwrap_or_else(|| {
            format!(
                "repair selected {} from runner and node evidence",
                selection.selected_action
            )
        });
        let previous_state = runtime.state;

        match selection.selected_action {
            "restart" => {
                let _ = self
                    .transition_runtime_session(
                        session_id,
                        VmRuntimeAction::Start,
                        "repair_restart",
                        Some(reason.clone()),
                        context,
                    )
                    .await?;
            }
            "restore" => {
                let checkpoint_id = selection.checkpoint_id.clone().ok_or_else(|| {
                    PlatformError::conflict(
                        "runtime repair selected restore without checkpoint evidence",
                    )
                })?;
                let _ = self
                    .restore_runtime_session(
                        session_id,
                        RestoreRuntimeRequest {
                            checkpoint_id: checkpoint_id.to_string(),
                            reason: Some(reason.clone()),
                        },
                        context,
                    )
                    .await?;
            }
            "migration" => {}
            _ => {
                return Err(PlatformError::conflict(
                    "runtime repair selected an unknown action",
                ));
            }
        }

        let detail = selection.evidence.join("; ");
        let linked_resource_kind = (selection.selected_action == "migration")
            .then_some(String::from("uvm_node_capability"));
        let linked_resource_id = selection
            .target_capability_id
            .as_ref()
            .map(ToString::to_string);
        let repair_operation = self
            .create_node_operation_record(NodeOperationCreateRequest {
                target_node_id: selection.target_node_id.clone(),
                runtime_session_id: Some(runtime.id.clone()),
                instance_id: Some(runtime.instance_id.clone()),
                reason: Some(reason.clone()),
                detail: Some(detail.clone()),
                phase: Some(String::from(selection.selected_action)),
                from_state: Some(previous_state),
                to_state: Some(match selection.selected_action {
                    "migration" => previous_state,
                    _ => VmRuntimeState::Running,
                }),
                checkpoint_id: selection.checkpoint_id.clone(),
                linked_resource_kind,
                linked_resource_id,
                ..NodeOperationCreateRequest::new(
                    UvmNodeOperationKind::Repair,
                    UvmNodeOperationState::Completed,
                    runtime.node_id.clone(),
                )
            })
            .await?;
        self.append_event(
            "uvm.node.runtime.repair.selected.v1",
            "uvm_node_operation",
            repair_operation.id.as_str(),
            selection.selected_action,
            serde_json::json!({
                "runtime_session_id": runtime.id,
                "reason": reason,
                "evidence": selection.evidence,
                "checkpoint_id": selection.checkpoint_id,
                "target_node_id": selection.target_node_id,
                "target_capability_id": selection.target_capability_id,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &repair_operation)
    }

    async fn preflight_runtime_migration(
        &self,
        request: RuntimeMigrationPreflightRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let runtime_session_id =
            UvmRuntimeSessionId::parse(request.runtime_session_id).map_err(|error| {
                PlatformError::invalid("invalid runtime_session_id").with_detail(error.to_string())
            })?;
        let target_node_id = NodeId::parse(request.to_node_id).map_err(|error| {
            PlatformError::invalid("invalid to_node_id").with_detail(error.to_string())
        })?;
        let target_capability_id = UvmNodeCapabilityId::parse(request.target_capability_id)
            .map_err(|error| {
                PlatformError::invalid("invalid target_capability_id")
                    .with_detail(error.to_string())
            })?;
        let runtime_stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if runtime_stored.value.state != VmRuntimeState::Running {
            return Err(PlatformError::conflict(
                "runtime migration preflight requires running runtime session",
            ));
        }
        if runtime_stored.value.migration_in_progress {
            return Err(PlatformError::conflict(
                "runtime migration preflight cannot run while runtime session is migration-locked",
            ));
        }
        if self
            .find_in_progress_runtime_migration(&runtime_session_id)
            .await?
            .is_some()
        {
            return Err(PlatformError::conflict(
                "runtime migration preflight cannot run while migration is in progress",
            ));
        }
        if runtime_stored.value.node_id == target_node_id {
            return Err(PlatformError::conflict(
                "runtime migration preflight target node must differ from source node",
            ));
        }
        let target_capability = self.lookup_capability(&target_capability_id).await?.value;
        if target_capability.node_id != target_node_id {
            return Err(PlatformError::conflict(
                "target capability does not belong to requested to_node_id",
            ));
        }
        self.ensure_node_accepts_new_runtime_work(&target_node_id)
            .await?;

        let guest_architecture =
            GuestArchitecture::parse(runtime_stored.value.guest_architecture.as_str())?;
        let apple_guest = is_apple_guest_os(&runtime_stored.value.guest_os);
        let execution_intent = match request.execution_intent.clone() {
            Some(intent) => intent,
            None => {
                self.resolve_runtime_session_execution_intent(
                    &runtime_session_id,
                    &runtime_stored.value.instance_id,
                    &runtime_stored.value.guest_profile,
                )
                .await?
            }
        };
        let require_secure_boot = request
            .require_secure_boot
            .unwrap_or_else(|| has_secure_boot_flag(&runtime_stored.value.launch_args));
        let strategy = MigrationStrategy::parse(&runtime_stored.value.migration_policy)?;
        let mut blockers = Vec::new();
        let migration_max_downtime_ms = if request.migration_max_downtime_ms == Some(0) {
            blockers.push(String::from("migration_max_downtime_ms must be at least 1"));
            None
        } else {
            request.migration_max_downtime_ms
        };
        let migration_max_iterations = if request.migration_max_iterations == Some(0) {
            blockers.push(String::from("migration_max_iterations must be at least 1"));
            None
        } else {
            request.migration_max_iterations
        };
        let migration_bandwidth_mbps = if request.migration_bandwidth_mbps == Some(0) {
            blockers.push(String::from("migration_bandwidth_mbps must be at least 1"));
            None
        } else {
            request.migration_bandwidth_mbps
        };
        let migration_dirty_page_rate_mbps = if request.migration_dirty_page_rate_mbps == Some(0) {
            blockers.push(String::from(
                "migration_dirty_page_rate_mbps must be at least 1",
            ));
            None
        } else {
            request.migration_dirty_page_rate_mbps
        };
        if strategy == MigrationStrategy::Cold {
            blockers.push(String::from(
                "runtime migration preflight requires a live migration policy",
            ));
        }
        let portability_request = BackendSelectionRequest {
            host: HostPlatform::parse(&target_capability.host_platform).map_err(|error| {
                PlatformError::invalid("capability host_platform is invalid")
                    .with_detail(error.to_string())
            })?,
            candidates: target_capability
                .accelerator_backends
                .iter()
                .map(|backend| HypervisorBackend::parse(backend))
                .collect::<Result<Vec<_>>>()?,
            guest_architecture,
            apple_guest,
            requires_live_migration: true,
            require_secure_boot,
        };
        let mut portability_assessment = assess_execution_intent(
            &portability_request,
            Some(&execution_intent),
            Some(target_capability.host_evidence_mode.as_str()),
        )?;
        if target_capability.architecture != guest_architecture.as_str() {
            portability_assessment.blockers.push(String::from(
                "host capability architecture does not match guest architecture",
            ));
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::NodeCapability,
                    summary: format!(
                        "capability_architecture={} guest_architecture={}",
                        target_capability.architecture,
                        guest_architecture.as_str()
                    ),
                    evidence_mode: Some(target_capability.host_evidence_mode.clone()),
                });
        }
        if !target_capability.supports_live_migration {
            portability_assessment.blockers.push(String::from(
                "selected capability does not support live migration",
            ));
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::NodeCapability,
                    summary: String::from("capability_live_migration=false"),
                    evidence_mode: Some(target_capability.host_evidence_mode.clone()),
                });
        }
        if require_secure_boot && !target_capability.supports_secure_boot {
            portability_assessment.blockers.push(String::from(
                "selected capability does not support secure boot",
            ));
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::NodeCapability,
                    summary: String::from("capability_secure_boot=false"),
                    evidence_mode: Some(target_capability.host_evidence_mode.clone()),
                });
        }
        if portability_assessment.selected_backend == Some(HypervisorBackend::SoftwareDbt)
            && !target_capability.software_runner_supported
        {
            portability_assessment.blockers.push(String::from(
                "software_dbt backend requires software_runner_supported capability posture",
            ));
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                    summary: String::from(
                        "software_dbt candidate rejected because software_runner_supported=false",
                    ),
                    evidence_mode: None,
                });
        }
        if portability_assessment.blockers.is_empty() {
            portability_assessment.supported = true;
        } else {
            portability_assessment.supported = false;
            portability_assessment.selected_backend = None;
            portability_assessment.selected_via_fallback = false;
            portability_assessment.selection_reason = None;
        }
        blockers.extend(portability_assessment.blockers.iter().cloned());
        let selection = if blockers.is_empty() {
            match portability_assessment.selected_backend {
                Some(backend) => Some(uhost_uvm::BackendSelection {
                    backend,
                    reason: portability_assessment
                        .selection_reason
                        .clone()
                        .unwrap_or_else(|| {
                            format!(
                                "selected {} from execution intent portability assessment",
                                backend.as_str()
                            )
                        }),
                }),
                None => {
                    blockers.push(String::from(
                        "no backend selected by execution intent portability assessment",
                    ));
                    None
                }
            }
        } else {
            None
        };
        let placement =
            self.evaluate_target_runtime_placement(&runtime_stored.value, &target_capability);
        blockers.extend(
            placement
                .as_ref()
                .ok()
                .map(|plan| plan.blockers.clone())
                .unwrap_or_default(),
        );
        if let Err(error) = placement.as_ref() {
            blockers.push(format!(
                "target placement evaluation failed: {}",
                error.message
            ));
        }
        let migration_budget = MigrationBudget {
            strategy,
            max_downtime_ms: migration_max_downtime_ms
                .unwrap_or(runtime_stored.value.planned_migration_downtime_ms),
            max_iterations: migration_max_iterations.unwrap_or(5),
            available_bandwidth_mbps: migration_bandwidth_mbps.unwrap_or(10_000),
            dirty_page_rate_mbps: migration_dirty_page_rate_mbps
                .unwrap_or((runtime_stored.value.memory_mb / 64).max(1)),
            memory_mb: runtime_stored.value.memory_mb,
        };
        let migration_plan = selection.as_ref().and_then(|selected| {
            evaluate_migration_budget(selected.backend, &migration_budget).ok()
        });
        if let Some(plan) = &migration_plan {
            blockers.extend(plan.blockers.clone());
        }
        let report_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime preflight id")
                .with_detail(error.to_string())
        })?;
        let report = UvmRuntimePreflightRecord {
            id: report_id.clone(),
            capability_id: target_capability_id.clone(),
            node_id: target_node_id.clone(),
            guest_architecture: String::from(guest_architecture.as_str()),
            guest_os: runtime_stored.value.guest_os.clone(),
            machine_family: runtime_stored.value.machine_family.clone(),
            guest_profile: runtime_stored.value.guest_profile.clone(),
            claim_tier: runtime_stored.value.claim_tier.clone(),
            apple_guest,
            legal_allowed: blockers.is_empty(),
            placement_admitted: placement
                .as_ref()
                .map(|plan| plan.admitted)
                .unwrap_or(false),
            placement_pinned_numa_nodes: placement
                .as_ref()
                .map(|plan| plan.pinned_numa_nodes.clone())
                .unwrap_or_default(),
            require_secure_boot,
            requires_live_migration: true,
            selected_backend: selection
                .as_ref()
                .map(|value| String::from(value.backend.as_str())),
            launch_program: selection.as_ref().and_then(|selected| {
                build_launch_command(
                    selected.backend,
                    &LaunchSpec {
                        runtime_session_id: runtime_stored.value.id.to_string(),
                        instance_id: runtime_stored.value.instance_id.to_string(),
                        guest_architecture,
                        vcpu: runtime_stored.value.vcpu,
                        memory_mb: runtime_stored.value.memory_mb,
                        require_secure_boot,
                        firmware_profile: String::from(if require_secure_boot {
                            "uefi_secure"
                        } else {
                            "uefi_standard"
                        }),
                        firmware_artifact: None,
                        disk_image: String::from("object://uvm-preview/runtime.img"),
                        cdrom_image: None,
                        boot_device: String::from(BootDevice::Disk.as_str()),
                    },
                )
                .ok()
                .map(|command| command.program)
            }),
            migration_recommended_checkpoint_kind: migration_plan
                .as_ref()
                .map(|plan| plan.recommended_checkpoint_kind.clone()),
            migration_expected_downtime_ms: migration_plan
                .as_ref()
                .map(|plan| plan.expected_downtime_ms),
            blockers: blockers.clone(),
            compatibility_assessment: None,
            portability_assessment: Some(portability_assessment),
            created_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(report_id.to_string()),
                sha256_hex(report_id.as_str().as_bytes()),
            ),
        };
        self.runtime_preflights
            .create(report.id.as_str(), report.clone())
            .await?;
        if request.execution_intent.is_none() {
            self.persist_runtime_session_portability_preflight(
                &runtime_session_id,
                &runtime_stored.value.instance_id,
                &execution_intent,
                &report.id,
            )
            .await?;
        }
        self.append_event(
            "uvm.migration.preflight.v1",
            "uvm_runtime_migration_preflight",
            report.id.as_str(),
            "preflight",
            serde_json::json!({
                "runtime_session_id": runtime_session_id,
                "to_node_id": target_node_id,
                "legal_allowed": report.legal_allowed,
                "blockers": blockers,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &report)
    }

    async fn start_runtime_migration(
        &self,
        request: StartRuntimeMigrationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let reason = normalize_reason(&request.reason)?;
        let runtime_session_id =
            UvmRuntimeSessionId::parse(request.runtime_session_id).map_err(|error| {
                PlatformError::invalid("invalid runtime_session_id").with_detail(error.to_string())
            })?;
        let to_node_id = NodeId::parse(request.to_node_id).map_err(|error| {
            PlatformError::invalid("invalid to_node_id").with_detail(error.to_string())
        })?;
        let target_capability_id = UvmNodeCapabilityId::parse(request.target_capability_id)
            .map_err(|error| {
                PlatformError::invalid("invalid target_capability_id")
                    .with_detail(error.to_string())
            })?;
        let runtime_stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if runtime_stored.value.state != VmRuntimeState::Running {
            return Err(PlatformError::conflict(
                "runtime migration start requires running runtime session",
            ));
        }
        let requested_kind = normalize_checkpoint_kind(&request.kind)?;
        let checkpoint_uri =
            normalize_storage_reference(&request.checkpoint_uri, "checkpoint_uri")?;
        let memory_bitmap_hash = normalize_memory_bitmap_hash(&request.memory_bitmap_hash)?;
        let in_progress_migration = self
            .find_in_progress_runtime_migration(&runtime_session_id)
            .await?;
        if let Some(existing) = in_progress_migration {
            if self
                .migration_matches_start_request(
                    &existing.value,
                    &to_node_id,
                    &target_capability_id,
                    &requested_kind,
                    &checkpoint_uri,
                    &memory_bitmap_hash,
                    request.disk_generation,
                    &reason,
                )
                .await?
            {
                return json_response(StatusCode::OK, &existing.value);
            }
            return Err(PlatformError::conflict(
                "runtime migration is already in progress for this session",
            ));
        }
        if runtime_stored.value.migration_in_progress {
            return Err(PlatformError::conflict(
                "runtime session is migration-locked without an active in-progress migration record",
            ));
        }
        if runtime_stored.value.node_id == to_node_id {
            return Err(PlatformError::conflict(
                "runtime migration target node must differ from source node",
            ));
        }
        let target_capability = self.lookup_capability(&target_capability_id).await?.value;
        if target_capability.node_id != to_node_id {
            return Err(PlatformError::conflict(
                "target capability does not belong to requested to_node_id",
            ));
        }
        self.ensure_node_accepts_new_runtime_work(&to_node_id)
            .await?;
        let guest_architecture =
            GuestArchitecture::parse(runtime_stored.value.guest_architecture.as_str())?;
        let apple_guest = is_apple_guest_os(&runtime_stored.value.guest_os);
        let require_secure_boot = has_secure_boot_flag(&runtime_stored.value.launch_args);
        let strategy = MigrationStrategy::parse(&runtime_stored.value.migration_policy)?;
        if strategy == MigrationStrategy::Cold {
            return Err(PlatformError::conflict(
                "runtime migration requires migration_policy best_effort_live/strict_live/live_postcopy",
            ));
        }
        if strategy == MigrationStrategy::LivePostCopy && requested_kind != "live_postcopy" {
            return Err(PlatformError::conflict(
                "live_postcopy policy requires checkpoint kind `live_postcopy`",
            ));
        }
        let target_placement =
            self.evaluate_target_runtime_placement(&runtime_stored.value, &target_capability)?;
        if !target_placement.admitted {
            return Err(PlatformError::conflict(format!(
                "target placement denied: {}",
                target_placement.blockers.join("; ")
            )));
        }
        let execution_intent = self
            .resolve_runtime_session_execution_intent(
                &runtime_session_id,
                &runtime_stored.value.instance_id,
                &runtime_stored.value.guest_profile,
            )
            .await?;
        let selected = self.select_backend_for_capability_with_execution_intent(
            &target_capability,
            guest_architecture,
            apple_guest,
            true,
            require_secure_boot,
            &execution_intent,
        )?;
        let migration_budget = MigrationBudget {
            strategy,
            max_downtime_ms: runtime_stored.value.planned_migration_downtime_ms.max(1),
            max_iterations: 5,
            available_bandwidth_mbps: 10_000,
            dirty_page_rate_mbps: (runtime_stored.value.memory_mb / 64).max(1),
            memory_mb: runtime_stored.value.memory_mb,
        };
        let migration_plan = evaluate_migration_budget(selected.backend, &migration_budget)?;
        if !migration_plan.allowed {
            return Err(PlatformError::conflict(format!(
                "runtime migration denied: {}",
                migration_plan.blockers.join("; ")
            )));
        }
        if runtime_stored.value.migration_policy == "strict_live"
            && requested_kind != migration_plan.recommended_checkpoint_kind
        {
            return Err(PlatformError::conflict(format!(
                "strict_live policy requires checkpoint kind `{}`",
                migration_plan.recommended_checkpoint_kind
            )));
        }

        let checkpoint_request = CreateCheckpointRequest {
            runtime_session_id: runtime_session_id.to_string(),
            kind: requested_kind.clone(),
            checkpoint_uri,
            memory_bitmap_hash,
            disk_generation: request.disk_generation,
            target_node_id: Some(to_node_id.to_string()),
        };
        let checkpoint = self.build_runtime_checkpoint(&checkpoint_request).await?;
        if self.find_matching_checkpoint(&checkpoint).await?.is_none() {
            self.store_runtime_checkpoint(checkpoint.clone(), context)
                .await?;
        }

        let latest_runtime = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;

        let mut locked_runtime = latest_runtime.value.clone();
        locked_runtime.migration_in_progress = true;
        locked_runtime.last_transition_at = OffsetDateTime::now_utc();
        locked_runtime
            .metadata
            .touch(sha256_hex(locked_runtime.id.as_str().as_bytes()));
        self.runtime_sessions
            .upsert(
                runtime_session_id.as_str(),
                locked_runtime,
                Some(latest_runtime.version),
            )
            .await?;

        let migration_id = UvmMigrationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime migration id")
                .with_detail(error.to_string())
        })?;
        let migration = UvmRuntimeMigrationRecord {
            id: migration_id.clone(),
            runtime_session_id: runtime_session_id.clone(),
            instance_id: runtime_stored.value.instance_id.clone(),
            source_node_id: runtime_stored.value.node_id.clone(),
            target_node_id: to_node_id.clone(),
            target_capability_id: target_capability_id.clone(),
            checkpoint_id: checkpoint.id.clone(),
            state: String::from("in_progress"),
            reason,
            failure_detail: None,
            updated_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(migration_id.to_string()),
                sha256_hex(migration_id.as_str().as_bytes()),
            ),
        };
        if let Err(error) = self
            .runtime_migrations
            .create(migration_id.as_str(), migration.clone())
            .await
        {
            if let Some(latest_runtime) = self
                .runtime_sessions
                .get(runtime_session_id.as_str())
                .await?
                && !latest_runtime.deleted
            {
                let mut unlocked = latest_runtime.value;
                unlocked.migration_in_progress = false;
                unlocked
                    .metadata
                    .touch(sha256_hex(unlocked.id.as_str().as_bytes()));
                let _ = self
                    .runtime_sessions
                    .upsert(
                        runtime_session_id.as_str(),
                        unlocked,
                        Some(latest_runtime.version),
                    )
                    .await;
            }
            return Err(error);
        }
        let _ = self
            .create_node_operation_record(NodeOperationCreateRequest {
                target_node_id: Some(migration.target_node_id.clone()),
                runtime_session_id: Some(migration.runtime_session_id.clone()),
                instance_id: Some(migration.instance_id.clone()),
                reason: Some(migration.reason.clone()),
                phase: Some(migration.state.clone()),
                from_state: Some(runtime_stored.value.state),
                checkpoint_id: Some(migration.checkpoint_id.clone()),
                linked_resource_kind: Some(String::from("runtime_migration")),
                linked_resource_id: Some(migration.id.to_string()),
                ..NodeOperationCreateRequest::new(
                    UvmNodeOperationKind::Migrate,
                    UvmNodeOperationState::InProgress,
                    migration.source_node_id.clone(),
                )
            })
            .await?;
        self.append_event(
            "uvm.migration.started.v1",
            "uvm_runtime_migration",
            migration_id.as_str(),
            "started",
            serde_json::json!({
                "runtime_session_id": runtime_session_id,
                "from_node_id": migration.source_node_id,
                "to_node_id": migration.target_node_id,
                "target_backend": selected.backend.as_str(),
                "checkpoint_id": checkpoint.id,
                "recommended_checkpoint_kind": migration_plan.recommended_checkpoint_kind,
                "expected_downtime_ms": migration_plan.expected_downtime_ms,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &migration)
    }

    async fn load_runtime_session_intent_record_with_lineage(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> Result<Option<UvmRuntimeSessionIntentRecord>> {
        // This is a lazy read-repair path rather than a pure load: if an older
        // stored record is missing a lineage id, the helper allocates and
        // persists one on first read so downstream code can assume the field is
        // populated.
        let Some(stored) = self
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await?
        else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        if stored.value.lineage_id.is_some() {
            return Ok(Some(stored.value));
        }

        let mut record = stored.value;
        record.lineage_id = Some(allocate_runtime_session_intent_lineage_id()?);
        record.metadata.touch(serialize_record_digest(
            &record,
            "failed to serialize runtime session intent record",
        )?);
        self.runtime_session_intents
            .upsert(
                runtime_session_id.as_str(),
                record.clone(),
                Some(stored.version),
            )
            .await?;
        Ok(Some(record))
    }

    async fn build_runtime_checkpoint_provenance(
        &self,
        runtime: &UvmRuntimeSessionRecord,
    ) -> Result<UvmRuntimeCheckpointProvenance> {
        let intent = self
            .load_runtime_session_intent_record_with_lineage(&runtime.id)
            .await?;
        let portability_preflight = match intent
            .as_ref()
            .and_then(|record| record.last_portability_preflight_id.clone())
        {
            Some(preflight_id) => self
                .runtime_preflights
                .get(preflight_id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .map(|stored| stored.value),
            None => None,
        };

        let mut heartbeats = self
            .runtime_heartbeats
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, stored)| {
                if stored.deleted || stored.value.runtime_session_id.as_str() != runtime.id.as_str()
                {
                    return None;
                }
                Some(stored.value)
            })
            .collect::<Vec<_>>();
        sort_runtime_heartbeat_records(&mut heartbeats);
        let heartbeats = heartbeat_records_for_runtime_incarnation(
            heartbeats,
            runtime
                .current_incarnation
                .as_ref()
                .map(|incarnation| incarnation.sequence),
        );

        let first_heartbeat = heartbeats.first().cloned();
        let last_heartbeat = heartbeats.last().cloned();
        let heartbeat_window = UvmRuntimeCheckpointHeartbeatWindow {
            first_heartbeat_id: first_heartbeat.as_ref().map(|record| record.id.clone()),
            first_sequence: first_heartbeat.as_ref().map(|record| record.sequence),
            first_observed_at: first_heartbeat.as_ref().map(|record| record.observed_at),
            last_heartbeat_id: last_heartbeat.as_ref().map(|record| record.id.clone()),
            last_sequence: last_heartbeat.as_ref().map(|record| record.sequence),
            last_observed_at: last_heartbeat.as_ref().map(|record| record.observed_at),
        };
        let source_pid = last_heartbeat
            .as_ref()
            .and_then(|record| record.observed_pid)
            .or(runtime.observed_pid);

        Ok(UvmRuntimeCheckpointProvenance {
            source_pid,
            heartbeat_window,
            execution_intent_lineage_id: intent
                .as_ref()
                .and_then(|record| record.lineage_id.clone()),
            portability_preflight_id: intent
                .as_ref()
                .and_then(|record| record.last_portability_preflight_id.clone()),
            witness_digests: UvmRuntimeCheckpointWitnessDigests {
                runtime_session: Some(serialize_record_digest(
                    runtime,
                    "failed to serialize runtime session witness",
                )?),
                execution_intent: intent
                    .as_ref()
                    .map(|record| {
                        serialize_record_digest(
                            record,
                            "failed to serialize runtime session intent witness",
                        )
                    })
                    .transpose()?,
                portability_preflight: portability_preflight
                    .as_ref()
                    .map(|record| {
                        serialize_record_digest(
                            record,
                            "failed to serialize runtime portability preflight witness",
                        )
                    })
                    .transpose()?,
                heartbeat_window_start: first_heartbeat
                    .as_ref()
                    .map(|record| {
                        serialize_record_digest(
                            record,
                            "failed to serialize first runtime heartbeat witness",
                        )
                    })
                    .transpose()?,
                heartbeat_window_end: last_heartbeat
                    .as_ref()
                    .map(|record| {
                        serialize_record_digest(
                            record,
                            "failed to serialize last runtime heartbeat witness",
                        )
                    })
                    .transpose()?,
            },
        })
    }

    async fn build_runtime_checkpoint(
        &self,
        request: &CreateCheckpointRequest,
    ) -> Result<UvmRuntimeCheckpointRecord> {
        let runtime_session_id = UvmRuntimeSessionId::parse(request.runtime_session_id.clone())
            .map_err(|error| {
                PlatformError::invalid("invalid runtime_session_id").with_detail(error.to_string())
            })?;
        let kind = normalize_checkpoint_kind(&request.kind)?;
        let checkpoint_uri =
            normalize_storage_reference(&request.checkpoint_uri, "checkpoint_uri")?;
        let memory_bitmap_hash = normalize_memory_bitmap_hash(&request.memory_bitmap_hash)?;
        let stored = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
        if !matches!(
            stored.value.state,
            VmRuntimeState::Running | VmRuntimeState::Stopped
        ) {
            return Err(PlatformError::conflict(
                "runtime checkpoints are allowed only for running or stopped sessions",
            ));
        }
        let target_node_id = request
            .target_node_id
            .as_deref()
            .map(NodeId::parse)
            .transpose()
            .map_err(|error| {
                PlatformError::invalid("invalid target_node_id").with_detail(error.to_string())
            })?
            .unwrap_or_else(|| stored.value.node_id.clone());
        if target_node_id != stored.value.node_id && stored.value.state != VmRuntimeState::Running {
            return Err(PlatformError::conflict(
                "cross-node checkpoints require a running runtime session",
            ));
        }
        let runtime = stored.value;
        let provenance = self.build_runtime_checkpoint_provenance(&runtime).await?;

        let envelope = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: runtime_session_id.to_string(),
            instance_id: runtime.instance_id.to_string(),
            source_node_id: runtime.node_id.to_string(),
            target_node_id: target_node_id.to_string(),
            checkpoint_uri,
            memory_bitmap_hash,
            disk_generation: request.disk_generation,
            created_at: OffsetDateTime::now_utc(),
        };
        let digest = envelope.canonical_digest()?;
        let checkpoint_id = UvmCheckpointId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate runtime checkpoint id")
                .with_detail(error.to_string())
        })?;

        Ok(UvmRuntimeCheckpointRecord {
            id: checkpoint_id.clone(),
            runtime_session_id: runtime_session_id.clone(),
            instance_id: runtime.instance_id,
            source_node_id: runtime.node_id,
            target_node_id,
            kind,
            checkpoint_uri: envelope.checkpoint_uri,
            memory_bitmap_hash: envelope.memory_bitmap_hash,
            disk_generation: envelope.disk_generation,
            envelope_digest: digest,
            provenance,
            created_at: envelope.created_at,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(checkpoint_id.to_string()),
                sha256_hex(checkpoint_id.as_str().as_bytes()),
            ),
        })
    }

    async fn store_runtime_checkpoint(
        &self,
        checkpoint: UvmRuntimeCheckpointRecord,
        context: &RequestContext,
    ) -> Result<()> {
        self.runtime_checkpoints
            .create(checkpoint.id.as_str(), checkpoint.clone())
            .await?;
        if let Some(stored) = self
            .runtime_sessions
            .get(checkpoint.runtime_session_id.as_str())
            .await?
            && !stored.deleted
        {
            let mut runtime = stored.value;
            runtime.last_checkpoint_id = Some(checkpoint.id.clone());
            runtime
                .metadata
                .touch(sha256_hex(runtime.id.as_str().as_bytes()));
            let runtime_key = runtime.id.to_string();
            self.runtime_sessions
                .upsert(runtime_key.as_str(), runtime, Some(stored.version))
                .await?;
        }
        self.append_event(
            "uvm.node.checkpoint.created.v1",
            "uvm_runtime_checkpoint",
            checkpoint.id.as_str(),
            "created",
            serde_json::json!({
                "runtime_session_id": checkpoint.runtime_session_id,
                "kind": checkpoint.kind,
                "envelope_digest": checkpoint.envelope_digest,
                "provenance": &checkpoint.provenance,
            }),
            context,
        )
        .await
    }

    async fn find_runtime_session_for_instance(
        &self,
        instance_id: &UvmInstanceId,
    ) -> Result<Option<StoredDocument<UvmRuntimeSessionRecord>>> {
        let values = self.runtime_sessions.list().await?;
        let mut selected: Option<StoredDocument<UvmRuntimeSessionRecord>> = None;
        for (_, stored) in values {
            if stored.deleted || stored.value.instance_id != *instance_id {
                continue;
            }
            if selected.is_some() {
                return Err(PlatformError::conflict(
                    "multiple runtime sessions exist for this instance",
                ));
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn find_matching_runtime_session(
        &self,
        candidate: &UvmRuntimeSessionRecord,
    ) -> Result<Option<UvmRuntimeSessionRecord>> {
        let values = self.runtime_sessions.list().await?;
        for (_, stored) in values {
            if stored.deleted {
                continue;
            }
            let value = stored.value;
            if runtime_session_registration_equivalent(&value, candidate) {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    async fn find_matching_checkpoint(
        &self,
        candidate: &UvmRuntimeCheckpointRecord,
    ) -> Result<Option<UvmRuntimeCheckpointRecord>> {
        let values = self.runtime_checkpoints.list().await?;
        for (_, stored) in values {
            if stored.deleted {
                continue;
            }
            let value = stored.value;
            if value.runtime_session_id == candidate.runtime_session_id
                && value.source_node_id == candidate.source_node_id
                && value.target_node_id == candidate.target_node_id
                && value.kind == candidate.kind
                && value.checkpoint_uri == candidate.checkpoint_uri
                && value.memory_bitmap_hash == candidate.memory_bitmap_hash
                && value.disk_generation == candidate.disk_generation
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    async fn find_in_progress_runtime_migration(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> Result<Option<StoredDocument<UvmRuntimeMigrationRecord>>> {
        let values = self.runtime_migrations.list().await?;
        let mut selected: Option<StoredDocument<UvmRuntimeMigrationRecord>> = None;
        for (_, stored) in values {
            if stored.deleted
                || stored.value.runtime_session_id != *runtime_session_id
                || stored.value.state != "in_progress"
            {
                continue;
            }
            if selected.is_some() {
                return Err(PlatformError::conflict(
                    "multiple in-progress runtime migration records exist for this runtime session",
                ));
            }
            selected = Some(stored);
        }
        Ok(selected)
    }

    async fn load_active_runner_supervision_record(
        &self,
        runtime: &UvmRuntimeSessionRecord,
    ) -> Result<Option<UvmRunnerSupervisionRecord>> {
        let Some(key) = active_runner_supervision_key(runtime) else {
            return Ok(None);
        };
        Ok(self
            .runner_supervision
            .get(&key)
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value))
    }

    async fn resolve_runtime_repair_checkpoint(
        &self,
        runtime: &UvmRuntimeSessionRecord,
    ) -> Result<Option<UvmRuntimeCheckpointRecord>> {
        if let Some(checkpoint_id) = runtime.last_checkpoint_id.as_ref()
            && let Some(stored) = self.runtime_checkpoints.get(checkpoint_id.as_str()).await?
            && !stored.deleted
            && stored.value.runtime_session_id == runtime.id
        {
            return Ok(Some(stored.value));
        }
        let mut selected: Option<UvmRuntimeCheckpointRecord> = None;
        for (_, stored) in self.runtime_checkpoints.list().await? {
            if stored.deleted || stored.value.runtime_session_id != runtime.id {
                continue;
            }
            if selected
                .as_ref()
                .map(|current| current.created_at >= stored.value.created_at)
                .unwrap_or(false)
            {
                continue;
            }
            selected = Some(stored.value);
        }
        Ok(selected)
    }

    async fn select_runtime_repair(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        stale_after_seconds: i64,
        hinted_target_node_id: Option<&NodeId>,
        hinted_target_capability_id: Option<&UvmNodeCapabilityId>,
        execution_intent_hint: Option<&UvmExecutionIntent>,
    ) -> Result<RuntimeRepairSelection> {
        let heartbeat_stale = runtime_heartbeat_is_stale(runtime, stale_after_seconds)?;
        let health_failed =
            HypervisorHealth::parse(&runtime.hypervisor_health)? == HypervisorHealth::Failed;
        let active_drain = self.find_active_node_drain(&runtime.node_id).await?;
        let active_drain_record = active_drain.as_ref().map(|stored| &stored.value);
        let runner_supervision = self.load_active_runner_supervision_record(runtime).await?;
        let checkpoint = self.resolve_runtime_repair_checkpoint(runtime).await?;
        let restart_budget_remaining = runtime_repair_restart_budget_remaining(runtime);
        let runner_stopped = runtime.state == VmRuntimeState::Stopped
            || runtime.runner_phase == "stopped"
            || runner_supervision
                .as_ref()
                .map(|record| record.state == "stopped")
                .unwrap_or(false);
        let runner_failed = runtime.state == VmRuntimeState::Failed
            || runtime.runner_phase == "failed"
            || runner_supervision
                .as_ref()
                .map(|record| {
                    record.state == "failed"
                        || record.failure_detail.is_some()
                        || record
                            .exit_status
                            .map(|status| status != 0)
                            .unwrap_or(false)
                })
                .unwrap_or(false);
        let node_requires_migration =
            heartbeat_stale || health_failed || active_drain_record.is_some();
        let mut evidence = runtime_repair_evidence(
            runtime,
            stale_after_seconds,
            heartbeat_stale,
            health_failed,
            active_drain_record,
            runner_supervision.as_ref(),
            checkpoint.as_ref(),
            restart_budget_remaining,
        );

        if node_requires_migration {
            if runtime.state != VmRuntimeState::Running {
                return Err(PlatformError::conflict(
                    "runtime repair requires migration, but the runtime session is not running",
                ));
            }
            if MigrationStrategy::parse(&runtime.migration_policy)? == MigrationStrategy::Cold {
                return Err(PlatformError::conflict(
                    "runtime repair requires migration, but migration_policy is cold_only",
                ));
            }
            let Some((target_node_id, target_capability_id)) = self
                .select_runtime_repair_migration_target(
                    runtime,
                    hinted_target_node_id,
                    hinted_target_capability_id,
                    execution_intent_hint,
                )
                .await?
            else {
                return Err(PlatformError::conflict(
                    "runtime repair requires migration, but no eligible target capability is available",
                ));
            };
            evidence.push(format!("selected_target_node_id={target_node_id}"));
            evidence.push(format!(
                "selected_target_capability_id={target_capability_id}"
            ));
            return Ok(RuntimeRepairSelection {
                selected_action: "migration",
                checkpoint_id: None,
                target_node_id: Some(target_node_id),
                target_capability_id: Some(target_capability_id),
                evidence,
            });
        }

        if runner_stopped && restart_budget_remaining {
            evidence.push(String::from("selected_action=restart"));
            return Ok(RuntimeRepairSelection {
                selected_action: "restart",
                checkpoint_id: None,
                target_node_id: None,
                target_capability_id: None,
                evidence,
            });
        }

        if (runner_failed || runtime.state == VmRuntimeState::Stopped)
            && let Some(checkpoint) = checkpoint
        {
            evidence.push(format!("selected_checkpoint_id={}", checkpoint.id));
            evidence.push(String::from("selected_action=restore"));
            return Ok(RuntimeRepairSelection {
                selected_action: "restore",
                checkpoint_id: Some(checkpoint.id),
                target_node_id: None,
                target_capability_id: None,
                evidence,
            });
        }

        if runner_stopped {
            return Err(PlatformError::conflict(
                "runtime repair found stopped runner evidence, but restart budget is exhausted and no checkpoint is available for restore",
            ));
        }
        if runner_failed {
            return Err(PlatformError::conflict(
                "runtime repair found failed runner evidence, but no checkpoint is available for restore",
            ));
        }
        Err(PlatformError::conflict(
            "runtime repair found no actionable runner or node evidence",
        ))
    }

    async fn select_runtime_repair_migration_target(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        hinted_target_node_id: Option<&NodeId>,
        hinted_target_capability_id: Option<&UvmNodeCapabilityId>,
        execution_intent_hint: Option<&UvmExecutionIntent>,
    ) -> Result<Option<(NodeId, UvmNodeCapabilityId)>> {
        let guest_architecture = GuestArchitecture::parse(runtime.guest_architecture.as_str())?;
        let apple_guest = is_apple_guest_os(&runtime.guest_os);
        let require_secure_boot = has_secure_boot_flag(&runtime.launch_args);
        let execution_intent = match execution_intent_hint {
            Some(intent) => intent.clone(),
            None => {
                self.resolve_runtime_session_execution_intent(
                    &runtime.id,
                    &runtime.instance_id,
                    &runtime.guest_profile,
                )
                .await?
            }
        };
        let mut candidates = self
            .capabilities
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|capability| capability.node_id != runtime.node_id)
            .filter(|capability| {
                hinted_target_node_id
                    .map(|node_id| capability.node_id == *node_id)
                    .unwrap_or(true)
            })
            .filter(|capability| {
                hinted_target_capability_id
                    .map(|capability_id| capability.id == *capability_id)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.node_id
                .as_str()
                .cmp(right.node_id.as_str())
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        });
        for capability in candidates {
            if self
                .find_active_node_drain(&capability.node_id)
                .await?
                .is_some()
            {
                continue;
            }
            if self
                .select_backend_for_capability_with_execution_intent(
                    &capability,
                    guest_architecture,
                    apple_guest,
                    true,
                    require_secure_boot,
                    &execution_intent,
                )
                .is_err()
            {
                continue;
            }
            let placement = match self.evaluate_target_runtime_placement(runtime, &capability) {
                Ok(placement) => placement,
                Err(_) => continue,
            };
            if !placement.admitted {
                continue;
            }
            return Ok(Some((capability.node_id, capability.id)));
        }
        if hinted_target_node_id.is_some() || hinted_target_capability_id.is_some() {
            return Err(PlatformError::conflict(
                "requested repair migration target is not eligible for this runtime session",
            ));
        }
        Ok(None)
    }

    async fn migration_matches_start_request(
        &self,
        existing: &UvmRuntimeMigrationRecord,
        to_node_id: &NodeId,
        target_capability_id: &UvmNodeCapabilityId,
        kind: &str,
        checkpoint_uri: &str,
        memory_bitmap_hash: &str,
        disk_generation: u64,
        reason: &str,
    ) -> Result<bool> {
        if existing.target_node_id != *to_node_id
            || existing.target_capability_id != *target_capability_id
            || existing.reason != reason
        {
            return Ok(false);
        }
        let checkpoint = self
            .runtime_checkpoints
            .get(existing.checkpoint_id.as_str())
            .await?
            .ok_or_else(|| {
                PlatformError::conflict(
                    "runtime migration references a checkpoint record that does not exist",
                )
            })?;
        if checkpoint.deleted {
            return Err(PlatformError::conflict(
                "runtime migration references a deleted checkpoint record",
            ));
        }
        Ok(checkpoint.value.kind == kind
            && checkpoint.value.checkpoint_uri == checkpoint_uri
            && checkpoint.value.memory_bitmap_hash == memory_bitmap_hash
            && checkpoint.value.disk_generation == disk_generation
            && checkpoint.value.target_node_id == *to_node_id)
    }

    async fn resolve_runtime_migration(
        &self,
        migration_id: &str,
        action: &str,
        request: ResolveRuntimeMigrationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let migration_id = UvmMigrationId::parse(migration_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid runtime migration id").with_detail(error.to_string())
        })?;
        let stored = self
            .runtime_migrations
            .get(migration_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime migration does not exist"))?;
        if stored.value.state == "in_progress" {
            let in_progress = self
                .find_in_progress_runtime_migration(&stored.value.runtime_session_id)
                .await?;
            let active = in_progress.ok_or_else(|| {
                PlatformError::conflict(
                    "runtime migration is marked in_progress but no active migration record exists",
                )
            })?;
            if active.value.id != stored.value.id {
                return Err(PlatformError::conflict(
                    "another runtime migration is in progress for this runtime session",
                ));
            }
        }
        if !migration_state_supports_action(&stored.value.state, action) {
            return Err(PlatformError::conflict(
                "runtime migration is not in progress",
            ));
        }
        let terminal_state = terminal_migration_state(action);
        if stored.value.state == terminal_state {
            if let Some(runtime_stored) = self
                .runtime_sessions
                .get(stored.value.runtime_session_id.as_str())
                .await?
                && !runtime_stored.deleted
            {
                if action == "commit"
                    && runtime_migration_cutover_is_already_applied(
                        &runtime_stored.value,
                        &stored.value,
                    )
                {
                    self.reconcile_migration_cutover_replay_side_effects(
                        &runtime_stored.value,
                        &stored.value,
                        context,
                    )
                    .await?;
                    self.project_runtime_session_into_node_plane(&runtime_stored.value)
                        .await?;
                }
                if matches!(action, "rollback" | "fail")
                    && runtime_migration_terminal_is_already_applied(
                        &runtime_stored.value,
                        &stored.value,
                    )
                {
                    self.reconcile_migration_terminal_replay_side_effects(
                        &runtime_stored.value,
                        &stored.value,
                        action,
                        context,
                    )
                    .await?;
                    self.project_runtime_session_into_node_plane(&runtime_stored.value)
                        .await?;
                }
            }
            return json_response(StatusCode::OK, &stored.value);
        }
        let failure_detail = normalize_optional_failure_detail(request.error)?;
        let mut migration = stored.value;
        match action {
            "commit" => {
                let runtime_stored = self
                    .runtime_sessions
                    .get(migration.runtime_session_id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("runtime session does not exist"))?;
                if runtime_migration_cutover_is_already_applied(&runtime_stored.value, &migration) {
                    migration.state = String::from("committed");
                    migration.failure_detail = None;
                } else {
                    if runtime_stored.value.state != VmRuntimeState::Running {
                        return Err(PlatformError::conflict(
                            "runtime migration commit requires running runtime session",
                        ));
                    }
                    if !runtime_stored.value.migration_in_progress {
                        return Err(PlatformError::conflict(
                            "runtime migration commit requires migration_in_progress lock on runtime session",
                        ));
                    }
                    let target_capability = self
                        .lookup_capability(&migration.target_capability_id)
                        .await?
                        .value;
                    self.ensure_node_accepts_new_runtime_work(&migration.target_node_id)
                        .await?;
                    let guest_architecture =
                        GuestArchitecture::parse(runtime_stored.value.guest_architecture.as_str())?;
                    let apple_guest = is_apple_guest_os(&runtime_stored.value.guest_os);
                    let require_secure_boot =
                        has_secure_boot_flag(&runtime_stored.value.launch_args);
                    let execution_intent = self
                        .resolve_runtime_session_execution_intent(
                            &migration.runtime_session_id,
                            &runtime_stored.value.instance_id,
                            &runtime_stored.value.guest_profile,
                        )
                        .await?;
                    let selected = self.select_backend_for_capability_with_execution_intent(
                        &target_capability,
                        guest_architecture,
                        apple_guest,
                        true,
                        require_secure_boot,
                        &execution_intent,
                    )?;
                    let placement = self.evaluate_target_runtime_placement(
                        &runtime_stored.value,
                        &target_capability,
                    )?;
                    if !placement.admitted {
                        return Err(PlatformError::conflict(format!(
                            "target placement denied at migration commit: {}",
                            placement.blockers.join("; ")
                        )));
                    }

                    let mut runtime = runtime_stored.value;
                    let launch_spec = launch_spec_from_runtime_session(&runtime)?;
                    let cpu_topology =
                        CpuTopologySpec::from_profile(&runtime.cpu_topology_profile, runtime.vcpu)?;
                    let numa_policy = NumaPolicySpec::from_profile(
                        &runtime.numa_policy_profile,
                        target_capability.numa_nodes.max(1),
                    )?;
                    let migration_strategy = MigrationStrategy::parse(&runtime.migration_policy)?;
                    let migration_plan = evaluate_migration_budget(
                        selected.backend,
                        &MigrationBudget {
                            strategy: migration_strategy,
                            max_downtime_ms: runtime.planned_migration_downtime_ms.max(1),
                            max_iterations: 5,
                            available_bandwidth_mbps: 10_000,
                            dirty_page_rate_mbps: (runtime.memory_mb / 64).max(1),
                            memory_mb: runtime.memory_mb,
                        },
                    )?;
                    let execution_plan = synthesize_execution_plan(&ExecutionPlanRequest {
                        backend: selected.backend,
                        launch_spec: &launch_spec,
                        placement: &placement,
                        migration_plan: &migration_plan,
                        cpu_topology: &cpu_topology,
                        numa_policy: &numa_policy,
                        isolation_profile: &runtime.isolation_profile,
                        restart_policy: &runtime.restart_policy,
                    })?;
                    let software_disk_artifact_uri =
                        if selected.backend == HypervisorBackend::SoftwareDbt {
                            self.resolve_verified_local_disk_artifact_uri(&launch_spec.disk_image)
                                .await?
                        } else {
                            None
                        };
                    let software_firmware_artifact_uri =
                        if selected.backend == HypervisorBackend::SoftwareDbt {
                            self.resolve_preserved_local_firmware_artifact_uri(&launch_spec)
                                .await?
                        } else {
                            None
                        };
                    let (launch_program, launch_args, launch_env) =
                        build_persisted_launch_contract(
                            selected.backend,
                            &execution_plan,
                            software_disk_artifact_uri.as_deref(),
                            software_firmware_artifact_uri.as_deref(),
                        )?;
                    let previous_state = runtime.state;
                    let source_node_id = runtime.node_id.clone();
                    let target_node_id = migration.target_node_id.clone();
                    let activated_at = OffsetDateTime::now_utc();
                    runtime.node_id = target_node_id.clone();
                    runtime.capability_id = migration.target_capability_id.clone();
                    runtime.accelerator_backend = String::from(selected.backend.as_str());
                    runtime.planned_pinned_numa_nodes = placement.pinned_numa_nodes;
                    runtime.planned_memory_per_numa_mb = placement.per_node_memory_mb;
                    runtime.launch_program = launch_program;
                    runtime.launch_args = launch_args;
                    runtime.launch_env = launch_env;
                    runtime.boot_path = execution_plan.boot_path;
                    runtime.execution_class = execution_plan.execution_class;
                    runtime.memory_backing = execution_plan.memory_backing;
                    runtime.device_model = execution_plan.device_model;
                    runtime.sandbox_layers = execution_plan.sandbox_layers;
                    runtime.telemetry_streams = execution_plan.telemetry_streams;
                    runtime.migration_in_progress = false;
                    runtime.last_transition_at = activated_at;
                    record_runtime_incarnation(
                        &mut runtime,
                        UvmRuntimeIncarnationKind::PostMigrationCutover,
                        Some(previous_state),
                        Some(source_node_id),
                        target_node_id,
                        Some(migration.checkpoint_id.clone()),
                        Some(migration.id.clone()),
                        Some(migration.reason.clone()),
                        activated_at,
                    );
                    runtime
                        .metadata
                        .touch(sha256_hex(runtime.id.as_str().as_bytes()));
                    let runtime_id = runtime.id.clone();
                    self.runtime_sessions
                        .upsert(runtime_id.as_str(), runtime, Some(runtime_stored.version))
                        .await?;
                    migration.state = String::from("committed");
                    migration.failure_detail = None;
                }
            }
            "rollback" => {
                if let Some(runtime_stored) = self
                    .runtime_sessions
                    .get(migration.runtime_session_id.as_str())
                    .await?
                    && !runtime_stored.deleted
                {
                    let mut runtime = runtime_stored.value;
                    runtime.migration_in_progress = false;
                    runtime.last_transition_at = OffsetDateTime::now_utc();
                    runtime
                        .metadata
                        .touch(sha256_hex(runtime.id.as_str().as_bytes()));
                    let runtime_id = runtime.id.clone();
                    self.runtime_sessions
                        .upsert(runtime_id.as_str(), runtime, Some(runtime_stored.version))
                        .await?;
                }
                migration.state = String::from("rolled_back");
                migration.failure_detail = None;
            }
            "fail" => {
                if let Some(runtime_stored) = self
                    .runtime_sessions
                    .get(migration.runtime_session_id.as_str())
                    .await?
                    && !runtime_stored.deleted
                {
                    let mut runtime = runtime_stored.value;
                    runtime.migration_in_progress = false;
                    runtime.last_transition_at = OffsetDateTime::now_utc();
                    runtime.last_error = failure_detail
                        .clone()
                        .or_else(|| Some(String::from("runtime migration failed without detail")));
                    runtime
                        .metadata
                        .touch(sha256_hex(runtime.id.as_str().as_bytes()));
                    let runtime_id = runtime.id.clone();
                    self.runtime_sessions
                        .upsert(runtime_id.as_str(), runtime, Some(runtime_stored.version))
                        .await?;
                }
                migration.state = String::from("failed");
                migration.failure_detail = failure_detail
                    .or_else(|| Some(String::from("runtime migration failed without detail")));
            }
            _ => {
                return Err(PlatformError::invalid(
                    "unknown runtime migration resolution action",
                ));
            }
        }

        migration.updated_at = OffsetDateTime::now_utc();
        migration
            .metadata
            .touch(sha256_hex(migration.id.as_str().as_bytes()));
        self.runtime_migrations
            .upsert(
                migration.id.as_str(),
                migration.clone(),
                Some(stored.version),
            )
            .await?;
        let current_runtime = if let Some(runtime_stored) = self
            .runtime_sessions
            .get(migration.runtime_session_id.as_str())
            .await?
            && !runtime_stored.deleted
        {
            self.project_runtime_session_into_node_plane(&runtime_stored.value)
                .await?;
            Some(runtime_stored.value)
        } else {
            None
        };
        let operation_state = match action {
            "commit" => UvmNodeOperationState::Completed,
            "rollback" => UvmNodeOperationState::RolledBack,
            "fail" => UvmNodeOperationState::Failed,
            _ => {
                return Err(PlatformError::invalid(
                    "unknown runtime migration resolution action",
                ));
            }
        };
        if action == "commit"
            && let Some(runtime) = current_runtime.as_ref()
            && runtime_migration_cutover_is_already_applied(runtime, &migration)
        {
            self.reconcile_migration_cutover_replay_side_effects(runtime, &migration, context)
                .await?;
            return json_response(StatusCode::OK, &migration);
        }
        if matches!(action, "rollback" | "fail")
            && let Some(runtime) = current_runtime.as_ref()
            && runtime_migration_terminal_is_already_applied(runtime, &migration)
        {
            self.reconcile_migration_terminal_replay_side_effects(
                runtime, &migration, action, context,
            )
            .await?;
            return json_response(StatusCode::OK, &migration);
        }
        if let Some(existing) = self
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration.id.as_str(),
            )
            .await?
        {
            let _ = self
                .update_node_operation_record(
                    existing,
                    Some(operation_state),
                    migration.failure_detail.clone(),
                    Some(migration.state.clone()),
                    current_runtime.as_ref().map(|runtime| runtime.state),
                    Some(migration.target_node_id.clone()),
                )
                .await?;
        } else {
            let _ = self
                .create_node_operation_record(NodeOperationCreateRequest {
                    target_node_id: Some(migration.target_node_id.clone()),
                    runtime_session_id: Some(migration.runtime_session_id.clone()),
                    instance_id: Some(migration.instance_id.clone()),
                    reason: Some(migration.reason.clone()),
                    detail: migration.failure_detail.clone(),
                    phase: Some(migration.state.clone()),
                    to_state: current_runtime.as_ref().map(|runtime| runtime.state),
                    checkpoint_id: Some(migration.checkpoint_id.clone()),
                    linked_resource_kind: Some(String::from("runtime_migration")),
                    linked_resource_id: Some(migration.id.to_string()),
                    ..NodeOperationCreateRequest::new(
                        UvmNodeOperationKind::Migrate,
                        operation_state,
                        migration.source_node_id.clone(),
                    )
                })
                .await?;
        }
        self.append_event(
            match action {
                "commit" => "uvm.migration.committed.v1",
                "rollback" => "uvm.migration.rolled_back.v1",
                "fail" => "uvm.migration.failed.v1",
                _ => "uvm.migration.unknown.v1",
            },
            "uvm_runtime_migration",
            migration.id.as_str(),
            action,
            serde_json::json!({
                "runtime_session_id": migration.runtime_session_id,
                "state": migration.state,
                "failure_detail": migration.failure_detail,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &migration)
    }

    async fn lookup_capability(
        &self,
        capability_id: &UvmNodeCapabilityId,
    ) -> Result<StoredDocument<UvmNodeCapabilityRecord>> {
        self.capabilities
            .get(capability_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("node capability does not exist"))
    }

    async fn resolve_registration_execution_intent(
        &self,
        instance_id: &UvmInstanceId,
        guest_profile: &str,
    ) -> Result<UvmExecutionIntent> {
        Ok(self
            .load_control_plane_instance_execution_intent(instance_id)
            .await?
            .unwrap_or_else(|| default_execution_intent_for_guest_profile(guest_profile)))
    }

    async fn resolve_runtime_session_execution_intent(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
        instance_id: &UvmInstanceId,
        guest_profile: &str,
    ) -> Result<UvmExecutionIntent> {
        if let Some(intent) = self
            .load_persisted_runtime_session_execution_intent(runtime_session_id)
            .await?
        {
            return Ok(intent);
        }
        Ok(self
            .load_control_plane_instance_execution_intent(instance_id)
            .await?
            .unwrap_or_else(|| default_execution_intent_for_guest_profile(guest_profile)))
    }

    fn assess_registration_portability_for_capability(
        &self,
        capability: &UvmNodeCapabilityRecord,
        guest_architecture: GuestArchitecture,
        apple_guest: bool,
        requires_live_migration: bool,
        require_secure_boot: bool,
        execution_intent: &UvmExecutionIntent,
        selected_backend: HypervisorBackend,
        image_compatibility_artifact: Option<&ScopedImageCompatibilityArtifact>,
    ) -> Result<UvmPortabilityAssessment> {
        let portability_request = BackendSelectionRequest {
            host: HostPlatform::parse(&capability.host_platform).map_err(|error| {
                PlatformError::invalid("capability host_platform is invalid")
                    .with_detail(error.to_string())
            })?,
            candidates: capability
                .accelerator_backends
                .iter()
                .map(|backend| HypervisorBackend::parse(backend))
                .collect::<Result<Vec<_>>>()?,
            guest_architecture,
            apple_guest,
            requires_live_migration,
            require_secure_boot,
        };
        let mut portability_assessment = assess_execution_intent(
            &portability_request,
            Some(execution_intent),
            Some(capability.host_evidence_mode.as_str()),
        )?;
        if portability_assessment.selected_backend == Some(HypervisorBackend::SoftwareDbt)
            && !capability.software_runner_supported
        {
            portability_assessment.blockers.push(String::from(
                "software_dbt backend requires software_runner_supported capability posture",
            ));
            portability_assessment.supported = false;
            portability_assessment.selected_backend = None;
            portability_assessment.selected_via_fallback = false;
            portability_assessment.selection_reason = None;
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                    summary: String::from(
                        "software_dbt candidate rejected because software_runner_supported=false",
                    ),
                    evidence_mode: None,
                });
        }
        if !portability_assessment.supported {
            let detail = if portability_assessment.blockers.is_empty() {
                String::from(
                    "execution intent portability assessment reported unsupported placement",
                )
            } else {
                portability_assessment.blockers.join("; ")
            };
            return Err(PlatformError::conflict(detail));
        }
        if portability_assessment.selected_backend != Some(selected_backend) {
            return Err(PlatformError::conflict(
                "runtime registration portability assessment drifted from selected backend",
            ));
        }
        if let Some(artifact) = image_compatibility_artifact {
            portability_assessment
                .evidence
                .push(UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::ImageContract,
                    summary: format!(
                        "scoped image compatibility artifact row_id={} host_class={} region={} cell={} accelerator_backend={} machine_family={} guest_profile={} claim_tier={} secure_boot_supported={} live_migration_supported={} policy_approved={}",
                        artifact.row_id,
                        artifact.host_class,
                        artifact.region,
                        artifact.cell,
                        artifact.accelerator_backend,
                        artifact.machine_family,
                        artifact.guest_profile,
                        artifact.claim_tier,
                        artifact.secure_boot_supported,
                        artifact.live_migration_supported,
                        artifact.policy_approved,
                    ),
                    evidence_mode: Some(if artifact.policy_approved {
                        String::from("policy_approved")
                    } else {
                        String::from("policy_blocked")
                    }),
                });
        }
        Ok(portability_assessment)
    }

    async fn load_control_plane_instance_execution_intent(
        &self,
        instance_id: &UvmInstanceId,
    ) -> Result<Option<UvmExecutionIntent>> {
        let Some(platform_root) = self.state_root.parent() else {
            return Ok(None);
        };
        let instances_path = platform_root.join("uvm-control").join("instances.json");
        if fs::metadata(&instances_path).await.is_err() {
            return Ok(None);
        }
        let bytes = fs::read(&instances_path).await.map_err(|error| {
            PlatformError::unavailable("failed to read UVM control-plane instance view")
                .with_detail(error.to_string())
        })?;
        let collection: DocumentCollection<serde_json::Value> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                PlatformError::invalid("failed to decode UVM control-plane instance view")
                    .with_detail(error.to_string())
            })?;
        let Some(stored) = collection.records.get(instance_id.as_str()) else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        let snapshot: UvmControlInstanceIntentSnapshot =
            serde_json::from_value(stored.value.clone()).map_err(|error| {
                PlatformError::invalid("failed to decode UVM control-plane instance snapshot")
                    .with_detail(error.to_string())
            })?;
        if snapshot.id != *instance_id {
            return Err(PlatformError::invalid(
                "control-plane instance snapshot id does not match record key",
            ));
        }
        Ok(snapshot.execution_intent)
    }

    async fn load_persisted_runtime_session_execution_intent(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> Result<Option<UvmExecutionIntent>> {
        Ok(self
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value.execution_intent))
    }

    async fn normalize_capability_host_classes(&self) -> Result<()> {
        let mut records = self.capabilities.list().await?;
        records.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in records {
            if stored.deleted {
                continue;
            }

            let mut capability = stored.value.clone();
            let host_platform =
                HostPlatform::parse(&capability.host_platform).map_err(|error| {
                    PlatformError::invalid("capability host_platform is invalid")
                        .with_detail(error.to_string())
                })?;
            let normalized_host_platform = String::from(host_platform.as_str());
            let normalized_host_evidence_mode =
                normalize_host_evidence_mode(&capability.host_evidence_mode)?;
            let derived_host_class = derive_node_host_class(
                host_platform,
                &normalized_host_evidence_mode,
                capability.container_restricted,
            );

            let mut changed = false;
            if capability.host_platform != normalized_host_platform {
                capability.host_platform = normalized_host_platform;
                changed = true;
            }
            if capability.host_evidence_mode != normalized_host_evidence_mode {
                capability.host_evidence_mode = normalized_host_evidence_mode;
                changed = true;
            }
            if capability.host_class != derived_host_class {
                capability.host_class = derived_host_class;
                changed = true;
            }

            if changed {
                self.capabilities
                    .upsert(&key, capability, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn persist_runtime_session_execution_intent(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
        instance_id: &UvmInstanceId,
        execution_intent: &UvmExecutionIntent,
        first_placement_portability_assessment: Option<&UvmPortabilityAssessment>,
    ) -> Result<()> {
        let supplied_assessment = first_placement_portability_assessment.cloned();
        if let Some(stored) = self
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await?
        {
            if stored.deleted {
                return Err(PlatformError::conflict(
                    "runtime session execution intent record was deleted unexpectedly",
                ));
            }
            if stored.value.instance_id != *instance_id
                || stored.value.execution_intent != *execution_intent
            {
                return Err(PlatformError::conflict(
                    "runtime session execution intent already exists for this session",
                ));
            }
            match (
                stored.value.first_placement_portability_assessment.as_ref(),
                supplied_assessment.as_ref(),
            ) {
                (Some(existing), Some(supplied)) if existing != supplied => {
                    return Err(PlatformError::conflict(
                        "runtime session first-placement portability assessment already exists for this session",
                    ));
                }
                (Some(_), _) | (None, None) => {
                    return Ok(());
                }
                (None, Some(_)) => {}
            }

            let mut record = stored.value;
            record.first_placement_portability_assessment = supplied_assessment;
            record
                .metadata
                .touch(sha256_hex(runtime_session_id.as_str().as_bytes()));
            self.runtime_session_intents
                .upsert(runtime_session_id.as_str(), record, Some(stored.version))
                .await?;
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        let record = UvmRuntimeSessionIntentRecord {
            lineage_id: Some(allocate_runtime_session_intent_lineage_id()?),
            runtime_session_id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            execution_intent: execution_intent.clone(),
            first_placement_portability_assessment: supplied_assessment,
            last_portability_preflight_id: None,
            created_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(runtime_session_id.to_string()),
                sha256_hex(runtime_session_id.as_str().as_bytes()),
            ),
        };
        self.runtime_session_intents
            .create(runtime_session_id.as_str(), record)
            .await?;
        Ok(())
    }

    async fn persist_runtime_session_portability_preflight(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
        instance_id: &UvmInstanceId,
        execution_intent: &UvmExecutionIntent,
        preflight_id: &AuditId,
    ) -> Result<()> {
        if let Some(stored) = self
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await?
        {
            if stored.deleted {
                return Err(PlatformError::conflict(
                    "runtime session execution intent record was deleted unexpectedly",
                ));
            }
            if stored.value.instance_id != *instance_id {
                return Err(PlatformError::conflict(
                    "runtime session execution intent record instance_id does not match runtime session",
                ));
            }
            if stored.value.execution_intent != *execution_intent {
                return Err(PlatformError::conflict(
                    "runtime session execution intent record does not match resolved execution intent",
                ));
            }
            if stored.value.last_portability_preflight_id.as_ref() == Some(preflight_id) {
                return Ok(());
            }

            let mut record = stored.value;
            record.last_portability_preflight_id = Some(preflight_id.clone());
            record
                .metadata
                .touch(sha256_hex(runtime_session_id.as_str().as_bytes()));
            self.runtime_session_intents
                .upsert(runtime_session_id.as_str(), record, Some(stored.version))
                .await?;
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        let record = UvmRuntimeSessionIntentRecord {
            lineage_id: Some(allocate_runtime_session_intent_lineage_id()?),
            runtime_session_id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            execution_intent: execution_intent.clone(),
            first_placement_portability_assessment: None,
            last_portability_preflight_id: Some(preflight_id.clone()),
            created_at: now,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(runtime_session_id.to_string()),
                sha256_hex(runtime_session_id.as_str().as_bytes()),
            ),
        };
        self.runtime_session_intents
            .create(runtime_session_id.as_str(), record)
            .await?;
        Ok(())
    }

    fn select_backend_for_capability_with_execution_intent(
        &self,
        capability: &UvmNodeCapabilityRecord,
        guest_architecture: GuestArchitecture,
        apple_guest: bool,
        requires_live_migration: bool,
        require_secure_boot: bool,
        execution_intent: &UvmExecutionIntent,
    ) -> Result<uhost_uvm::BackendSelection> {
        if capability.architecture != guest_architecture.as_str() {
            return Err(PlatformError::conflict(
                "host capability architecture does not match guest architecture",
            ));
        }
        if requires_live_migration && !capability.supports_live_migration {
            return Err(PlatformError::conflict(
                "selected capability does not support live migration",
            ));
        }
        if require_secure_boot && !capability.supports_secure_boot {
            return Err(PlatformError::conflict(
                "selected capability does not support secure boot",
            ));
        }

        let host = HostPlatform::parse(&capability.host_platform).map_err(|error| {
            PlatformError::invalid("capability host_platform is invalid")
                .with_detail(error.to_string())
        })?;
        let candidates = capability
            .accelerator_backends
            .iter()
            .map(|backend| HypervisorBackend::parse(backend))
            .collect::<Result<Vec<_>>>()?;
        let portability_request = BackendSelectionRequest {
            host,
            candidates,
            guest_architecture,
            apple_guest,
            requires_live_migration,
            require_secure_boot,
        };
        let portability_assessment = assess_execution_intent(
            &portability_request,
            Some(execution_intent),
            Some(capability.host_evidence_mode.as_str()),
        )?;
        if !portability_assessment.supported {
            let detail = if portability_assessment.blockers.is_empty() {
                String::from(
                    "execution intent portability assessment reported unsupported placement",
                )
            } else {
                portability_assessment.blockers.join("; ")
            };
            return Err(PlatformError::conflict(detail));
        }
        let selected_backend = portability_assessment.selected_backend.ok_or_else(|| {
            PlatformError::conflict(
                "no backend selected by execution intent portability assessment",
            )
        })?;
        if selected_backend == HypervisorBackend::SoftwareDbt
            && !capability.software_runner_supported
        {
            return Err(PlatformError::conflict(
                "software_dbt backend requires software_runner_supported capability posture",
            ));
        }
        Ok(uhost_uvm::BackendSelection {
            backend: selected_backend,
            reason: portability_assessment.selection_reason.unwrap_or_else(|| {
                format!(
                    "selected {} from execution intent portability assessment",
                    selected_backend.as_str()
                )
            }),
        })
    }

    fn select_backend_for_capability(
        &self,
        capability: &UvmNodeCapabilityRecord,
        guest_architecture: GuestArchitecture,
        apple_guest: bool,
        requires_live_migration: bool,
        require_secure_boot: bool,
    ) -> Result<uhost_uvm::BackendSelection> {
        if capability.architecture != guest_architecture.as_str() {
            return Err(PlatformError::conflict(
                "host capability architecture does not match guest architecture",
            ));
        }
        if requires_live_migration && !capability.supports_live_migration {
            return Err(PlatformError::conflict(
                "selected capability does not support live migration",
            ));
        }
        if require_secure_boot && !capability.supports_secure_boot {
            return Err(PlatformError::conflict(
                "selected capability does not support secure boot",
            ));
        }

        let candidates = capability
            .accelerator_backends
            .iter()
            .map(|backend| HypervisorBackend::parse(backend))
            .collect::<Result<Vec<_>>>()?;
        let host = HostPlatform::parse(&capability.host_platform).map_err(|error| {
            PlatformError::invalid("capability host_platform is invalid")
                .with_detail(error.to_string())
        })?;
        let request = BackendSelectionRequest {
            host,
            candidates,
            guest_architecture,
            apple_guest,
            requires_live_migration,
            require_secure_boot,
        };
        let selection = select_backend(&request)?;
        if selection.backend == HypervisorBackend::SoftwareDbt
            && !capability.software_runner_supported
        {
            return Err(PlatformError::conflict(
                "software_dbt backend requires software_runner_supported capability posture",
            ));
        }
        Ok(selection)
    }

    fn evaluate_target_runtime_placement(
        &self,
        runtime: &UvmRuntimeSessionRecord,
        capability: &UvmNodeCapabilityRecord,
    ) -> Result<uhost_uvm::PlacementPlan> {
        let cpu_topology =
            CpuTopologySpec::from_profile(&runtime.cpu_topology_profile, runtime.vcpu)?;
        let numa_policy =
            NumaPolicySpec::from_profile(&runtime.numa_policy_profile, capability.numa_nodes)?;
        plan_placement(&PlacementRequest {
            requested_vcpu: runtime.vcpu,
            requested_memory_mb: runtime.memory_mb,
            host_max_vcpu: capability.max_vcpu.max(1),
            host_max_memory_mb: capability.max_memory_mb.max(256),
            host_numa_nodes: capability.numa_nodes.max(1),
            cpu_topology,
            numa_policy,
        })
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
                source_service: String::from("uvm-node"),
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
            .enqueue(event_type, event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for UvmNodeService {
    fn name(&self) -> &'static str {
        "uvm-node"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/uvm/node"),
            uhost_runtime::RouteClaim::prefix("/uvm/node-capabilities"),
            uhost_runtime::RouteClaim::prefix("/uvm/device-profiles"),
            uhost_runtime::RouteClaim::prefix("/uvm/node-operations"),
            uhost_runtime::RouteClaim::prefix("/uvm/node-drains"),
            uhost_runtime::RouteClaim::prefix("/uvm/runtime"),
            uhost_runtime::RouteClaim::prefix("/uvm/node-outbox"),
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
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["uvm", "node"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "node_operations": "uvm/node-operations",
                        "node_drains": "uvm/node-drains",
                    }),
                )
                .map(Some),
                (Method::GET, ["uvm", "node-capabilities"]) => {
                    let values = self
                        .capabilities
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "node-capabilities"]) => {
                    let body: CreateNodeCapabilityRequest = parse_json(request).await?;
                    self.create_node_capability(body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "node-capabilities", "select-adapter"]) => {
                    let body: SelectAdapterRequest = parse_json(request).await?;
                    self.select_adapter(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "device-profiles"]) => {
                    let values = self
                        .device_profiles
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "device-profiles"]) => {
                    let body: CreateDeviceProfileRequest = parse_json(request).await?;
                    self.create_device_profile(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "node-operations"]) => {
                    let values = self
                        .node_operations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "node-operations", operation_id]) => {
                    let operation_id =
                        AuditId::parse(operation_id.to_owned()).map_err(|error| {
                            PlatformError::invalid("invalid node operation id")
                                .with_detail(error.to_string())
                        })?;
                    let stored = self
                        .node_operations
                        .get(operation_id.as_str())
                        .await?
                        .ok_or_else(|| PlatformError::not_found("node operation does not exist"))?;
                    if stored.deleted {
                        return Err(PlatformError::not_found("node operation does not exist"));
                    }
                    json_response(StatusCode::OK, &stored.value).map(Some)
                }
                (Method::GET, ["uvm", "node-drains"]) => {
                    let mut values = Vec::new();
                    for (_, stored) in self.node_drains.list().await? {
                        if stored.deleted {
                            continue;
                        }
                        values.push(self.materialize_node_drain_record(&stored.value).await?);
                    }
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "node-drains", drain_id]) => {
                    let drain_id = UvmNodeDrainId::parse(drain_id.to_owned()).map_err(|error| {
                        PlatformError::invalid("invalid node drain id")
                            .with_detail(error.to_string())
                    })?;
                    let stored = self
                        .node_drains
                        .get(drain_id.as_str())
                        .await?
                        .ok_or_else(|| PlatformError::not_found("node drain does not exist"))?;
                    if stored.deleted {
                        return Err(PlatformError::not_found("node drain does not exist"));
                    }
                    let materialized = self.materialize_node_drain_record(&stored.value).await?;
                    json_response(StatusCode::OK, &materialized).map(Some)
                }
                (Method::POST, ["uvm", "node-drains"]) => {
                    let body: CreateNodeDrainRequest = parse_json(request).await?;
                    self.create_node_drain(body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "node-drains", drain_id, "evacuate"]) => self
                    .transition_node_drain(drain_id, "evacuate", None, &context)
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "node-drains", drain_id, "complete"]) => self
                    .transition_node_drain(drain_id, "complete", None, &context)
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "node-drains", drain_id, "fail"]) => {
                    let body: ResolveNodeDrainRequest = parse_json(request).await?;
                    self.transition_node_drain(drain_id, "fail", body.error, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "runtime"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "runtime_sessions": "uvm/runtime/instances",
                        "runtime_preflight": "uvm/runtime/preflight",
                        "runtime_checkpoints": "uvm/runtime/checkpoints",
                        "runtime_migrations": "uvm/runtime/migrations",
                        "runtime_heartbeats": "uvm/runtime/heartbeats",
                        "runtime_health": "uvm/runtime/health",
                        "runtime_restore": "uvm/runtime/instances/{id}/restore",
                        "runtime_repair": "uvm/runtime/instances/{id}/repair",
                    }),
                )
                .map(Some),
                (Method::GET, ["uvm", "runtime", "instances"]) => {
                    let values = self
                        .runtime_sessions
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "runtime", "instances", session_id]) => {
                    self.get_runtime_session(session_id).await.map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances"]) => {
                    let body: RegisterRuntimeSessionRequest = parse_json(request).await?;
                    self.register_runtime_session(body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances", session_id, "prepare"]) => self
                    .transition_runtime_session(
                        session_id,
                        VmRuntimeAction::Prepare,
                        "prepare",
                        None,
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "runtime", "instances", session_id, "start"]) => self
                    .transition_runtime_session(
                        session_id,
                        VmRuntimeAction::Start,
                        "start",
                        None,
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "runtime", "instances", session_id, "stop"]) => self
                    .transition_runtime_session(
                        session_id,
                        VmRuntimeAction::Stop,
                        "stop",
                        None,
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "runtime", "instances", session_id, "restore"]) => {
                    let body: RestoreRuntimeRequest = parse_json(request).await?;
                    self.restore_runtime_session(session_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances", session_id, "repair"]) => {
                    let body: RepairRuntimeRequest = parse_json(request).await?;
                    self.repair_runtime_session(session_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances", session_id, "mark-failed"]) => {
                    let body: RuntimeFailureRequest = parse_json(request).await?;
                    self.transition_runtime_session(
                        session_id,
                        VmRuntimeAction::Fail,
                        "mark_failed",
                        Some(body.error),
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances", session_id, "recover"]) => {
                    let body: RuntimeRecoverRequest = parse_json(request).await?;
                    self.transition_runtime_session(
                        session_id,
                        VmRuntimeAction::BeginRecover,
                        "recover",
                        body.reason,
                        &context,
                    )
                    .await
                    .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "instances", session_id, "heartbeat"]) => {
                    let body: RuntimeHeartbeatRequest = parse_json(request).await?;
                    self.heartbeat_runtime_session(session_id, body, &context)
                        .await
                        .map(Some)
                }
                (
                    Method::POST,
                    [
                        "uvm",
                        "runtime",
                        "instances",
                        session_id,
                        "recover-complete",
                    ],
                ) => self
                    .transition_runtime_session(
                        session_id,
                        VmRuntimeAction::CompleteRecover,
                        "recover_complete",
                        None,
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::GET, ["uvm", "runtime", "checkpoints"]) => {
                    let values = self
                        .runtime_checkpoints
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "runtime", "checkpoints", checkpoint_id]) => {
                    self.get_runtime_checkpoint(checkpoint_id).await.map(Some)
                }
                (Method::POST, ["uvm", "runtime", "checkpoints"]) => {
                    let body: CreateCheckpointRequest = parse_json(request).await?;
                    self.create_checkpoint(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "runtime", "heartbeats"]) => {
                    let mut values = self
                        .runtime_heartbeats
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    sort_runtime_heartbeat_records(&mut values);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "runtime", "preflight"]) => {
                    let values = self
                        .runtime_preflights
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "runtime", "preflight"]) => {
                    let body: RuntimePreflightRequest = parse_json(request).await?;
                    self.preflight_runtime(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "runtime", "health"]) => {
                    let stale_after_seconds =
                        query_param_i64(&path, "stale_after_seconds").unwrap_or(120);
                    let summary = self.runtime_health_summary(stale_after_seconds).await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["uvm", "runtime", "migrations"]) => {
                    let values = self
                        .runtime_migrations
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, value)| !value.deleted)
                        .map(|(_, value)| value.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "runtime", "migrations", migration_id]) => {
                    self.get_runtime_migration(migration_id).await.map(Some)
                }
                (Method::POST, ["uvm", "runtime", "migrations", "preflight"]) => {
                    let body: RuntimeMigrationPreflightRequest = parse_json(request).await?;
                    self.preflight_runtime_migration(body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["uvm", "runtime", "migrations"]) => {
                    let body: StartRuntimeMigrationRequest = parse_json(request).await?;
                    self.start_runtime_migration(body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "runtime", "migrations", migration_id, "commit"]) => self
                    .resolve_runtime_migration(
                        migration_id,
                        "commit",
                        ResolveRuntimeMigrationRequest { error: None },
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "runtime", "migrations", migration_id, "rollback"]) => self
                    .resolve_runtime_migration(
                        migration_id,
                        "rollback",
                        ResolveRuntimeMigrationRequest { error: None },
                        &context,
                    )
                    .await
                    .map(Some),
                (Method::POST, ["uvm", "runtime", "migrations", migration_id, "fail"]) => {
                    let body: ResolveRuntimeMigrationRequest = parse_json(request).await?;
                    self.resolve_runtime_migration(migration_id, "fail", body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "node-outbox"]) => {
                    let values = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "node-outbox", message_id]) => {
                    self.get_outbox_message(message_id).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
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

fn default_hypervisor_health_key() -> String {
    String::from(HypervisorHealth::Unknown.as_str())
}

fn query_param_i64(path: &str, key: &str) -> Option<i64> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let current_key = parts.next()?;
        if current_key != key {
            continue;
        }
        return parts.next()?.parse::<i64>().ok();
    }
    None
}

fn normalize_guest_os(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("guest_os may not be empty"));
    }
    Ok(normalized)
}

fn normalize_profile(value: &str, field_name: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid(format!(
            "{field_name} exceeds 128 bytes"
        )));
    }
    if normalized.chars().any(|value| value.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not contain control characters"
        )));
    }
    Ok(normalized)
}

fn normalize_migration_policy(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "cold_only" | "best_effort_live" | "strict_live" | "live_postcopy" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "migration_policy must be one of cold_only/best_effort_live/strict_live/live_postcopy",
        )),
    }
}

fn normalize_backend(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "software_dbt" | "kvm" | "hyperv_whp" | "apple_virtualization" | "bhyve" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "backend must be one of software_dbt/kvm/hyperv_whp/apple_virtualization/bhyve",
        )),
    }
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

fn default_guest_profile_for_guest_os(guest_os: &str) -> String {
    String::from(GuestProfile::default_for_guest(guest_os).as_str())
}

fn default_machine_family_for_guest(
    guest_architecture: GuestArchitecture,
    guest_os: &str,
) -> String {
    String::from(MachineFamily::default_for_guest(guest_architecture, guest_os).as_str())
}

fn supported_machine_families_for_capability(
    architecture: &str,
    accelerator_backends: &[String],
) -> Vec<String> {
    let has_kvm = accelerator_backends
        .iter()
        .any(|backend| backend == HypervisorBackend::Kvm.as_str());
    let mut values = if architecture == "aarch64" {
        vec![String::from(MachineFamily::Aarch64Virt.as_str())]
    } else {
        vec![String::from(MachineFamily::GeneralPurposePci.as_str())]
    };
    if architecture == "x86_64" && has_kvm {
        values.push(String::from(MachineFamily::MicrovmLinux.as_str()));
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn supported_guest_profiles_for_capability(
    host_platform: HostPlatform,
    architecture: &str,
    accelerator_backends: &[String],
) -> Vec<String> {
    let has_kvm = accelerator_backends
        .iter()
        .any(|backend| backend == HypervisorBackend::Kvm.as_str());
    let has_hyperv = accelerator_backends
        .iter()
        .any(|backend| backend == HypervisorBackend::HypervWhp.as_str());
    let has_bhyve = accelerator_backends
        .iter()
        .any(|backend| backend == HypervisorBackend::Bhyve.as_str());
    let has_apple = accelerator_backends
        .iter()
        .any(|backend| backend == HypervisorBackend::AppleVirtualization.as_str());

    let mut values = vec![String::from(GuestProfile::LinuxStandard.as_str())];
    if has_kvm {
        values.push(String::from(GuestProfile::LinuxDirectKernel.as_str()));
    }
    if architecture == "x86_64" && (has_kvm || has_hyperv) {
        values.push(String::from(GuestProfile::WindowsGeneral.as_str()));
    }
    if architecture == "x86_64" && (has_kvm || has_bhyve) {
        values.push(String::from(GuestProfile::BsdGeneral.as_str()));
    }
    if host_platform == HostPlatform::Macos && architecture == "aarch64" && has_apple {
        values.push(String::from(GuestProfile::AppleGuest.as_str()));
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn compatibility_summary_from_capability(
    capability: &UvmNodeCapabilityRecord,
) -> Result<UvmNodeCompatibilitySummary> {
    Ok(UvmNodeCompatibilitySummary {
        host_platform: HostPlatform::parse(&capability.host_platform).map_err(|error| {
            PlatformError::invalid("capability host_platform is invalid")
                .with_detail(error.to_string())
        })?,
        host_class: HostClass::parse(&capability.host_class).map_err(|error| {
            PlatformError::invalid("capability host_class is invalid")
                .with_detail(error.to_string())
        })?,
        accelerator_backends: capability
            .accelerator_backends
            .iter()
            .map(|backend| HypervisorBackend::parse(backend))
            .collect::<Result<Vec<_>>>()?,
        supported_machine_families: capability
            .supported_machine_families
            .iter()
            .map(|family| MachineFamily::parse(family))
            .collect::<Result<Vec<_>>>()?,
        supported_guest_profiles: capability
            .supported_guest_profiles
            .iter()
            .map(|profile| GuestProfile::parse(profile))
            .collect::<Result<Vec<_>>>()?,
        supports_secure_boot: capability.supports_secure_boot,
        supports_live_migration: capability.supports_live_migration,
        evidence_mode: Some(capability.host_evidence_mode.clone()),
    })
}

fn default_software_runner_supported() -> bool {
    true
}

fn default_host_evidence_mode_key() -> String {
    String::from("direct_host")
}

fn default_runner_phase_key() -> String {
    String::from("registered")
}

fn default_runtime_network_mode_key() -> String {
    String::from("guest_control_only")
}

fn allocate_runtime_session_intent_lineage_id() -> Result<AuditId> {
    AuditId::generate().map_err(|error| {
        PlatformError::unavailable("failed to allocate runtime session intent lineage id")
            .with_detail(error.to_string())
    })
}

fn serialize_record_digest<T: Serialize>(value: &T, message: &'static str) -> Result<String> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| PlatformError::unavailable(message).with_detail(error.to_string()))?;
    Ok(sha256_hex(&payload))
}

fn software_runner_worker_states_for_phase(phase: &str) -> Vec<String> {
    match phase {
        "restored" => vec![
            String::from("supervisor:running"),
            String::from("core:restored"),
            String::from("block:running"),
            String::from("net:running"),
        ],
        state => ["supervisor", "core", "block", "net"]
            .into_iter()
            .map(|role| format!("{role}:{state}"))
            .collect(),
    }
}

fn default_runtime_evidence_mode_key() -> String {
    String::from("direct_host")
}

fn default_execution_intent_for_guest_profile(guest_profile: &str) -> UvmExecutionIntent {
    GuestProfile::parse(guest_profile)
        .map(UvmExecutionIntent::default_for_guest_profile)
        .unwrap_or_default()
}

fn deserialize_optional_control_execution_intent<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<UvmExecutionIntent>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StoredControlExecutionIntent>::deserialize(deserializer)?
        .map(|value| match value {
            StoredControlExecutionIntent::Contract(intent) => Ok(intent),
            StoredControlExecutionIntent::LegacyKey(key) => {
                parse_legacy_control_execution_intent_key(&key)
            }
        })
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn parse_legacy_control_execution_intent_key(
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

fn host_class_environment_from_node_posture(
    host_evidence_mode: &str,
    container_restricted: bool,
) -> HostClassEnvironment {
    if container_restricted || host_evidence_mode == "container_restricted" {
        HostClassEnvironment::ContainerRestricted
    } else if host_evidence_mode == "operator_declared" {
        HostClassEnvironment::OperatorDeclared
    } else {
        HostClassEnvironment::BareMetal
    }
}

fn derive_node_host_class(
    host_platform: HostPlatform,
    host_evidence_mode: &str,
    container_restricted: bool,
) -> String {
    HostClass::from_platform_environment(
        host_platform,
        host_class_environment_from_node_posture(host_evidence_mode, container_restricted),
    )
    .into_string()
}

fn normalize_host_evidence_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "direct_host" | "container_restricted" | "operator_declared" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "host_evidence_mode must be one of direct_host/container_restricted/operator_declared",
        )),
    }
}

fn image_compatibility_artifact_value<'a>(summary: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{field}=");
    summary
        .split_whitespace()
        .find_map(|part| part.strip_prefix(prefix.as_str()))
}

fn normalize_runner_phase(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "registered" | "prepared" | "running" | "stopped" | "failed" | "recovering"
        | "restored" | "external_adapter" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "runner_phase must be one of registered/prepared/running/stopped/failed/recovering/restored/external_adapter",
        )),
    }
}

fn normalize_worker_states(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(PlatformError::invalid("worker state may not be empty"));
            }
            if normalized.len() > 128 {
                return Err(PlatformError::invalid("worker state exceeds 128 bytes"));
            }
            if !normalized.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '-' | '.')
            }) {
                return Err(PlatformError::invalid(
                    "worker state may only contain lowercase ascii letters, digits, ':', '_', '-', and '.'",
                ));
            }
            Ok(normalized)
        })
        .collect()
}

fn normalize_restart_policy(value: Option<&str>) -> Result<String> {
    let normalized = value.unwrap_or("on-failure").trim().to_ascii_lowercase();
    match normalized.as_str() {
        "never" | "on-failure" | "always" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "restart_policy must be one of never/on-failure/always",
        )),
    }
}

fn normalize_isolation_profile(value: Option<&str>) -> Result<String> {
    let normalized = value
        .unwrap_or("platform_default")
        .trim()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("isolation_profile may not be empty"));
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

fn normalize_boot_device(value: Option<&str>, has_cdrom_image: bool) -> Result<String> {
    let boot_device = match value {
        Some(value) => BootDevice::parse(value)?,
        None if has_cdrom_image => BootDevice::Cdrom,
        None => BootDevice::Disk,
    };
    Ok(String::from(boot_device.as_str()))
}

fn normalize_checkpoint_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "crash_consistent" | "live_precopy" | "live_postcopy" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "checkpoint kind must be crash_consistent/live_precopy/live_postcopy",
        )),
    }
}

fn normalize_non_control(
    value: impl Into<String>,
    field_name: &str,
    max_len: usize,
) -> Result<String> {
    let value = value.into();
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    if normalized.len() > max_len {
        return Err(PlatformError::invalid(format!(
            "{field_name} exceeds {max_len} bytes"
        )));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not contain control characters"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_reason(value: &str) -> Result<String> {
    normalize_non_control(value.to_owned(), "reason", 512)
}

fn normalize_optional_failure_detail(value: Option<String>) -> Result<Option<String>> {
    value
        .map(|value| normalize_non_control(value, "error", 2048))
        .transpose()
}

fn parse_optional_audit_id(value: Option<String>, field_name: &str) -> Result<Option<AuditId>> {
    value
        .map(|value| {
            AuditId::parse(value).map_err(|error| {
                PlatformError::invalid(format!("invalid {field_name}"))
                    .with_detail(error.to_string())
            })
        })
        .transpose()
}

fn parse_optional_runner_string_array(
    event: &serde_json::Value,
    field_name: &str,
    max_entries: usize,
    max_len: usize,
) -> Result<Option<Vec<String>>> {
    let Some(value) = event.get(field_name) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| PlatformError::invalid(format!("{field_name} must be an array")))?;
    if values.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty when present"
        )));
    }
    if values.len() > max_entries {
        return Err(PlatformError::invalid(format!(
            "{field_name} exceeds {max_entries} entries"
        )));
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or_else(|| {
                PlatformError::invalid(format!("{field_name} entries must be strings"))
            })?;
            normalize_non_control(value.to_owned(), field_name, max_len)
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn parse_optional_runner_bool(event: &serde_json::Value, field_name: &str) -> Result<Option<bool>> {
    match event.get(field_name) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| PlatformError::invalid(format!("{field_name} must be a boolean")))
            .map(Some),
        None => Ok(None),
    }
}

fn parse_optional_runner_network_access(
    event: &serde_json::Value,
) -> Result<Option<UvmRuntimeNetworkAccessRecord>> {
    let Some(value) = event.get("network_access") else {
        return Ok(None);
    };
    let mut network_access = serde_json::from_value::<UvmRuntimeNetworkAccessRecord>(value.clone())
        .map_err(|error| {
            PlatformError::invalid("network_access must be a valid object")
                .with_detail(error.to_string())
        })?;
    network_access.network_mode = normalize_non_control(
        network_access.network_mode,
        "network_access.network_mode",
        128,
    )?;
    network_access.egress_transport = network_access
        .egress_transport
        .map(|value| normalize_non_control(value, "network_access.egress_transport", 128))
        .transpose()?;
    network_access.ingress_transport = network_access
        .ingress_transport
        .map(|value| normalize_non_control(value, "network_access.ingress_transport", 128))
        .transpose()?;
    network_access.ingress_http_bind = network_access
        .ingress_http_bind
        .map(|value| normalize_non_control(value, "network_access.ingress_http_bind", 256))
        .transpose()?;
    network_access.ingress_http_url = network_access
        .ingress_http_url
        .map(|value| normalize_non_control(value, "network_access.ingress_http_url", 2048))
        .transpose()?;
    network_access.ingress_tcp_bind = network_access
        .ingress_tcp_bind
        .map(|value| normalize_non_control(value, "network_access.ingress_tcp_bind", 256))
        .transpose()?;
    network_access.ingress_tcp_service = network_access
        .ingress_tcp_service
        .map(|value| normalize_non_control(value, "network_access.ingress_tcp_service", 256))
        .transpose()?;
    network_access.ingress_udp_bind = network_access
        .ingress_udp_bind
        .map(|value| normalize_non_control(value, "network_access.ingress_udp_bind", 256))
        .transpose()?;
    network_access.ingress_udp_service = network_access
        .ingress_udp_service
        .map(|value| normalize_non_control(value, "network_access.ingress_udp_service", 256))
        .transpose()?;
    network_access.guest_web_root = network_access
        .guest_web_root
        .map(|value| normalize_non_control(value, "network_access.guest_web_root", 1024))
        .transpose()?;
    network_access.supported_guest_commands = network_access
        .supported_guest_commands
        .into_iter()
        .map(|value| normalize_non_control(value, "network_access.supported_guest_commands", 256))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(network_access))
}

fn parse_optional_runner_workers(
    event: &serde_json::Value,
) -> Result<Option<Vec<serde_json::Value>>> {
    let Some(value) = event.get("workers") else {
        return Ok(None);
    };
    let workers = value
        .as_array()
        .ok_or_else(|| PlatformError::invalid("workers must be an array"))?;
    if workers.is_empty() {
        return Err(PlatformError::invalid(
            "workers may not be empty when present",
        ));
    }
    if workers.len() > 16 {
        return Err(PlatformError::invalid("workers exceeds 16 entries"));
    }
    workers
        .iter()
        .map(validate_runner_worker_payload)
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn validate_runner_worker_payload(worker: &serde_json::Value) -> Result<serde_json::Value> {
    let Some(object) = worker.as_object() else {
        return Err(PlatformError::invalid("workers entries must be objects"));
    };
    for field_name in [
        "name",
        "state",
        "process_binding",
        "sandbox_enforcement_mode",
        "sandbox_contract_source",
        "seccomp_profile",
        "execution_scope",
    ] {
        let value = object
            .get(field_name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                PlatformError::invalid(format!("workers entries must include `{field_name}`"))
            })?;
        let normalized_field = format!("workers[].{field_name}");
        let _ = normalize_non_control(value.to_owned(), normalized_field.as_str(), 128)?;
    }
    let observed_pid = object
        .get("observed_pid")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| PlatformError::invalid("workers entries must include `observed_pid`"))?;
    if observed_pid == 0 {
        return Err(PlatformError::invalid(
            "workers entries must include a positive `observed_pid`",
        ));
    }
    let sandbox_layers = object
        .get("sandbox_layers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| PlatformError::invalid("workers entries must include `sandbox_layers`"))?;
    if sandbox_layers.is_empty() {
        return Err(PlatformError::invalid(
            "workers[].sandbox_layers may not be empty",
        ));
    }
    if sandbox_layers.len() > 8 {
        return Err(PlatformError::invalid(
            "workers[].sandbox_layers exceeds 8 entries",
        ));
    }
    for sandbox_layer in sandbox_layers {
        let value = sandbox_layer.as_str().ok_or_else(|| {
            PlatformError::invalid("workers[].sandbox_layers entries must be strings")
        })?;
        let _ = normalize_non_control(value.to_owned(), "workers[].sandbox_layers", 64)?;
    }
    let detail = object
        .get("detail")
        .ok_or_else(|| PlatformError::invalid("workers entries must include `detail`"))?;
    if !detail.is_object() {
        return Err(PlatformError::invalid("workers[].detail must be an object"));
    }
    let detail_len = serde_json::to_vec(detail).map_err(|error| {
        PlatformError::invalid("failed to serialize workers[].detail")
            .with_detail(error.to_string())
    })?;
    if detail_len.len() > 4_096 {
        return Err(PlatformError::invalid(
            "workers[].detail exceeds 4096 bytes",
        ));
    }
    let worker_len = serde_json::to_vec(worker).map_err(|error| {
        PlatformError::invalid("failed to serialize workers entry").with_detail(error.to_string())
    })?;
    if worker_len.len() > 8_192 {
        return Err(PlatformError::invalid("workers entry exceeds 8192 bytes"));
    }
    Ok(worker.clone())
}

fn validate_optional_positive_u16(value: Option<u16>, field_name: &str) -> Result<Option<u16>> {
    match value {
        Some(0) => Err(PlatformError::invalid(format!(
            "{field_name} must be greater than zero"
        ))),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn validate_optional_positive_u32(value: Option<u32>, field_name: &str) -> Result<Option<u32>> {
    match value {
        Some(0) => Err(PlatformError::invalid(format!(
            "{field_name} must be greater than zero"
        ))),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn validate_optional_positive_u64(value: Option<u64>, field_name: &str) -> Result<Option<u64>> {
    match value {
        Some(0) => Err(PlatformError::invalid(format!(
            "{field_name} must be greater than zero"
        ))),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn normalize_storage_reference(value: &str, field_name: &'static str) -> Result<String> {
    normalize_path_or_uri_reference(value, field_name)
}

fn normalize_memory_bitmap_hash(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() < 4 || normalized.len() > 256 {
        return Err(PlatformError::invalid(
            "memory_bitmap_hash length must be between 4 and 256 bytes",
        ));
    }
    if !normalized
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PlatformError::invalid(
            "memory_bitmap_hash must be hexadecimal",
        ));
    }
    Ok(normalized)
}

fn normalize_env_key(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() || normalized.len() > 128 {
        return Err(PlatformError::invalid(
            "launch env key must be between 1 and 128 bytes",
        ));
    }
    if !normalized
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(PlatformError::invalid(
            "launch env key may only include ASCII alphanumeric characters and `_`",
        ));
    }
    Ok(normalized)
}

fn build_service_platform_event(
    event_type: &str,
    resource_kind: &str,
    resource_id: &str,
    action: &str,
    details: serde_json::Value,
    context: &RequestContext,
) -> Result<PlatformEvent> {
    Ok(PlatformEvent {
        header: EventHeader {
            event_id: AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate audit id")
                    .with_detail(error.to_string())
            })?,
            event_type: event_type.to_owned(),
            schema_version: 1,
            source_service: String::from("uvm-node"),
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
    })
}

fn restore_runtime_incarnation<'a>(
    runtime: &'a UvmRuntimeSessionRecord,
    checkpoint_id: &UvmCheckpointId,
) -> Result<&'a UvmRuntimeIncarnationRecord> {
    let incarnation = runtime.current_incarnation.as_ref().ok_or_else(|| {
        PlatformError::conflict("runtime restore replay requires a current restore incarnation")
    })?;
    if incarnation.kind != UvmRuntimeIncarnationKind::Restore {
        return Err(PlatformError::conflict(
            "runtime restore replay requires the current incarnation to be a restore",
        ));
    }
    if incarnation.checkpoint_id.as_ref() != Some(checkpoint_id) {
        return Err(PlatformError::conflict(
            "runtime restore replay requires a checkpoint-matched restore incarnation",
        ));
    }
    Ok(incarnation)
}

fn restore_replay_key(
    runtime: &UvmRuntimeSessionRecord,
    checkpoint_id: &UvmCheckpointId,
) -> Result<String> {
    let incarnation = restore_runtime_incarnation(runtime, checkpoint_id)?;
    Ok(format!(
        "runtime_restore:{}:{}:{}",
        runtime.id.as_str(),
        incarnation.sequence,
        checkpoint_id.as_str()
    ))
}

fn restore_event_details(
    runtime: &UvmRuntimeSessionRecord,
    checkpoint_id: &UvmCheckpointId,
    replay_key: &str,
) -> Result<serde_json::Value> {
    let incarnation = restore_runtime_incarnation(runtime, checkpoint_id)?;
    Ok(serde_json::json!({
        "checkpoint_id": checkpoint_id,
        "reason": incarnation.reason.clone(),
        "restore_count": runtime.restore_count,
        "restore_replay_key": replay_key,
        "runtime_incarnation_sequence": incarnation.sequence,
    }))
}

fn restore_event_matches_replay_candidate(
    event: &PlatformEvent,
    runtime: &UvmRuntimeSessionRecord,
    checkpoint_id: &UvmCheckpointId,
    replay_key: &str,
) -> bool {
    let incarnation = match restore_runtime_incarnation(runtime, checkpoint_id) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    if event.header.event_type != "uvm.node.runtime.restored.v1" {
        return false;
    }
    let EventPayload::Service(service) = &event.payload else {
        return false;
    };
    if service.resource_kind != "uvm_runtime_session"
        || service.resource_id != runtime.id.as_str()
        || service.action != "restore"
    {
        return false;
    }
    if service
        .details
        .get("restore_replay_key")
        .and_then(serde_json::Value::as_str)
        == Some(replay_key)
    {
        return true;
    }
    if service
        .details
        .get("checkpoint_id")
        .and_then(serde_json::Value::as_str)
        != Some(checkpoint_id.as_str())
    {
        return false;
    }
    if service
        .details
        .get("runtime_incarnation_sequence")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(incarnation.sequence))
    {
        return true;
    }
    service
        .details
        .get("restore_count")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(runtime.restore_count))
}

fn restore_node_operation_matches_replay_candidate(
    operation: &UvmNodeOperationRecord,
    runtime: &UvmRuntimeSessionRecord,
    checkpoint_id: &UvmCheckpointId,
) -> bool {
    let incarnation = match restore_runtime_incarnation(runtime, checkpoint_id) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    if operation.kind != UvmNodeOperationKind::Restore
        || operation.runtime_session_id.as_ref() != Some(&runtime.id)
        || operation.checkpoint_id.as_ref() != Some(checkpoint_id)
        || operation.node_id != runtime.node_id
        || operation.to_state.as_deref() != Some(runtime.state.as_str())
    {
        return false;
    }
    if operation.created_at < incarnation.activated_at {
        return false;
    }
    match incarnation.previous_state {
        Some(previous_state) => operation.from_state.as_deref() == Some(previous_state.as_str()),
        None => operation.from_state.is_none(),
    }
}

fn migration_cutover_incarnation<'a>(
    runtime: &'a UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> Result<&'a UvmRuntimeIncarnationRecord> {
    let incarnation = runtime.current_incarnation.as_ref().ok_or_else(|| {
        PlatformError::conflict("runtime migration replay requires a current cutover incarnation")
    })?;
    if incarnation.kind != UvmRuntimeIncarnationKind::PostMigrationCutover {
        return Err(PlatformError::conflict(
            "runtime migration replay requires the current incarnation to be a cutover",
        ));
    }
    if incarnation.migration_id.as_ref() != Some(&migration.id)
        || incarnation.checkpoint_id.as_ref() != Some(&migration.checkpoint_id)
        || incarnation.source_node_id.as_ref() != Some(&migration.source_node_id)
        || incarnation.target_node_id != migration.target_node_id
    {
        return Err(PlatformError::conflict(
            "runtime migration replay requires a migration-matched cutover incarnation",
        ));
    }
    Ok(incarnation)
}

fn migration_cutover_replay_key(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> Result<String> {
    let incarnation = migration_cutover_incarnation(runtime, migration)?;
    Ok(format!(
        "migration_cutover:{}:{}:{}",
        runtime.id.as_str(),
        incarnation.sequence,
        migration.id.as_str()
    ))
}

fn migration_cutover_event_details(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    replay_key: &str,
) -> Result<serde_json::Value> {
    let incarnation = migration_cutover_incarnation(runtime, migration)?;
    Ok(serde_json::json!({
        "runtime_session_id": runtime.id,
        "checkpoint_id": migration.checkpoint_id,
        "source_node_id": migration.source_node_id,
        "target_node_id": migration.target_node_id,
        "state": "committed",
        "failure_detail": migration.failure_detail,
        "migration_cutover_replay_key": replay_key,
        "runtime_incarnation_sequence": incarnation.sequence,
    }))
}

fn migration_cutover_event_matches_replay_candidate(
    event: &PlatformEvent,
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    replay_key: &str,
) -> bool {
    let incarnation = match migration_cutover_incarnation(runtime, migration) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    if event.header.event_type != "uvm.migration.committed.v1" {
        return false;
    }
    let EventPayload::Service(service) = &event.payload else {
        return false;
    };
    if service.resource_kind != "uvm_runtime_migration"
        || service.resource_id != migration.id.as_str()
        || service.action != "commit"
    {
        return false;
    }
    if service
        .details
        .get("migration_cutover_replay_key")
        .and_then(serde_json::Value::as_str)
        == Some(replay_key)
    {
        return true;
    }
    if service
        .details
        .get("runtime_incarnation_sequence")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(incarnation.sequence))
    {
        return true;
    }
    service
        .details
        .get("runtime_session_id")
        .and_then(serde_json::Value::as_str)
        == Some(runtime.id.as_str())
        && service
            .details
            .get("state")
            .and_then(serde_json::Value::as_str)
            == Some("committed")
}

fn migration_cutover_node_operation_matches_replay_candidate(
    operation: &UvmNodeOperationRecord,
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> bool {
    let incarnation = match migration_cutover_incarnation(runtime, migration) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    if operation.kind != UvmNodeOperationKind::Migrate
        || operation.runtime_session_id.as_ref() != Some(&runtime.id)
        || operation.checkpoint_id.as_ref() != Some(&migration.checkpoint_id)
        || operation.node_id != migration.source_node_id
        || operation.target_node_id.as_ref() != Some(&migration.target_node_id)
    {
        return false;
    }
    if let Some(phase) = operation.phase.as_deref()
        && phase != "in_progress"
        && phase != "committed"
    {
        return false;
    }
    if let Some(from_state) = operation.from_state.as_deref()
        && incarnation.previous_state.map(VmRuntimeState::as_str) != Some(from_state)
    {
        return false;
    }
    if let Some(to_state) = operation.to_state.as_deref()
        && to_state != runtime.state.as_str()
    {
        return false;
    }
    true
}

fn migration_terminal_event_type(action: &str) -> Option<&'static str> {
    match action {
        "rollback" => Some("uvm.migration.rolled_back.v1"),
        "fail" => Some("uvm.migration.failed.v1"),
        _ => None,
    }
}

fn migration_terminal_source_incarnation<'a>(
    runtime: &'a UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> Result<&'a UvmRuntimeIncarnationRecord> {
    let incarnation = runtime.current_incarnation.as_ref().ok_or_else(|| {
        PlatformError::conflict(
            "runtime migration terminal replay requires a current source incarnation",
        )
    })?;
    if runtime.id != migration.runtime_session_id
        || runtime.instance_id != migration.instance_id
        || runtime.node_id != migration.source_node_id
    {
        return Err(PlatformError::conflict(
            "runtime migration terminal replay requires the source runtime lineage to stay active",
        ));
    }
    if incarnation.target_node_id != migration.source_node_id {
        return Err(PlatformError::conflict(
            "runtime migration terminal replay requires the current incarnation to remain on the source node",
        ));
    }
    if incarnation.activated_at > migration.updated_at {
        return Err(PlatformError::conflict(
            "runtime migration terminal replay requires the current incarnation to predate the terminal migration resolution",
        ));
    }
    Ok(incarnation)
}

fn migration_terminal_replay_key(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    action: &str,
) -> Result<String> {
    let incarnation = migration_terminal_source_incarnation(runtime, migration)?;
    Ok(format!(
        "migration_terminal:{}:{}:{}:{}",
        action,
        runtime.id.as_str(),
        incarnation.sequence,
        migration.id.as_str()
    ))
}

fn migration_terminal_event_details(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    action: &str,
    replay_key: &str,
) -> Result<serde_json::Value> {
    let incarnation = migration_terminal_source_incarnation(runtime, migration)?;
    Ok(serde_json::json!({
        "runtime_session_id": runtime.id,
        "checkpoint_id": migration.checkpoint_id,
        "source_node_id": migration.source_node_id,
        "target_node_id": migration.target_node_id,
        "state": terminal_migration_state(action),
        "failure_detail": migration.failure_detail,
        "migration_terminal_replay_key": replay_key,
        "runtime_incarnation_sequence": incarnation.sequence,
    }))
}

fn migration_terminal_event_matches_replay_candidate(
    event: &PlatformEvent,
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    action: &str,
    replay_key: &str,
) -> bool {
    let incarnation = match migration_terminal_source_incarnation(runtime, migration) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    let Some(event_type) = migration_terminal_event_type(action) else {
        return false;
    };
    if event.header.event_type != event_type {
        return false;
    }
    let EventPayload::Service(service) = &event.payload else {
        return false;
    };
    if service.resource_kind != "uvm_runtime_migration"
        || service.resource_id != migration.id.as_str()
        || service.action != action
    {
        return false;
    }
    if service
        .details
        .get("migration_terminal_replay_key")
        .and_then(serde_json::Value::as_str)
        == Some(replay_key)
    {
        return true;
    }
    if let Some(checkpoint_id) = service
        .details
        .get("checkpoint_id")
        .and_then(serde_json::Value::as_str)
        && checkpoint_id != migration.checkpoint_id.as_str()
    {
        return false;
    }
    if service
        .details
        .get("runtime_incarnation_sequence")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(incarnation.sequence))
    {
        return true;
    }
    service
        .details
        .get("runtime_session_id")
        .and_then(serde_json::Value::as_str)
        == Some(runtime.id.as_str())
        && service
            .details
            .get("state")
            .and_then(serde_json::Value::as_str)
            == Some(terminal_migration_state(action))
}

fn migration_terminal_node_operation_matches_replay_candidate(
    operation: &UvmNodeOperationRecord,
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
    action: &str,
) -> bool {
    let incarnation = match migration_terminal_source_incarnation(runtime, migration) {
        Ok(incarnation) => incarnation,
        Err(_) => return false,
    };
    let terminal_state = terminal_migration_state(action);
    if operation.kind != UvmNodeOperationKind::Migrate
        || operation.runtime_session_id.as_ref() != Some(&runtime.id)
        || operation.checkpoint_id.as_ref() != Some(&migration.checkpoint_id)
        || operation.node_id != migration.source_node_id
        || operation.target_node_id.as_ref() != Some(&migration.target_node_id)
    {
        return false;
    }
    if operation.created_at < incarnation.activated_at {
        return false;
    }
    if let Some(phase) = operation.phase.as_deref()
        && phase != "in_progress"
        && phase != terminal_state
    {
        return false;
    }
    if let Some(from_state) = operation.from_state.as_deref()
        && from_state != runtime.state.as_str()
    {
        return false;
    }
    if let Some(to_state) = operation.to_state.as_deref()
        && to_state != runtime.state.as_str()
    {
        return false;
    }
    true
}

fn runtime_migration_node_operation_needs_link_backfill(
    operation: &UvmNodeOperationRecord,
) -> bool {
    if operation.kind != UvmNodeOperationKind::Migrate {
        return false;
    }
    match operation.linked_resource_kind.as_deref() {
        Some("runtime_migration") => operation.linked_resource_id.is_none(),
        Some(_) => false,
        None => true,
    }
}

fn runtime_migration_matches_legacy_node_operation(
    operation: &UvmNodeOperationRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> bool {
    if operation.kind != UvmNodeOperationKind::Migrate
        || operation.checkpoint_id.as_ref() != Some(&migration.checkpoint_id)
        || operation.node_id != migration.source_node_id
    {
        return false;
    }
    if let Some(runtime_session_id) = operation.runtime_session_id.as_ref()
        && runtime_session_id != &migration.runtime_session_id
    {
        return false;
    }
    if let Some(instance_id) = operation.instance_id.as_ref()
        && instance_id != &migration.instance_id
    {
        return false;
    }
    if let Some(target_node_id) = operation.target_node_id.as_ref()
        && target_node_id != &migration.target_node_id
    {
        return false;
    }
    if let Some(reason) = operation.reason.as_deref()
        && reason != migration.reason.as_str()
    {
        return false;
    }
    if let Some(linked_resource_kind) = operation.linked_resource_kind.as_deref()
        && linked_resource_kind != "runtime_migration"
    {
        return false;
    }
    if let Some(linked_resource_id) = operation.linked_resource_id.as_deref()
        && linked_resource_id != migration.id.as_str()
    {
        return false;
    }
    true
}

fn default_host_platform_key() -> String {
    String::from(HostPlatform::current().as_str())
}

fn heartbeat_records_for_runtime_incarnation(
    heartbeats: Vec<UvmRuntimeHeartbeatRecord>,
    runtime_incarnation_sequence: Option<u32>,
) -> Vec<UvmRuntimeHeartbeatRecord> {
    let Some(runtime_incarnation_sequence) = runtime_incarnation_sequence else {
        return heartbeats;
    };
    let scoped = heartbeats
        .iter()
        .filter(|record| record.runtime_incarnation_sequence == Some(runtime_incarnation_sequence))
        .cloned()
        .collect::<Vec<_>>();
    if scoped.is_empty() {
        heartbeats
    } else {
        scoped
    }
}

fn sort_runtime_heartbeat_records(heartbeats: &mut [UvmRuntimeHeartbeatRecord]) {
    heartbeats.sort_by(|left, right| {
        left.runtime_session_id
            .as_str()
            .cmp(right.runtime_session_id.as_str())
            .then(
                left.runtime_incarnation_sequence
                    .cmp(&right.runtime_incarnation_sequence),
            )
            .then(
                left.runner_sequence_id
                    .unwrap_or(left.sequence)
                    .cmp(&right.runner_sequence_id.unwrap_or(right.sequence)),
            )
            .then(left.sequence.cmp(&right.sequence))
            .then(left.observed_at.cmp(&right.observed_at))
            .then(left.id.as_str().cmp(right.id.as_str()))
    });
}

fn runtime_restore_is_already_applied(
    runtime: &UvmRuntimeSessionRecord,
    checkpoint: &UvmRuntimeCheckpointRecord,
) -> bool {
    if runtime.state != VmRuntimeState::Running {
        return false;
    }
    if runtime.restored_from_checkpoint_id.as_ref() != Some(&checkpoint.id) {
        return false;
    }
    let Some(incarnation) = runtime.current_incarnation.as_ref() else {
        return false;
    };
    incarnation.kind == UvmRuntimeIncarnationKind::Restore
        && incarnation.checkpoint_id.as_ref() == Some(&checkpoint.id)
        && incarnation.source_node_id.as_ref() == Some(&checkpoint.source_node_id)
        && incarnation.target_node_id == runtime.node_id
}

fn runtime_migration_cutover_is_already_applied(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> bool {
    if runtime.state != VmRuntimeState::Running || runtime.migration_in_progress {
        return false;
    }
    if runtime.node_id != migration.target_node_id
        || runtime.capability_id != migration.target_capability_id
    {
        return false;
    }
    let Some(incarnation) = runtime.current_incarnation.as_ref() else {
        return false;
    };
    incarnation.kind == UvmRuntimeIncarnationKind::PostMigrationCutover
        && incarnation.migration_id.as_ref() == Some(&migration.id)
        && incarnation.checkpoint_id.as_ref() == Some(&migration.checkpoint_id)
        && incarnation.source_node_id.as_ref() == Some(&migration.source_node_id)
        && incarnation.target_node_id == migration.target_node_id
}

fn runtime_migration_terminal_is_already_applied(
    runtime: &UvmRuntimeSessionRecord,
    migration: &UvmRuntimeMigrationRecord,
) -> bool {
    runtime.state == VmRuntimeState::Running
        && !runtime.migration_in_progress
        && migration_terminal_source_incarnation(runtime, migration).is_ok()
}

fn record_runtime_incarnation(
    runtime: &mut UvmRuntimeSessionRecord,
    kind: UvmRuntimeIncarnationKind,
    previous_state: Option<VmRuntimeState>,
    source_node_id: Option<NodeId>,
    target_node_id: NodeId,
    checkpoint_id: Option<UvmCheckpointId>,
    migration_id: Option<UvmMigrationId>,
    reason: Option<String>,
    activated_at: OffsetDateTime,
) {
    let previous_sequence = runtime
        .incarnation_lineage
        .last()
        .map(|value| value.sequence)
        .or_else(|| {
            runtime
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence)
        });
    let sequence = previous_sequence.unwrap_or(0).saturating_add(1);
    let incarnation = UvmRuntimeIncarnationRecord {
        sequence,
        kind,
        previous_sequence,
        previous_state,
        source_node_id,
        target_node_id,
        checkpoint_id,
        migration_id,
        reason,
        activated_at,
    };
    runtime.current_incarnation = Some(incarnation.clone());
    runtime.incarnation_lineage.push(incarnation);
}

fn runtime_incarnation_for_start(
    previous_state: VmRuntimeState,
) -> Option<UvmRuntimeIncarnationKind> {
    match previous_state {
        VmRuntimeState::Registered | VmRuntimeState::Prepared => {
            Some(UvmRuntimeIncarnationKind::OriginalBoot)
        }
        VmRuntimeState::Stopped => Some(UvmRuntimeIncarnationKind::Restart),
        VmRuntimeState::Running | VmRuntimeState::Failed | VmRuntimeState::Recovering => None,
    }
}

fn runner_supervision_key(
    runtime_session_id: &UvmRuntimeSessionId,
    runtime_incarnation: u32,
) -> String {
    format!("{}:{runtime_incarnation}", runtime_session_id.as_str())
}

fn active_runner_supervision_key(runtime: &UvmRuntimeSessionRecord) -> Option<String> {
    runtime
        .current_incarnation
        .as_ref()
        .map(|incarnation| runner_supervision_key(&runtime.id, incarnation.sequence))
}

fn watch_runner_supervision_process(
    service: UvmNodeService,
    runtime_handle: tokio::runtime::Handle,
    key: String,
    record: UvmRunnerSupervisionRecord,
) {
    let mut command = Command::new(&record.launch_program);
    command.args(&record.launch_args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    for entry in &record.launch_env {
        let Some((env_key, env_value)) = entry.split_once('=') else {
            let detail = format!("invalid launch env entry `{entry}`");
            let _ = runtime_handle.block_on(service.finish_runner_supervision(
                &key,
                "failed",
                None,
                Some(detail),
            ));
            return;
        };
        command.env(env_key, env_value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let detail = format!(
                "failed to spawn runner process `{}`: {error}",
                record.launch_program
            );
            let _ = runtime_handle.block_on(service.finish_runner_supervision(
                &key,
                "failed",
                None,
                Some(detail),
            ));
            return;
        }
    };
    let pid = child.id();
    let _ = runtime_handle.block_on(service.note_runner_supervision_spawned(&key, pid));

    let Some(stdout) = child.stdout.take() else {
        let detail = String::from("runner process stdout pipe was unavailable");
        let _ = child.kill();
        let _ = child.wait();
        let _ = runtime_handle.block_on(service.finish_runner_supervision(
            &key,
            "failed",
            None,
            Some(detail),
        ));
        return;
    };
    let stderr_reader = child.stderr.take().map(|stderr| {
        thread::spawn(move || -> std::result::Result<String, String> {
            let mut reader = BufReader::new(stderr);
            let mut output = String::new();
            reader
                .read_to_string(&mut output)
                .map_err(|error| error.to_string())?;
            Ok(output)
        })
    });

    let stdout_reader = BufReader::new(stdout);
    for line in stdout_reader.lines() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(event) => {
                        if let Err(error) = runtime_handle
                            .block_on(service.note_runner_supervision_event(&key, &event))
                        {
                            let detail = if let Some(context) = error.detail.as_deref() {
                                format!(
                                    "failed to apply runner event: {}; {context}",
                                    error.message
                                )
                            } else {
                                format!("failed to apply runner event: {}", error.message)
                            };
                            let _ = runtime_handle.block_on(
                                service.note_runner_supervision_parse_error(&key, detail),
                            );
                        }
                    }
                    Err(error) => {
                        let _ =
                            runtime_handle.block_on(service.note_runner_supervision_parse_error(
                                &key,
                                format!("failed to parse runner event: {error}"),
                            ));
                    }
                }
            }
            Err(error) => {
                let _ = runtime_handle.block_on(service.note_runner_supervision_parse_error(
                    &key,
                    format!("failed to read runner stdout: {error}"),
                ));
                break;
            }
        }
    }

    let stderr_output = stderr_reader
        .map(|handle| match handle.join() {
            Ok(Ok(output)) => output,
            Ok(Err(detail)) => detail,
            Err(_) => String::from("runner stderr reader panicked"),
        })
        .unwrap_or_default();
    match child.wait() {
        Ok(status) => {
            let failure_detail = (!status.success()).then(|| {
                let stderr_output = stderr_output.trim();
                if stderr_output.is_empty() {
                    format!("runner process exited unsuccessfully: {status}")
                } else {
                    format!(
                        "runner process exited unsuccessfully: {status}; stderr: {stderr_output}"
                    )
                }
            });
            let _ = runtime_handle.block_on(service.finish_runner_supervision(
                &key,
                if status.success() {
                    "stopped"
                } else {
                    "failed"
                },
                status.code(),
                failure_detail,
            ));
        }
        Err(error) => {
            let detail = format!("failed to wait for runner process: {error}");
            let _ = runtime_handle.block_on(service.finish_runner_supervision(
                &key,
                "failed",
                None,
                Some(detail),
            ));
        }
    }
}

fn runtime_session_registration_equivalent(
    left: &UvmRuntimeSessionRecord,
    right: &UvmRuntimeSessionRecord,
) -> bool {
    left.state == VmRuntimeState::Registered
        && right.state == VmRuntimeState::Registered
        && !left.migration_in_progress
        && !right.migration_in_progress
        && left.instance_id == right.instance_id
        && left.node_id == right.node_id
        && left.capability_id == right.capability_id
        && left.guest_architecture == right.guest_architecture
        && left.vcpu == right.vcpu
        && left.memory_mb == right.memory_mb
        && left.guest_os == right.guest_os
        && left.cpu_topology_profile == right.cpu_topology_profile
        && left.numa_policy_profile == right.numa_policy_profile
        && left.planned_pinned_numa_nodes == right.planned_pinned_numa_nodes
        && left.planned_memory_per_numa_mb == right.planned_memory_per_numa_mb
        && left.migration_policy == right.migration_policy
        && left.machine_family == right.machine_family
        && left.guest_profile == right.guest_profile
        && left.claim_tier == right.claim_tier
        && left.planned_migration_checkpoint_kind == right.planned_migration_checkpoint_kind
        && left.planned_migration_downtime_ms == right.planned_migration_downtime_ms
        && left.accelerator_backend == right.accelerator_backend
        && left.launch_program == right.launch_program
        && left.launch_args == right.launch_args
        && left.launch_env == right.launch_env
        && left.isolation_profile == right.isolation_profile
        && left.restart_policy == right.restart_policy
        && left.max_restarts == right.max_restarts
}

fn is_runtime_transition_noop(state: VmRuntimeState, action: VmRuntimeAction) -> bool {
    matches!(
        (state, action),
        (VmRuntimeState::Prepared, VmRuntimeAction::Prepare)
            | (VmRuntimeState::Running, VmRuntimeAction::Start)
            | (VmRuntimeState::Stopped, VmRuntimeAction::Stop)
            | (VmRuntimeState::Recovering, VmRuntimeAction::BeginRecover)
            | (VmRuntimeState::Running, VmRuntimeAction::CompleteRecover)
    )
}

fn terminal_migration_state(action: &str) -> &str {
    match action {
        "commit" => "committed",
        "rollback" => "rolled_back",
        "fail" => "failed",
        _ => "unknown",
    }
}

fn migration_state_supports_action(state: &str, action: &str) -> bool {
    state == "in_progress" || state == terminal_migration_state(action)
}

fn runtime_state_blocks_drain_completion(state: VmRuntimeState) -> bool {
    matches!(
        state,
        VmRuntimeState::Registered
            | VmRuntimeState::Prepared
            | VmRuntimeState::Running
            | VmRuntimeState::Recovering
    )
}

fn node_drain_state_blocks_new_runtime_work(state: &str) -> bool {
    matches!(state, "quiesce" | "evacuate")
}

fn node_drain_state_requires_live_snapshot(state: &str) -> bool {
    node_drain_state_blocks_new_runtime_work(state)
}

fn runtime_heartbeat_is_stale(
    runtime: &UvmRuntimeSessionRecord,
    stale_after_seconds: i64,
) -> Result<bool> {
    if stale_after_seconds <= 0 {
        return Err(PlatformError::invalid(
            "stale_after_seconds must be greater than zero",
        ));
    }
    Ok(matches!(
        runtime.state,
        VmRuntimeState::Running | VmRuntimeState::Recovering
    ) && runtime
        .last_heartbeat_at
        .map(|heartbeat| {
            (OffsetDateTime::now_utc() - heartbeat).whole_seconds() > stale_after_seconds
        })
        .unwrap_or(true))
}

fn runtime_repair_restart_budget_remaining(runtime: &UvmRuntimeSessionRecord) -> bool {
    runtime.restart_policy != "never" && runtime.start_attempts < runtime.max_restarts
}

fn runtime_repair_evidence(
    runtime: &UvmRuntimeSessionRecord,
    stale_after_seconds: i64,
    heartbeat_stale: bool,
    health_failed: bool,
    active_drain: Option<&UvmNodeDrainOperationRecord>,
    runner_supervision: Option<&UvmRunnerSupervisionRecord>,
    checkpoint: Option<&UvmRuntimeCheckpointRecord>,
    restart_budget_remaining: bool,
) -> Vec<String> {
    let mut evidence = vec![
        format!("state={}", runtime.state.as_str()),
        format!("runner_phase={}", runtime.runner_phase),
        format!("hypervisor_health={}", runtime.hypervisor_health),
        format!(
            "restart_budget_remaining={restart_budget_remaining}:attempts={}/{}",
            runtime.start_attempts, runtime.max_restarts
        ),
        format!("stale_after_seconds={stale_after_seconds}"),
    ];
    if let Some(last_heartbeat_at) = runtime.last_heartbeat_at {
        evidence.push(format!("last_heartbeat_at={last_heartbeat_at}"));
    } else {
        evidence.push(String::from("last_heartbeat_at=missing"));
    }
    evidence.push(format!("heartbeat_stale={heartbeat_stale}"));
    evidence.push(format!("node_health_failed={health_failed}"));
    if let Some(drain) = active_drain {
        evidence.push(format!("active_node_drain_id={}", drain.id));
        evidence.push(format!("active_node_drain_state={}", drain.state));
    }
    if let Some(supervision) = runner_supervision {
        evidence.push(format!("runner_supervision_state={}", supervision.state));
        if let Some(last_event_kind) = supervision.last_event_kind.as_ref() {
            evidence.push(format!("runner_supervision_event={last_event_kind}"));
        }
        if let Some(last_runner_phase) = supervision.last_runner_phase.as_ref() {
            evidence.push(format!("runner_supervision_phase={last_runner_phase}"));
        }
        if let Some(failure_detail) = supervision.failure_detail.as_ref() {
            evidence.push(format!("runner_supervision_failure={failure_detail}"));
        }
        evidence.extend(summarize_runner_supervision_workers(
            supervision.workers.as_slice(),
        ));
    }
    if let Some(last_exit_reason) = runtime.last_exit_reason.as_ref() {
        evidence.push(format!("last_exit_reason={last_exit_reason}"));
    }
    if let Some(last_error) = runtime.last_error.as_ref() {
        evidence.push(format!("last_error={last_error}"));
    }
    if let Some(checkpoint) = checkpoint {
        evidence.push(format!("checkpoint_available={}", checkpoint.id));
    } else {
        evidence.push(String::from("checkpoint_available=false"));
    }
    evidence
}

fn summarize_runner_supervision_workers(workers: &[serde_json::Value]) -> Vec<String> {
    if workers.is_empty() {
        return Vec::new();
    }
    let mut evidence = vec![format!("runner_supervision_workers={}", workers.len())];
    for worker in workers.iter().take(4) {
        if let Some(summary) = summarize_runner_supervision_worker(worker) {
            evidence.push(summary);
        }
    }
    if workers.len() > 4 {
        evidence.push(format!(
            "runner_supervision_workers_truncated={}",
            workers.len().saturating_sub(4)
        ));
    }
    evidence
}

fn summarize_runner_supervision_worker(worker: &serde_json::Value) -> Option<String> {
    let object = worker.as_object()?;
    let name = object.get("name")?.as_str()?;
    let state = object.get("state")?.as_str()?;
    let observed_pid = object.get("observed_pid")?.as_u64()?;
    let execution_scope = object.get("execution_scope")?.as_str()?;
    let seccomp_profile = object.get("seccomp_profile")?.as_str()?;
    let mut summary = format!(
        "runner_supervision_worker[{name}]=state={state},pid={observed_pid},scope={execution_scope},seccomp={seccomp_profile}"
    );
    if let Some(detail) = object.get("detail").and_then(serde_json::Value::as_object) {
        let detail_summary = summarize_runner_supervision_worker_detail(detail);
        if !detail_summary.is_empty() {
            summary.push(',');
            summary.push_str(detail_summary.as_str());
        }
    }
    Some(summary)
}

fn summarize_runner_supervision_worker_detail(
    detail: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut keys = detail.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys.into_iter()
        .take(6)
        .filter_map(|key| {
            let value = detail.get(&key)?;
            Some(format!(
                "detail.{key}={}",
                summarize_runner_supervision_worker_value(value)
            ))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn summarize_runner_supervision_worker_value(value: &serde_json::Value) -> String {
    let rendered = serde_json::to_string(value)
        .unwrap_or_else(|error| format!("\"detail_serialization_error:{}\"", error));
    truncate_runner_supervision_worker_value(rendered, 160)
}

fn truncate_runner_supervision_worker_value(value: String, max_len: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_len {
        return value;
    }
    let truncated = value.chars().take(max_len).collect::<String>();
    format!("{truncated}...")
}

fn sort_runtime_session_ids(ids: &mut [UvmRuntimeSessionId]) {
    ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
}

fn merge_runtime_session_ids(
    left: &[UvmRuntimeSessionId],
    right: &[UvmRuntimeSessionId],
) -> Vec<UvmRuntimeSessionId> {
    let mut merged = left.to_vec();
    for value in right {
        if merged.iter().any(|existing| existing == value) {
            continue;
        }
        merged.push(value.clone());
    }
    sort_runtime_session_ids(&mut merged);
    merged
}

fn format_runtime_session_id_list(runtime_session_ids: &[UvmRuntimeSessionId]) -> String {
    runtime_session_ids
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

fn has_secure_boot_flag(launch_args: &[String]) -> bool {
    launch_args.iter().any(|value| value == "--secure-boot")
}

fn launch_arg_value<'a>(launch_args: &'a [String], flag: &str) -> Option<&'a str> {
    launch_args
        .windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].as_str())
}

fn launch_arg_value_index(launch_args: &[String], flag: &str) -> Result<Option<usize>> {
    let Some(flag_index) = launch_args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    let value_index = flag_index.saturating_add(1);
    if value_index >= launch_args.len() {
        return Err(PlatformError::conflict(format!(
            "runtime session launch args are missing value for `{flag}`"
        )));
    }
    Ok(Some(value_index))
}

fn set_or_append_launch_arg(
    launch_args: &mut Vec<String>,
    flag: &str,
    value: String,
) -> Result<()> {
    if let Some(value_index) = launch_arg_value_index(launch_args, flag)? {
        launch_args[value_index] = value;
    } else {
        launch_args.push(String::from(flag));
        launch_args.push(value);
    }
    Ok(())
}

fn launch_args_with_stop_sentinel(
    launch_args: &[String],
    stop_sentinel_path: &str,
) -> Result<Vec<String>> {
    let mut args = launch_args.to_vec();
    set_or_append_launch_arg(
        &mut args,
        "--stop-sentinel",
        normalize_non_control(stop_sentinel_path.to_owned(), "runner stop sentinel", 2048)?,
    )?;
    Ok(args)
}

fn normalize_local_file_artifact_uri(value: &str, field_name: &'static str) -> Result<String> {
    let normalized = normalize_storage_reference(value, field_name)?;
    if !normalized.starts_with("file:///") {
        return Err(PlatformError::conflict(format!(
            "software-backed launch contracts require local absolute file:// artifacts for `{field_name}`"
        )));
    }
    Ok(normalized)
}

fn launch_spec_from_runtime_session(runtime: &UvmRuntimeSessionRecord) -> Result<LaunchSpec> {
    let firmware_profile = launch_arg_value(&runtime.launch_args, "--firmware")
        .ok_or_else(|| {
            PlatformError::conflict(
                "runtime session launch args are missing required `--firmware` flag",
            )
        })?
        .to_owned();
    let disk_image = launch_arg_value(&runtime.launch_args, "--disk")
        .ok_or_else(|| {
            PlatformError::conflict(
                "runtime session launch args are missing required `--disk` flag",
            )
        })?
        .to_owned();
    let cdrom_image = launch_arg_value(&runtime.launch_args, "--cdrom").map(str::to_owned);
    let boot_device = match launch_arg_value(&runtime.launch_args, "--boot-device") {
        Some(value) => String::from(BootDevice::parse(value)?.as_str()),
        None => String::from(BootDevice::Disk.as_str()),
    };
    Ok(LaunchSpec {
        runtime_session_id: runtime.id.to_string(),
        instance_id: runtime.instance_id.to_string(),
        guest_architecture: GuestArchitecture::parse(&runtime.guest_architecture)?,
        vcpu: runtime.vcpu,
        memory_mb: runtime.memory_mb,
        require_secure_boot: has_secure_boot_flag(&runtime.launch_args),
        firmware_profile,
        firmware_artifact: launch_arg_value(&runtime.launch_args, "--firmware-artifact")
            .map(str::to_owned),
        disk_image,
        cdrom_image,
        boot_device,
    })
}

fn build_persisted_launch_contract(
    backend: HypervisorBackend,
    execution_plan: &uhost_uvm::UvmExecutionPlan,
    software_disk_artifact_uri: Option<&str>,
    software_firmware_artifact_uri: Option<&str>,
) -> Result<(String, Vec<String>, Vec<String>)> {
    let launch = execution_plan.launch.clone();
    let _ = launch.canonical_digest()?;
    let launch_program = normalize_profile(&launch.program, "launch program")?;
    let mut launch_args = launch
        .args
        .into_iter()
        .map(|argument| normalize_non_control(argument, "launch argument", 512))
        .collect::<Result<Vec<_>>>()?;
    if backend == HypervisorBackend::SoftwareDbt {
        if let Some(disk_value_index) = launch_arg_value_index(&launch_args, "--disk")? {
            if let Some(verified_uri) = software_disk_artifact_uri {
                launch_args[disk_value_index] =
                    normalize_local_file_artifact_uri(verified_uri, "disk_image")?;
            }
        } else {
            return Err(PlatformError::conflict(
                "runtime session launch args are missing required `--disk` flag",
            ));
        }
        if let Some(firmware_artifact_uri) = software_firmware_artifact_uri {
            set_or_append_launch_arg(
                &mut launch_args,
                "--firmware-artifact",
                normalize_local_file_artifact_uri(firmware_artifact_uri, "firmware_artifact")?,
            )?;
        } else if let Some(firmware_artifact_value_index) =
            launch_arg_value_index(&launch_args, "--firmware-artifact")?
        {
            launch_args[firmware_artifact_value_index] = normalize_local_file_artifact_uri(
                launch_args[firmware_artifact_value_index].as_str(),
                "firmware_artifact",
            )?;
        }
    }
    let mut launch_env = launch
        .env
        .into_iter()
        .map(|(key, value)| {
            let key = normalize_env_key(&key)?;
            let value = normalize_non_control(value, "launch env value", 2048)?;
            Ok(format!("{key}={value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    launch_env.sort_unstable();
    Ok((launch_program, launch_args, launch_env))
}

struct RuntimeRegistrationExpectation<'a> {
    node_id: &'a NodeId,
    capability_id: &'a UvmNodeCapabilityId,
    guest_architecture: GuestArchitecture,
    guest_os: &'a str,
    vcpu: u16,
    memory_mb: u64,
    cpu_topology_profile: &'a str,
    numa_policy_profile: &'a str,
    migration_policy: &'a str,
    machine_family: &'a str,
    guest_profile: &'a str,
    claim_tier: &'a str,
    placement: &'a uhost_uvm::PlacementPlan,
    migration_plan: &'a uhost_uvm::MigrationPlan,
    backend: HypervisorBackend,
    isolation_profile: &'a str,
    restart_policy: &'a str,
    max_restarts: u16,
    runtime_evidence_mode: &'a str,
    runner_phase: &'a str,
    worker_states: &'a [String],
    boot_path: &'a str,
    execution_class: &'a str,
    memory_backing: &'a str,
    device_model: &'a str,
    sandbox_layers: &'a [String],
    telemetry_streams: &'a [String],
    launch_program: &'a str,
    launch_args: &'a [String],
    launch_env: &'a [String],
}

fn runtime_registration_matches(
    existing: &UvmRuntimeSessionRecord,
    expected: &RuntimeRegistrationExpectation<'_>,
) -> Result<bool> {
    if existing.state != VmRuntimeState::Registered || existing.migration_in_progress {
        return Ok(false);
    }
    if existing.node_id != *expected.node_id
        || existing.capability_id != *expected.capability_id
        || existing.guest_architecture != expected.guest_architecture.as_str()
        || existing.guest_os != expected.guest_os
        || existing.vcpu != expected.vcpu
        || existing.memory_mb != expected.memory_mb
        || existing.cpu_topology_profile != expected.cpu_topology_profile
        || existing.numa_policy_profile != expected.numa_policy_profile
        || existing.migration_policy != expected.migration_policy
        || existing.machine_family != expected.machine_family
        || existing.guest_profile != expected.guest_profile
        || existing.claim_tier != expected.claim_tier
        || existing.accelerator_backend != expected.backend.as_str()
        || existing.planned_pinned_numa_nodes != expected.placement.pinned_numa_nodes
        || existing.planned_memory_per_numa_mb != expected.placement.per_node_memory_mb
        || existing.planned_migration_checkpoint_kind
            != expected.migration_plan.recommended_checkpoint_kind
        || existing.planned_migration_downtime_ms != expected.migration_plan.expected_downtime_ms
        || existing.isolation_profile != expected.isolation_profile
        || existing.restart_policy != expected.restart_policy
        || existing.max_restarts != expected.max_restarts
        || existing.runtime_evidence_mode != expected.runtime_evidence_mode
        || existing.runner_phase != expected.runner_phase
        || existing.worker_states != expected.worker_states
        || existing.boot_path != expected.boot_path
        || existing.execution_class != expected.execution_class
        || existing.memory_backing != expected.memory_backing
        || existing.device_model != expected.device_model
        || existing.sandbox_layers != expected.sandbox_layers
        || existing.telemetry_streams != expected.telemetry_streams
        || existing.launch_program != expected.launch_program
        || existing.launch_args != expected.launch_args
        || existing.launch_env != expected.launch_env
    {
        return Ok(false);
    }
    Ok(true)
}

fn is_apple_guest_os(guest_os: &str) -> bool {
    guest_os.contains("macos") || guest_os.contains("ios")
}

fn node_plane_workload_id(runtime_session_id: &UvmRuntimeSessionId) -> Result<WorkloadId> {
    let (_, body) = runtime_session_id
        .as_str()
        .split_once('_')
        .ok_or_else(|| PlatformError::invalid("runtime session id missing prefix separator"))?;
    WorkloadId::parse(format!("wrk_{body}")).map_err(|error| {
        PlatformError::invalid("failed to synthesize node-plane workload id")
            .with_detail(error.to_string())
    })
}

fn node_plane_process_exit_code(runtime: &UvmRuntimeSessionRecord) -> Option<i32> {
    if runtime.state == VmRuntimeState::Stopped {
        return Some(0);
    }
    if runtime.state == VmRuntimeState::Failed
        || matches!(
            HypervisorHealth::parse(&runtime.hypervisor_health),
            Ok(HypervisorHealth::Failed)
        )
    {
        return Some(1);
    }
    None
}

fn node_plane_process_updated_at(runtime: &UvmRuntimeSessionRecord) -> OffsetDateTime {
    let mut updated_at = runtime.last_transition_at;
    if let Some(last_restore_at) = runtime.last_restore_at
        && last_restore_at > updated_at
    {
        updated_at = last_restore_at;
    }
    if let Some(last_heartbeat_at) = runtime.last_heartbeat_at
        && last_heartbeat_at > updated_at
    {
        updated_at = last_heartbeat_at;
    }
    updated_at
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use bytes::Bytes;
    use http::StatusCode;
    use http::{Method, Request};
    use http_body_util::{BodyExt, Full};
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;

    use super::{
        CreateCheckpointRequest, CreateNodeCapabilityRequest, CreateNodeDrainRequest,
        RegisterRuntimeSessionRequest, RepairRuntimeRequest, ResolveRuntimeMigrationRequest,
        RestoreRuntimeRequest, RuntimeHeartbeatRequest, RuntimeMigrationPreflightRequest,
        RuntimePreflightRequest, SelectAdapterRequest, StartRuntimeMigrationRequest,
        UvmFirmwareBundleArtifactRecord, UvmImageArtifactRecord, UvmNodeOperationKind,
        UvmNodeOperationRecord, UvmNodeOperationState, UvmNodeService, UvmRunnerSupervisionRecord,
        UvmRuntimeCheckpointRecord, UvmRuntimeHeartbeatRecord, UvmRuntimeIncarnationKind,
        UvmRuntimeMigrationRecord, UvmRuntimeSessionRecord, VmRuntimeState,
        active_runner_supervision_key, default_host_platform_key, launch_spec_from_runtime_session,
        migration_cutover_event_matches_replay_candidate, migration_cutover_replay_key,
        migration_terminal_event_matches_replay_candidate, migration_terminal_event_type,
        migration_terminal_replay_key, node_plane_workload_id,
        restore_event_matches_replay_candidate, restore_replay_key, runner_supervision_key,
        software_runner_worker_states_for_phase,
    };
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_runtime::{HttpService, RequestBody};
    use uhost_store::OutboxMessage;
    use uhost_types::{
        AuditId, NodeId, PlatformEvent, UvmCheckpointId, UvmInstanceId, UvmMigrationId,
        UvmRuntimeSessionId,
    };
    use uhost_uvm::{
        HypervisorBackend, UvmBackendFallbackPolicy, UvmCompatibilityEvidence,
        UvmCompatibilityEvidenceSource, UvmEvidenceStrictness, UvmExecutionIntent,
        UvmPortabilityTier, VmRuntimeAction,
    };

    async fn seed_control_plane_instance_execution_intent(
        state_root: &std::path::Path,
        instance_id: &UvmInstanceId,
        execution_intent: &UvmExecutionIntent,
    ) {
        let control_root = state_root.join("uvm-control");
        tokio::fs::create_dir_all(&control_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut collection = uhost_store::DocumentCollection::<serde_json::Value>::default();
        collection.records.insert(
            instance_id.to_string(),
            uhost_store::StoredDocument {
                version: 1,
                updated_at: time::OffsetDateTime::now_utc(),
                deleted: false,
                value: serde_json::json!({
                    "id": instance_id,
                    "execution_intent": execution_intent,
                }),
            },
        );
        let payload = serde_json::to_vec(&collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(control_root.join("instances.json"), payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_uvm_image_artifacts(
        state_root: &std::path::Path,
        images: Vec<(String, UvmImageArtifactRecord)>,
        firmware_bundles: Vec<(String, UvmFirmwareBundleArtifactRecord)>,
    ) {
        let image_root = state_root.join("uvm-image");
        tokio::fs::create_dir_all(&image_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut image_collection =
            uhost_store::DocumentCollection::<UvmImageArtifactRecord>::default();
        for (key, value) in images {
            image_collection.records.insert(
                key,
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: time::OffsetDateTime::now_utc(),
                    deleted: false,
                    value,
                },
            );
        }
        let image_payload =
            serde_json::to_vec(&image_collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(image_root.join("images.json"), image_payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut bundle_collection =
            uhost_store::DocumentCollection::<UvmFirmwareBundleArtifactRecord>::default();
        for (key, value) in firmware_bundles {
            bundle_collection.records.insert(
                key,
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: time::OffsetDateTime::now_utc(),
                    deleted: false,
                    value,
                },
            );
        }
        let bundle_payload =
            serde_json::to_vec(&bundle_collection).unwrap_or_else(|error| panic!("{error}"));
        tokio::fs::write(image_root.join("firmware_bundles.json"), bundle_payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    fn scoped_image_compatibility_evidence(
        row_id: &str,
        host_class: &str,
        accelerator_backend: &str,
        policy_approved: bool,
        secure_boot_supported: bool,
        live_migration_supported: bool,
    ) -> UvmCompatibilityEvidence {
        UvmCompatibilityEvidence {
            source: UvmCompatibilityEvidenceSource::ImageContract,
            summary: format!(
                "compatibility_artifact row_id={row_id} host_class={host_class} region=global cell=global host_family=linux accelerator_backend={accelerator_backend} machine_family=general_purpose_pci guest_profile=linux_standard claim_tier=compatible secure_boot_supported={secure_boot_supported} live_migration_supported={live_migration_supported} policy_approved={policy_approved} notes=approved"
            ),
            evidence_mode: Some(if policy_approved {
                String::from("policy_approved")
            } else {
                String::from("policy_blocked")
            }),
        }
    }

    async fn register_software_runtime_session(
        service: &UvmNodeService,
        context: &RequestContext,
    ) -> UvmRuntimeSessionRecord {
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);
        service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .unwrap_or_else(|| panic!("missing runtime session"))
    }

    async fn update_runtime_launch_program(
        service: &UvmNodeService,
        runtime_session_id: &str,
        launch_program: String,
    ) {
        let stored = service
            .runtime_sessions
            .get(runtime_session_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        let mut record = stored.value;
        record.launch_program = launch_program;
        service
            .runtime_sessions
            .upsert(runtime_session_id, record, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[cfg(unix)]
    async fn write_stub_runner_script(root: &std::path::Path) -> String {
        let path = root.join("uhost-uvm-runner-stub.sh");
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
session=""
instance=""
stop=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --session)
      session="$2"
      shift 2
      ;;
    --instance)
      instance="$2"
      shift 2
      ;;
    --stop-sentinel)
      stop="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '{"event":"lifecycle","state":"started","session_id":"%s","instance_id":"%s","phase":"running"}\n' "$session" "$instance"
printf '{"event":"heartbeat","session_id":"%s","instance_id":"%s","phase":"running","heartbeat_sequence":1,"workers":[{"name":"block","state":"running","process_binding":"shared_runner_process","observed_pid":321,"sandbox_layers":["capability_drop","cgroup_v2","namespaces","seccomp"],"sandbox_enforcement_mode":"worker_contract","sandbox_contract_source":"launch_contract","seccomp_profile":"block_io_v1","execution_scope":"artifact_staging","detail":{"artifact_count":2,"disk_image":"object://images/linux.raw","cdrom_image":null}},{"name":"net","state":"running","process_binding":"shared_runner_process","observed_pid":321,"sandbox_layers":["capability_drop","cgroup_v2","namespaces","seccomp"],"sandbox_enforcement_mode":"worker_contract","sandbox_contract_source":"launch_contract","seccomp_profile":"net_io_v1","execution_scope":"virtio_net_observation","detail":{"virtio_net_mmio_present":true,"guest_control_ready":true}}]}\n' "$session" "$instance"
while [[ ! -f "$stop" ]]; do
  sleep 0.02
done
printf '{"event":"lifecycle","state":"stopping","session_id":"%s","instance_id":"%s","reason":"stop_sentinel_detected","final_heartbeat_sequence":1}\n' "$session" "$instance"
printf '{"event":"lifecycle","state":"stopped","session_id":"%s","instance_id":"%s","phase":"stopped","final_heartbeat_sequence":1}\n' "$session" "$instance"
"#;
        tokio::fs::write(&path, script)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut permissions = tokio::fs::metadata(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions();
        permissions.set_mode(0o755);
        tokio::fs::set_permissions(&path, permissions)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        path.to_string_lossy().into_owned()
    }

    async fn wait_for_runner_supervision<F>(
        service: &UvmNodeService,
        key: &str,
        predicate: F,
    ) -> UvmRunnerSupervisionRecord
    where
        F: Fn(&UvmRunnerSupervisionRecord) -> bool,
    {
        for _ in 0..120 {
            if let Some(stored) = service
                .runner_supervision
                .get(key)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                && !stored.deleted
                && predicate(&stored.value)
            {
                return stored.value;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for runner supervision record `{key}`");
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

    fn runner_supervision_worker<'a>(
        workers: &'a [serde_json::Value],
        name: &str,
    ) -> &'a serde_json::Value {
        workers
            .iter()
            .find(|worker| worker["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing runner supervision worker `{name}`"))
    }

    async fn list_node_operations(service: &UvmNodeService) -> Vec<UvmNodeOperationRecord> {
        service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect()
    }

    fn read_audit_events(path: &std::path::Path) -> Vec<PlatformEvent> {
        let Ok(payload) = std::fs::read(path) else {
            return Vec::new();
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

    async fn count_restore_outbox_events_for_runtime(
        service: &UvmNodeService,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint_id: &UvmCheckpointId,
    ) -> usize {
        let replay_key =
            restore_replay_key(runtime, checkpoint_id).unwrap_or_else(|error| panic!("{error}"));
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| {
                restore_event_matches_replay_candidate(
                    &message.payload,
                    runtime,
                    checkpoint_id,
                    &replay_key,
                )
            })
            .count()
    }

    fn count_restore_audit_events_for_runtime(
        audit_log_path: &std::path::Path,
        runtime: &UvmRuntimeSessionRecord,
        checkpoint_id: &UvmCheckpointId,
    ) -> usize {
        let replay_key =
            restore_replay_key(runtime, checkpoint_id).unwrap_or_else(|error| panic!("{error}"));
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| {
                restore_event_matches_replay_candidate(event, runtime, checkpoint_id, &replay_key)
            })
            .count()
    }

    fn is_restore_event_for_runtime(
        event: &PlatformEvent,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> bool {
        if event.header.event_type != "uvm.node.runtime.restored.v1" {
            return false;
        }
        let uhost_types::EventPayload::Service(service) = &event.payload else {
            return false;
        };
        service.resource_kind == "uvm_runtime_session"
            && service.resource_id == runtime_session_id.as_str()
            && service.action == "restore"
    }

    async fn count_total_restore_outbox_events_for_runtime(
        service: &UvmNodeService,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> usize {
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| is_restore_event_for_runtime(&message.payload, runtime_session_id))
            .count()
    }

    fn count_total_restore_audit_events_for_runtime(
        audit_log_path: &std::path::Path,
        runtime_session_id: &UvmRuntimeSessionId,
    ) -> usize {
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| is_restore_event_for_runtime(event, runtime_session_id))
            .count()
    }

    #[allow(dead_code)]
    async fn count_migration_cutover_outbox_events_for_migration(
        service: &UvmNodeService,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
    ) -> usize {
        let replay_key = migration_cutover_replay_key(runtime, migration)
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| {
                migration_cutover_event_matches_replay_candidate(
                    &message.payload,
                    runtime,
                    migration,
                    &replay_key,
                )
            })
            .count()
    }

    #[allow(dead_code)]
    fn count_migration_cutover_audit_events_for_migration(
        audit_log_path: &std::path::Path,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
    ) -> usize {
        let replay_key = migration_cutover_replay_key(runtime, migration)
            .unwrap_or_else(|error| panic!("{error}"));
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| {
                migration_cutover_event_matches_replay_candidate(
                    event,
                    runtime,
                    migration,
                    &replay_key,
                )
            })
            .count()
    }

    #[allow(dead_code)]
    fn is_migration_cutover_event_for_migration(
        event: &PlatformEvent,
        migration_id: &UvmMigrationId,
    ) -> bool {
        if event.header.event_type != "uvm.migration.committed.v1" {
            return false;
        }
        let uhost_types::EventPayload::Service(service) = &event.payload else {
            return false;
        };
        service.resource_kind == "uvm_runtime_migration"
            && service.resource_id == migration_id.as_str()
            && service.action == "commit"
    }

    #[allow(dead_code)]
    async fn count_total_migration_cutover_outbox_events_for_migration(
        service: &UvmNodeService,
        migration_id: &UvmMigrationId,
    ) -> usize {
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| {
                is_migration_cutover_event_for_migration(&message.payload, migration_id)
            })
            .count()
    }

    #[allow(dead_code)]
    fn count_total_migration_cutover_audit_events_for_migration(
        audit_log_path: &std::path::Path,
        migration_id: &UvmMigrationId,
    ) -> usize {
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| is_migration_cutover_event_for_migration(event, migration_id))
            .count()
    }

    async fn count_migration_terminal_outbox_events_for_migration(
        service: &UvmNodeService,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
    ) -> usize {
        let replay_key = migration_terminal_replay_key(runtime, migration, action)
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| {
                migration_terminal_event_matches_replay_candidate(
                    &message.payload,
                    runtime,
                    migration,
                    action,
                    &replay_key,
                )
            })
            .count()
    }

    fn count_migration_terminal_audit_events_for_migration(
        audit_log_path: &std::path::Path,
        runtime: &UvmRuntimeSessionRecord,
        migration: &UvmRuntimeMigrationRecord,
        action: &str,
    ) -> usize {
        let replay_key = migration_terminal_replay_key(runtime, migration, action)
            .unwrap_or_else(|error| panic!("{error}"));
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| {
                migration_terminal_event_matches_replay_candidate(
                    event,
                    runtime,
                    migration,
                    action,
                    &replay_key,
                )
            })
            .count()
    }

    fn is_migration_terminal_event_for_migration(
        event: &PlatformEvent,
        migration_id: &UvmMigrationId,
        action: &str,
    ) -> bool {
        let Some(event_type) = migration_terminal_event_type(action) else {
            panic!("unsupported migration terminal action");
        };
        if event.header.event_type != event_type {
            return false;
        }
        let uhost_types::EventPayload::Service(service) = &event.payload else {
            return false;
        };
        service.resource_kind == "uvm_runtime_migration"
            && service.resource_id == migration_id.as_str()
            && service.action == action
    }

    async fn count_total_migration_terminal_outbox_events_for_migration(
        service: &UvmNodeService,
        migration_id: &UvmMigrationId,
        action: &str,
    ) -> usize {
        service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|message| {
                is_migration_terminal_event_for_migration(&message.payload, migration_id, action)
            })
            .count()
    }

    fn count_total_migration_terminal_audit_events_for_migration(
        audit_log_path: &std::path::Path,
        migration_id: &UvmMigrationId,
        action: &str,
    ) -> usize {
        read_audit_events(audit_log_path)
            .into_iter()
            .filter(|event| is_migration_terminal_event_for_migration(event, migration_id, action))
            .count()
    }

    async fn create_test_node_capability(
        service: &UvmNodeService,
        context: &RequestContext,
        node_id: &NodeId,
        accelerator_backends: Vec<String>,
    ) -> String {
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends,
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .iter()
            .find(|(_, value)| value.value.node_id == *node_id)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"))
    }

    async fn register_basic_runtime_session(
        service: &UvmNodeService,
        context: &RequestContext,
        instance_id: &UvmInstanceId,
        node_id: &NodeId,
        capability_id: &str,
    ) -> http::Response<uhost_api::ApiBody> {
        service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id: String::from(capability_id),
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn node_operation_records_capture_runtime_lifecycle_and_recovery() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/node-ops"),
                    memory_bitmap_hash: String::from("bead"),
                    disk_generation: 1,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let checkpoint = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing checkpoint"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id: checkpoint.id.to_string(),
                    reason: Some(String::from("operator restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Fail,
                "mark_failed",
                Some(String::from("guest crash")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::BeginRecover,
                "recover",
                Some(String::from("runner evidence")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::CompleteRecover,
                "recover_complete",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let operations = list_node_operations(&service).await;
        let start = operations
            .iter()
            .find(|operation| operation.kind == UvmNodeOperationKind::Start)
            .unwrap_or_else(|| panic!("missing start node operation"));
        assert_eq!(start.state, UvmNodeOperationState::Completed);
        assert_eq!(start.runtime_session_id.as_ref(), Some(&runtime.id));
        assert_eq!(start.from_state.as_deref(), Some("registered"));
        assert_eq!(start.to_state.as_deref(), Some("running"));

        let stop = operations
            .iter()
            .find(|operation| operation.kind == UvmNodeOperationKind::Stop)
            .unwrap_or_else(|| panic!("missing stop node operation"));
        assert_eq!(stop.state, UvmNodeOperationState::Completed);
        assert_eq!(stop.from_state.as_deref(), Some("running"));
        assert_eq!(stop.to_state.as_deref(), Some("stopped"));

        let restore = operations
            .iter()
            .find(|operation| operation.kind == UvmNodeOperationKind::Restore)
            .unwrap_or_else(|| panic!("missing restore node operation"));
        assert_eq!(restore.state, UvmNodeOperationState::Completed);
        assert_eq!(restore.reason.as_deref(), Some("operator restore"));
        assert_eq!(restore.checkpoint_id.as_ref(), Some(&checkpoint.id));
        assert_eq!(restore.from_state.as_deref(), Some("stopped"));
        assert_eq!(restore.to_state.as_deref(), Some("running"));

        let recover = operations
            .iter()
            .find(|operation| operation.kind == UvmNodeOperationKind::Recover)
            .unwrap_or_else(|| panic!("missing recover node operation"));
        assert_eq!(recover.state, UvmNodeOperationState::Completed);
        assert_eq!(recover.reason.as_deref(), Some("runner evidence"));
        assert_eq!(recover.phase.as_deref(), Some("completed"));
        assert_eq!(recover.from_state.as_deref(), Some("failed"));
        assert_eq!(recover.to_state.as_deref(), Some("running"));
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation.kind == UvmNodeOperationKind::Recover)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn node_operation_records_track_migration_resolution() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node_id,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime.id.to_string(),
                    to_node_id: target_node_id.to_string(),
                    target_capability_id: target_capability_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/migrate-node-op"),
                    memory_bitmap_hash: String::from("facefeed"),
                    disk_generation: 7,
                    reason: String::from("rebalance node"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing migration"));

        let operations = list_node_operations(&service).await;
        let migrate = operations
            .iter()
            .find(|operation| {
                operation.kind == UvmNodeOperationKind::Migrate
                    && operation.linked_resource_id.as_deref() == Some(migration.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing migrate node operation"));
        assert_eq!(migrate.state, UvmNodeOperationState::InProgress);
        assert_eq!(migrate.node_id, source_node_id);
        assert_eq!(migrate.target_node_id.as_ref(), Some(&target_node_id));
        assert_eq!(migrate.reason.as_deref(), Some("rebalance node"));
        assert_eq!(migrate.phase.as_deref(), Some("in_progress"));
        assert_eq!(
            migrate.linked_resource_kind.as_deref(),
            Some("runtime_migration")
        );

        let committed = service
            .resolve_runtime_migration(
                migration.id.as_str(),
                "commit",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(committed.status(), StatusCode::OK);

        let operations = list_node_operations(&service).await;
        let migrate = operations
            .iter()
            .find(|operation| {
                operation.kind == UvmNodeOperationKind::Migrate
                    && operation.linked_resource_id.as_deref() == Some(migration.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing committed migrate node operation"));
        assert_eq!(migrate.state, UvmNodeOperationState::Completed);
        assert_eq!(migrate.phase.as_deref(), Some("committed"));
        assert_eq!(migrate.to_state.as_deref(), Some("running"));
        assert_eq!(
            operations
                .iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Migrate
                        && operation.linked_resource_id.as_deref() == Some(migration.id.as_str())
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn node_operation_records_track_drain_phases() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_node_drain(
                CreateNodeDrainRequest {
                    node_id: node_id.to_string(),
                    reason: String::from("maintenance window"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let drain: serde_json::Value = parse_api_body(created).await;
        let drain_id = drain["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing node drain id"))
            .to_owned();

        let operations = list_node_operations(&service).await;
        let drain_operation = operations
            .iter()
            .find(|operation| {
                operation.kind == UvmNodeOperationKind::Drain
                    && operation.linked_resource_id.as_deref() == Some(drain_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing initial drain node operation"));
        assert_eq!(drain_operation.state, UvmNodeOperationState::InProgress);
        assert_eq!(drain_operation.phase.as_deref(), Some("quiesce"));
        assert_eq!(
            drain_operation.reason.as_deref(),
            Some("maintenance window")
        );

        let evacuated = service
            .transition_node_drain(drain_id.as_str(), "evacuate", None, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(evacuated.status(), StatusCode::OK);
        let completed = service
            .transition_node_drain(drain_id.as_str(), "complete", None, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed.status(), StatusCode::OK);

        let operations = list_node_operations(&service).await;
        let drain_operation = operations
            .iter()
            .find(|operation| {
                operation.kind == UvmNodeOperationKind::Drain
                    && operation.linked_resource_id.as_deref() == Some(drain_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing final drain node operation"));
        assert_eq!(drain_operation.state, UvmNodeOperationState::Completed);
        assert_eq!(drain_operation.phase.as_deref(), Some("completed"));
        assert_eq!(
            operations
                .iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Drain
                        && operation.linked_resource_id.as_deref() == Some(drain_id.as_str())
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn read_helpers_return_runtime_records_and_outbox_messages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node_id,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                &runtime_session_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migration = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node_id.to_string(),
                    target_capability_id,
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/read-helper.snap"),
                    memory_bitmap_hash: String::from("0123456789abcdef0123456789abcdef"),
                    disk_generation: 7,
                    reason: String::from("reader-drill"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(migration.status(), StatusCode::CREATED);
        let checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime checkpoint"));
        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let outbox_message_id = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|value| value.id.clone())
            .unwrap_or_else(|| panic!("missing node outbox message"));

        let runtime_session: UvmRuntimeSessionRecord = parse_api_body(
            service
                .get_runtime_session(&runtime_session_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(runtime_session.id.to_string(), runtime_session_id);

        let checkpoint: UvmRuntimeCheckpointRecord = parse_api_body(
            service
                .get_runtime_checkpoint(&checkpoint_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(checkpoint.id.to_string(), checkpoint_id);

        let runtime_migration: UvmRuntimeMigrationRecord = parse_api_body(
            service
                .get_runtime_migration(&migration_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(runtime_migration.id.to_string(), migration_id);

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
    async fn runtime_repair_selects_restart_for_stopped_session() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stopped_runtime = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stopped runtime session"));
        let supervision_key = active_runner_supervision_key(&stopped_runtime.value)
            .unwrap_or_else(|| panic!("missing active runner supervision key"));
        let runtime_incarnation = stopped_runtime
            .value
            .current_incarnation
            .as_ref()
            .map(|incarnation| incarnation.sequence)
            .unwrap_or_else(|| panic!("missing current runtime incarnation"));
        let now = time::OffsetDateTime::now_utc();
        service
            .runner_supervision
            .create(
                &supervision_key,
                UvmRunnerSupervisionRecord {
                    runtime_session_id: stopped_runtime.value.id.clone(),
                    runtime_incarnation,
                    instance_id: stopped_runtime.value.instance_id.clone(),
                    node_id: stopped_runtime.value.node_id.clone(),
                    launch_program: String::from("uhost-uvm-runner"),
                    launch_args: Vec::new(),
                    launch_env: Vec::new(),
                    stop_sentinel_path: String::from("/tmp/runtime-repair.stop"),
                    state: String::from("stopped"),
                    observed_pid: Some(9001),
                    last_event_kind: Some(String::from("lifecycle")),
                    last_lifecycle_state: Some(String::from("stopped")),
                    last_runner_phase: Some(String::from("stopped")),
                    workers: vec![
                        serde_json::json!({
                            "name": "block",
                            "state": "running",
                            "process_binding": "shared_runner_process",
                            "observed_pid": 9001,
                            "sandbox_layers": ["capability_drop", "cgroup_v2", "namespaces", "seccomp"],
                            "sandbox_enforcement_mode": "worker_contract",
                            "sandbox_contract_source": "launch_contract",
                            "seccomp_profile": "block_io_v1",
                            "execution_scope": "artifact_staging",
                            "detail": {
                                "artifact_count": 2,
                                "disk_image": "object://images/linux.raw",
                                "cdrom_image": "object://images/installer.iso"
                            }
                        }),
                        serde_json::json!({
                            "name": "net",
                            "state": "running",
                            "process_binding": "shared_runner_process",
                            "observed_pid": 9001,
                            "sandbox_layers": ["capability_drop", "cgroup_v2", "namespaces", "seccomp"],
                            "sandbox_enforcement_mode": "worker_contract",
                            "sandbox_contract_source": "launch_contract",
                            "seccomp_profile": "net_io_v1",
                            "execution_scope": "virtio_net_observation",
                            "detail": {
                                "virtio_net_mmio_present": true,
                                "guest_control_ready": true
                            }
                        }),
                    ],
                    network_access: None,
                    boot_stages: Vec::new(),
                    console_trace: Vec::new(),
                    guest_control_ready: true,
                    last_heartbeat_sequence: Some(7),
                    stop_reason: Some(String::from("operator requested stop")),
                    exit_status: Some(0),
                    failure_detail: None,
                    requested_at: now,
                    started_at: Some(now),
                    last_event_at: now,
                    finished_at: Some(now),
                    metadata: uhost_types::ResourceMetadata::new(
                        uhost_types::OwnershipScope::Platform,
                        Some(supervision_key.clone()),
                        uhost_core::sha256_hex(supervision_key.as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair: UvmNodeOperationRecord = parse_api_body(
            service
                .repair_runtime_session(
                    runtime.id.as_str(),
                    RepairRuntimeRequest {
                        reason: Some(String::from("restart stopped runtime")),
                        stale_after_seconds: None,
                        target_node_id: None,
                        target_capability_id: None,
                        execution_intent: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(repair.kind, UvmNodeOperationKind::Repair);
        assert_eq!(repair.state, UvmNodeOperationState::Completed);
        assert_eq!(repair.phase.as_deref(), Some("restart"));
        assert_eq!(repair.from_state.as_deref(), Some("stopped"));
        assert_eq!(repair.to_state.as_deref(), Some("running"));
        let detail = repair
            .detail
            .as_deref()
            .unwrap_or_else(|| panic!("missing repair detail"));
        assert!(detail.contains("runner_supervision_workers=2"));
        assert!(detail.contains("runner_supervision_worker[block]=state=running"));
        assert!(detail.contains("detail.artifact_count=2"));
        assert!(detail.contains("detail.disk_image=\"object://images/linux.raw\""));
        assert!(detail.contains("runner_supervision_worker[net]=state=running"));
        assert!(detail.contains("detail.guest_control_ready=true"));
        assert!(detail.contains("detail.virtio_net_mmio_present=true"));

        let runtime = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.state, VmRuntimeState::Running);
    }

    #[tokio::test]
    async fn runtime_repair_selects_restore_for_failed_session_with_checkpoint() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/repair-restore"),
                    memory_bitmap_hash: String::from("feedface"),
                    disk_generation: 3,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Fail,
                "mark_failed",
                Some(String::from("guest panic")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair: UvmNodeOperationRecord = parse_api_body(
            service
                .repair_runtime_session(
                    runtime.id.as_str(),
                    RepairRuntimeRequest {
                        reason: Some(String::from("restore failed runtime")),
                        stale_after_seconds: None,
                        target_node_id: None,
                        target_capability_id: None,
                        execution_intent: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(repair.kind, UvmNodeOperationKind::Repair);
        assert_eq!(repair.state, UvmNodeOperationState::Completed);
        assert_eq!(repair.phase.as_deref(), Some("restore"));
        assert_eq!(repair.from_state.as_deref(), Some("failed"));
        assert_eq!(repair.to_state.as_deref(), Some("running"));
        assert!(repair.checkpoint_id.is_some());

        let runtime = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.state, VmRuntimeState::Running);
        assert_eq!(runtime.value.restore_count, 1);
        assert!(runtime.value.restored_from_checkpoint_id.is_some());
    }

    #[tokio::test]
    async fn runtime_repair_selects_migration_for_active_node_drain() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node_id,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node_id,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_drain(
                CreateNodeDrainRequest {
                    node_id: source_node_id.to_string(),
                    reason: String::from("planned evacuation"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair: UvmNodeOperationRecord = parse_api_body(
            service
                .repair_runtime_session(
                    runtime.id.as_str(),
                    RepairRuntimeRequest {
                        reason: Some(String::from("migrate draining node")),
                        stale_after_seconds: None,
                        target_node_id: None,
                        target_capability_id: None,
                        execution_intent: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(repair.kind, UvmNodeOperationKind::Repair);
        assert_eq!(repair.state, UvmNodeOperationState::Completed);
        assert_eq!(repair.phase.as_deref(), Some("migration"));
        assert_eq!(repair.from_state.as_deref(), Some("running"));
        assert_eq!(repair.to_state.as_deref(), Some("running"));
        assert_eq!(repair.target_node_id, Some(target_node_id));
        assert_eq!(
            repair.linked_resource_id.as_deref(),
            Some(target_capability_id.as_str())
        );

        let runtime = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.state, VmRuntimeState::Running);
        assert!(!runtime.value.migration_in_progress);
    }

    #[tokio::test]
    async fn node_drain_quiesce_blocks_new_runtime_work() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let drained = service
            .create_node_drain(
                CreateNodeDrainRequest {
                    node_id: node_id.to_string(),
                    reason: String::from("planned maintenance"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(drained.status(), StatusCode::CREATED);
        let drain_record = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing node drain"));
        assert_eq!(drain_record.state, "quiesce");
        assert!(
            drain_record
                .tracked_runtime_session_ids
                .iter()
                .any(|value| value.as_str() == runtime_session_id)
        );

        let start_error = service
            .transition_runtime_session(
                &runtime_session_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_err();
        assert!(
            start_error
                .to_string()
                .contains("not accepting new runtime work")
        );

        let second_instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let registration_error = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: second_instance.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/second.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_err();
        assert!(
            registration_error
                .to_string()
                .contains("not accepting new runtime work")
        );
    }

    #[tokio::test]
    async fn node_drain_evacuate_tracks_remaining_sessions_and_completes_after_stop() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let started = service
            .transition_runtime_session(
                &runtime_session_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::OK);

        let drained = service
            .create_node_drain(
                CreateNodeDrainRequest {
                    node_id: node_id.to_string(),
                    reason: String::from("hardware replacement"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(drained.status(), StatusCode::CREATED);
        let drain_id = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing node drain"));

        let evacuated = service
            .transition_node_drain(&drain_id, "evacuate", None, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(evacuated.status(), StatusCode::OK);
        let drain_record = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing node drain"));
        assert_eq!(drain_record.state, "evacuate");
        assert!(
            drain_record
                .active_runtime_session_ids
                .iter()
                .any(|value| value.as_str() == runtime_session_id)
        );

        let stopped = service
            .transition_runtime_session(
                &runtime_session_id,
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stopped.status(), StatusCode::OK);
        let completed = service
            .transition_node_drain(&drain_id, "complete", None, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed.status(), StatusCode::OK);
        let completed_record = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing node drain"));
        assert_eq!(completed_record.state, "completed");
        assert!(completed_record.active_runtime_session_ids.is_empty());
        assert!(
            completed_record
                .inactive_runtime_session_ids
                .iter()
                .any(|value| value.as_str() == runtime_session_id)
        );
    }

    #[tokio::test]
    async fn node_drain_fail_records_failure_and_releases_quiesce() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let drained = service
            .create_node_drain(
                CreateNodeDrainRequest {
                    node_id: node_id.to_string(),
                    reason: String::from("evacuation rehearsal"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(drained.status(), StatusCode::CREATED);
        let drain_id = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing node drain"));

        let failed = service
            .transition_node_drain(
                &drain_id,
                "fail",
                Some(String::from("evacuation timed out")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed.status(), StatusCode::OK);
        let failed_record = service
            .node_drains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing node drain"));
        assert_eq!(failed_record.state, "failed");
        assert_eq!(
            failed_record.failure_detail.as_deref(),
            Some("evacuation timed out")
        );

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn select_adapter_prefers_kvm() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let (architecture, accelerator_backends, expected_backend) =
            match uhost_uvm::HostPlatform::current() {
                uhost_uvm::HostPlatform::Linux => {
                    (String::from("x86_64"), vec![String::from("kvm")], "kvm")
                }
                uhost_uvm::HostPlatform::Windows => (
                    String::from("x86_64"),
                    vec![String::from("hyperv_whp")],
                    "hyperv_whp",
                ),
                uhost_uvm::HostPlatform::Macos => (
                    String::from("aarch64"),
                    vec![String::from("apple_virtualization")],
                    "apple_virtualization",
                ),
                uhost_uvm::HostPlatform::FreeBsd
                | uhost_uvm::HostPlatform::OpenBsd
                | uhost_uvm::HostPlatform::NetBsd
                | uhost_uvm::HostPlatform::DragonFlyBsd => {
                    (String::from("x86_64"), vec![String::from("bhyve")], "bhyve")
                }
                _ => return,
            };

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture,
                    accelerator_backends,
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: true,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let selected = service
            .select_adapter(
                SelectAdapterRequest {
                    capability_id,
                    guest_architecture: String::from(
                        if expected_backend == "apple_virtualization" {
                            "aarch64"
                        } else {
                            "x86_64"
                        },
                    ),
                    apple_guest: false,
                    requires_live_migration: false,
                    require_secure_boot: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(selected.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn node_capability_derives_host_class_from_posture() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 4,
                    max_memory_mb: 4_096,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: Some(true),
                    host_evidence_mode: Some(String::from("container_restricted")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let capability = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .unwrap_or_else(|| panic!("missing capability"));
        assert_eq!(capability.host_class, "linux_container_restricted");
    }

    #[tokio::test]
    async fn software_dbt_runtime_registration_uses_runner_contract() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.accelerator_backend, "software_dbt");
        assert_eq!(runtime_session.launch_program, "uhost-uvm-runner");
        assert_eq!(runtime_session.machine_family, "general_purpose_pci");
        assert_eq!(runtime_session.guest_profile, "linux_standard");
        assert_eq!(
            runtime_session.worker_states,
            software_runner_worker_states_for_phase("registered")
        );
        assert!(
            runtime_session
                .launch_args
                .windows(2)
                .any(|pair| pair[0] == "--machine-family" && pair[1] == "general_purpose_pci")
        );
        assert!(
            runtime_session
                .launch_args
                .windows(2)
                .any(|pair| pair[0] == "--runner-mode" && pair[1] == "supervise")
        );
        assert!(
            runtime_session
                .launch_args
                .windows(2)
                .any(|pair| pair[0] == "--heartbeat-interval-ms" && pair[1] == "1000")
        );
        assert!(
            runtime_session
                .launch_args
                .windows(2)
                .any(|pair| pair[0] == "--memory-backing" && pair[1] == "file_backed")
        );
        assert!(
            runtime_session
                .launch_env
                .iter()
                .any(|value| value == "UVM_BACKEND=software_dbt")
        );
        assert!(runtime_session.launch_env.iter().any(
            |value| value == "UVM_SANDBOX_LAYERS=capability_drop,cgroup_v2,namespaces,seccomp"
        ));
        assert!(
            runtime_session
                .launch_env
                .iter()
                .any(|value| value == "UVM_SOFTVM_WORKERS=supervisor,core,block,net")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_runtime_session_spawns_and_watches_runner_supervision_record() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session = register_software_runtime_session(&service, &context).await;
        let stub_runner = write_stub_runner_script(temp.path()).await;
        update_runtime_launch_program(&service, runtime_session.id.as_str(), stub_runner).await;

        let response = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let started_runtime = service
            .runtime_sessions
            .get(runtime_session.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing started runtime session"))
            .value;
        let supervision_key = active_runner_supervision_key(&started_runtime)
            .unwrap_or_else(|| panic!("missing runner supervision key"));
        let running = wait_for_runner_supervision(&service, &supervision_key, |record| {
            record.state == "running" && record.last_heartbeat_sequence == Some(1)
        })
        .await;
        assert_eq!(running.runtime_session_id, runtime_session.id);
        assert_eq!(running.runtime_incarnation, 1);
        assert!(running.observed_pid.is_some());
        assert_eq!(running.last_lifecycle_state.as_deref(), Some("started"));
        assert_eq!(running.last_heartbeat_sequence, Some(1));
        let running_block = runner_supervision_worker(&running.workers, "block");
        let running_net = runner_supervision_worker(&running.workers, "net");
        assert_eq!(running_block["detail"]["artifact_count"].as_u64(), Some(2));
        assert_eq!(
            running_net["detail"]["guest_control_ready"].as_bool(),
            Some(true)
        );

        let stop_response = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stop_response.status(), StatusCode::OK);

        let stopped = wait_for_runner_supervision(&service, &supervision_key, |record| {
            record.state == "stopped" && record.finished_at.is_some()
        })
        .await;
        assert_eq!(stopped.last_lifecycle_state.as_deref(), Some("stopped"));
        assert_eq!(stopped.exit_status, Some(0));
        let stopped_block = runner_supervision_worker(&stopped.workers, "block");
        let stopped_net = runner_supervision_worker(&stopped.workers, "net");
        assert_eq!(stopped_block["detail"]["artifact_count"].as_u64(), Some(2));
        assert_eq!(
            stopped_net["detail"]["guest_control_ready"].as_bool(),
            Some(true)
        );
    }

    #[tokio::test]
    async fn runner_supervision_records_are_keyed_by_runtime_incarnation_and_survive_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session = register_software_runtime_session(&service, &context).await;
        let stub_runner = write_stub_runner_script(temp.path()).await;
        update_runtime_launch_program(&service, runtime_session.id.as_str(), stub_runner).await;

        let first_start = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_start.status(), StatusCode::OK);
        let first_runtime = service
            .runtime_sessions
            .get(runtime_session.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first-start runtime session"))
            .value;
        let first_key = active_runner_supervision_key(&first_runtime)
            .unwrap_or_else(|| panic!("missing first runner supervision key"));
        assert_eq!(first_key, runner_supervision_key(&runtime_session.id, 1));
        let first_running = wait_for_runner_supervision(&service, &first_key, |record| {
            record.state == "running" && record.last_heartbeat_sequence == Some(1)
        })
        .await;
        assert_eq!(first_running.runtime_incarnation, 1);
        assert!(
            first_running
                .stop_sentinel_path
                .contains("/runner_supervision/")
        );
        assert!(first_running.stop_sentinel_path.contains("/incarnation-1/"));

        let first_stop = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_stop.status(), StatusCode::OK);
        let first_stopped = wait_for_runner_supervision(&service, &first_key, |record| {
            record.state == "stopped" && record.finished_at.is_some()
        })
        .await;
        assert_eq!(first_stopped.exit_status, Some(0));

        let second_start = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Start,
                "restart",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_start.status(), StatusCode::OK);
        let second_runtime = service
            .runtime_sessions
            .get(runtime_session.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second-start runtime session"))
            .value;
        let second_key = active_runner_supervision_key(&second_runtime)
            .unwrap_or_else(|| panic!("missing second runner supervision key"));
        assert_eq!(second_key, runner_supervision_key(&runtime_session.id, 2));
        assert_ne!(second_key, first_key);
        let second_running = wait_for_runner_supervision(&service, &second_key, |record| {
            record.state == "running" && record.last_heartbeat_sequence == Some(1)
        })
        .await;
        assert_eq!(second_running.runtime_incarnation, 2);
        assert!(
            second_running
                .stop_sentinel_path
                .contains("/incarnation-2/")
        );
        let second_block = runner_supervision_worker(&second_running.workers, "block");
        let second_net = runner_supervision_worker(&second_running.workers, "net");
        assert_eq!(second_block["detail"]["artifact_count"].as_u64(), Some(2));
        assert_eq!(
            second_net["detail"]["guest_control_ready"].as_bool(),
            Some(true)
        );

        let second_stop = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_stop.status(), StatusCode::OK);
        let second_stopped = wait_for_runner_supervision(&service, &second_key, |record| {
            record.state == "stopped" && record.finished_at.is_some()
        })
        .await;
        assert_eq!(second_stopped.exit_status, Some(0));

        let reopened_service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_first = reopened_service
            .runner_supervision
            .get(&first_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first runner supervision record after reopen"));
        let reopened_second = reopened_service
            .runner_supervision
            .get(&second_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing second runner supervision record after reopen"));
        assert_eq!(reopened_first.value.runtime_incarnation, 1);
        assert_eq!(reopened_second.value.runtime_incarnation, 2);
        assert_eq!(reopened_first.value.runtime_session_id, runtime_session.id);
        assert_eq!(reopened_second.value.runtime_session_id, runtime_session.id);
        assert_eq!(reopened_first.value.state, "stopped");
        assert_eq!(reopened_second.value.state, "stopped");
        assert_eq!(reopened_first.value.last_heartbeat_sequence, Some(1));
        assert_eq!(reopened_second.value.last_heartbeat_sequence, Some(1));
        assert!(
            reopened_first
                .value
                .stop_sentinel_path
                .contains("/incarnation-1/")
        );
        assert!(
            reopened_second
                .value
                .stop_sentinel_path
                .contains("/incarnation-2/")
        );
    }

    #[tokio::test]
    async fn start_runtime_session_records_runner_supervision_spawn_failure() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session = register_software_runtime_session(&service, &context).await;
        update_runtime_launch_program(
            &service,
            runtime_session.id.as_str(),
            String::from("/definitely/missing/uhost-uvm-runner"),
        )
        .await;

        let response = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let started_runtime = service
            .runtime_sessions
            .get(runtime_session.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing started runtime session"))
            .value;
        let supervision_key = active_runner_supervision_key(&started_runtime)
            .unwrap_or_else(|| panic!("missing runner supervision key"));
        let failed = wait_for_runner_supervision(&service, &supervision_key, |record| {
            record.state == "failed" && record.finished_at.is_some()
        })
        .await;
        assert!(failed.observed_pid.is_none());
        assert!(failed.failure_detail.is_some());
        assert!(
            failed
                .failure_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("failed to spawn runner process"))
        );
    }

    #[tokio::test]
    async fn software_runtime_registration_rejects_verified_non_local_disk_artifact() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_uvm_image_artifacts(
            temp.path(),
            vec![(
                String::from("img_non_local"),
                UvmImageArtifactRecord {
                    source_uri: String::from("object://images/linux.raw"),
                    verified: true,
                    ..Default::default()
                },
            )],
            Vec::new(),
        )
        .await;

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: None,
                    restart_policy: None,
                    max_restarts: None,
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(
                "software-backed launch contracts require local absolute file:// artifacts"
            )
        );
    }

    #[tokio::test]
    async fn software_runtime_registration_attaches_verified_local_firmware_artifact() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_uvm_image_artifacts(
            temp.path(),
            vec![(
                String::from("img_local"),
                UvmImageArtifactRecord {
                    source_uri: String::from("file:///var/lib/uhost/images/linux.raw"),
                    verified: true,
                    ..Default::default()
                },
            )],
            vec![(
                String::from("fw_local"),
                UvmFirmwareBundleArtifactRecord {
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("file:///var/lib/uhost/firmware/uefi-standard.fd"),
                    verified: true,
                },
            )],
        )
        .await;

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("file:///var/lib/uhost/images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: None,
                    restart_policy: None,
                    max_restarts: None,
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert!(runtime_session.launch_args.windows(2).any(|pair| {
            pair[0] == "--firmware-artifact"
                && pair[1] == "file:///var/lib/uhost/firmware/uefi-standard.fd"
        }));
        assert!(runtime_session.launch_args.windows(2).any(|pair| {
            pair[0] == "--disk" && pair[1] == "file:///var/lib/uhost/images/linux.raw"
        }));
    }

    #[tokio::test]
    async fn preserved_launch_spec_firmware_artifact_is_preferred_over_profile_lookup() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        seed_uvm_image_artifacts(
            temp.path(),
            Vec::new(),
            vec![(
                String::from("fw_default"),
                UvmFirmwareBundleArtifactRecord {
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("file:///var/lib/uhost/firmware/uefi-standard.fd"),
                    verified: true,
                },
            )],
        )
        .await;

        let launch_spec = uhost_uvm::LaunchSpec {
            runtime_session_id: String::from("urs_preserved_fw_1"),
            instance_id: String::from("uvi_preserved_fw_1"),
            guest_architecture: uhost_uvm::GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: Some(String::from(
                "file:///var/lib/uhost/firmware/custom-explicit.fd",
            )),
            disk_image: String::from("file:///var/lib/uhost/images/linux.raw"),
            cdrom_image: None,
            boot_device: String::from(uhost_uvm::BootDevice::Disk.as_str()),
        };

        let resolved = service
            .resolve_preserved_local_firmware_artifact_uri(&launch_spec)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            resolved.as_deref(),
            Some("file:///var/lib/uhost/firmware/custom-explicit.fd")
        );
    }

    #[tokio::test]
    async fn runtime_registration_consumes_scoped_image_compatibility_artifact() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_uvm_image_artifacts(
            temp.path(),
            vec![(
                String::from("img_scoped"),
                UvmImageArtifactRecord {
                    source_uri: String::from("object://images/linux.raw"),
                    verified: true,
                    architecture: String::from("x86_64"),
                    compatibility_evidence: vec![scoped_image_compatibility_evidence(
                        "row-kvm-global",
                        "linux_bare_metal",
                        "kvm",
                        true,
                        true,
                        true,
                    )],
                    ..Default::default()
                },
            )],
            Vec::new(),
        )
        .await;

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2_048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.accelerator_backend, "kvm");

        let stored_intent = service
            .runtime_session_intents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session intent"));
        let first_placement = stored_intent
            .first_placement_portability_assessment
            .unwrap_or_else(|| panic!("missing first-placement portability assessment"));
        assert_eq!(
            first_placement.selected_backend,
            Some(HypervisorBackend::Kvm)
        );
        let scoped_evidence = first_placement
            .evidence
            .iter()
            .find(|row| {
                row.source == UvmCompatibilityEvidenceSource::ImageContract
                    && row
                        .summary
                        .starts_with("scoped image compatibility artifact ")
            })
            .unwrap_or_else(|| panic!("missing scoped image compatibility evidence"));
        assert_eq!(
            scoped_evidence.evidence_mode.as_deref(),
            Some("policy_approved")
        );
        assert!(scoped_evidence.summary.contains("row_id=row-kvm-global"));
        assert!(
            scoped_evidence
                .summary
                .contains("host_class=linux_bare_metal")
        );
        assert!(scoped_evidence.summary.contains("region=global"));
        assert!(scoped_evidence.summary.contains("cell=global"));
        assert!(scoped_evidence.summary.contains("accelerator_backend=kvm"));
        assert!(
            scoped_evidence
                .summary
                .contains("machine_family=general_purpose_pci")
        );
        assert!(
            scoped_evidence
                .summary
                .contains("guest_profile=linux_standard")
        );
        assert!(scoped_evidence.summary.contains("claim_tier=compatible"));
        assert!(scoped_evidence.summary.contains("policy_approved=true"));
    }

    #[tokio::test]
    async fn runtime_registration_rejects_mismatched_scoped_image_compatibility_artifact() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_uvm_image_artifacts(
            temp.path(),
            vec![(
                String::from("img_scoped_mismatch"),
                UvmImageArtifactRecord {
                    source_uri: String::from("object://images/linux.raw"),
                    verified: true,
                    architecture: String::from("x86_64"),
                    compatibility_evidence: vec![scoped_image_compatibility_evidence(
                        "row-software-only",
                        "linux_bare_metal",
                        "software_dbt",
                        true,
                        true,
                        true,
                    )],
                    ..Default::default()
                },
            )],
            Vec::new(),
        )
        .await;

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2_048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(
            error
                .to_string()
                .contains("image compatibility artifacts do not publish backend `kvm`")
        );
        assert!(
            error
                .to_string()
                .contains("host_class `linux_bare_metal` in scope `global/global`")
        );
        assert!(
            service
                .runtime_sessions
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        assert!(
            service
                .runtime_session_intents
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn runtime_registration_persists_safe_default_execution_intent_when_control_plane_record_is_missing()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt"), String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(true),
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.accelerator_backend, "kvm");

        let stored_intent = service
            .runtime_session_intents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session intent"));
        assert_eq!(stored_intent.runtime_session_id, runtime_session.id);
        assert_eq!(stored_intent.instance_id, instance_id);
        assert_eq!(
            stored_intent.execution_intent,
            UvmExecutionIntent::default()
        );
        assert!(stored_intent.lineage_id.is_some());
        assert!(stored_intent.last_portability_preflight_id.is_none());
        let first_placement = stored_intent
            .first_placement_portability_assessment
            .unwrap_or_else(|| panic!("missing first-placement portability assessment"));
        assert!(first_placement.supported);
        assert_eq!(first_placement.intent, UvmExecutionIntent::default());
        assert_eq!(
            first_placement.selected_backend,
            Some(HypervisorBackend::Kvm)
        );
    }

    #[tokio::test]
    async fn runtime_registration_prefers_control_plane_execution_intent_and_persists_it() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt"), String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(true),
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let explicit_intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::SoftwareDbt),
            fallback_policy: UvmBackendFallbackPolicy::AllowCompatible,
            required_portability_tier: UvmPortabilityTier::Portable,
            evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
        };
        seed_control_plane_instance_execution_intent(temp.path(), &instance_id, &explicit_intent)
            .await;

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.accelerator_backend, "software_dbt");
        assert_eq!(runtime_session.launch_program, "uhost-uvm-runner");

        let stored_intent = service
            .runtime_session_intents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session intent"));
        assert_eq!(stored_intent.runtime_session_id, runtime_session.id);
        assert_eq!(stored_intent.execution_intent, explicit_intent);
        assert!(stored_intent.lineage_id.is_some());
        let first_placement = stored_intent
            .first_placement_portability_assessment
            .unwrap_or_else(|| panic!("missing first-placement portability assessment"));
        assert!(first_placement.supported);
        assert_eq!(first_placement.intent, explicit_intent);
        assert_eq!(
            first_placement.selected_backend,
            Some(HypervisorBackend::SoftwareDbt)
        );
    }

    #[tokio::test]
    async fn software_runner_capability_posture_gates_software_backend_selection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(false),
                    container_restricted: Some(true),
                    host_evidence_mode: Some(String::from("container_restricted")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let error = service
            .select_adapter(
                SelectAdapterRequest {
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    apple_guest: false,
                    requires_live_migration: false,
                    require_secure_boot: Some(false),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected software-runner posture conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn software_runner_capability_defaults_to_full_vm_profiles() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: Some(true),
                    host_evidence_mode: Some(String::from("container_restricted")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let capability = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing capability"));
        assert_eq!(
            capability.supported_machine_families,
            vec![String::from("general_purpose_pci")]
        );
        assert_eq!(
            capability.supported_guest_profiles,
            vec![String::from("linux_standard")]
        );
    }

    #[tokio::test]
    async fn software_runner_restore_updates_lineage_and_health_summary() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("software_dbt")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: false,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(true),
                    container_restricted: Some(true),
                    host_evidence_mode: Some(String::from("container_restricted")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(31337),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![
                        String::from("core:running"),
                        String::from("net:running"),
                    ]),
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime_id.clone(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/softvm.snap"),
                    memory_bitmap_hash: String::from("abcd"),
                    disk_generation: 1,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing checkpoint"));

        let _ = service
            .transition_runtime_session(&runtime_id, VmRuntimeAction::Stop, "stop", None, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restored = service
            .restore_runtime_session(
                &runtime_id,
                RestoreRuntimeRequest {
                    checkpoint_id,
                    reason: Some(String::from("checkpoint replay")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored.status(), StatusCode::OK);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.restore_count, 1);
        assert!(runtime_session.last_checkpoint_id.is_some());
        assert!(runtime_session.restored_from_checkpoint_id.is_some());
        assert!(runtime_session.last_restore_at.is_some());
        assert_eq!(runtime_session.runner_phase, "restored");
        assert_eq!(runtime_session.incarnation_lineage.len(), 2);
        assert_eq!(
            runtime_session.incarnation_lineage[0].kind,
            UvmRuntimeIncarnationKind::OriginalBoot
        );
        let current_incarnation = runtime_session
            .current_incarnation
            .as_ref()
            .unwrap_or_else(|| panic!("missing current runtime incarnation"));
        assert_eq!(current_incarnation.kind, UvmRuntimeIncarnationKind::Restore);
        assert_eq!(current_incarnation.previous_sequence, Some(1));
        assert_eq!(
            current_incarnation.previous_state,
            Some(VmRuntimeState::Stopped)
        );
        assert_eq!(
            current_incarnation.checkpoint_id.as_ref(),
            runtime_session.restored_from_checkpoint_id.as_ref()
        );
        assert_eq!(
            current_incarnation.target_node_id.as_str(),
            runtime_session.node_id.as_str()
        );
        assert!(
            runtime_session
                .worker_states
                .iter()
                .any(|value| value == "core:restored")
        );
        assert!(
            runtime_session
                .worker_states
                .iter()
                .any(|value| value == "supervisor:running")
        );
        assert!(
            runtime_session
                .worker_states
                .iter()
                .any(|value| value == "block:running")
        );
        assert!(
            runtime_session
                .worker_states
                .iter()
                .any(|value| value == "net:running")
        );
        assert_eq!(
            runtime_session.runtime_evidence_mode,
            "container_restricted"
        );

        let summary = service
            .runtime_health_summary(60)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.software_backend_sessions, 1);
        assert_eq!(summary.restored_sessions, 1);
    }

    #[tokio::test]
    async fn restore_retry_is_lineage_idempotent() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/retry-restore"),
                    memory_bitmap_hash: String::from("feedbead"),
                    disk_generation: 2,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing checkpoint"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restore_request = RestoreRuntimeRequest {
            checkpoint_id,
            reason: Some(String::from("retry-safe restore")),
        };
        let restored = service
            .restore_runtime_session(runtime.id.as_str(), restore_request.clone(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored.status(), StatusCode::OK);
        let after_first_restore = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let checkpoint_id = after_first_restore
            .restored_from_checkpoint_id
            .clone()
            .unwrap_or_else(|| panic!("missing restored checkpoint id"));
        let audit_log_path = temp.path().join("uvm-node/audit.log");

        let restored_retry = service
            .restore_runtime_session(runtime.id.as_str(), restore_request, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_retry.status(), StatusCode::OK);
        let after_retry = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;

        assert_eq!(after_retry.restore_count, 1);
        assert_eq!(after_retry.incarnation_lineage.len(), 2);
        assert_eq!(
            after_retry
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence),
            after_first_restore
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence)
        );
        assert_eq!(
            after_retry.last_restore_at,
            after_first_restore.last_restore_at
        );
        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| operation.kind == UvmNodeOperationKind::Restore)
                .count(),
            1
        );
        assert_eq!(
            count_restore_outbox_events_for_runtime(&service, &after_retry, &checkpoint_id).await,
            1
        );
        assert_eq!(
            count_restore_audit_events_for_runtime(&audit_log_path, &after_retry, &checkpoint_id),
            1
        );
    }

    #[tokio::test]
    async fn restore_retry_replays_missing_side_records_without_duplicate_audit() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/replay-restore"),
                    memory_bitmap_hash: String::from("facefeed"),
                    disk_generation: 3,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing checkpoint"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id,
                    reason: Some(String::from("replay restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restored_runtime = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let checkpoint_id = restored_runtime
            .restored_from_checkpoint_id
            .clone()
            .unwrap_or_else(|| panic!("missing restored checkpoint"));
        let audit_log_path = temp.path().join("uvm-node/audit.log");
        assert_eq!(
            count_restore_audit_events_for_runtime(
                &audit_log_path,
                &restored_runtime,
                &checkpoint_id
            ),
            1
        );

        let restore_operation = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Restore
                    && stored.value.runtime_session_id.as_ref() == Some(&restored_runtime.id)
            })
            .unwrap_or_else(|| panic!("missing restore node operation"));
        service
            .node_operations
            .soft_delete(
                restore_operation.0.as_str(),
                Some(restore_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_key = restore_replay_key(&restored_runtime, &checkpoint_id)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut outbox_collection =
            uhost_store::DocumentCollection::<OutboxMessage<PlatformEvent>>::default();
        for stored in service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            if restore_event_matches_replay_candidate(
                &stored.payload,
                &restored_runtime,
                &checkpoint_id,
                &replay_key,
            ) {
                continue;
            }
            outbox_collection.records.insert(
                stored.id.clone(),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: stored.updated_at,
                    deleted: false,
                    value: stored,
                },
            );
        }
        std::fs::write(
            temp.path().join("uvm-node/outbox.json"),
            serde_json::to_vec(&outbox_collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let restored_retry = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id: checkpoint_id.to_string(),
                    reason: Some(String::from("replay restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_retry.status(), StatusCode::OK);

        let after_retry = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        assert_eq!(after_retry.restore_count, 1);
        assert_eq!(after_retry.incarnation_lineage.len(), 2);
        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Restore
                        && operation.runtime_session_id.as_ref() == Some(&after_retry.id)
                })
                .count(),
            1
        );
        assert_eq!(
            count_restore_outbox_events_for_runtime(&service, &after_retry, &checkpoint_id).await,
            1
        );
        assert_eq!(
            count_restore_audit_events_for_runtime(&audit_log_path, &after_retry, &checkpoint_id),
            1
        );
    }

    #[tokio::test]
    async fn restore_retry_reuses_latest_legacy_side_records_without_duplicates() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            create_test_node_capability(&service, &context, &node_id, vec![String::from("kvm")])
                .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &node_id,
            &capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/legacy-restore-first"),
                    memory_bitmap_hash: String::from("feedf11d"),
                    disk_generation: 4,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing first checkpoint"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id: first_checkpoint_id,
                    reason: Some(String::from("first replay-safe restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/legacy-restore-current"),
                    memory_bitmap_hash: String::from("deadc0de"),
                    disk_generation: 5,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_checkpoint_id = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .map(|(_, stored)| stored.value)
            .find(|record| record.checkpoint_uri == "object://checkpoints/legacy-restore-current")
            .map(|record| record.id.to_string())
            .unwrap_or_else(|| panic!("missing second checkpoint"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id: second_checkpoint_id,
                    reason: Some(String::from("current legacy replay restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let after_second_restore = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let current_checkpoint_id = after_second_restore
            .restored_from_checkpoint_id
            .clone()
            .unwrap_or_else(|| panic!("missing current restored checkpoint"));
        let current_sequence = after_second_restore
            .current_incarnation
            .as_ref()
            .map(|value| value.sequence)
            .unwrap_or_else(|| panic!("missing current restore incarnation"));
        let audit_log_path = temp.path().join("uvm-node/audit.log");
        assert_eq!(
            count_total_restore_audit_events_for_runtime(&audit_log_path, &after_second_restore.id),
            2
        );
        assert_eq!(
            count_total_restore_outbox_events_for_runtime(&service, &after_second_restore.id).await,
            2
        );

        let restore_operations = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Restore
                    && stored.value.runtime_session_id.as_ref() == Some(&after_second_restore.id)
            })
            .collect::<Vec<_>>();
        assert_eq!(restore_operations.len(), 2);
        let historical_restore_operation = restore_operations
            .iter()
            .find(|(_, stored)| stored.value.checkpoint_id.as_ref() != Some(&current_checkpoint_id))
            .unwrap_or_else(|| panic!("missing historical restore node operation"));
        service
            .node_operations
            .soft_delete(
                historical_restore_operation.0.as_str(),
                Some(historical_restore_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current_restore_operation = restore_operations
            .iter()
            .find(|(_, stored)| stored.value.checkpoint_id.as_ref() == Some(&current_checkpoint_id))
            .unwrap_or_else(|| panic!("missing current restore node operation"));
        let mut legacy_current_restore_operation = current_restore_operation.1.value.clone();
        legacy_current_restore_operation.linked_resource_kind = None;
        legacy_current_restore_operation.linked_resource_id = None;
        legacy_current_restore_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_current_restore_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_current_restore_operation.id.as_str().as_bytes(),
            ));
        service
            .node_operations
            .upsert(
                current_restore_operation.0.as_str(),
                legacy_current_restore_operation,
                Some(current_restore_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_key = restore_replay_key(&after_second_restore, &current_checkpoint_id)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut outbox_collection =
            uhost_store::DocumentCollection::<OutboxMessage<PlatformEvent>>::default();
        for stored in service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            let mut value = stored;
            if restore_event_matches_replay_candidate(
                &value.payload,
                &after_second_restore,
                &current_checkpoint_id,
                &replay_key,
            ) {
                let uhost_types::EventPayload::Service(service_event) = &mut value.payload.payload
                else {
                    panic!("restore outbox payload should be a service event");
                };
                let details = service_event
                    .details
                    .as_object_mut()
                    .unwrap_or_else(|| panic!("restore outbox details should be an object"));
                details.remove("restore_replay_key");
                details.remove("restore_count");
            }
            outbox_collection.records.insert(
                value.id.clone(),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: value.updated_at,
                    deleted: false,
                    value,
                },
            );
        }
        std::fs::write(
            temp.path().join("uvm-node/outbox.json"),
            serde_json::to_vec(&outbox_collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let mut audit_events = read_audit_events(&audit_log_path);
        for event in &mut audit_events {
            if !restore_event_matches_replay_candidate(
                event,
                &after_second_restore,
                &current_checkpoint_id,
                &replay_key,
            ) {
                continue;
            }
            let uhost_types::EventPayload::Service(service_event) = &mut event.payload else {
                panic!("restore audit payload should be a service event");
            };
            let details = service_event
                .details
                .as_object_mut()
                .unwrap_or_else(|| panic!("restore audit details should be an object"));
            details.remove("restore_replay_key");
            details.remove("restore_count");
        }
        let mut audit_payload = Vec::new();
        for event in audit_events {
            audit_payload.extend_from_slice(
                &serde_json::to_vec(&event).unwrap_or_else(|error| panic!("{error}")),
            );
            audit_payload.push(b'\n');
        }
        std::fs::write(&audit_log_path, audit_payload).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Restore
                        && operation.runtime_session_id.as_ref() == Some(&after_second_restore.id)
                })
                .count(),
            1
        );
        assert_eq!(
            count_total_restore_audit_events_for_runtime(&audit_log_path, &after_second_restore.id),
            2
        );
        assert_eq!(
            count_total_restore_outbox_events_for_runtime(&service, &after_second_restore.id).await,
            2
        );

        let restored_retry = service
            .restore_runtime_session(
                runtime.id.as_str(),
                RestoreRuntimeRequest {
                    checkpoint_id: current_checkpoint_id.to_string(),
                    reason: Some(String::from("current legacy replay restore")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restored_retry.status(), StatusCode::OK);

        let after_retry = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        assert_eq!(after_retry.restore_count, 2);
        assert_eq!(after_retry.incarnation_lineage.len(), 3);
        assert_eq!(
            after_retry
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence),
            Some(current_sequence)
        );
        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Restore
                        && operation.runtime_session_id.as_ref() == Some(&after_retry.id)
                })
                .count(),
            1
        );
        assert_eq!(
            count_total_restore_audit_events_for_runtime(&audit_log_path, &after_retry.id),
            2
        );
        assert_eq!(
            count_total_restore_outbox_events_for_runtime(&service, &after_retry.id).await,
            2
        );
        assert_eq!(
            count_restore_outbox_events_for_runtime(&service, &after_retry, &current_checkpoint_id)
                .await,
            1
        );
        assert_eq!(
            count_restore_audit_events_for_runtime(
                &audit_log_path,
                &after_retry,
                &current_checkpoint_id,
            ),
            1
        );
    }

    #[tokio::test]
    async fn runtime_registration_lifecycle_and_checkpoint_flow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(5),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let runtime_session = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime_session.state, VmRuntimeState::Registered);
        assert_eq!(runtime_session.boot_path, "microvm");
        assert_eq!(runtime_session.device_model, "virtio_minimal");
        assert_eq!(runtime_session.memory_backing, "hugepages");
        assert!(
            runtime_session
                .sandbox_layers
                .iter()
                .any(|layer| layer == "seccomp")
        );
        assert!(
            runtime_session
                .telemetry_streams
                .iter()
                .any(|stream| stream == "heartbeat")
        );
        assert!(
            runtime_session
                .launch_env
                .iter()
                .any(|value| value == "UVM_EXECUTION_CLASS=balanced")
        );

        let _started = service
            .transition_runtime_session(
                runtime_session.id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let running = service
            .runtime_sessions
            .get(runtime_session.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(running.value.state, VmRuntimeState::Running);

        let checkpoint = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime_session.id.to_string(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/c1"),
                    memory_bitmap_hash: String::from("feedface"),
                    disk_generation: 7,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn runtime_heartbeat_updates_health_summary() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(true),
                    migration_max_downtime_ms: Some(250),
                    migration_max_iterations: Some(5),
                    migration_bandwidth_mbps: Some(10_000),
                    migration_dirty_page_rate_mbps: Some(64),
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let heartbeat = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(4242),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("degraded"),
                    exit_reason: Some(String::from("host memory pressure")),
                    runner_phase: None,
                    worker_states: None,
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(heartbeat.status(), StatusCode::OK);

        let summary = service
            .runtime_health_summary(60)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.total_sessions, 1);
        assert_eq!(summary.running_sessions, 1);
        assert_eq!(summary.degraded_sessions, 1);
        assert_eq!(summary.stale_sessions, 0);
    }

    #[tokio::test]
    async fn runtime_session_projects_generic_node_process_report() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, stored)| stored.value)
            .unwrap_or_else(|| panic!("missing runtime session"));
        let workload_id =
            node_plane_workload_id(&runtime.id).unwrap_or_else(|error| panic!("{error}"));

        let projected = service
            .node_process_reports
            .get(workload_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing projected node process report"));
        assert_eq!(projected.value.node_id, node_id);
        assert_eq!(projected.value.workload_id, workload_id);
        assert_eq!(projected.value.state, "registered");
        assert!(projected.value.exit_code.is_none());

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let running = service
            .node_process_reports
            .get(workload_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing projected running report"));
        assert_eq!(running.value.state, "running");
        assert!(running.value.exit_code.is_none());

        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Fail,
                "fail",
                Some(String::from("guest crash")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failed = service
            .node_process_reports
            .get(workload_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing projected failed report"));
        assert_eq!(failed.value.state, "failed");
        assert_eq!(failed.value.exit_code, Some(1));
    }

    #[tokio::test]
    async fn runtime_health_summary_counts_failed_session_once_when_state_and_health_fail() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let created = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime-failed.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Fail,
                "fail",
                Some(String::from("guest crash")),
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(5150),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("failed"),
                    exit_reason: Some(String::from("guest crash")),
                    runner_phase: None,
                    worker_states: None,
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .runtime_health_summary(60)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.total_sessions, 1);
        assert_eq!(summary.failed_sessions, 1);
        assert_eq!(summary.degraded_sessions, 0);
    }

    #[tokio::test]
    async fn runtime_heartbeat_persists_runner_lineage_markers() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime-lineage.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let lifecycle_event_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(6101),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: Some(7),
                    lifecycle_event_id: Some(lifecycle_event_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = service
            .runtime_sessions
            .get(&runtime_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session after heartbeat"));
        assert_eq!(runtime.value.heartbeat_sequence, 1);
        assert_eq!(runtime.value.last_runner_sequence_id, Some(7));
        assert_eq!(
            runtime.value.last_lifecycle_event_id,
            Some(lifecycle_event_id.clone())
        );

        let heartbeat = service
            .runtime_heartbeats
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing runtime heartbeat"));
        assert_eq!(heartbeat.sequence, 1);
        assert_eq!(heartbeat.runner_sequence_id, Some(7));
        assert_eq!(heartbeat.lifecycle_event_id, Some(lifecycle_event_id));
    }

    #[tokio::test]
    async fn runner_supervision_event_persists_lifecycle_witness() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let key = runner_supervision_key(&runtime_session_id, 1);
        let now = time::OffsetDateTime::now_utc();
        service
            .runner_supervision
            .create(
                &key,
                UvmRunnerSupervisionRecord {
                    runtime_session_id,
                    runtime_incarnation: 1,
                    instance_id,
                    node_id,
                    launch_program: String::from("uhost-uvm-runner"),
                    launch_args: Vec::new(),
                    launch_env: Vec::new(),
                    stop_sentinel_path: String::from("/tmp/runner.stop"),
                    state: String::from("running"),
                    observed_pid: Some(9001),
                    last_event_kind: Some(String::from("spawned")),
                    last_lifecycle_state: None,
                    last_runner_phase: None,
                    workers: Vec::new(),
                    network_access: None,
                    boot_stages: Vec::new(),
                    console_trace: Vec::new(),
                    guest_control_ready: false,
                    last_heartbeat_sequence: None,
                    stop_reason: None,
                    exit_status: None,
                    failure_detail: None,
                    requested_at: now,
                    started_at: Some(now),
                    last_event_at: now,
                    finished_at: None,
                    metadata: uhost_types::ResourceMetadata::new(
                        uhost_types::OwnershipScope::Platform,
                        Some(key.clone()),
                        uhost_core::sha256_hex(key.as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .note_runner_supervision_event(
                &key,
                &serde_json::json!({
                    "event": "lifecycle",
                    "state": "started",
                    "phase": "running",
                    "boot_stages": ["bios:grub_menu_observed", "native_control:ready"],
                    "console_trace": [
                        "SeaBIOS 1.16.3",
                        "native executor reached guest control handoff"
                    ],
                    "guest_control_ready": true
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .note_runner_supervision_event(
                &key,
                &serde_json::json!({
                    "event": "heartbeat",
                    "phase": "running",
                    "heartbeat_sequence": 3,
                    "guest_control_ready": true,
                    "network_access": {
                        "network_mode": "guest_owned_usernet_nat",
                        "internet_nat": true,
                        "ssh_available": false,
                        "guest_exec_route_available": false,
                        "egress_transport": "guest_owned_tcp_udp_http_https_nat_v1",
                        "ingress_transport": "guest_owned_tcp_udp_http_nat_v1",
                        "ingress_http_ready": true,
                        "ingress_tcp_ready": true,
                        "ingress_udp_ready": true,
                        "ingress_http_bind": "127.0.0.1:19421",
                        "ingress_http_url": "http://127.0.0.1:19421",
                        "ingress_tcp_bind": "127.0.0.1:19422",
                        "ingress_tcp_service": "default",
                        "ingress_udp_bind": "127.0.0.1:19423",
                        "ingress_udp_service": "default",
                        "guest_web_root": "/var/www",
                        "supported_guest_commands": [
                            "ip addr",
                            "ip route",
                            "hostname -I",
                            "resolvectl status",
                            "nslookup <hostname>",
                            "getent hosts <hostname>",
                            "curl <http-or-https-url>",
                            "curl -I <http-or-https-url>",
                            "fetch <http-or-https-url>",
                            "nc <host> <port>",
                            "nc -z <host> <port>",
                            "nc <host> <port> <payload>",
                            "nc -u <host> <port>",
                            "nc -zu <host> <port>",
                            "nc -u <host> <port> <payload>"
                        ]
                    },
                    "workers": [
                        {
                            "name": "block",
                            "state": "running",
                            "process_binding": "shared_runner_process",
                            "observed_pid": 9001,
                            "sandbox_layers": ["capability_drop", "cgroup_v2", "namespaces", "seccomp"],
                            "sandbox_enforcement_mode": "worker_contract",
                            "sandbox_contract_source": "launch_contract",
                            "seccomp_profile": "block_io_v1",
                            "execution_scope": "artifact_staging",
                            "detail": {
                                "artifact_count": 3,
                                "disk_image": "object://images/linux.raw",
                                "cdrom_image": "object://images/installer.iso"
                            }
                        },
                        {
                            "name": "net",
                            "state": "running",
                            "process_binding": "shared_runner_process",
                            "observed_pid": 9001,
                            "sandbox_layers": ["capability_drop", "cgroup_v2", "namespaces", "seccomp"],
                            "sandbox_enforcement_mode": "worker_contract",
                            "sandbox_contract_source": "launch_contract",
                            "seccomp_profile": "net_io_v1",
                            "execution_scope": "virtio_net_observation",
                            "detail": {
                                "virtio_net_mmio_present": true,
                                "guest_control_ready": true
                            }
                        }
                    ]
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .note_runner_supervision_event(
                &key,
                &serde_json::json!({
                    "event": "lifecycle",
                    "state": "stopped",
                    "phase": "stopped",
                    "final_heartbeat_sequence": 3
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .runner_supervision
            .get(&key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runner supervision record"));
        assert_eq!(
            stored.value.boot_stages,
            vec![
                String::from("bios:grub_menu_observed"),
                String::from("native_control:ready")
            ]
        );
        assert_eq!(
            stored.value.console_trace,
            vec![
                String::from("SeaBIOS 1.16.3"),
                String::from("native executor reached guest control handoff")
            ]
        );
        assert!(stored.value.guest_control_ready);
        assert_eq!(stored.value.last_heartbeat_sequence, Some(3));
        assert_eq!(
            stored.value.last_lifecycle_state.as_deref(),
            Some("stopped")
        );
        let network_access = stored
            .value
            .network_access
            .unwrap_or_else(|| panic!("missing stored network access"));
        assert_eq!(network_access.network_mode, "guest_owned_usernet_nat");
        assert!(network_access.internet_nat);
        assert!(network_access.ingress_http_ready);
        assert!(network_access.ingress_tcp_ready);
        assert!(network_access.ingress_udp_ready);
        assert_eq!(
            network_access.ingress_http_url.as_deref(),
            Some("http://127.0.0.1:19421")
        );
        assert_eq!(
            network_access.ingress_tcp_bind.as_deref(),
            Some("127.0.0.1:19422")
        );
        assert_eq!(
            network_access.ingress_tcp_service.as_deref(),
            Some("default")
        );
        assert_eq!(
            network_access.ingress_udp_bind.as_deref(),
            Some("127.0.0.1:19423")
        );
        assert_eq!(
            network_access.ingress_udp_service.as_deref(),
            Some("default")
        );
        let block = runner_supervision_worker(&stored.value.workers, "block");
        let net = runner_supervision_worker(&stored.value.workers, "net");
        assert_eq!(block["detail"]["artifact_count"].as_u64(), Some(3));
        assert_eq!(net["detail"]["guest_control_ready"].as_bool(), Some(true));
    }

    #[tokio::test]
    async fn runtime_heartbeat_rejects_non_advancing_runner_sequence_id() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime-sequence.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(7001),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: Some(4),
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(7001),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: Some(4),
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected non-advancing runner sequence to conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn runtime_heartbeat_lineage_fields_are_queryable_and_ordered() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/runtime-lineage-query.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("platform_default")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(1),
                    apple_guest_approved: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                &runtime_id,
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_event_id =
            AuditId::parse("aud_lineageeventfirst").unwrap_or_else(|error| panic!("{error}"));
        let second_event_id =
            AuditId::parse("aud_lineageeventsecond").unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(7201),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: Some(11),
                    lifecycle_event_id: Some(first_event_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                &runtime_id,
                RuntimeHeartbeatRequest {
                    observed_pid: Some(7201),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: Some(12),
                    lifecycle_event_id: Some(second_event_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime_session: UvmRuntimeSessionRecord = parse_api_body(
            service
                .get_runtime_session(&runtime_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(runtime_session.last_runner_sequence_id, Some(12));
        assert_eq!(
            runtime_session.last_lifecycle_event_id,
            Some(second_event_id.clone())
        );

        let older_event_id =
            AuditId::parse("aud_lineageeventolder").unwrap_or_else(|error| panic!("{error}"));
        let runtime_incarnation_sequence = runtime_session
            .current_incarnation
            .as_ref()
            .map(|incarnation| incarnation.sequence);
        let older_heartbeat_id =
            AuditId::parse("aud_lineageheartbeatolder").unwrap_or_else(|error| panic!("{error}"));
        service
            .runtime_heartbeats
            .create(
                older_heartbeat_id.as_str(),
                UvmRuntimeHeartbeatRecord {
                    id: older_heartbeat_id.clone(),
                    runtime_session_id: runtime_session.id.clone(),
                    runtime_incarnation_sequence,
                    sequence: 3,
                    runner_sequence_id: Some(6),
                    hypervisor_health: String::from("healthy"),
                    observed_pid: Some(7201),
                    observed_assigned_memory_mb: Some(2048),
                    exit_reason: None,
                    runner_phase: String::from("running"),
                    worker_states: vec![String::from("core:running")],
                    lifecycle_event_id: Some(older_event_id.clone()),
                    observed_at: time::OffsetDateTime::now_utc() - time::Duration::seconds(30),
                    metadata: uhost_types::ResourceMetadata::new(
                        uhost_types::OwnershipScope::Platform,
                        Some(String::from(older_heartbeat_id.as_str())),
                        uhost_core::sha256_hex(older_heartbeat_id.as_str().as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/uvm/runtime/heartbeats")
            .body(RequestBody::Right(Full::new(Bytes::new())))
            .unwrap_or_else(|error| panic!("{error}"));
        let response = HttpService::handle(
            &service,
            request,
            RequestContext::new().unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing runtime heartbeats response"));
        let heartbeats: Vec<UvmRuntimeHeartbeatRecord> = parse_api_body(response).await;
        let scoped = heartbeats
            .into_iter()
            .filter(|heartbeat| heartbeat.runtime_session_id == runtime_session.id)
            .collect::<Vec<_>>();
        assert_eq!(scoped.len(), 3);
        assert_eq!(scoped[0].runner_sequence_id, Some(6));
        assert_eq!(scoped[0].lifecycle_event_id, Some(older_event_id));
        assert_eq!(scoped[1].runner_sequence_id, Some(11));
        assert_eq!(scoped[1].lifecycle_event_id, Some(first_event_id));
        assert_eq!(scoped[2].runner_sequence_id, Some(12));
        assert_eq!(scoped[2].lifecycle_event_id, Some(second_event_id));
    }

    #[tokio::test]
    async fn declared_host_platform_rejects_incompatible_backend() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: Some(String::from("windows")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 8,
                    max_memory_mb: 16_384,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected invalid backend/host_platform conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn duplicate_runtime_registration_returns_existing_session() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let request = RegisterRuntimeSessionRequest {
            instance_id: instance_id.to_string(),
            node_id: node_id.to_string(),
            capability_id,
            guest_architecture: String::from("x86_64"),
            guest_os: String::from("linux"),
            disk_image: String::from("object://images/linux.raw"),
            cdrom_image: None,
            boot_device: None,
            vcpu: Some(2),
            memory_mb: Some(4096),
            firmware_profile: Some(String::from("uefi_standard")),
            cpu_topology: Some(String::from("balanced")),
            numa_policy: Some(String::from("preferred_local")),
            migration_policy: Some(String::from("cold_only")),
            require_secure_boot: Some(false),
            requires_live_migration: Some(false),
            migration_max_downtime_ms: None,
            migration_max_iterations: None,
            migration_bandwidth_mbps: None,
            migration_dirty_page_rate_mbps: None,
            isolation_profile: Some(String::from("cgroup_v2")),
            restart_policy: Some(String::from("on-failure")),
            max_restarts: Some(5),
            apple_guest_approved: None,
        };

        let created = service
            .register_runtime_session(request.clone(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);

        let duplicate = service
            .register_runtime_session(request, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert_eq!(
            service
                .runtime_sessions
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn divergent_runtime_registration_for_same_instance_is_rejected() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id: capability_id.clone(),
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(5),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(4),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(5),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected divergent runtime registration rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn runtime_migration_commit_moves_runtime_session_to_target_node() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capabilities = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == source_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing source capability"));
        let target_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == target_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing target capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id: source_capability,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(true),
                    migration_max_downtime_ms: Some(400),
                    migration_max_iterations: Some(6),
                    migration_bandwidth_mbps: Some(20_000),
                    migration_dirty_page_rate_mbps: Some(200),
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight = service
            .preflight_runtime_migration(
                RuntimeMigrationPreflightRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability.clone(),
                    require_secure_boot: Some(true),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(preflight.status(), StatusCode::OK);

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/live-1"),
                    memory_bitmap_hash: String::from("beadfeed"),
                    disk_generation: 12,
                    reason: String::from("test migration"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);
        let blocked_transition = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected runtime transition lock while migrating"));
        assert_eq!(blocked_transition.code, uhost_core::ErrorCode::Conflict);
        let duplicate = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/live-duplicate"),
                    memory_bitmap_hash: String::from("beadfeed2"),
                    disk_generation: 13,
                    reason: String::from("duplicate migration"),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate in-progress migration rejection"));
        assert_eq!(duplicate.code, uhost_core::ErrorCode::Conflict);
        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));

        let committed = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "commit",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(committed.status(), StatusCode::OK);

        let runtime = service
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.node_id, target_node);
        assert!(!runtime.value.migration_in_progress);
        assert_eq!(runtime.value.incarnation_lineage.len(), 2);
        assert_eq!(
            runtime.value.incarnation_lineage[0].kind,
            UvmRuntimeIncarnationKind::OriginalBoot
        );
        let current_incarnation = runtime
            .value
            .current_incarnation
            .as_ref()
            .unwrap_or_else(|| panic!("missing cutover incarnation"));
        assert_eq!(
            current_incarnation.kind,
            UvmRuntimeIncarnationKind::PostMigrationCutover
        );
        assert_eq!(current_incarnation.previous_sequence, Some(1));
        assert_eq!(
            current_incarnation.previous_state,
            Some(VmRuntimeState::Running)
        );
        assert_eq!(
            current_incarnation.source_node_id.as_ref(),
            Some(&source_node)
        );
        assert_eq!(
            current_incarnation.target_node_id.as_str(),
            target_node.as_str()
        );
        let migration = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing committed migration"));
        assert_eq!(
            current_incarnation.migration_id.as_ref(),
            Some(&migration.value.id)
        );
        assert_eq!(
            current_incarnation.checkpoint_id.as_ref(),
            Some(&migration.value.checkpoint_id)
        );
    }

    #[tokio::test]
    async fn migration_commit_rebuilds_launch_contract_for_target_host_platform() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: Some(String::from("linux")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: Some(String::from("windows")),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("hyperv_whp")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capabilities = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == source_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing source capability"));
        let target_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == target_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing target capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id: source_capability,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(true),
                    migration_max_downtime_ms: Some(300),
                    migration_max_iterations: Some(5),
                    migration_bandwidth_mbps: Some(20_000),
                    migration_dirty_page_rate_mbps: Some(100),
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("always")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability,
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/cross-platform"),
                    memory_bitmap_hash: String::from("feedbeef"),
                    disk_generation: 21,
                    reason: String::from("cross-platform target contract"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let _ = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "commit",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let runtime = service
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.accelerator_backend, "hyperv_whp");
        assert_eq!(runtime.value.launch_program, "uvm-hyperv");
        assert!(
            runtime
                .value
                .launch_env
                .iter()
                .any(|entry| entry == "UVM_BACKEND=hyperv_whp")
        );
    }

    #[tokio::test]
    async fn checkpoint_creation_is_idempotent_for_equivalent_request() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/idempotent-c1"),
                    memory_bitmap_hash: String::from("beefcafe"),
                    disk_generation: 2,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id,
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/idempotent-c1"),
                    memory_bitmap_hash: String::from("beefcafe"),
                    disk_generation: 2,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), StatusCode::OK);

        let checkpoint_count = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .count();
        assert_eq!(checkpoint_count, 1);
    }

    #[tokio::test]
    async fn migration_start_rejects_cold_policy_runtime() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capabilities = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == source_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing source capability"));
        let target_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == target_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing target capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id: source_capability,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id,
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability,
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/cold-migration"),
                    memory_bitmap_hash: String::from("f00dbabe"),
                    disk_generation: 7,
                    reason: String::from("disallowed"),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected cold migration policy conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn preflight_blocks_unapproved_apple_guest() {
        if uhost_uvm::HostPlatform::current() != uhost_uvm::HostPlatform::Macos {
            return;
        }
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("aarch64"),
                    accelerator_backends: vec![String::from("apple_virtualization")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let response = service
            .preflight_runtime(
                RuntimePreflightRequest {
                    capability_id,
                    guest_architecture: String::from("aarch64"),
                    guest_os: String::from("macos"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    apple_guest_approved: Some(false),
                    compatibility_requirement: None,
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let report = service
            .runtime_preflights
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing preflight report"));
        assert!(!report.legal_allowed);
        assert!(!report.blockers.is_empty());
    }

    #[tokio::test]
    async fn apple_guest_requires_apple_backend() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("aarch64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let error = service
            .select_adapter(
                SelectAdapterRequest {
                    capability_id,
                    guest_architecture: String::from("aarch64"),
                    apple_guest: true,
                    requires_live_migration: false,
                    require_secure_boot: Some(false),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected missing backend conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn stopped_runtime_session_allows_manual_restart() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let restarted = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(restarted.status(), StatusCode::OK);
        let runtime = service
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"));
        assert_eq!(runtime.value.start_attempts, 1);
        assert_eq!(runtime.value.incarnation_lineage.len(), 2);
        assert_eq!(
            runtime.value.incarnation_lineage[0].kind,
            UvmRuntimeIncarnationKind::OriginalBoot
        );
        let current_incarnation = runtime
            .value
            .current_incarnation
            .as_ref()
            .unwrap_or_else(|| panic!("missing restart incarnation"));
        assert_eq!(current_incarnation.kind, UvmRuntimeIncarnationKind::Restart);
        assert_eq!(current_incarnation.previous_sequence, Some(1));
        assert_eq!(
            current_incarnation.previous_state,
            Some(VmRuntimeState::Stopped)
        );
    }

    #[tokio::test]
    async fn stopped_runtime_checkpoint_cannot_target_another_node() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .iter()
            .find(|(_, value)| value.value.node_id == source_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("always")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let error = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id,
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/stopped-cross-node"),
                    memory_bitmap_hash: String::from("facefeed"),
                    disk_generation: 1,
                    target_node_id: Some(target_node.to_string()),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected cross-node checkpoint conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn checkpoint_creation_is_idempotent_for_same_payload() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("always")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let payload = CreateCheckpointRequest {
            runtime_session_id,
            kind: String::from("crash_consistent"),
            checkpoint_uri: String::from("object://checkpoints/retry-safe"),
            memory_bitmap_hash: String::from("feedface"),
            disk_generation: 3,
            target_node_id: None,
        };
        let created = service
            .create_checkpoint(payload.clone(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let idempotent = service
            .create_checkpoint(payload, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(idempotent.status(), StatusCode::OK);
        assert_eq!(
            service
                .runtime_checkpoints
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn checkpoint_creation_persists_runtime_lineage_provenance() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(false),
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: Some(default_host_platform_key()),
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 32,
                    max_memory_mb: 131_072,
                    numa_nodes: 2,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: Some(false),
                    container_restricted: None,
                    host_evidence_mode: Some(String::from("direct_host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_capability = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find_map(|(_, value)| {
                (value.value.node_id == source_node).then_some(value.value.id.to_string())
            })
            .unwrap_or_else(|| panic!("missing source capability"));
        let target_capability = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find_map(|(_, value)| {
                (value.value.node_id == target_node).then_some(value.value.id.to_string())
            })
            .unwrap_or_else(|| panic!("missing target capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id: source_capability,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(4),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(true),
                    migration_max_downtime_ms: Some(400),
                    migration_max_iterations: Some(6),
                    migration_bandwidth_mbps: Some(20_000),
                    migration_dirty_page_rate_mbps: Some(200),
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("always")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                runtime_session_id.as_str(),
                RuntimeHeartbeatRequest {
                    observed_pid: Some(4_242),
                    observed_assigned_memory_mb: Some(4096),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![
                        String::from("core:running"),
                        String::from("net:running"),
                    ]),
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                runtime_session_id.as_str(),
                RuntimeHeartbeatRequest {
                    observed_pid: Some(4_343),
                    observed_assigned_memory_mb: Some(4096),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![
                        String::from("core:running"),
                        String::from("net:running"),
                    ]),
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .preflight_runtime_migration(
                RuntimeMigrationPreflightRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability,
                    require_secure_boot: Some(true),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    execution_intent: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);

        let checkpoint = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/provenance"),
                    memory_bitmap_hash: String::from("cafe1234"),
                    disk_generation: 7,
                    target_node_id: Some(target_node.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.status(), StatusCode::CREATED);

        let stored_intent = service
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session intent"));
        let stored_checkpoint = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value.value)
            .unwrap_or_else(|| panic!("missing runtime checkpoint"));
        assert_eq!(stored_checkpoint.provenance.source_pid, Some(4_343));
        assert_eq!(
            stored_checkpoint.provenance.execution_intent_lineage_id,
            stored_intent.value.lineage_id
        );
        assert_eq!(
            stored_checkpoint.provenance.portability_preflight_id,
            stored_intent.value.last_portability_preflight_id
        );
        assert_eq!(
            stored_checkpoint.provenance.heartbeat_window.first_sequence,
            Some(1)
        );
        assert_eq!(
            stored_checkpoint.provenance.heartbeat_window.last_sequence,
            Some(2)
        );
        assert!(
            stored_checkpoint
                .provenance
                .heartbeat_window
                .first_heartbeat_id
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .heartbeat_window
                .last_heartbeat_id
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .heartbeat_window
                .first_observed_at
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .heartbeat_window
                .last_observed_at
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .witness_digests
                .runtime_session
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .witness_digests
                .execution_intent
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .witness_digests
                .portability_preflight
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .witness_digests
                .heartbeat_window_start
                .is_some()
        );
        assert!(
            stored_checkpoint
                .provenance
                .witness_digests
                .heartbeat_window_end
                .is_some()
        );
    }

    #[tokio::test]
    async fn checkpoint_provenance_heartbeat_window_scopes_to_current_incarnation() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: node_id.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: false,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capability_id = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing capability"));

        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: node_id.to_string(),
                    capability_id,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(2048),
                    firmware_profile: Some(String::from("uefi_standard")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("cold_only")),
                    require_secure_boot: Some(false),
                    requires_live_migration: Some(false),
                    migration_max_downtime_ms: None,
                    migration_max_iterations: None,
                    migration_bandwidth_mbps: None,
                    migration_dirty_page_rate_mbps: None,
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("on-failure")),
                    max_restarts: Some(2),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));

        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        for observed_pid in [1_001_u32, 1_002_u32] {
            let _ = service
                .heartbeat_runtime_session(
                    runtime_session_id.as_str(),
                    RuntimeHeartbeatRequest {
                        observed_pid: Some(observed_pid),
                        observed_assigned_memory_mb: Some(2048),
                        hypervisor_health: String::from("healthy"),
                        exit_reason: None,
                        runner_phase: Some(String::from("running")),
                        worker_states: Some(vec![String::from("core:running")]),
                        runner_sequence_id: None,
                        lifecycle_event_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                VmRuntimeAction::Stop,
                "stop",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .heartbeat_runtime_session(
                runtime_session_id.as_str(),
                RuntimeHeartbeatRequest {
                    observed_pid: Some(2_001),
                    observed_assigned_memory_mb: Some(2048),
                    hypervisor_health: String::from("healthy"),
                    exit_reason: None,
                    runner_phase: Some(String::from("running")),
                    worker_states: Some(vec![String::from("core:running")]),
                    runner_sequence_id: None,
                    lifecycle_event_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut heartbeats = service
            .runtime_heartbeats
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        heartbeats.sort_by_key(|record| record.sequence);
        assert_eq!(
            heartbeats
                .iter()
                .map(|record| record.runtime_incarnation_sequence)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(1), Some(2)]
        );

        let checkpoint = service
            .create_checkpoint(
                CreateCheckpointRequest {
                    runtime_session_id: runtime_session_id.clone(),
                    kind: String::from("crash_consistent"),
                    checkpoint_uri: String::from("object://checkpoints/incarnation-window"),
                    memory_bitmap_hash: String::from("deadbeef"),
                    disk_generation: 4,
                    target_node_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.status(), StatusCode::CREATED);

        let stored_checkpoint = service
            .runtime_checkpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value.value)
            .unwrap_or_else(|| panic!("missing runtime checkpoint"));
        assert_eq!(stored_checkpoint.provenance.source_pid, Some(2_001));
        assert_eq!(
            stored_checkpoint.provenance.heartbeat_window.first_sequence,
            Some(3)
        );
        assert_eq!(
            stored_checkpoint.provenance.heartbeat_window.last_sequence,
            Some(3)
        );
    }

    #[tokio::test]
    async fn runtime_migration_start_and_commit_are_idempotent() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: source_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node_capability(
                CreateNodeCapabilityRequest {
                    node_id: target_node.to_string(),
                    host_platform: None,
                    architecture: String::from("x86_64"),
                    accelerator_backends: vec![String::from("kvm")],
                    max_vcpu: 16,
                    max_memory_mb: 65_536,
                    numa_nodes: 1,
                    supports_secure_boot: true,
                    supports_live_migration: true,
                    supports_pci_passthrough: false,
                    software_runner_supported: None,
                    container_restricted: None,
                    host_evidence_mode: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let capabilities = service
            .capabilities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let source_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == source_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing source capability"));
        let target_capability = capabilities
            .iter()
            .find(|(_, value)| value.value.node_id == target_node)
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing target capability"));
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .register_runtime_session(
                RegisterRuntimeSessionRequest {
                    instance_id: instance_id.to_string(),
                    node_id: source_node.to_string(),
                    capability_id: source_capability,
                    guest_architecture: String::from("x86_64"),
                    guest_os: String::from("linux"),
                    disk_image: String::from("object://images/linux.raw"),
                    cdrom_image: None,
                    boot_device: None,
                    vcpu: Some(2),
                    memory_mb: Some(4096),
                    firmware_profile: Some(String::from("uefi_secure")),
                    cpu_topology: Some(String::from("balanced")),
                    numa_policy: Some(String::from("preferred_local")),
                    migration_policy: Some(String::from("best_effort_live")),
                    require_secure_boot: Some(true),
                    requires_live_migration: Some(true),
                    migration_max_downtime_ms: Some(350),
                    migration_max_iterations: Some(6),
                    migration_bandwidth_mbps: Some(20_000),
                    migration_dirty_page_rate_mbps: Some(100),
                    isolation_profile: Some(String::from("cgroup_v2")),
                    restart_policy: Some(String::from("always")),
                    max_restarts: Some(3),
                    apple_guest_approved: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime_session_id.as_str(),
                uhost_uvm::VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let start_payload = StartRuntimeMigrationRequest {
            runtime_session_id: runtime_session_id.clone(),
            to_node_id: target_node.to_string(),
            target_capability_id: target_capability,
            kind: String::from("live_precopy"),
            checkpoint_uri: String::from("object://checkpoints/retry-live"),
            memory_bitmap_hash: String::from("a11ce5eed"),
            disk_generation: 9,
            reason: String::from("retry-safe migration"),
        };
        let started = service
            .start_runtime_migration(start_payload.clone(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);
        let started_retry = service
            .start_runtime_migration(start_payload, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started_retry.status(), StatusCode::OK);

        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing migration"));
        let committed = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "commit",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(committed.status(), StatusCode::OK);
        let committed_retry = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "commit",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(committed_retry.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn migration_rollback_retry_is_lineage_idempotent_after_runtime_stays_on_source() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime.id.to_string(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/rollback-retry"),
                    memory_bitmap_hash: String::from("0ddba11"),
                    disk_generation: 4,
                    reason: String::from("retry-safe rollback"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let rolled_back = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "rollback",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rolled_back.status(), StatusCode::OK);

        let runtime_after_rollback = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let rollback_incarnation = runtime_after_rollback
            .current_incarnation
            .clone()
            .unwrap_or_else(|| panic!("missing source incarnation"));
        let migration_stored = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let audit_log_path = temp.path().join("uvm-node/audit.log");
        assert_eq!(runtime_after_rollback.node_id, source_node);
        assert_eq!(runtime_after_rollback.state, VmRuntimeState::Running);
        assert!(!runtime_after_rollback.migration_in_progress);
        assert_eq!(migration_stored.value.state, "rolled_back");
        assert_eq!(
            count_migration_terminal_outbox_events_for_migration(
                &service,
                &runtime_after_rollback,
                &migration_stored.value,
                "rollback",
            )
            .await,
            1
        );
        assert_eq!(
            count_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &runtime_after_rollback,
                &migration_stored.value,
                "rollback",
            ),
            1
        );
        let migrate_operation = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Migrate
                    && stored.value.runtime_session_id.as_ref() == Some(&runtime_after_rollback.id)
                    && stored.value.linked_resource_id.as_deref()
                        == Some(migration_stored.value.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing rollback migrate node operation"));
        let rollback_operation_id = migrate_operation.1.value.id.clone();
        let mut legacy_migrate_operation = migrate_operation.1.value.clone();
        legacy_migrate_operation.linked_resource_kind = None;
        legacy_migrate_operation.linked_resource_id = None;
        legacy_migrate_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_migrate_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_migrate_operation.id.as_str().as_bytes(),
            ));
        service
            .node_operations
            .upsert(
                migrate_operation.0.as_str(),
                legacy_migrate_operation,
                Some(migrate_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .find_node_operation_for_linked_resource(
                    UvmNodeOperationKind::Migrate,
                    "runtime_migration",
                    migration_stored.value.id.as_str(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let mut replay_migration = migration_stored.value;
        replay_migration.state = String::from("in_progress");
        replay_migration.updated_at = time::OffsetDateTime::now_utc();
        replay_migration.metadata.touch(uhost_core::sha256_hex(
            replay_migration.id.as_str().as_bytes(),
        ));
        service
            .runtime_migrations
            .upsert(
                migration_id.as_str(),
                replay_migration,
                Some(migration_stored.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let rollback_retry = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "rollback",
                ResolveRuntimeMigrationRequest { error: None },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rollback_retry.status(), StatusCode::OK);

        let runtime_after_retry = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let migration_after_retry = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"))
            .value;
        assert_eq!(runtime_after_retry.node_id, source_node);
        assert_eq!(runtime_after_retry.state, VmRuntimeState::Running);
        assert!(!runtime_after_retry.migration_in_progress);
        assert_eq!(
            runtime_after_retry
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence),
            Some(rollback_incarnation.sequence)
        );
        assert_eq!(migration_after_retry.state, "rolled_back");
        assert_eq!(
            count_migration_terminal_outbox_events_for_migration(
                &service,
                &runtime_after_retry,
                &migration_after_retry,
                "rollback",
            )
            .await,
            1
        );
        assert_eq!(
            count_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &runtime_after_retry,
                &migration_after_retry,
                "rollback",
            ),
            1
        );
        let linked_operation = service
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration_after_retry.id.as_str(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing relinked rollback migrate node operation"));
        assert_eq!(linked_operation.value.id, rollback_operation_id);
        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Migrate
                        && operation.runtime_session_id.as_ref() == Some(&runtime_after_retry.id)
                        && operation.checkpoint_id.as_ref()
                            == Some(&migration_after_retry.checkpoint_id)
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn migration_fail_retry_replays_missing_side_records_after_terminal_failure() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime.id.to_string(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/fail-retry"),
                    memory_bitmap_hash: String::from("bad0ff1"),
                    disk_generation: 10,
                    reason: String::from("retry-safe failure"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let failed = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "fail",
                ResolveRuntimeMigrationRequest {
                    error: Some(String::from("transport stalled")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed.status(), StatusCode::OK);

        let runtime_after_fail = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let failure_sequence = runtime_after_fail
            .current_incarnation
            .as_ref()
            .map(|value| value.sequence)
            .unwrap_or_else(|| panic!("missing source incarnation"));
        let migration_after_fail = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"))
            .value;
        let audit_log_path = temp.path().join("uvm-node/audit.log");
        assert_eq!(migration_after_fail.state, "failed");
        assert_eq!(
            migration_after_fail.failure_detail.as_deref(),
            Some("transport stalled")
        );
        assert_eq!(runtime_after_fail.node_id, source_node);
        assert_eq!(
            runtime_after_fail.last_error.as_deref(),
            Some("transport stalled")
        );
        assert_eq!(
            count_total_migration_terminal_outbox_events_for_migration(
                &service,
                &migration_after_fail.id,
                "fail",
            )
            .await,
            1
        );
        assert_eq!(
            count_total_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &migration_after_fail.id,
                "fail",
            ),
            1
        );

        let migrate_operation = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Migrate
                    && stored.value.runtime_session_id.as_ref() == Some(&runtime_after_fail.id)
                    && stored.value.linked_resource_id.as_deref()
                        == Some(migration_after_fail.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing migrate node operation"));
        let mut legacy_migrate_operation = migrate_operation.1.value.clone();
        legacy_migrate_operation.linked_resource_kind = None;
        legacy_migrate_operation.linked_resource_id = None;
        legacy_migrate_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_migrate_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_migrate_operation.id.as_str().as_bytes(),
            ));
        service
            .node_operations
            .upsert(
                migrate_operation.0.as_str(),
                legacy_migrate_operation,
                Some(migrate_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_key =
            migration_terminal_replay_key(&runtime_after_fail, &migration_after_fail, "fail")
                .unwrap_or_else(|error| panic!("{error}"));
        let mut outbox_collection =
            uhost_store::DocumentCollection::<OutboxMessage<PlatformEvent>>::default();
        for stored in service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            if migration_terminal_event_matches_replay_candidate(
                &stored.payload,
                &runtime_after_fail,
                &migration_after_fail,
                "fail",
                &replay_key,
            ) {
                continue;
            }
            outbox_collection.records.insert(
                stored.id.clone(),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: stored.updated_at,
                    deleted: false,
                    value: stored,
                },
            );
        }
        std::fs::write(
            temp.path().join("uvm-node/outbox.json"),
            serde_json::to_vec(&outbox_collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let mut audit_events = read_audit_events(&audit_log_path);
        for event in &mut audit_events {
            if !migration_terminal_event_matches_replay_candidate(
                event,
                &runtime_after_fail,
                &migration_after_fail,
                "fail",
                &replay_key,
            ) {
                continue;
            }
            let uhost_types::EventPayload::Service(service_event) = &mut event.payload else {
                panic!("migration audit payload should be a service event");
            };
            let details = service_event
                .details
                .as_object_mut()
                .unwrap_or_else(|| panic!("migration audit details should be an object"));
            details.remove("migration_terminal_replay_key");
            details.remove("runtime_incarnation_sequence");
        }
        let mut audit_payload = Vec::new();
        for event in audit_events {
            audit_payload.extend_from_slice(
                &serde_json::to_vec(&event).unwrap_or_else(|error| panic!("{error}")),
            );
            audit_payload.push(b'\n');
        }
        std::fs::write(&audit_log_path, audit_payload).unwrap_or_else(|error| panic!("{error}"));

        let reopened_service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            count_total_migration_terminal_outbox_events_for_migration(
                &reopened_service,
                &migration_after_fail.id,
                "fail",
            )
            .await,
            0
        );
        assert_eq!(
            count_total_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &migration_after_fail.id,
                "fail",
            ),
            1
        );
        let relinked_operation = reopened_service
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration_after_fail.id.as_str(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reopened fail migrate node operation"));
        let relinked_operation_id = relinked_operation.value.id.clone();
        let mut legacy_reopened_operation = relinked_operation.value.clone();
        legacy_reopened_operation.linked_resource_kind = None;
        legacy_reopened_operation.linked_resource_id = None;
        legacy_reopened_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_reopened_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_reopened_operation.id.as_str().as_bytes(),
            ));
        reopened_service
            .node_operations
            .upsert(
                relinked_operation_id.as_str(),
                legacy_reopened_operation,
                Some(relinked_operation.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            reopened_service
                .find_node_operation_for_linked_resource(
                    UvmNodeOperationKind::Migrate,
                    "runtime_migration",
                    migration_after_fail.id.as_str(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let failed_retry = reopened_service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "fail",
                ResolveRuntimeMigrationRequest {
                    error: Some(String::from("transport stalled")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed_retry.status(), StatusCode::OK);

        let runtime_after_retry = reopened_service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let migration_after_retry = reopened_service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"))
            .value;
        assert_eq!(migration_after_retry.state, "failed");
        assert_eq!(
            migration_after_retry.failure_detail.as_deref(),
            Some("transport stalled")
        );
        assert_eq!(runtime_after_retry.node_id, source_node);
        assert_eq!(
            runtime_after_retry.last_error.as_deref(),
            Some("transport stalled")
        );
        assert_eq!(
            runtime_after_retry
                .current_incarnation
                .as_ref()
                .map(|value| value.sequence),
            Some(failure_sequence)
        );
        assert_eq!(
            list_node_operations(&reopened_service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Migrate
                        && operation.runtime_session_id.as_ref() == Some(&runtime_after_retry.id)
                        && operation.checkpoint_id.as_ref()
                            == Some(&migration_after_retry.checkpoint_id)
                })
                .count(),
            1
        );
        assert_eq!(
            count_total_migration_terminal_outbox_events_for_migration(
                &reopened_service,
                &migration_after_retry.id,
                "fail",
            )
            .await,
            1
        );
        assert_eq!(
            count_total_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &migration_after_retry.id,
                "fail",
            ),
            1
        );
        assert_eq!(
            count_migration_terminal_outbox_events_for_migration(
                &reopened_service,
                &runtime_after_retry,
                &migration_after_retry,
                "fail",
            )
            .await,
            1
        );
        assert_eq!(
            count_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &runtime_after_retry,
                &migration_after_retry,
                "fail",
            ),
            1
        );
        let linked_operation = reopened_service
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration_after_retry.id.as_str(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing relinked fail migrate node operation"));
        assert_eq!(linked_operation.value.id, relinked_operation_id);
    }

    #[tokio::test]
    async fn migration_fail_terminal_retry_relinks_legacy_operation_without_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime.id.to_string(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/fail-terminal-replay"),
                    memory_bitmap_hash: String::from("fa11bac1"),
                    disk_generation: 11,
                    reason: String::from("terminal replay relink"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration_id = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let failed = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "fail",
                ResolveRuntimeMigrationRequest {
                    error: Some(String::from("transport stalled")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed.status(), StatusCode::OK);

        let runtime_after_fail = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let migration_after_fail = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"))
            .value;
        let audit_log_path = temp.path().join("uvm-node/audit.log");

        let migrate_operation = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Migrate
                    && stored.value.runtime_session_id.as_ref() == Some(&runtime_after_fail.id)
                    && stored.value.linked_resource_id.as_deref()
                        == Some(migration_after_fail.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing fail migrate node operation"));
        let migrate_operation_id = migrate_operation.1.value.id.clone();
        let mut legacy_migrate_operation = migrate_operation.1.value.clone();
        legacy_migrate_operation.linked_resource_kind = None;
        legacy_migrate_operation.linked_resource_id = None;
        legacy_migrate_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_migrate_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_migrate_operation.id.as_str().as_bytes(),
            ));
        service
            .node_operations
            .upsert(
                migrate_operation.0.as_str(),
                legacy_migrate_operation,
                Some(migrate_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .find_node_operation_for_linked_resource(
                    UvmNodeOperationKind::Migrate,
                    "runtime_migration",
                    migration_after_fail.id.as_str(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let failed_retry = service
            .resolve_runtime_migration(
                migration_id.as_str(),
                "fail",
                ResolveRuntimeMigrationRequest {
                    error: Some(String::from("transport stalled")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed_retry.status(), StatusCode::OK);

        let runtime_after_retry = service
            .runtime_sessions
            .get(runtime.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime session"))
            .value;
        let migration_after_retry = service
            .runtime_migrations
            .get(migration_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime migration"))
            .value;
        assert_eq!(migration_after_retry.state, "failed");
        assert_eq!(
            count_total_migration_terminal_outbox_events_for_migration(
                &service,
                &migration_after_retry.id,
                "fail",
            )
            .await,
            1
        );
        assert_eq!(
            count_total_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &migration_after_retry.id,
                "fail",
            ),
            1
        );
        assert_eq!(
            count_migration_terminal_outbox_events_for_migration(
                &service,
                &runtime_after_retry,
                &migration_after_retry,
                "fail",
            )
            .await,
            1
        );
        assert_eq!(
            count_migration_terminal_audit_events_for_migration(
                &audit_log_path,
                &runtime_after_retry,
                &migration_after_retry,
                "fail",
            ),
            1
        );
        let linked_operation = service
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration_after_retry.id.as_str(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing relinked fail migrate node operation"));
        assert_eq!(linked_operation.value.id, migrate_operation_id);
        assert_eq!(
            list_node_operations(&service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Migrate
                        && operation.runtime_session_id.as_ref() == Some(&runtime_after_retry.id)
                        && operation.checkpoint_id.as_ref()
                            == Some(&migration_after_retry.checkpoint_id)
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn open_backfills_legacy_runtime_migration_node_operation_links() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let source_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let target_node = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let source_capability_id = create_test_node_capability(
            &service,
            &context,
            &source_node,
            vec![String::from("kvm")],
        )
        .await;
        let target_capability_id = create_test_node_capability(
            &service,
            &context,
            &target_node,
            vec![String::from("kvm")],
        )
        .await;
        let instance_id = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let created = register_basic_runtime_session(
            &service,
            &context,
            &instance_id,
            &source_node,
            &source_capability_id,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let runtime = service
            .runtime_sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime session"));
        let _ = service
            .transition_runtime_session(
                runtime.id.as_str(),
                VmRuntimeAction::Start,
                "start",
                None,
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let started = service
            .start_runtime_migration(
                StartRuntimeMigrationRequest {
                    runtime_session_id: runtime.id.to_string(),
                    to_node_id: target_node.to_string(),
                    target_capability_id: target_capability_id.clone(),
                    kind: String::from("live_precopy"),
                    checkpoint_uri: String::from("object://checkpoints/open-relink"),
                    memory_bitmap_hash: String::from("0ddba11"),
                    disk_generation: 12,
                    reason: String::from("open backfill relink"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.status(), StatusCode::CREATED);

        let migration = service
            .runtime_migrations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.clone())
            .unwrap_or_else(|| panic!("missing runtime migration"));
        let migrate_operation = service
            .node_operations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| {
                !stored.deleted
                    && stored.value.kind == UvmNodeOperationKind::Migrate
                    && stored.value.runtime_session_id.as_ref() == Some(&runtime.id)
                    && stored.value.linked_resource_id.as_deref() == Some(migration.id.as_str())
            })
            .unwrap_or_else(|| panic!("missing linked migrate node operation"));
        let migrate_operation_id = migrate_operation.1.value.id.clone();
        let mut legacy_migrate_operation = migrate_operation.1.value.clone();
        legacy_migrate_operation.linked_resource_kind = None;
        legacy_migrate_operation.linked_resource_id = None;
        legacy_migrate_operation.updated_at = time::OffsetDateTime::now_utc();
        legacy_migrate_operation
            .metadata
            .touch(uhost_core::sha256_hex(
                legacy_migrate_operation.id.as_str().as_bytes(),
            ));
        service
            .node_operations
            .upsert(
                migrate_operation.0.as_str(),
                legacy_migrate_operation,
                Some(migrate_operation.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .find_node_operation_for_linked_resource(
                    UvmNodeOperationKind::Migrate,
                    "runtime_migration",
                    migration.id.as_str(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let reopened_service = UvmNodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let relinked_operation = reopened_service
            .find_node_operation_for_linked_resource(
                UvmNodeOperationKind::Migrate,
                "runtime_migration",
                migration.id.as_str(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing relinked migrate node operation after open"));
        assert_eq!(relinked_operation.value.id, migrate_operation_id);
        assert_eq!(
            relinked_operation.value.linked_resource_kind.as_deref(),
            Some("runtime_migration")
        );
        assert_eq!(
            relinked_operation.value.linked_resource_id.as_deref(),
            Some(migration.id.as_str())
        );
        assert_eq!(
            list_node_operations(&reopened_service)
                .await
                .into_iter()
                .filter(|operation| {
                    operation.kind == UvmNodeOperationKind::Migrate
                        && operation.runtime_session_id.as_ref() == Some(&runtime.id)
                        && operation.checkpoint_id.as_ref() == Some(&migration.checkpoint_id)
                })
                .count(),
            1
        );
    }

    #[test]
    fn launch_spec_is_recoverable_from_runtime_session_record() {
        let runtime_session_id =
            uhost_types::UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let instance_id =
            uhost_types::UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            uhost_types::UvmNodeCapabilityId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime = super::UvmRuntimeSessionRecord {
            id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            node_id,
            capability_id,
            guest_architecture: String::from("x86_64"),
            vcpu: 2,
            memory_mb: 2048,
            guest_os: String::from("linux"),
            cpu_topology_profile: String::from("balanced"),
            numa_policy_profile: String::from("preferred_local"),
            planned_pinned_numa_nodes: vec![0],
            planned_memory_per_numa_mb: vec![2048],
            migration_policy: String::from("cold_only"),
            machine_family: String::from("microvm_linux"),
            guest_profile: String::from("linux_direct_kernel"),
            claim_tier: String::from("compatible"),
            planned_migration_checkpoint_kind: String::from("crash_consistent"),
            planned_migration_downtime_ms: 5000,
            accelerator_backend: String::from("kvm"),
            launch_program: String::from("uvm-kvm"),
            launch_args: vec![
                String::from("--session"),
                runtime_session_id.to_string(),
                String::from("--instance"),
                instance_id.to_string(),
                String::from("--arch"),
                String::from("x86_64"),
                String::from("--vcpu"),
                String::from("2"),
                String::from("--memory-mb"),
                String::from("2048"),
                String::from("--firmware"),
                String::from("uefi_secure"),
                String::from("--disk"),
                String::from("object://images/linux.raw"),
                String::from("--boot-device"),
                String::from("disk"),
                String::from("--secure-boot"),
            ],
            launch_env: vec![String::from("UVM_BACKEND=kvm")],
            isolation_profile: String::from("cgroup_v2"),
            boot_path: String::from("microvm"),
            execution_class: String::from("balanced"),
            memory_backing: String::from("anonymous"),
            device_model: String::from("virtio_minimal"),
            sandbox_layers: vec![String::from("seccomp"), String::from("cgroup_v2")],
            telemetry_streams: vec![String::from("heartbeat"), String::from("exit")],
            restart_policy: String::from("always"),
            max_restarts: 3,
            start_attempts: 0,
            state: VmRuntimeState::Registered,
            runner_phase: String::from("external_adapter"),
            worker_states: Vec::new(),
            runtime_evidence_mode: String::from("direct_host"),
            last_heartbeat_at: None,
            heartbeat_sequence: 0,
            last_runner_sequence_id: None,
            last_lifecycle_event_id: None,
            observed_pid: None,
            observed_assigned_memory_mb: None,
            hypervisor_health: String::from("unknown"),
            last_exit_reason: None,
            migration_in_progress: false,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            restore_count: 0,
            last_restore_at: None,
            current_incarnation: None,
            incarnation_lineage: Vec::new(),
            last_error: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            last_transition_at: time::OffsetDateTime::UNIX_EPOCH,
            metadata: uhost_types::ResourceMetadata::new(
                uhost_types::OwnershipScope::Platform,
                Some(runtime_session_id.to_string()),
                String::from("fingerprint"),
            ),
        };
        let launch_spec =
            launch_spec_from_runtime_session(&runtime).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            launch_spec.runtime_session_id,
            runtime_session_id.to_string()
        );
        assert_eq!(launch_spec.instance_id, instance_id.to_string());
        assert_eq!(launch_spec.disk_image, "object://images/linux.raw");
        assert_eq!(launch_spec.firmware_profile, "uefi_secure");
        assert!(launch_spec.firmware_artifact.is_none());
        assert_eq!(launch_spec.boot_device, "disk");
        assert!(launch_spec.cdrom_image.is_none());
        assert!(launch_spec.require_secure_boot);
    }

    #[test]
    fn software_launch_spec_recovery_preserves_firmware_artifact() {
        let runtime_session_id =
            uhost_types::UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let instance_id =
            uhost_types::UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let capability_id =
            uhost_types::UvmNodeCapabilityId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime = super::UvmRuntimeSessionRecord {
            id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            node_id,
            capability_id,
            guest_architecture: String::from("x86_64"),
            vcpu: 2,
            memory_mb: 2048,
            guest_os: String::from("linux"),
            cpu_topology_profile: String::from("balanced"),
            numa_policy_profile: String::from("preferred_local"),
            planned_pinned_numa_nodes: vec![0],
            planned_memory_per_numa_mb: vec![2048],
            migration_policy: String::from("cold_only"),
            machine_family: String::from("general_purpose_pci"),
            guest_profile: String::from("linux_standard"),
            claim_tier: String::from("compatible"),
            planned_migration_checkpoint_kind: String::from("crash_consistent"),
            planned_migration_downtime_ms: 5000,
            accelerator_backend: String::from("software_dbt"),
            launch_program: String::from("uhost-uvm-runner"),
            launch_args: vec![
                String::from("--session"),
                runtime_session_id.to_string(),
                String::from("--instance"),
                instance_id.to_string(),
                String::from("--arch"),
                String::from("x86_64"),
                String::from("--vcpu"),
                String::from("2"),
                String::from("--memory-mb"),
                String::from("2048"),
                String::from("--firmware"),
                String::from("uefi_standard"),
                String::from("--firmware-artifact"),
                String::from("file:///var/lib/uhost/firmware/custom-explicit.fd"),
                String::from("--disk"),
                String::from("file:///var/lib/uhost/images/linux.raw"),
                String::from("--boot-device"),
                String::from("disk"),
            ],
            launch_env: vec![String::from("UVM_BACKEND=software_dbt")],
            isolation_profile: String::from("cgroup_v2"),
            boot_path: String::from("general_purpose"),
            execution_class: String::from("balanced"),
            memory_backing: String::from("file_backed"),
            device_model: String::from("virtio_balanced"),
            sandbox_layers: vec![
                String::from("capability_drop"),
                String::from("cgroup_v2"),
                String::from("namespaces"),
                String::from("seccomp"),
            ],
            telemetry_streams: vec![String::from("heartbeat"), String::from("lifecycle")],
            restart_policy: String::from("on-failure"),
            max_restarts: 3,
            start_attempts: 0,
            state: VmRuntimeState::Registered,
            runner_phase: String::from("registered"),
            worker_states: software_runner_worker_states_for_phase("registered"),
            runtime_evidence_mode: String::from("simulated_guest"),
            last_heartbeat_at: None,
            heartbeat_sequence: 0,
            last_runner_sequence_id: None,
            last_lifecycle_event_id: None,
            observed_pid: None,
            observed_assigned_memory_mb: None,
            hypervisor_health: String::from("unknown"),
            last_exit_reason: None,
            migration_in_progress: false,
            last_checkpoint_id: None,
            restored_from_checkpoint_id: None,
            restore_count: 0,
            last_restore_at: None,
            current_incarnation: None,
            incarnation_lineage: Vec::new(),
            last_error: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            last_transition_at: time::OffsetDateTime::UNIX_EPOCH,
            metadata: uhost_types::ResourceMetadata::new(
                uhost_types::OwnershipScope::Platform,
                Some(runtime_session_id.to_string()),
                String::from("fingerprint"),
            ),
        };

        let launch_spec =
            launch_spec_from_runtime_session(&runtime).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            launch_spec.firmware_artifact.as_deref(),
            Some("file:///var/lib/uhost/firmware/custom-explicit.fd")
        );
        assert_eq!(launch_spec.firmware_profile, "uefi_standard");
        assert_eq!(
            launch_spec.disk_image,
            "file:///var/lib/uhost/images/linux.raw"
        );
    }
}
